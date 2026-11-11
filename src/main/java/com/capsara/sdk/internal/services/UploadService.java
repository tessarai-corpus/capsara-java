package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.SdkVersion;
import com.capsara.sdk.internal.http.ApiErrorParser;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpRetry;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.internal.upload.MultipartBuilder;
import com.capsara.sdk.models.PartyKey;
import com.capsara.sdk.models.SendResult;
import com.capsara.sdk.models.SystemLimits;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;

/** Service for uploading capsas to the API. */
public final class UploadService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    /** Server codes meaning our view of the party graph is stale — rebuild and retry. */
    private static final Set<String> STALE_PARTY_GRAPH_CODES =
            Set.of("KEYCHAIN_DELEGATES_MISMATCH", "KEYCHAIN_KEY_OUTDATED");

    /** Keychain rebuilds attempted per batch before giving up. */
    private static final int MAX_KEYCHAIN_REBUILDS = 1;

    /** A builder failed to build its capsa. */
    static final String BUILD_FAILED = "BUILD_FAILED";

    /** Fetching party keys or sending a request failed for a reason other than the transport. */
    static final String UPLOAD_FAILED = "UPLOAD_FAILED";

    /** The upload request timed out. */
    static final String UPLOAD_TIMEOUT = "UPLOAD_TIMEOUT";

    /** The send result body could not be read. */
    static final String INVALID_RESPONSE = "INVALID_RESPONSE";

    /** The server reported a capsa failure without a code. */
    static final String UNKNOWN_ERROR = "UNKNOWN_ERROR";

    /** Capsa id conflicts, reported per capsa and never retried automatically. */
    private static final Set<String> CAPSA_ID_CONFLICT_CODES =
            Set.of("ENVELOPE_ALREADY_EXISTS", "ENVELOPE_CREATION_IN_PROGRESS");

    /** Used when the API does not advertise a request limit. */
    private static final long FALLBACK_MAX_REQUEST_SIZE = 2048L * 1024 * 1024;
    private static final long FALLBACK_MAX_REQUEST_FIELD_BYTES = 64L * 1024 * 1024;
    private static final int FALLBACK_MAX_FILES_PER_REQUEST = 500;

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final KeyService keyService;
    private final int maxBatchSize;
    private final RetryConfig retryConfig;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;

    /** Reads the API-advertised limits, so the client splits on the server's number. */
    private Supplier<SystemLimits> limitsSupplier;

    /**
     * Constructs an UploadService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param keyService        key service for fetching public keys
     * @param maxBatchSize      maximum batch size for capsas
     * @param retryConfig       retry configuration
     * @param timeout           timeout configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public UploadService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                         KeyService keyService, int maxBatchSize, RetryConfig retryConfig,
                         HttpTimeoutConfig timeout, String userAgent, ConcurrencyConfig concurrencyConfig) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.keyService = keyService;
        this.maxBatchSize = Math.max(maxBatchSize, 1);
        this.retryConfig = retryConfig != null ? retryConfig : RetryConfig.defaults();
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
    }

    /**
     * Supply the API-advertised limits, used to split requests on the same byte count
     * the server measures. Without one, a conservative default applies.
     *
     * @param limitsSupplier reads the current system limits
     */
    public void setLimitsSupplier(Supplier<SystemLimits> limitsSupplier) {
        this.limitsSupplier = limitsSupplier;
    }

    /**
     * Send capsas with automatic batch splitting.
     *
     * @param builders  array of CapsaBuilder instances
     * @param creatorId creator party ID
     * @return send result
     */
    public CompletableFuture<SendResult> sendCapsasAsync(CapsaBuilder[] builders, String creatorId) {
        return CompletableFuture.supplyAsync(() -> {
            if (builders == null || builders.length == 0) {
                throw CapsaraException.validationError("No capsas provided to send", null);
            }

            if (builders.length > 500) {
                throw CapsaraException.validationError("Send limited to 500 capsas per request", null);
            }

            SystemLimits limits = null;
            RuntimeException limitsFailure = null;
            try {
                limits = limitsSupplier == null ? null : limitsSupplier.get();
            } catch (RuntimeException ex) {
                limitsFailure = ex;
            }
            int maxFilesPerRequest = effectiveFileLimit(limits == null ? null : limits.getMaxFilesPerRequest());

            for (int i = 0; i < builders.length; i++) {
                if (builders[i].getRecipientIds().length == 0) {
                    throw CapsaraException.validationError(
                            String.format("Capsa at index %d has no recipient. Call addRecipient() "
                                    + "with the party this capsa is sent to.", i), Map.of("index", i));
                }
                int fileCount = builders[i].getFileCount();
                if (fileCount > maxFilesPerRequest) {
                    throw CapsaraException.validationError(
                            String.format("Capsa at index %d has %d files, exceeding the batch limit of %d files.",
                                    i, fileCount, maxFilesPerRequest), Map.of("index", i));
                }
            }

            return sendInBalancedBatches(builders, creatorId, limits, limitsFailure, maxFilesPerRequest);
        });
    }

    private SendResult sendInBalancedBatches(CapsaBuilder[] builders, String creatorId, SystemLimits limits,
            RuntimeException limitsFailure, int maxFilesPerRequest) {
        List<CapsaBuilder[]> chunks = new ArrayList<>();
        List<CapsaBuilder> currentChunk = new ArrayList<>();
        int currentChunkFileCount = 0;

        for (CapsaBuilder builder : builders) {
            int builderFileCount = builder.getFileCount();
            boolean wouldExceedCapsaLimit = currentChunk.size() >= maxBatchSize;
            boolean wouldExceedFileLimit = currentChunkFileCount + builderFileCount > maxFilesPerRequest;

            if (!currentChunk.isEmpty() && (wouldExceedCapsaLimit || wouldExceedFileLimit)) {
                chunks.add(currentChunk.toArray(new CapsaBuilder[0]));
                currentChunk = new ArrayList<>();
                currentChunk.add(builder);
                currentChunkFileCount = builderFileCount;
            } else {
                currentChunk.add(builder);
                currentChunkFileCount += builderFileCount;
            }
        }

        if (!currentChunk.isEmpty()) {
            chunks.add(currentChunk.toArray(new CapsaBuilder[0]));
        }

        List<SendResult.CreatedCapsa> created = new ArrayList<>();
        List<SendResult.SendError> errors = new ArrayList<>();
        List<String> batchIds = new ArrayList<>();
        int offset = 0;

        for (CapsaBuilder[] chunk : chunks) {
            List<Pending> pending = new ArrayList<>();
            Set<String> allPartyIds = new HashSet<>();
            allPartyIds.add(creatorId);
            for (int i = 0; i < chunk.length; i++) {
                pending.add(new Pending(chunk[i], offset + i, null));
                Collections.addAll(allPartyIds, chunk[i].getRecipientIds());
            }
            offset += chunk.length;
            String[] partyIds = allPartyIds.toArray(new String[0]);

            PartyKey[] partyKeys;
            try {
                partyKeys = keyService.fetchPartyKeysAsync(partyIds).join();
            } catch (RuntimeException ex) {
                for (Pending p : pending) {
                    errors.add(failure(p.position, null, ex, UPLOAD_FAILED));
                }
                continue;
            }

            List<Pending> built = buildAll(pending, partyKeys, errors);
            if (built.isEmpty()) {
                continue;
            }

            List<List<Pending>> groups;
            try {
                if (limitsFailure != null) {
                    throw limitsFailure;
                }
                groups = splitByRequestSize(built,
                        effectiveLimit(limits == null ? null : limits.getMaxRequestSize(),
                                FALLBACK_MAX_REQUEST_SIZE),
                        effectiveLimit(limits == null ? null : limits.getMaxRequestFieldBytes(),
                                FALLBACK_MAX_REQUEST_FIELD_BYTES));
            } catch (RuntimeException ex) {
                for (Pending p : built) {
                    errors.add(failure(p.position, p.built.getCapsa().getPackageId(), ex, UPLOAD_FAILED));
                }
                continue;
            }

            for (List<Pending> group : groups) {
                try {
                    GroupOutcome outcome = sendGroup(group, creatorId, partyIds);
                    created.addAll(outcome.created);
                    errors.addAll(outcome.errors);
                    if (outcome.batchId != null) {
                        batchIds.add(outcome.batchId);
                    }
                } catch (RuntimeException ex) {
                    for (Pending p : group) {
                        errors.add(failure(p.position, p.built.getCapsa().getPackageId(), ex, UPLOAD_FAILED));
                    }
                }
            }
        }

        created.sort(Comparator.comparingInt(SendResult.CreatedCapsa::getIndex));
        errors.sort(Comparator.comparingInt(SendResult.SendError::getIndex));

        SendResult aggregated = new SendResult();
        aggregated.setBatchId(batchIds.isEmpty() ? "batch_" + System.currentTimeMillis() : batchIds.get(0));
        aggregated.setSuccessful(created.size());
        aggregated.setFailed(errors.size());
        aggregated.setPartialSuccess(!created.isEmpty() && !errors.isEmpty());
        aggregated.setCreated(created);
        aggregated.setErrors(errors.isEmpty() ? null : errors);

        return aggregated;
    }

    /** A builder, its position in the caller's array, and its built capsa once built. */
    private static final class Pending {
        private final CapsaBuilder builder;
        private final int position;
        private final BuiltCapsa built;

        Pending(CapsaBuilder builder, int position, BuiltCapsa built) {
            this.builder = builder;
            this.position = position;
            this.built = built;
        }
    }

    /** Created and failed capsas reported for one request, indexed by caller position. */
    private static final class GroupOutcome {
        private final String batchId;
        private final List<SendResult.CreatedCapsa> created;
        private final List<SendResult.SendError> errors;

        GroupOutcome(String batchId, List<SendResult.CreatedCapsa> created, List<SendResult.SendError> errors) {
            this.batchId = batchId;
            this.created = created;
            this.errors = errors;
        }
    }

    /**
     * Build each pending capsa, recording a failure for any that does not build.
     *
     * @param pending   capsas to build
     * @param partyKeys public keys of every party referenced
     * @param errors    receives a failure per capsa that did not build
     * @return the capsas that built
     */
    private static List<Pending> buildAll(List<Pending> pending, PartyKey[] partyKeys,
                                          List<SendResult.SendError> errors) {
        List<Pending> built = new ArrayList<>();
        for (Pending p : pending) {
            try {
                built.add(new Pending(p.builder, p.position, p.builder.buildAsync(partyKeys).join()));
            } catch (RuntimeException ex) {
                errors.add(failure(p.position, null, ex, BUILD_FAILED));
            }
        }
        return built;
    }

    /**
     * A per-capsa failure; an SDK exception keeps its own code.
     *
     * @param position     capsa position in the caller's array
     * @param packageId    built capsa id, may be null
     * @param error        the failure
     * @param fallbackCode code used when the failure is not an SDK exception
     * @return the failure entry
     */
    private static SendResult.SendError failure(int position, String packageId, Throwable error,
                                                String fallbackCode) {
        Throwable cause = error instanceof CompletionException && error.getCause() != null
                ? error.getCause()
                : error;
        SendResult.SendError sendError = new SendResult.SendError();
        sendError.setIndex(position);
        sendError.setPackageId(packageId);
        sendError.setCode(cause instanceof CapsaraException ? ((CapsaraException) cause).getCode() : fallbackCode);
        sendError.setMessage(cause.getMessage());
        return sendError;
    }

    private static long encryptedSize(BuiltCapsa built) {
        long total = 0;
        for (BuiltCapsa.EncryptedFileData file : built.getFiles()) {
            total += file.getData().length;
        }
        return total;
    }

    /**
     * UTF-8 byte length of a capsa's JSON form field, serialized as it is sent.
     *
     * @param capsa capsa upload data
     * @return bytes of the serialized field
     */
    static long jsonBytes(Object capsa) {
        try {
            return OBJECT_MAPPER.writeValueAsString(capsa).getBytes(StandardCharsets.UTF_8).length;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize capsa metadata", e);
        }
    }

    /**
     * An advertised limit, or the fallback when it is missing or not positive.
     *
     * @param advertised value from the API, may be null
     * @param fallback   value used otherwise
     * @return the limit to apply
     */
    static long effectiveLimit(Long advertised, long fallback) {
        return advertised != null && advertised > 0 ? advertised : fallback;
    }

    /**
     * The advertised files-per-request limit, or 500 when it is missing or not positive.
     *
     * @param advertised value from the API, may be null
     * @return the file count limit to apply per request
     */
    static int effectiveFileLimit(Integer advertised) {
        return advertised != null && advertised > 0 ? advertised : FALLBACK_MAX_FILES_PER_REQUEST;
    }

    /**
     * Plan requests greedily in send order under the request byte and JSON field byte limits.
     *
     * @param jsonBytes            JSON field bytes per capsa
     * @param fileBytes            encrypted file bytes per capsa
     * @param maxRequestSize       maximum JSON plus file bytes per request
     * @param maxRequestFieldBytes maximum JSON field bytes per request
     * @return capsa indexes per request; a capsa over a limit on its own goes alone
     */
    static List<List<Integer>> planRequests(long[] jsonBytes, long[] fileBytes, long maxRequestSize,
            long maxRequestFieldBytes) {
        List<List<Integer>> plan = new ArrayList<>();
        List<Integer> current = new ArrayList<>();
        long requestCost = 0;
        long requestJson = 0;
        for (int i = 0; i < jsonBytes.length; i++) {
            long cost = jsonBytes[i] + fileBytes[i];
            if (!current.isEmpty()
                    && (requestCost + cost > maxRequestSize || requestJson + jsonBytes[i] > maxRequestFieldBytes)) {
                plan.add(current);
                current = new ArrayList<>();
                requestCost = 0;
                requestJson = 0;
            }
            current.add(i);
            requestCost += cost;
            requestJson += jsonBytes[i];
        }
        if (!current.isEmpty()) {
            plan.add(current);
        }
        return plan;
    }

    private static List<List<Pending>> splitByRequestSize(List<Pending> pairs, long maxRequestSize,
            long maxRequestFieldBytes) {
        long[] json = new long[pairs.size()];
        long[] files = new long[pairs.size()];
        for (int i = 0; i < pairs.size(); i++) {
            json[i] = jsonBytes(pairs.get(i).built.getCapsa());
            files[i] = encryptedSize(pairs.get(i).built);
        }
        List<List<Pending>> groups = new ArrayList<>();
        for (List<Integer> request : planRequests(json, files, maxRequestSize, maxRequestFieldBytes)) {
            List<Pending> group = new ArrayList<>();
            for (int index : request) {
                group.add(pairs.get(index));
            }
            groups.add(group);
        }
        return groups;
    }

    /**
     * Assemble and send one group, rebuilding once if the party graph moved.
     *
     * @param group     built capsas with their caller positions
     * @param creatorId creator party ID
     * @param partyIds  every party referenced by the enclosing batch
     * @return created and failed capsas, indexed by caller position
     */
    private GroupOutcome sendGroup(List<Pending> group, String creatorId, String[] partyIds) {
        List<Pending> current = group;
        List<SendResult.SendError> rebuildErrors = new ArrayList<>();

        for (int attempt = 0; ; attempt++) {
            MultipartBuilder multipartBuilder = new MultipartBuilder();
            multipartBuilder.addMetadata(current.size(), creatorId);

            for (int capsaIndex = 0; capsaIndex < current.size(); capsaIndex++) {
                BuiltCapsa builtCapsa = current.get(capsaIndex).built;
                multipartBuilder.addCapsaMetadata(builtCapsa.getCapsa(), capsaIndex);

                for (BuiltCapsa.EncryptedFileData file : builtCapsa.getFiles()) {
                    multipartBuilder.addFileBinary(file.getData(), file.getMetadata().getFileId());
                }
            }

            GroupOutcome outcome;
            try {
                JsonNode body = sendRequestAsync(multipartBuilder.build(), multipartBuilder.getContentType())
                        .join();
                outcome = mapResponse(body, current);
            } catch (CompletionException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                if (cause instanceof CapsaraException
                        && CAPSA_ID_CONFLICT_CODES.contains(((CapsaraException) cause).getCode())) {
                    outcome = idConflict(current, (CapsaraException) cause);
                } else if (!isStalePartyGraph(e) || attempt >= MAX_KEYCHAIN_REBUILDS) {
                    throw e;
                } else {
                    PartyKey[] partyKeys = keyService.fetchPartyKeysAsync(partyIds).join();
                    current = buildAll(current, partyKeys, rebuildErrors);
                    if (current.isEmpty()) {
                        return new GroupOutcome(null, new ArrayList<>(), rebuildErrors);
                    }
                    continue;
                }
            }

            outcome.errors.addAll(rebuildErrors);
            return outcome;
        }
    }

    /**
     * Map a send result body to caller positions using each item's index within the request.
     *
     * @param body send result body
     * @param sent capsas in the order they were sent
     * @return created and failed capsas, indexed by caller position
     */
    private static GroupOutcome mapResponse(JsonNode body, List<Pending> sent) {
        List<JsonNode> createdItems = items(body, "created");
        List<JsonNode> errorItems = items(body, "errors");
        String batchId = text(body, "batchId");

        boolean[] answered = new boolean[sent.size()];
        List<JsonNode> allItems = new ArrayList<>(createdItems);
        allItems.addAll(errorItems);
        for (JsonNode item : allItems) {
            int index = requestIndex(item, sent.size());
            if (index < 0 || answered[index]) {
                List<SendResult.SendError> errors = new ArrayList<>();
                for (Pending p : sent) {
                    errors.add(invalidResponse(p,
                            "Send response has a missing, duplicate or out-of-range capsa index"));
                }
                return new GroupOutcome(batchId, new ArrayList<>(), errors);
            }
            answered[index] = true;
        }

        List<SendResult.CreatedCapsa> created = new ArrayList<>();
        for (JsonNode item : createdItems) {
            SendResult.CreatedCapsa createdCapsa = new SendResult.CreatedCapsa();
            createdCapsa.setIndex(sent.get(item.get("index").asInt()).position);
            createdCapsa.setPackageId(text(item, "packageId"));
            createdCapsa.setCreatedAt(text(item, "createdAt"));
            created.add(createdCapsa);
        }

        List<SendResult.SendError> errors = new ArrayList<>();
        for (JsonNode item : errorItems) {
            String code = text(item, "code");
            String message = text(item, "message");
            SendResult.SendError sendError = new SendResult.SendError();
            sendError.setIndex(sent.get(item.get("index").asInt()).position);
            sendError.setPackageId(text(item, "packageId"));
            sendError.setCode(code == null || code.isEmpty() ? UNKNOWN_ERROR : code);
            sendError.setMessage(message == null ? "Capsa was not created" : message);
            errors.add(sendError);
        }

        for (int i = 0; i < sent.size(); i++) {
            if (!answered[i]) {
                errors.add(invalidResponse(sent.get(i), "Send response did not report this capsa"));
            }
        }

        return new GroupOutcome(batchId, created, errors);
    }

    /**
     * Position of a result item within its request.
     *
     * @param item        a created or errors item
     * @param requestSize number of capsas in the request
     * @return the index, or -1 when it is missing, not an integer or out of range
     */
    private static int requestIndex(JsonNode item, int requestSize) {
        JsonNode index = item == null ? null : item.get("index");
        if (index == null || !index.isNumber()) {
            return -1;
        }
        double value = index.doubleValue();
        if (value != Math.rint(value) || value < 0 || value >= requestSize) {
            return -1;
        }
        return (int) value;
    }

    private static SendResult.SendError invalidResponse(Pending pending, String message) {
        SendResult.SendError sendError = new SendResult.SendError();
        sendError.setIndex(pending.position);
        sendError.setPackageId(pending.built.getCapsa().getPackageId());
        sendError.setCode(INVALID_RESPONSE);
        sendError.setMessage(message);
        return sendError;
    }

    private static List<JsonNode> items(JsonNode body, String field) {
        List<JsonNode> items = new ArrayList<>();
        JsonNode array = body.get(field);
        if (array != null && array.isArray()) {
            array.forEach(items::add);
        }
        return items;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    /**
     * Per-capsa failures for a group refused with a capsa id conflict.
     *
     * @param sent  the capsas that were sent
     * @param error the 409 the server answered with
     * @return every capsa of the group failed with the server's code
     */
    private static GroupOutcome idConflict(List<Pending> sent, CapsaraException error) {
        List<SendResult.SendError> errors = new ArrayList<>();
        for (Pending p : sent) {
            SendResult.SendError sendError = new SendResult.SendError();
            sendError.setIndex(p.position);
            sendError.setPackageId(p.built.getCapsa().getPackageId());
            sendError.setCode(error.getCode());
            sendError.setMessage(error.getMessage());
            errors.add(sendError);
        }
        return new GroupOutcome(null, new ArrayList<>(), errors);
    }

    /**
     * Whether a failed upload was rejected because our party graph view was stale.
     *
     * @param error the failure thrown by the upload
     * @return true if the server reported outdated keys or delegates
     */
    private static boolean isStalePartyGraph(Throwable error) {
        Throwable cause = error.getCause() != null ? error.getCause() : error;
        return cause instanceof CapsaraException
                && STALE_PARTY_GRAPH_CODES.contains(((CapsaraException) cause).getCode());
    }

    /**
     * POST one multipart request under the shared retry policy.
     *
     * @param body        multipart body
     * @param contentType multipart content type with boundary
     * @return send result body for this request, indexes relative to the request
     */
    private CompletableFuture<JsonNode> sendRequestAsync(byte[] body, String contentType) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/capsas"))
                .timeout(timeout.getUploadTimeout())
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));

        if (userAgent != null && !userAgent.isEmpty()) {
            builder.header("User-Agent", userAgent);
        }
        builder.header("X-SDK-Version", SdkVersion.VERSION);

        String token = tokenSupplier != null ? tokenSupplier.get() : null;
        if (token != null && !token.isEmpty()) {
            builder.header("Authorization", "Bearer " + token);
        }

        HttpRequest request = builder.build();

        return HttpRetry.send(httpClient, request, HttpResponse.BodyHandlers.ofString(), retryConfig,
                        concurrencyConfig)
                .handle((response, error) -> {
                    if (error != null) {
                        throw uploadFailure(HttpRetry.unwrap(error));
                    }
                    int status = response.statusCode();
                    String responseBody = response.body();

                    if (status >= 200 && status < 300) {
                        JsonNode result = readJsonObject(responseBody);
                        if (result == null) {
                            throw new CapsaraException("Send response could not be parsed", INVALID_RESPONSE,
                                    status, null, responseBody);
                        }
                        return result;
                    }

                    if (status == 422) {
                        JsonNode result = readJsonObject(responseBody);
                        if (result != null && (result.path("created").isArray() || result.path("errors").isArray())) {
                            return result;
                        }
                    }

                    throw CapsaraCapsaException.fromApiError(
                            ApiErrorParser.parse(status, responseBody, response.headers()));
                });
    }

    private RuntimeException uploadFailure(Throwable cause) {
        if (cause instanceof CapsaraException) {
            return (CapsaraException) cause;
        }
        if (cause instanceof HttpTimeoutException) {
            return new CapsaraException(
                    "Upload timed out after " + timeout.getUploadTimeout().toSeconds() + " seconds",
                    UPLOAD_TIMEOUT, 0, null, null, null, cause);
        }
        if (cause instanceof IOException) {
            return CapsaraException.networkError(cause);
        }
        return cause instanceof RuntimeException ? (RuntimeException) cause : new CompletionException(cause);
    }

    /**
     * Parse a response body as a JSON object.
     *
     * @param responseBody response body
     * @return the object, or null when the body is not a JSON object
     */
    private static JsonNode readJsonObject(String responseBody) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(responseBody);
            return root != null && root.isObject() ? root : null;
        } catch (Exception e) {
            return null;
        }
    }

}
