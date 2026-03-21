package com.capsara.sdk.internal.services;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.SdkVersion;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.internal.upload.MultipartBuilder;
import com.capsara.sdk.models.PartyKey;
import com.capsara.sdk.models.SendResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/** Service for uploading capsas to the API. */
public final class UploadService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final int MAX_FILES_PER_BATCH = 500;

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final KeyService keyService;
    private final int maxBatchSize;
    private final RetryConfig retryConfig;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;

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
        this.maxBatchSize = maxBatchSize > 0 ? maxBatchSize : 100;
        this.retryConfig = retryConfig != null ? retryConfig : RetryConfig.defaults();
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
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
                throw new IllegalArgumentException("No capsas provided to send");
            }

            if (builders.length > 500) {
                throw new IllegalArgumentException("Send limited to 500 capsas per request");
            }

            for (int i = 0; i < builders.length; i++) {
                int fileCount = builders[i].getFileCount();
                if (fileCount > MAX_FILES_PER_BATCH) {
                    throw new IllegalArgumentException(
                            String.format("Capsa at index %d has %d files, exceeding the batch limit of %d files.",
                                    i, fileCount, MAX_FILES_PER_BATCH));
                }
            }

            return sendInBalancedBatches(builders, creatorId);
        });
    }

    private SendResult sendInBalancedBatches(CapsaBuilder[] builders, String creatorId) {
        List<CapsaBuilder[]> chunks = new ArrayList<>();
        List<CapsaBuilder> currentChunk = new ArrayList<>();
        int currentChunkFileCount = 0;

        for (CapsaBuilder builder : builders) {
            int builderFileCount = builder.getFileCount();
            boolean wouldExceedCapsaLimit = currentChunk.size() >= maxBatchSize;
            boolean wouldExceedFileLimit = currentChunkFileCount + builderFileCount > MAX_FILES_PER_BATCH;

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

        List<SendResult> results = new ArrayList<>();
        int currentOffset = 0;

        for (CapsaBuilder[] chunk : chunks) {
            try {
                Set<String> allPartyIds = new HashSet<>();
                allPartyIds.add(creatorId);
                for (CapsaBuilder builder : chunk) {
                    Collections.addAll(allPartyIds, builder.getRecipientIds());
                }

                PartyKey[] partyKeys = keyService.fetchPartyKeysAsync(
                        allPartyIds.toArray(new String[0])).join();

                List<BuiltCapsa> builtCapsas = new ArrayList<>();
                for (CapsaBuilder builder : chunk) {
                    BuiltCapsa built = builder.buildAsync(partyKeys).join();
                    builtCapsas.add(built);
                }

                MultipartBuilder multipartBuilder = new MultipartBuilder();
                multipartBuilder.addMetadata(chunk.length, creatorId);

                for (int capsaIndex = 0; capsaIndex < builtCapsas.size(); capsaIndex++) {
                    BuiltCapsa builtCapsa = builtCapsas.get(capsaIndex);
                    multipartBuilder.addCapsaMetadata(builtCapsa.getCapsa(), capsaIndex);

                    for (BuiltCapsa.EncryptedFileData file : builtCapsa.getFiles()) {
                        multipartBuilder.addFileBinary(file.getData(), file.getMetadata().getFileId());
                    }
                }

                byte[] body = multipartBuilder.build();
                SendResult result = sendWithRetryAsync(body, multipartBuilder.getContentType(), 0).join();

                List<SendResult.CreatedCapsa> adjustedCreated = new ArrayList<>();
                if (result.getCreated() != null) {
                    for (SendResult.CreatedCapsa c : result.getCreated()) {
                        SendResult.CreatedCapsa adjusted = new SendResult.CreatedCapsa();
                        adjusted.setPackageId(c.getPackageId());
                        adjusted.setIndex(c.getIndex() + currentOffset);
                        adjustedCreated.add(adjusted);
                    }
                }

                List<SendResult.SendError> adjustedErrors = null;
                if (result.getErrors() != null) {
                    adjustedErrors = new ArrayList<>();
                    for (SendResult.SendError e : result.getErrors()) {
                        SendResult.SendError adjusted = new SendResult.SendError();
                        adjusted.setIndex(e.getIndex() + currentOffset);
                        adjusted.setPackageId(e.getPackageId());
                        adjusted.setError(e.getError());
                        adjustedErrors.add(adjusted);
                    }
                }

                SendResult adjustedResult = new SendResult();
                adjustedResult.setBatchId(result.getBatchId());
                adjustedResult.setSuccessful(result.getSuccessful());
                adjustedResult.setFailed(result.getFailed());
                adjustedResult.setPartialSuccess(result.getPartialSuccess());
                adjustedResult.setCreated(adjustedCreated);
                adjustedResult.setErrors(adjustedErrors);

                results.add(adjustedResult);
                currentOffset += chunk.length;
            } catch (Exception ex) {
                List<SendResult.SendError> failedErrors = new ArrayList<>();
                for (int index = 0; index < chunk.length; index++) {
                    SendResult.SendError error = new SendResult.SendError();
                    error.setIndex(currentOffset + index);
                    error.setPackageId("");
                    error.setError(ex.getMessage());
                    failedErrors.add(error);
                }

                SendResult failedResult = new SendResult();
                failedResult.setBatchId("");
                failedResult.setSuccessful(0);
                failedResult.setFailed(chunk.length);
                failedResult.setPartialSuccess(false);
                failedResult.setCreated(new ArrayList<>());
                failedResult.setErrors(failedErrors);

                results.add(failedResult);
                currentOffset += chunk.length;
            }
        }

        List<SendResult.SendError> allErrors = results.stream()
                .filter(r -> r.getErrors() != null)
                .flatMap(r -> r.getErrors().stream())
                .collect(Collectors.toList());

        List<SendResult.CreatedCapsa> allCreated = results.stream()
                .filter(r -> r.getCreated() != null)
                .flatMap(r -> r.getCreated().stream())
                .collect(Collectors.toList());

        int totalSuccessful = results.stream().mapToInt(SendResult::getSuccessful).sum();
        int totalFailed = results.stream().mapToInt(SendResult::getFailed).sum();

        boolean partialSuccess = results.stream().anyMatch(r -> Boolean.TRUE.equals(r.getPartialSuccess())) ||
                (results.stream().anyMatch(r -> r.getSuccessful() > 0) &&
                        results.stream().anyMatch(r -> r.getFailed() > 0));

        SendResult aggregated = new SendResult();
        aggregated.setBatchId(results.isEmpty() || results.get(0).getBatchId() == null
                ? "batch_" + System.currentTimeMillis()
                : results.get(0).getBatchId());
        aggregated.setSuccessful(totalSuccessful);
        aggregated.setFailed(totalFailed);
        aggregated.setPartialSuccess(partialSuccess);
        aggregated.setCreated(allCreated);
        aggregated.setErrors(allErrors.isEmpty() ? null : allErrors);

        return aggregated;
    }

    private CompletableFuture<SendResult> sendWithRetryAsync(byte[] body, String contentType, int retryCount) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/capsas"))
                .timeout(timeout.getRequestTimeout())
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

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenComposeAsync(response -> {
                    String responseBody = response.body();

                    if (response.statusCode() >= 200 && response.statusCode() < 300 || response.statusCode() == 207) {
                        try {
                            return CompletableFuture.completedFuture(
                                    OBJECT_MAPPER.readValue(responseBody, SendResult.class));
                        } catch (Exception e) {
                            return CompletableFuture.failedFuture(CapsaraException.networkError(e));
                        }
                    }

                    boolean isRetryable = response.statusCode() == 503 || response.statusCode() == 429;
                    if (isRetryable && retryCount < retryConfig.getMaxRetries()) {
                        return delayedRetryUpload(body, contentType, responseBody, retryCount);
                    }

                    return CompletableFuture.failedFuture(
                            CapsaraCapsaException.fromHttpResponse(response.statusCode(), responseBody));
                }, concurrencyConfig.getResponseExecutor())
                .exceptionallyCompose(error -> {
                    Throwable cause = error.getCause() != null ? error.getCause() : error;

                    if (cause instanceof CapsaraException) {
                        return CompletableFuture.failedFuture(cause);
                    }

                    if (retryCount < retryConfig.getMaxRetries()) {
                        return delayedRetryUpload(body, contentType, null, retryCount);
                    }

                    return CompletableFuture.failedFuture(CapsaraException.networkError(cause));
                });
    }

    private CompletableFuture<SendResult> delayedRetryUpload(byte[] body, String contentType,
                                                              String responseBody, int retryCount) {
        Duration delay = calculateRetryDelay(responseBody, retryCount);
        Executor delayedExecutor = CompletableFuture.delayedExecutor(delay.toMillis(), TimeUnit.MILLISECONDS);
        return CompletableFuture.supplyAsync(() -> null, delayedExecutor)
                .thenCompose(ignored -> sendWithRetryAsync(body, contentType, retryCount + 1));
    }

    private Duration calculateRetryDelay(String responseBody, int retryCount) {
        try {
            JsonNode doc = OBJECT_MAPPER.readTree(responseBody);
            JsonNode errorNode = doc.get("error");
            if (errorNode != null) {
                JsonNode retryAfterNode = errorNode.get("retryAfter");
                if (retryAfterNode != null && retryAfterNode.isInt()) {
                    Duration serverDelay = Duration.ofSeconds(retryAfterNode.asInt());
                    return serverDelay.compareTo(retryConfig.getMaxDelay()) > 0
                            ? retryConfig.getMaxDelay()
                            : serverDelay;
                }
            }
        } catch (Exception ignored) {
            // Parse failed, use exponential backoff
        }

        Duration baseDelay = retryConfig.getDelayForAttempt(retryCount);
        double jitter = Math.random() * 0.3 * baseDelay.toMillis();
        Duration totalDelay = Duration.ofMillis((long) (baseDelay.toMillis() + jitter));

        return totalDelay.compareTo(retryConfig.getMaxDelay()) > 0
                ? retryConfig.getMaxDelay()
                : totalDelay;
    }
}
