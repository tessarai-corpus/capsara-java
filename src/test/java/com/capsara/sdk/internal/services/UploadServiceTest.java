package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.SendResult;
import com.capsara.sdk.models.SystemLimits;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/** Send path against a local server: per-capsa results, codes and the stale-keychain rebuild. */
class UploadServiceTest {

    private static final String CREATOR = "party_creator_upload";
    private static final String RECIPIENT = "party_recipient_upload";
    private static final String UNUSABLE_KEY_RECIPIENT = "party_unusable_key";
    private static final String CAPSAS = "/api/capsas";
    private static final String KEYS = "/api/party/keys";

    private StubServer server;
    private ConcurrencyConfig concurrency;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        concurrency = new ConcurrencyConfig();
        server.on(KEYS, StubServer.json(200, partyKeysBody()));
    }

    @AfterEach
    void stop() {
        server.close();
        concurrency.shutdown();
    }

    private UploadService service(int maxBatchSize) {
        return service(maxBatchSize, null);
    }

    private UploadService service(int maxBatchSize, HttpTimeoutConfig timeout) {
        HttpClient client = HttpClientFactory.createDefault();
        RetryConfig retry = new RetryConfig(2, Duration.ofMillis(1), 1.0, Duration.ofMillis(5));
        KeyService keys = new KeyService(client, server.baseUrl(), () -> "token", null, retry, null, concurrency);
        return new UploadService(client, server.baseUrl(), () -> "token", keys, maxBatchSize, retry,
                timeout, null, concurrency);
    }

    private static CapsaBuilder builder() {
        return builder(RECIPIENT);
    }

    private static CapsaBuilder builder(String recipient) {
        GeneratedKeyPairResult creator = SharedKeyFixture.getPrimaryKeyPair();
        CapsaBuilder builder = new CapsaBuilder(CREATOR, creator.getPrivateKey(), null);
        builder.setExpiresAt(OffsetDateTime.now().plusDays(7));
        builder.addRecipient(recipient).addTextFile("a.txt", "hello").withSubject("s");
        return builder;
    }

    private static String partyKeysBody() {
        ObjectNode root = JsonMapper.getInstance().createObjectNode();
        ArrayNode parties = root.putArray("parties");
        addParty(parties, CREATOR, SharedKeyFixture.getPrimaryKeyPair());
        addParty(parties, RECIPIENT, SharedKeyFixture.getSecondaryKeyPair());
        ObjectNode unusable = parties.addObject();
        unusable.put("id", UNUSABLE_KEY_RECIPIENT);
        unusable.put("publicKey", "not a public key");
        unusable.put("fingerprint", "00");
        unusable.put("kind", "user");
        return root.toString();
    }

    private static void addParty(ArrayNode parties, String id, GeneratedKeyPairResult keys) {
        ObjectNode party = parties.addObject();
        party.put("id", id);
        party.put("publicKey", keys.getPublicKey());
        party.put("fingerprint", keys.getFingerprint());
        party.put("kind", "user");
    }

    private SendResult send(UploadService service, CapsaBuilder... builders) {
        return service.sendCapsasAsync(builders, CREATOR).join();
    }

    @Test
    void staleKeychain409_refetchesKeysOnceAndResends() {
        server.on(CAPSAS,
                StubServer.json(409, "{\"error\":{\"code\":\"KEYCHAIN_KEY_OUTDATED\","
                        + "\"message\":\"Recipient key changed; rebuild and retry\"}}"),
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}]}"));

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(KEYS)).hasSize(2);
        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(result.getSuccessful()).isEqualTo(1);
        assertThat(result.getCreated()).extracting(SendResult.CreatedCapsa::getIndex).containsExactly(0);
        assertThat(result.getErrors()).isNull();
    }

    @Test
    void staleKeychainTwice_failsAfterOneRebuildWithServerCode() {
        server.on(CAPSAS, StubServer.json(409, "{\"error\":{\"code\":\"KEYCHAIN_DELEGATES_MISMATCH\","
                + "\"message\":\"Delegates changed\"}}"));

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(result.getFailed()).isEqualTo(1);
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("KEYCHAIN_DELEGATES_MISMATCH");
            assertThat(e.getMessage()).isEqualTo("Delegates changed");
        });
    }

    @Test
    void partial207_mapsEachResultToItsBuilderAndKeepsCodes() {
        server.on(CAPSAS, StubServer.json(207, "{\"success\":true,\"successful\":1,\"failed\":1,"
                + "\"created\":[{\"index\":1,\"packageId\":\"capsa_b\"}],"
                + "\"errors\":[{\"index\":0,\"packageId\":\"capsa_a\",\"code\":\"KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED\","
                + "\"message\":\"Exactly one principal is required\"}]}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getSuccessful()).isEqualTo(1);
        assertThat(result.getFailed()).isEqualTo(1);
        assertThat(result.getPartialSuccess()).isTrue();
        assertThat(result.getCreated()).singleElement().satisfies(c -> {
            assertThat(c.getIndex()).isEqualTo(1);
            assertThat(c.getPackageId()).isEqualTo("capsa_b");
        });
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED");
            assertThat(e.getMessage()).isEqualTo("Exactly one principal is required");
        });
    }

    @Test
    void allFailed422_isReportedPerCapsaNotThrown() {
        server.on(CAPSAS, StubServer.json(422, "{\"success\":false,\"successful\":0,\"failed\":2,\"created\":[],"
                + "\"errors\":[{\"index\":0,\"code\":\"SIGNATURE_INVALID\",\"message\":\"bad\"},"
                + "{\"index\":1,\"code\":\"FILE_HASH_MISMATCH\",\"message\":\"hash\"}]}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getSuccessful()).isZero();
        assertThat(result.getFailed()).isEqualTo(2);
        assertThat(result.getCreated()).isEmpty();
        assertThat(result.getErrors()).extracting(SendResult.SendError::getCode)
                .containsExactly("SIGNATURE_INVALID", "FILE_HASH_MISMATCH");
    }

    @Test
    void indexesAcrossBatches_areOffsetToTheCallersBuilderPosition() {
        server.on(CAPSAS,
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}]}"),
                StubServer.json(422, "{\"success\":false,\"successful\":0,\"failed\":1,\"created\":[],"
                        + "\"errors\":[{\"index\":0,\"code\":\"INVALID_CAPSA_METADATA\",\"message\":\"m\"}]}"));

        SendResult result = send(service(1), builder(), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(result.getCreated()).extracting(SendResult.CreatedCapsa::getIndex).containsExactly(0);
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isEqualTo(1);
            assertThat(e.getCode()).isEqualTo("INVALID_CAPSA_METADATA");
        });
        assertThat(result.getSuccessful() + result.getFailed()).isEqualTo(2);
    }

    @Test
    void alreadyExists409_isReportedPerCapsa() {
        server.on(CAPSAS, StubServer.json(409, "{\"error\":{\"code\":\"ENVELOPE_ALREADY_EXISTS\","
                + "\"message\":\"A capsa with this id already exists\"}}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getFailed()).isEqualTo(2);
        assertThat(result.getErrors()).hasSize(2).allSatisfy(e -> {
            assertThat(e.getCode()).isEqualTo("ENVELOPE_ALREADY_EXISTS");
            assertThat(e.getPackageId()).startsWith("capsa_");
        });
        assertThat(result.getErrors()).extracting(SendResult.SendError::getIndex).containsExactly(0, 1);
    }

    @Test
    void creationInProgress409_isReportedPerCapsaWithoutRetry() {
        server.on(CAPSAS, StubServer.json(409, "{\"error\":{\"code\":\"ENVELOPE_CREATION_IN_PROGRESS\","
                + "\"message\":\"Creation in progress\"}}"));

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getErrors()).singleElement()
                .satisfies(e -> assertThat(e.getCode()).isEqualTo("ENVELOPE_CREATION_IN_PROGRESS"));
    }

    @Test
    void perCapsaConflictCodes_andReplayCreatedAt_areSurfaced() {
        server.on(CAPSAS, StubServer.json(207, "{\"success\":true,\"successful\":1,\"failed\":1,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\",\"createdAt\":\"2026-11-07T10:00:00.000Z\"}],"
                + "\"errors\":[{\"index\":1,\"packageId\":\"capsa_b\",\"code\":\"ENVELOPE_CREATION_IN_PROGRESS\","
                + "\"message\":\"Creation in progress\"}]}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getCreated()).singleElement()
                .satisfies(c -> assertThat(c.getCreatedAt()).isEqualTo("2026-11-07T10:00:00.000Z"));
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isEqualTo(1);
            assertThat(e.getCode()).isEqualTo("ENVELOPE_CREATION_IN_PROGRESS");
        });
    }

    @Test
    void batchLevelError_keepsServerCodeForEveryCapsa() {
        server.on(CAPSAS, StubServer.json(400, "{\"error\":{\"code\":\"TOO_MANY_FILES\",\"message\":\"Too many\"}}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getErrors()).hasSize(2).allSatisfy(e -> {
            assertThat(e.getCode()).isEqualTo("TOO_MANY_FILES");
            assertThat(e.getMessage()).isEqualTo("Too many");
        });
    }

    @Test
    void nonJsonErrorBody_givesHttpStatusCode() {
        server.on(CAPSAS, StubServer.text(500, "upstream exploded"));

        SendResult result = send(service(150), builder());

        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getCode()).isEqualTo("HTTP_500");
            assertThat(e.getMessage()).isEqualTo("Internal Server Error");
        });
    }

    @Test
    void droppedConnection_isRetriedAndTheReplayCounts() {
        server.on(CAPSAS,
                StubServer.dropConnection(),
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}]}"));

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(server.requestsTo(CAPSAS).get(0).body).isEqualTo(server.requestsTo(CAPSAS).get(1).body);
        assertThat(result.getSuccessful()).isEqualTo(1);
    }

    @Test
    void serviceUnavailable_isRetriedHonouringRetryAfter() {
        server.on(CAPSAS,
                StubServer.json(503, "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"busy\","
                        + "\"retryAfter\":0}}", Map.of("Retry-After", "0")),
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}]}"));

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(result.getSuccessful()).isEqualTo(1);
    }

    @Test
    void builderThatFails_isReportedAsBuildFailedAndTheRestAreSent() {
        server.on(CAPSAS, StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_b\"}]}"));

        SendResult result = send(service(150), builder(UNUSABLE_KEY_RECIPIENT), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getCreated()).singleElement().satisfies(c -> {
            assertThat(c.getIndex()).isEqualTo(1);
            assertThat(c.getPackageId()).isEqualTo("capsa_b");
        });
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("BUILD_FAILED");
        });
        assertThat(result.getPartialSuccess()).isTrue();
    }

    @Test
    void recipientWithoutRegisteredKey_failsThatCapsaWithRecipientKeyNotFound() {
        server.on(CAPSAS, StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_b\"}]}"));

        SendResult result = send(service(150), builder("party_without_key"), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getCreated()).singleElement()
                .satisfies(c -> assertThat(c.getIndex()).isEqualTo(1));
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("RECIPIENT_KEY_NOT_FOUND");
            assertThat(e.getMessage()).isEqualTo("Recipient party_without_key has no registered public key");
        });
    }

    @Test
    void everyRecipientWithoutKey_sendsNothing() {
        SendResult result = send(service(150), builder("party_without_key"));

        assertThat(server.requestsTo(CAPSAS)).isEmpty();
        assertThat(result.getSuccessful()).isZero();
        assertThat(result.getErrors()).singleElement()
                .satisfies(e -> assertThat(e.getCode()).isEqualTo("RECIPIENT_KEY_NOT_FOUND"));
    }

    @Test
    void emptyFile_isBuildFailedForThatCapsaOnly() {
        server.on(CAPSAS, StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_b\"}]}"));
        CapsaBuilder empty = builder();
        empty.addFile(new byte[0], "empty.bin");

        SendResult result = send(service(150), empty, builder());

        assertThat(result.getCreated()).singleElement()
                .satisfies(c -> assertThat(c.getIndex()).isEqualTo(1));
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("BUILD_FAILED");
            assertThat(e.getMessage()).isEqualTo("File \"empty.bin\" is empty");
        });
    }

    @Test
    void requestLevelFailureOfOneGroup_failsOnlyThatGroupAndSendsTheRest() {
        server.on(CAPSAS,
                StubServer.json(413, "{\"error\":{\"code\":\"REQUEST_TOO_LARGE\",\"message\":\"Too large\"}}"),
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_b\"}]}"),
                StubServer.json(201, "{\"success\":true,\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"index\":0,\"packageId\":\"capsa_c\"}]}"));
        UploadService service = service(150);
        SystemLimits limits = new SystemLimits();
        limits.setMaxRequestSize(1L);
        service.setLimitsSupplier(() -> limits);

        SendResult result = send(service, builder(), builder(), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(3);
        assertThat(result.getCreated()).extracting(SendResult.CreatedCapsa::getIndex).containsExactly(1, 2);
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("REQUEST_TOO_LARGE");
        });
    }

    private static CapsaBuilder builderWithFiles(int files) {
        GeneratedKeyPairResult creator = SharedKeyFixture.getPrimaryKeyPair();
        CapsaBuilder builder = new CapsaBuilder(CREATOR, creator.getPrivateKey(), null);
        builder.setExpiresAt(OffsetDateTime.now().plusDays(7));
        builder.addRecipient(RECIPIENT).withSubject("s");
        for (int i = 0; i < files; i++) {
            builder.addTextFile("f" + i + ".txt", "hello " + i);
        }
        return builder;
    }

    private static String createdBody(int count) {
        StringBuilder created = new StringBuilder();
        for (int i = 0; i < count; i++) {
            created.append(i == 0 ? "" : ",").append("{\"index\":").append(i)
                    .append(",\"packageId\":\"capsa_").append(i).append("\"}");
        }
        return "{\"success\":true,\"created\":[" + created + "]}";
    }

    private UploadService serviceWithFileLimit(Integer maxFilesPerRequest) {
        UploadService service = service(150);
        SystemLimits limits = new SystemLimits();
        limits.setMaxFilesPerRequest(maxFilesPerRequest);
        service.setLimitsSupplier(() -> limits);
        return service;
    }

    @Test
    void publishedFilesPerRequest_splitsTheBatchOnFileCount() {
        server.on(CAPSAS, StubServer.json(201, createdBody(1)));

        SendResult result = send(serviceWithFileLimit(10), builderWithFiles(5), builderWithFiles(6));

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
        assertThat(result.getSuccessful()).isEqualTo(2);
    }

    @Test
    void publishedFilesPerRequest_keepsCapsasTogetherUpToTheLimit() {
        server.on(CAPSAS, StubServer.json(201, createdBody(2)));

        SendResult result = send(serviceWithFileLimit(10), builderWithFiles(5), builderWithFiles(5));

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getSuccessful()).isEqualTo(2);
    }

    @Test
    void capsaOverThePublishedFilesPerRequest_isRejectedBeforeSending() {
        UploadService service = serviceWithFileLimit(2);

        assertThatThrownBy(() -> send(service, builderWithFiles(3)))
                .hasRootCauseMessage("Capsa at index 0 has 3 files, exceeding the batch limit of 2 files.");
        assertThat(server.requestsTo(CAPSAS)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void nonPositiveFilesPerRequest_fallsBackTo500(int value) {
        server.on(CAPSAS, StubServer.json(201, createdBody(1)));

        send(serviceWithFileLimit(value), builderWithFiles(300), builderWithFiles(300));

        assertThat(server.requestsTo(CAPSAS)).hasSize(2);
    }

    @Test
    void absentFilesPerRequest_fallsBackTo500() {
        server.on(CAPSAS, StubServer.json(201, createdBody(2)));

        send(serviceWithFileLimit(null), builderWithFiles(250), builderWithFiles(250));

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
    }

    @Test
    void limitsAreReadOncePerSend() {
        server.on(CAPSAS, StubServer.json(201, createdBody(1)));
        UploadService service = service(150);
        SystemLimits limits = new SystemLimits();
        limits.setMaxFilesPerRequest(1);
        java.util.concurrent.atomic.AtomicInteger reads = new java.util.concurrent.atomic.AtomicInteger();
        service.setLimitsSupplier(() -> {
            reads.incrementAndGet();
            return limits;
        });

        send(service, builder(), builder(), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(3);
        assertThat(reads).hasValue(1);
    }

    @Test
    void connectionDroppedOnEveryAttempt_isNetworkError() {
        server.on(CAPSAS, StubServer.dropConnection());

        SendResult result = send(service(150), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(3);
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getCode()).isEqualTo("NETWORK_ERROR");
            assertThat(e.getPackageId()).startsWith("capsa_");
        });
    }

    @Test
    void uploadThatTimesOut_isUploadTimeoutAndNotRetried() {
        HttpTimeoutConfig timeout = HttpTimeoutConfig.defaults();
        timeout.setUploadTimeout(Duration.ofMillis(200));
        server.on(CAPSAS, StubServer.delayed(StubServer.json(201, "{\"created\":[]}"), 1000));

        SendResult result = send(service(150, timeout), builder());

        assertThat(server.requestsTo(CAPSAS)).hasSize(1);
        assertThat(result.getErrors()).singleElement()
                .satisfies(e -> assertThat(e.getCode()).isEqualTo("UPLOAD_TIMEOUT"));
    }

    @Test
    void unparseableCreatedBody_isInvalidResponseForEveryCapsa() {
        server.on(CAPSAS, StubServer.text(201, "created!"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getCreated()).isEmpty();
        assertThat(result.getErrors()).hasSize(2).allSatisfy(e -> {
            assertThat(e.getCode()).isEqualTo("INVALID_RESPONSE");
            assertThat(e.getPackageId()).startsWith("capsa_");
        });
    }

    @Test
    void perCapsaErrorWithoutCode_isUnknownError() {
        server.on(CAPSAS, StubServer.json(422, "{\"success\":false,\"created\":[],"
                + "\"errors\":[{\"index\":0,\"message\":\"rejected\"}]}"));

        SendResult result = send(service(150), builder());

        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getCode()).isEqualTo("UNKNOWN_ERROR");
            assertThat(e.getMessage()).isEqualTo("rejected");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}],\"errors\":[{\"index\":2,\"code\":\"X\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}],\"errors\":[{\"index\":-1,\"code\":\"X\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"}],\"errors\":[{\"index\":0,\"code\":\"X\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"},{\"packageId\":\"capsa_b\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"},{\"index\":1.5,\"packageId\":\"capsa_b\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"},{\"index\":\"1\",\"packageId\":\"capsa_b\"}]",
        "\"created\":[{\"index\":0,\"packageId\":\"capsa_a\"},null]"
    })
    void badIndexInResponse_failsEveryCapsaOfTheRequestAsInvalidResponse(String items) {
        server.on(CAPSAS, StubServer.json(207, "{\"success\":true," + items + "}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getSuccessful()).isZero();
        assertThat(result.getCreated()).isEmpty();
        assertThat(result.getErrors()).hasSize(2).allSatisfy(e -> {
            assertThat(e.getCode()).isEqualTo("INVALID_RESPONSE");
            assertThat(e.getMessage())
                    .isEqualTo("Send response has a missing, duplicate or out-of-range capsa index");
            assertThat(e.getPackageId()).startsWith("capsa_").isNotIn("capsa_a", "capsa_b");
        });
        assertThat(result.getErrors()).extracting(SendResult.SendError::getIndex).containsExactly(0, 1);
    }

    @Test
    void capsaMissingFromResponse_failsAloneAsInvalidResponse() {
        server.on(CAPSAS, StubServer.json(207, "{\"success\":true,"
                + "\"created\":[{\"index\":1,\"packageId\":\"capsa_b\"}],\"errors\":[]}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getCreated()).singleElement()
                .satisfies(c -> assertThat(c.getIndex()).isEqualTo(1));
        assertThat(result.getErrors()).singleElement().satisfies(e -> {
            assertThat(e.getIndex()).isZero();
            assertThat(e.getCode()).isEqualTo("INVALID_RESPONSE");
            assertThat(e.getMessage()).isEqualTo("Send response did not report this capsa");
            assertThat(e.getPackageId()).startsWith("capsa_");
        });
    }

    @Test
    void resultsAreMappedByIndexNotPackageId() {
        server.on(CAPSAS, StubServer.json(201, "{\"success\":true,\"created\":["
                + "{\"index\":1,\"packageId\":\"capsa_first\"},{\"index\":0,\"packageId\":\"capsa_second\"}]}"));

        SendResult result = send(service(150), builder(), builder());

        assertThat(result.getErrors()).isNull();
        assertThat(result.getCreated()).extracting(SendResult.CreatedCapsa::getIndex, SendResult.CreatedCapsa::getPackageId)
                .containsExactly(tuple(0, "capsa_second"), tuple(1, "capsa_first"));
    }

    @Test
    void uploadRequest_usesTheUploadTimeoutNotTheRequestTimeout() {
        HttpTimeoutConfig defaults = HttpTimeoutConfig.defaults();

        assertThat(defaults.getUploadTimeout()).isEqualTo(Duration.ofMinutes(15));
        assertThat(defaults.getUploadTimeout()).isGreaterThan(defaults.getRequestTimeout());
    }
}
