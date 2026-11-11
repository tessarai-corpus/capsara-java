package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.SendResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Send-time validation and per-capsa rejection reporting, against a local HTTP server. */
class UploadServiceValidationTest {

    private static final String CREATOR_ID = "party_creator_validation";
    private static final String AGENT_ID = "party_agent";
    private static final String VENDOR_ID = "party_vendor";

    private HttpServer server;
    private ConcurrencyConfig concurrency;
    private UploadService upload;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile int uploadStatus;
    private volatile String uploadBody;

    @BeforeEach
    void start() throws IOException {
        GeneratedKeyPairResult keys = SharedKeyFixture.getPrimaryKeyPair();
        String partyKeys = "{\"parties\":["
                + partyJson(CREATOR_ID, keys) + "," + partyJson(AGENT_ID, keys) + ","
                + partyJson(VENDOR_ID, keys) + "]}";

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/party/keys", exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, partyKeys);
        });
        server.createContext("/api/capsas", exchange -> {
            requests.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            respond(exchange, uploadStatus, uploadBody);
        });
        server.start();

        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        concurrency = new ConcurrencyConfig();
        HttpClient client = HttpClient.newHttpClient();
        KeyService keyService = new KeyService(client, baseUrl, () -> "token", null,
                RetryConfig.defaults(), null, concurrency);
        upload = new UploadService(client, baseUrl, () -> "token", keyService, 100,
                RetryConfig.defaults(), null, null, concurrency);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        concurrency.shutdown();
    }

    @Test
    void sendRejectsCapsaWithoutRecipientBeforeAnyRequest() {
        try (CapsaBuilder withRecipient = builder(AGENT_ID);
             CapsaBuilder noRecipient = builder(null)) {
            assertThatThrownBy(() -> upload.sendCapsasAsync(
                    new CapsaBuilder[]{withRecipient, noRecipient}, CREATOR_ID).join())
                    .isInstanceOf(CompletionException.class)
                    .hasRootCauseInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                    .satisfies(e -> {
                        com.capsara.sdk.exceptions.CapsaraException error =
                                (com.capsara.sdk.exceptions.CapsaraException) e.getCause();
                        assertThat(error.getCode()).isEqualTo("VALIDATION_ERROR");
                        assertThat(error.getStatusCode()).isZero();
                        assertThat(error.getDetails()).isEqualTo(java.util.Map.of("index", 1));
                    })
                    .rootCause()
                    .hasMessage("Capsa at index 1 has no recipient. Call addRecipient() "
                            + "with the party this capsa is sent to.");
        }
        assertThat(requests.get()).isZero();
    }

    @Test
    void allRejectedBatchKeepsEachCapsasCode() {
        uploadStatus = 422;
        uploadBody = "{\"success\":false,\"successful\":0,\"failed\":2,\"created\":[],\"errors\":["
                + "{\"index\":0,\"code\":\"KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED\","
                + "\"message\":\"Exactly one principal is required\"},"
                + "{\"index\":1,\"code\":\"DELEGATE_PRINCIPAL_MISMATCH\","
                + "\"message\":\"Delegate acts for another party\"}]}";

        try (CapsaBuilder toAgent = builder(AGENT_ID); CapsaBuilder toVendor = builder(VENDOR_ID)) {
            SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{toAgent, toVendor}, CREATOR_ID).join();

            assertThat(result.getFailed()).isEqualTo(2);
            assertThat(result.getErrors()).hasSize(2);
            assertThat(result.getErrors().get(0).getIndex()).isZero();
            assertThat(result.getErrors().get(0).getCode()).isEqualTo("KEYCHAIN_SINGLE_PRINCIPAL_REQUIRED");
            assertThat(result.getErrors().get(0).getMessage()).isEqualTo("Exactly one principal is required");
            assertThat(result.getErrors().get(1).getIndex()).isEqualTo(1);
            assertThat(result.getErrors().get(1).getCode()).isEqualTo("DELEGATE_PRINCIPAL_MISMATCH");
        }
    }

    @Test
    void rejectedRequestCarriesServerCode() {
        uploadStatus = 400;
        uploadBody = "{\"error\":{\"code\":\"DELEGATE_PRINCIPAL_MISMATCH\","
                + "\"message\":\"Delegate acts for another party\"}}";

        try (CapsaBuilder toAgent = builder(AGENT_ID)) {
            SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{toAgent}, CREATOR_ID).join();

            assertThat(result.getErrors().get(0).getCode()).isEqualTo("DELEGATE_PRINCIPAL_MISMATCH");
            assertThat(result.getErrors().get(0).getMessage()).isEqualTo("Delegate acts for another party");
        }
    }

    @Test
    void partialSuccessPassesThroughPerCapsaCode() {
        uploadStatus = 207;
        uploadBody = "{\"batchId\":\"batch_1\",\"successful\":1,\"failed\":1,\"partialSuccess\":true,"
                + "\"created\":[{\"packageId\":\"capsa_1\",\"index\":0,\"createdAt\":\"2026-01-01T00:00:00Z\"}],"
                + "\"errors\":[{\"index\":1,\"packageId\":\"capsa_2\","
                + "\"message\":\"Delegate acts for another party\",\"code\":\"DELEGATE_PRINCIPAL_MISMATCH\"}]}";

        try (CapsaBuilder toAgent = builder(AGENT_ID); CapsaBuilder toVendor = builder(VENDOR_ID)) {
            SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{toAgent, toVendor}, CREATOR_ID).join();

            assertThat(result.getSuccessful()).isEqualTo(1);
            assertThat(result.getErrors().get(0).getIndex()).isEqualTo(1);
            assertThat(result.getErrors().get(0).getCode()).isEqualTo("DELEGATE_PRINCIPAL_MISMATCH");
        }
    }

    @Test
    void anyTwoHundredStatus_isMappedPerCapsa() {
        uploadStatus = 200;
        uploadBody = "{\"success\":true,\"successful\":1,\"failed\":0,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_1\",\"createdAt\":\"2026-01-01T00:00:00Z\"}]}";

        try (CapsaBuilder toAgent = builder(AGENT_ID)) {
            SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{toAgent}, CREATOR_ID).join();

            assertThat(result.getSuccessful()).isEqualTo(1);
            assertThat(result.getFailed()).isZero();
        }
    }

    @Test
    void twoHundredWithArrayBody_isInvalidResponse() {
        uploadStatus = 201;
        uploadBody = "[]";

        try (CapsaBuilder toAgent = builder(AGENT_ID)) {
            SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{toAgent}, CREATOR_ID).join();

            assertThat(result.getErrors().get(0).getCode()).isEqualTo("INVALID_RESPONSE");
        }
    }

    @Test
    void maxBatchSizeZero_sendsOneCapsaPerRequest() {
        uploadStatus = 201;
        uploadBody = "{\"success\":true,\"successful\":1,\"failed\":0,"
                + "\"created\":[{\"index\":0,\"packageId\":\"capsa_1\",\"createdAt\":\"2026-01-01T00:00:00Z\"}]}";
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        HttpClient client = HttpClient.newHttpClient();
        KeyService keyService = new KeyService(client, baseUrl, () -> "token", null,
                RetryConfig.defaults(), null, concurrency);
        UploadService unbatched = new UploadService(client, baseUrl, () -> "token", keyService, 0,
                RetryConfig.defaults(), null, null, concurrency);

        try (CapsaBuilder toAgent = builder(AGENT_ID); CapsaBuilder toVendor = builder(VENDOR_ID)) {
            SendResult result = unbatched.sendCapsasAsync(new CapsaBuilder[]{toAgent, toVendor}, CREATOR_ID).join();

            assertThat(result.getSuccessful()).isEqualTo(2);
            assertThat(requests.get()).isEqualTo(4);
        }
    }

    private static CapsaBuilder builder(String recipientId) {
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID,
                SharedKeyFixture.getPrimaryKeyPair().getPrivateKey(), null);
        builder.withExpiration(OffsetDateTime.now().plusDays(30)).addTextFile("note.txt", "hello");
        if (recipientId != null) {
            builder.addRecipient(recipientId);
        }
        return builder;
    }

    private static String partyJson(String id, GeneratedKeyPairResult keys) {
        return "{\"id\":\"" + id + "\",\"publicKey\":\"" + keys.getPublicKey().replace("\r", "").replace("\n", "\\n")
                + "\",\"fingerprint\":\"" + keys.getFingerprint() + "\"}";
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
