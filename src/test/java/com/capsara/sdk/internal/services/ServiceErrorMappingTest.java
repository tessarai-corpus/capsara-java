package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAuditException;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.KeyHistoryEntry;
import com.capsara.sdk.models.PublicKeyInfo;
import com.capsara.sdk.models.SystemLimits;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Every service reports API failures through the shared parser, with server codes verbatim. */
class ServiceErrorMappingTest {

    private StubServer server;
    private ConcurrencyConfig concurrency;
    private HttpClient client;
    private final RetryConfig retry = new RetryConfig(2, Duration.ofMillis(1), 1.0, Duration.ofMillis(5));

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        concurrency = new ConcurrencyConfig();
        client = HttpClientFactory.createDefault();
    }

    @AfterEach
    void stop() {
        server.close();
        concurrency.shutdown();
    }

    private static CapsaraException failure(CompletableFuture<?> future) {
        Throwable thrown = catchThrowable(future::join);
        assertThat(thrown).isInstanceOf(CompletionException.class);
        assertThat(thrown.getCause()).isInstanceOf(CapsaraException.class);
        return (CapsaraException) thrown.getCause();
    }

    private CapsaService capsaService() {
        return new CapsaService(client, server.baseUrl(), () -> "t", null, retry, null, concurrency);
    }

    private DownloadService downloadService() {
        return new DownloadService(client, client, server.baseUrl(), () -> "t", null, retry, null, concurrency);
    }

    private AccountService accountService() {
        return new AccountService(client, server.baseUrl(), () -> "t", null, retry, null, concurrency);
    }

    // Capsa reads

    @Test
    void getCapsa404_isCapsaExceptionWithServerCode() {
        server.on("/api/capsas/capsa_x", StubServer.json(404,
                "{\"error\":{\"code\":\"ENVELOPE_NOT_FOUND\",\"message\":\"Capsa not found\"}}"));

        CapsaraException ex = failure(capsaService().getCapsaAsync("capsa_x"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("ENVELOPE_NOT_FOUND");
        assertThat(ex.getStatusCode()).isEqualTo(404);
        assertThat(ex.getMessage()).isEqualTo("Capsa not found");
    }

    @Test
    void getExpiredCapsa410_isEnvelopeExpiredWithDetails() {
        server.on("/api/capsas/capsa_x", StubServer.json(410,
                "{\"error\":{\"code\":\"ENVELOPE_EXPIRED\",\"message\":\"Capsa has expired\","
                        + "\"details\":{\"status\":\"expired\",\"expiredAt\":\"2026-11-01T00:00:00.000Z\"}}}"));

        CapsaraException ex = failure(capsaService().getCapsaAsync("capsa_x"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("ENVELOPE_EXPIRED");
        assertThat(ex.getStatusCode()).isEqualTo(410);
        assertThat(ex.getDetails())
                .isEqualTo(Map.of("status", "expired", "expiredAt", "2026-11-01T00:00:00.000Z"));
    }

    @Test
    void downloadDeletedCapsa410_isEnvelopeDeleted() {
        server.on("/api/capsas/capsa_x/files/file_1.enc/download", StubServer.json(410,
                "{\"error\":{\"code\":\"ENVELOPE_DELETED\",\"message\":\"Capsa has been deleted\","
                        + "\"details\":{\"status\":\"soft_deleted\",\"deletedAt\":\"2026-11-02T00:00:00.000Z\"}}}"));

        CapsaraException ex = failure(downloadService().downloadEncryptedFileAsync("capsa_x", "file_1.enc"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("ENVELOPE_DELETED");
        assertThat(ex.getStatusCode()).isEqualTo(410);
        assertThat(ex.getDetails()).isEqualTo(
                Map.of("status", "soft_deleted", "deletedAt", "2026-11-02T00:00:00.000Z"));
    }

    @Test
    void downloadExpiredFile410_isFileExpiredWithDetails() {
        server.on("/api/capsas/capsa_x/files/file_1.enc/download", StubServer.json(410,
                "{\"error\":{\"code\":\"FILE_EXPIRED\",\"message\":\"File has expired\","
                        + "\"details\":{\"fileId\":\"file_1.enc\",\"expiredAt\":\"2026-11-03T00:00:00.000Z\"}}}"));

        CapsaraException ex = failure(downloadService().downloadEncryptedFileAsync("capsa_x", "file_1.enc"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("FILE_EXPIRED");
        assertThat(ex.getStatusCode()).isEqualTo(410);
        assertThat(ex.getDetails()).isEqualTo(
                Map.of("fileId", "file_1.enc", "expiredAt", "2026-11-03T00:00:00.000Z"));
    }

    @Test
    void blobFailure_namesTheCapsaAndFileAndKeepsTheCause() {
        server.on("/api/capsas/capsa_x/files/file_1.enc/download", StubServer.json(200,
                "{\"fileId\":\"file_1.enc\",\"downloadUrl\":\"" + server.baseUrl() + "/blob/file_1.enc\","
                        + "\"expiresAt\":\"2026-11-08T00:00:00Z\"}"));
        server.on("/blob/file_1.enc", StubServer.text(500, "storage down"));

        CapsaraException ex = failure(downloadService().downloadEncryptedFileAsync("capsa_x", "file_1.enc"));

        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(ex.getMessage()).contains("capsa_x").contains("file_1.enc");
        assertThat(ex.getCause()).hasMessageContaining("500");
    }

    @Test
    void listValidation400_keepsArrayDetails() {
        server.on("/api/capsas", StubServer.json(400, "{\"error\":{\"code\":\"VALIDATION_ERROR\","
                + "\"message\":\"Invalid query\",\"details\":[{\"path\":\"limit\",\"message\":\"Too big\"}]}}"));

        CapsaraException ex = failure(capsaService().listCapsasAsync(null));

        assertThat(ex.getCode()).isEqualTo("VALIDATION_ERROR");
        assertThat(ex.getDetails()).isEqualTo(List.of(Map.of("path", "limit", "message", "Too big")));
    }

    @Test
    void rateLimited429_exhaustingRetries_exposesRetryAfter() {
        server.on("/api/capsas/capsa_x", StubServer.json(429,
                "{\"error\":{\"code\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"Slow down\",\"retryAfter\":0}}"));

        CapsaraException ex = failure(capsaService().getCapsaAsync("capsa_x"));

        assertThat(ex.getCode()).isEqualTo("RATE_LIMIT_EXCEEDED");
        assertThat(ex.getRetryAfter()).isZero();
        assertThat(server.requestsTo("/api/capsas/capsa_x")).hasSize(3);
    }

    @Test
    void rateLimited429WithoutHint_isRetriedWithBackoff() {
        server.on("/api/capsas/capsa_x", StubServer.json(429,
                "{\"error\":{\"code\":\"TOO_MANY_FAILURES\",\"message\":\"Blocked\"}}"));

        CapsaraException ex = failure(capsaService().getCapsaAsync("capsa_x"));

        assertThat(ex.getCode()).isEqualTo("TOO_MANY_FAILURES");
        assertThat(ex.getRetryAfter()).isNull();
        assertThat(server.requestsTo("/api/capsas/capsa_x")).hasSize(3);
    }

    @Test
    void audit503ThenOk_isRetried() {
        server.on("/api/capsas/capsa_x/audit",
                StubServer.json(503, "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"busy\"}}"),
                StubServer.json(201, "{\"success\":true}"));
        AuditService audit = new AuditService(client, server.baseUrl(), () -> "t", null, retry, null, concurrency);
        CreateAuditEntryRequest entry = new CreateAuditEntryRequest();
        entry.setAction("log");
        entry.setDetails(Map.of("note", "x"));

        assertThat(audit.createAuditEntryAsync("capsa_x", entry).join()).isTrue();
        assertThat(server.requestsTo("/api/capsas/capsa_x/audit")).hasSize(2);
    }

    @Test
    void currentKey503ThenOk_isRetried() {
        server.on("/api/account/key",
                StubServer.json(503, "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"busy\"}}"),
                StubServer.json(200, "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"abc\"}"));

        assertThat(accountService().getCurrentPublicKeyAsync().join().getKeyFingerprint()).isEqualTo("abc");
        assertThat(server.requestsTo("/api/account/key")).hasSize(2);
    }

    @Test
    void blob503ThenOk_isRetried() {
        server.on("/api/capsas/capsa_x/files/file_1.enc/download", StubServer.json(200,
                "{\"fileId\":\"file_1.enc\",\"downloadUrl\":\"" + server.baseUrl() + "/blob/file_1.enc\","
                        + "\"expiresAt\":\"2026-11-08T00:00:00Z\"}"));
        server.on("/blob/file_1.enc", StubServer.text(503, "busy"), StubServer.text(200, "data"));

        byte[] data = downloadService().downloadEncryptedFileAsync("capsa_x", "file_1.enc").join();

        assertThat(new String(data, java.nio.charset.StandardCharsets.UTF_8)).isEqualTo("data");
        assertThat(server.requestsTo("/blob/file_1.enc")).hasSize(2);
    }

    @Test
    void unavailable503ThenOk_isRetried() {
        server.on("/api/capsas",
                StubServer.json(503, "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"busy\"}}",
                        Map.of("Retry-After", "0")),
                StubServer.json(200, "{\"capsas\":[],\"pagination\":{\"limit\":100,\"hasMore\":false}}"));

        assertThat(capsaService().listCapsasAsync(null).join().getCapsas()).isEmpty();
        assertThat(server.requestsTo("/api/capsas")).hasSize(2);
    }

    @Test
    void partyKeys_nonJsonGatewayError_isHttpStatusCode() {
        server.on("/api/party/keys", StubServer.text(502, "<html>bad gateway</html>"));
        KeyService keys = new KeyService(client, server.baseUrl(), () -> "t", null, retry, null, concurrency);

        CapsaraException ex = failure(keys.fetchPartyKeysAsync(new String[]{"party_a"}));

        assertThat(ex.getCode()).isEqualTo("HTTP_502");
        assertThat(ex.getMessage()).isEqualTo("Bad Gateway");
    }

    // Audit

    @Test
    void auditErrors_useServerCodes() {
        server.on("/api/capsas/capsa_x/audit",
                StubServer.json(403, "{\"error\":{\"code\":\"INSUFFICIENT_PERMISSIONS\",\"message\":\"Creator only\"}}"));
        AuditService audit = new AuditService(client, server.baseUrl(), () -> "t", null, retry, null, concurrency);

        CreateAuditEntryRequest entry = new CreateAuditEntryRequest();
        entry.setAction("log");
        entry.setDetails(Map.of("note", "x"));
        CapsaraException createEx = failure(audit.createAuditEntryAsync("capsa_x", entry));
        CapsaraException getEx = failure(audit.getAuditEntriesAsync("capsa_x", null));

        assertThat(createEx).isInstanceOf(CapsaraAuditException.class);
        assertThat(createEx.getCode()).isEqualTo("INSUFFICIENT_PERMISSIONS");
        assertThat(getEx).isInstanceOf(CapsaraAuditException.class);
        assertThat(getEx.getStatusCode()).isEqualTo(403);
    }

    // Account

    @Test
    void keyRegistrationErrors_useServerCodes() {
        server.on("/api/account/key", StubServer.json(400,
                "{\"error\":{\"code\":\"PUBLIC_KEY_TOO_SMALL\",\"message\":\"RSA key must be at least 4096 bits\"}}"));

        CapsaraException ex = failure(accountService().addPublicKeyAsync("pem", "fp", null));

        assertThat(ex.getCode()).isEqualTo("PUBLIC_KEY_TOO_SMALL");
        assertThat(ex.getStatusCode()).isEqualTo(400);
    }

    @Test
    void currentKey_nullOnlyWhenServerSaysNone() {
        server.on("/api/account/key", StubServer.json(200,
                "{\"publicKey\":null,\"publicKeyFingerprint\":null,\"message\":\"No key\"}"));

        PublicKeyInfo info = accountService().getCurrentPublicKeyAsync().join();

        assertThat(info).isNull();
    }

    @Test
    void currentKey_serverErrorThrowsInsteadOfReportingNoKey() {
        server.on("/api/account/key", StubServer.json(503,
                "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"busy\",\"retryAfter\":2}}"));

        CapsaraException ex = failure(accountService().getCurrentPublicKeyAsync());

        assertThat(ex.getCode()).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(ex.getRetryAfter()).isEqualTo(2.0);
    }

    @Test
    void currentKey_returnsKeyAndFingerprint() {
        server.on("/api/account/key", StubServer.json(200,
                "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"abc\"}"));

        PublicKeyInfo info = accountService().getCurrentPublicKeyAsync().join();

        assertThat(info.getPublicKey()).isEqualTo("PEM");
        assertThat(info.getKeyFingerprint()).isEqualTo("abc");
    }

    @Test
    void keyHistory_readsServerShape() {
        server.on("/api/account/key/history", StubServer.json(200,
                "{\"keyHistory\":[{\"keyFingerprint\":\"aa11\",\"rotatedAt\":\"2026-10-01T00:00:00Z\","
                        + "\"rotatedBy\":\"party_me\",\"reason\":\"scheduled\",\"envelopesAffected\":3}],\"total\":1}"));

        KeyHistoryEntry[] history = accountService().getKeyHistoryAsync().join();

        assertThat(history).hasSize(1);
        assertThat(history[0].getKeyFingerprint()).isEqualTo("aa11");
        assertThat(history[0].getRotatedAt()).isEqualTo("2026-10-01T00:00:00Z");
        assertThat(history[0].getRotatedBy()).isEqualTo("party_me");
        assertThat(history[0].getReason()).isEqualTo("scheduled");
        assertThat(history[0].getEnvelopesAffected()).isEqualTo(3);
    }

    @Test
    void keyHistory_errorThrows() {
        server.on("/api/account/key/history", StubServer.json(401,
                "{\"error\":{\"code\":\"INVALID_TOKEN\",\"message\":\"Token expired\"}}"));

        CapsaraException ex = failure(accountService().getKeyHistoryAsync());

        assertThat(ex.getCode()).isEqualTo("INVALID_TOKEN");
    }

    @Test
    void unreadableSuccessBody_isInvalidResponse() {
        server.on("/api/account/key/history", StubServer.text(200, "not json"));

        CapsaraException ex = failure(accountService().getKeyHistoryAsync());

        assertThat(ex.getCode()).isEqualTo("INVALID_RESPONSE");
    }

    // Limits

    @Test
    void limitsFallback_isNotKeptAfterTheServerRecovers() {
        server.on("/api/limits",
                StubServer.json(500, "{\"error\":{\"code\":\"INTERNAL_ERROR\",\"message\":\"down\"}}"),
                StubServer.json(200, "{\"maxFileSize\":1,\"maxFilesPerCapsa\":2,\"maxTotalSize\":3,"
                        + "\"maxRequestSize\":4}"));
        LimitsService limits = new LimitsService(client, server.baseUrl(), () -> "t", null, null, concurrency,
                Duration.ZERO);

        assertThat(limits.getLimitsAsync().join()).isSameAs(SystemLimits.DEFAULT);
        SystemLimits fetched = limits.getLimitsAsync().join();

        assertThat(fetched).isNotSameAs(SystemLimits.DEFAULT);
        assertThat(fetched.getMaxRequestSize()).isEqualTo(4L);
        // Real limits are cached
        limits.getLimitsAsync().join();
        assertThat(server.requestsTo("/api/limits")).hasSize(2);
    }

    @Test
    void limitsFallback_isKeptOnlyBriefly() {
        assertThat(LimitsService.FALLBACK_TTL).isLessThanOrEqualTo(Duration.ofMinutes(5));
    }
}
