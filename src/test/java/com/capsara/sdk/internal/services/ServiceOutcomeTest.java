package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAccountException;
import com.capsara.sdk.exceptions.CapsaraAuditException;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import com.capsara.sdk.models.GetAuditEntriesResponse;
import com.capsara.sdk.models.PartyKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Service outcomes for transport failures, unusual bodies and request shapes. */
class ServiceOutcomeTest {

    private StubServer server;
    private ConcurrencyConfig concurrency;
    private HttpClient client;
    private final RetryConfig retry = new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5));

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

    private static String deadBaseUrl() throws Exception {
        StubServer dead = new StubServer();
        String url = dead.baseUrl();
        dead.close();
        return url;
    }

    private static HttpTimeoutConfig shortTimeout() {
        return new HttpTimeoutConfig(Duration.ofSeconds(5), Duration.ofMillis(200), Duration.ofMillis(200));
    }

    private CapsaService capsaService(String baseUrl, HttpTimeoutConfig timeout) {
        return new CapsaService(client, baseUrl, () -> "t", timeout, retry, null, concurrency);
    }

    private AuditService auditService(String baseUrl, HttpTimeoutConfig timeout) {
        return new AuditService(client, baseUrl, () -> "t", timeout, retry, null, concurrency);
    }

    private AccountService accountService(String baseUrl, HttpTimeoutConfig timeout) {
        return new AccountService(client, baseUrl, () -> "t", timeout, retry, null, concurrency);
    }

    private KeyService keyService(String baseUrl) {
        return new KeyService(client, baseUrl, () -> "t", null, retry, null, concurrency);
    }

    private DownloadService downloadService(String baseUrl, HttpTimeoutConfig timeout) {
        HttpClient blob = HttpClientFactory.createForBlob(timeout);
        return new DownloadService(client, blob, baseUrl, () -> "t", timeout, retry, null, concurrency);
    }

    private static void assertNetworkError(CapsaraException ex, Class<? extends CapsaraException> type) {
        assertThat(ex).isInstanceOf(type);
        assertThat(ex.getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isInstanceOf(Map.class);
        assertThat(((Map<?, ?>) ex.getDetails()).get("originalError")).isInstanceOf(String.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> details(CapsaraException ex) {
        return (Map<String, Object>) ex.getDetails();
    }

    @Test
    void requestId_isExposedFromTheErrorBody() {
        server.on("/api/capsas/capsa_x", StubServer.json(404,
                "{\"error\":{\"code\":\"ENVELOPE_NOT_FOUND\",\"message\":\"m\"},\"requestId\":\"req_1\"}"));

        CapsaraException ex = failure(capsaService(server.baseUrl(), null).getCapsaAsync("capsa_x"));

        assertThat(ex.getRequestId()).isEqualTo("req_1");
    }

    @Test
    void requestId_isNullWhenAbsentOrNotAString() {
        server.on("/api/capsas/capsa_x", StubServer.json(404,
                "{\"error\":{\"code\":\"ENVELOPE_NOT_FOUND\"},\"requestId\":5}"));

        CapsaraException ex = failure(capsaService(server.baseUrl(), null).getCapsaAsync("capsa_x"));

        assertThat(ex.getRequestId()).isNull();
    }

    @Test
    void errorWithMessageButNoCode_usesStatusCodeAndReasonPhraseAndDropsDetails() {
        server.on("/api/capsas/capsa_x", StubServer.json(500,
                "{\"error\":{\"message\":\"db down\",\"details\":{\"x\":1}},\"requestId\":\"req_2\"}"));

        CapsaraException ex = failure(capsaService(server.baseUrl(), null).getCapsaAsync("capsa_x"));

        assertThat(ex.getCode()).isEqualTo("HTTP_500");
        assertThat(ex.getMessage()).isEqualTo("Internal Server Error");
        assertThat(ex.getDetails()).isNull();
        assertThat(ex.getRequestId()).isEqualTo("req_2");
    }

    @Test
    void networkFailure_onEachService_isThatServiceTypeWithNetworkError() throws Exception {
        String dead = deadBaseUrl();

        assertNetworkError(failure(capsaService(dead, null).getCapsaAsync("c")), CapsaraCapsaException.class);
        assertNetworkError(failure(capsaService(dead, null).listCapsasAsync(null)), CapsaraCapsaException.class);
        assertNetworkError(failure(auditService(dead, null).getAuditEntriesAsync("c", null)),
                CapsaraAuditException.class);
        assertNetworkError(failure(auditService(dead, null).createAuditEntryAsync("c",
                new CreateAuditEntryRequest("processed", null))), CapsaraAuditException.class);
        assertNetworkError(failure(accountService(dead, null).getCurrentPublicKeyAsync()),
                CapsaraAccountException.class);
        assertNetworkError(failure(accountService(dead, null).getKeyHistoryAsync()),
                CapsaraAccountException.class);
        assertNetworkError(failure(accountService(dead, null).addPublicKeyAsync("k", "f", null)),
                CapsaraAccountException.class);
        assertNetworkError(failure(keyService(dead).fetchPartyKeysAsync(new String[]{"p"})),
                CapsaraException.class);
        assertNetworkError(failure(downloadService(dead, null).downloadEncryptedFileAsync("c", "f")),
                CapsaraCapsaException.class);
    }

    @Test
    void timeout_onAuditAndAccountCalls_isNetworkErrorOnThatType() {
        server.on("/api/capsas/c/audit", StubServer.delayed(StubServer.json(200, "{}"), 1500));
        server.on("/api/account/key", StubServer.delayed(StubServer.json(200, "{}"), 1500));

        assertNetworkError(failure(auditService(server.baseUrl(), shortTimeout()).getAuditEntriesAsync("c", null)),
                CapsaraAuditException.class);
        assertNetworkError(failure(accountService(server.baseUrl(), shortTimeout())
                .addPublicKeyAsync("k", "f", null)), CapsaraAccountException.class);
    }

    @Test
    void accountServerError_isAccountTypeWithServerCode() {
        server.on("/api/account/key", StubServer.json(400,
                "{\"error\":{\"code\":\"INVALID_PUBLIC_KEY\",\"message\":\"bad key\"}}"));

        CapsaraException ex = failure(accountService(server.baseUrl(), null).addPublicKeyAsync("k", "f", null));

        assertThat(ex).isInstanceOf(CapsaraAccountException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_PUBLIC_KEY");
        assertThat(ex.getStatusCode()).isEqualTo(400);
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>", "", "null", "[]", "5"})
    void accountNonObjectBody_isInvalidResponse(String body) {
        server.on("/api/account/key", StubServer.text(200, body));
        server.on("/api/account/key/history", StubServer.text(200, body));

        for (CompletableFuture<?> call : new CompletableFuture<?>[]{
            accountService(server.baseUrl(), null).getCurrentPublicKeyAsync(),
            accountService(server.baseUrl(), null).getKeyHistoryAsync(),
            accountService(server.baseUrl(), null).addPublicKeyAsync("k", "f", null),
        }) {
            CapsaraException ex = failure(call);
            assertThat(ex).isInstanceOf(CapsaraAccountException.class);
            assertThat(ex.getCode()).isEqualTo("INVALID_RESPONSE");
            assertThat(ex.getStatusCode()).isZero();
            assertThat(ex.getDetails()).isNull();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"publicKey\":\"\"}", "{\"publicKey\":null}", "{}"})
    void currentPublicKey_emptyOrMissing_isNull(String body) {
        server.on("/api/account/key", StubServer.json(200, body));

        assertThat(accountService(server.baseUrl(), null).getCurrentPublicKeyAsync().join()).isNull();
    }

    @Test
    void currentPublicKey_present_isReturned() {
        server.on("/api/account/key", StubServer.json(200, "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"ab\"}"));

        assertThat(accountService(server.baseUrl(), null).getCurrentPublicKeyAsync().join().getPublicKey())
                .isEqualTo("PEM");
    }

    @Test
    void keyHistory_missingEnvelopesAffected_staysNull() {
        server.on("/api/account/key/history", StubServer.json(200,
                "{\"keyHistory\":[{\"keyFingerprint\":\"a\",\"envelopesAffected\":0},{\"keyFingerprint\":\"b\"}]}"));

        com.capsara.sdk.models.KeyHistoryEntry[] history =
                accountService(server.baseUrl(), null).getKeyHistoryAsync().join();

        assertThat(history[0].getEnvelopesAffected()).isZero();
        assertThat(history[1].getEnvelopesAffected()).isNull();
    }

    @Test
    void addPublicKey_sendsReasonOnlyWhenNonEmpty() {
        server.on("/api/account/key", StubServer.json(200, "{\"publicKey\":\"k\",\"publicKeyFingerprint\":\"f\"}"));

        accountService(server.baseUrl(), null).addPublicKeyAsync("k", "f", "compromised").join();
        accountService(server.baseUrl(), null).addPublicKeyAsync("k", "f", "").join();

        assertThat(server.requestsTo("/api/account/key").get(0).body).contains("\"reason\":\"compromised\"");
        assertThat(server.requestsTo("/api/account/key").get(1).body).doesNotContain("reason");
    }

    @Test
    void rotateKey_sendsTheReason() {
        server.on("/api/account/key", StubServer.json(200, "{\"publicKey\":\"k\",\"publicKeyFingerprint\":\"f\"}"));

        accountService(server.baseUrl(), null).rotateKeyAsync(null, "scheduled").join();

        assertThat(server.requestsTo("/api/account/key").get(0).body).contains("\"reason\":\"scheduled\"");
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>", "", "null", "[1]", "\"x\""})
    void getCapsa_nonObjectBody_isInvalidResponseWithCapsaId(String body) {
        server.on("/api/capsas/capsa_x", StubServer.text(200, body));

        CapsaraException ex = failure(capsaService(server.baseUrl(), null).getCapsaAsync("capsa_x"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_RESPONSE");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(Map.of("capsaId", "capsa_x"));
    }

    @Test
    void getCapsa_objectWithFractionalTotalSize_decodes() {
        server.on("/api/capsas/capsa_x", StubServer.json(200, "{\"id\":\"capsa_x\",\"totalSize\":5.5}"));

        assertThat(capsaService(server.baseUrl(), null).getCapsaAsync("capsa_x").join().getTotalSize()).isNull();
    }

    @Test
    void listCapsas_nonJsonBody_isAnEmptyPage() {
        server.on("/api/capsas", StubServer.text(200, "<html>"));
        CapsaListFilters filters = new CapsaListFilters();
        filters.setLimit(7);

        CapsaListResponse page = capsaService(server.baseUrl(), null).listCapsasAsync(filters).join();

        assertThat(page.getCapsas()).isEmpty();
        assertThat(page.getPagination().getLimit()).isEqualTo(7);
        assertThat(page.getPagination().isHasMore()).isFalse();
    }

    @Test
    void listCapsas_paginationWithoutLimit_usesTheFilterLimit() {
        server.on("/api/capsas", StubServer.json(200, "{\"capsas\":[],\"pagination\":{\"hasMore\":true}}"));
        CapsaListFilters filters = new CapsaListFilters();
        filters.setLimit(7);

        CapsaListResponse page = capsaService(server.baseUrl(), null).listCapsasAsync(filters).join();

        assertThat(page.getPagination().getLimit()).isEqualTo(7);
        assertThat(page.getPagination().isHasMore()).isTrue();
    }

    @Test
    void listCapsas_noLimitAnywhere_defaultsTo20() {
        server.on("/api/capsas", StubServer.json(200, "{\"capsas\":[]}"));

        assertThat(capsaService(server.baseUrl(), null).listCapsasAsync(null).join().getPagination().getLimit())
                .isEqualTo(20);
    }

    @Test
    void emptyStringFilters_areSent() {
        server.on("/api/capsas", StubServer.json(200, "{\"capsas\":[]}"));
        server.on("/api/capsas/c/audit", StubServer.json(200, "{\"auditEntries\":[]}"));
        CapsaListFilters filters = new CapsaListFilters();
        filters.setAfter("");
        filters.setCreatedBy(null);
        GetAuditEntriesFilters auditFilters = new GetAuditEntriesFilters();
        auditFilters.setAction("");

        capsaService(server.baseUrl(), null).listCapsasAsync(filters).join();
        auditService(server.baseUrl(), null).getAuditEntriesAsync("c", auditFilters).join();

        assertThat(server.requestsTo("/api/capsas").get(0).query).isEqualTo("after=");
        assertThat(server.requestsTo("/api/capsas/c/audit").get(0).query).isEqualTo("action=");
    }

    @Test
    void auditEntries_nonJsonBody_isAnEmptyPage() {
        server.on("/api/capsas/c/audit", StubServer.text(200, "<html>"));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getAuditEntries()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "5", "\"x\"", "[1,2]", "true"})
    void auditEntries_nullOrNonObjectPagination_isAllNullAndKeepsEntries(String pagination) {
        server.on("/api/capsas/c/audit", StubServer.json(200,
                "{\"auditEntries\":[{\"action\":\"created\"}],\"pagination\":" + pagination + "}"));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getAuditEntries()).hasSize(1);
        assertThat(page.getAuditEntries()[0].getAction()).isEqualTo("created");
        assertThat(page.getPagination()).isNotNull();
        assertThat(page.getPagination().getPage()).isNull();
        assertThat(page.getPagination().getLimit()).isNull();
        assertThat(page.getPagination().getTotal()).isNull();
        assertThat(page.getPagination().getTotalPages()).isNull();
    }

    @Test
    void auditEntries_missingPagination_isAllNull() {
        server.on("/api/capsas/c/audit", StubServer.json(200, "{\"auditEntries\":[]}"));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getPagination()).isNotNull();
        assertThat(page.getPagination().getPage()).isNull();
    }

    @Test
    void auditEntries_objectPagination_keepsValuesIncludingZero() {
        server.on("/api/capsas/c/audit", StubServer.json(200,
                "{\"auditEntries\":[],\"pagination\":{\"page\":2,\"limit\":0,\"totalPages\":null}}"));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getPagination().getPage()).isEqualTo(2);
        assertThat(page.getPagination().getLimit()).isZero();
        assertThat(page.getPagination().getTotal()).isNull();
        assertThat(page.getPagination().getTotalPages()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"[]", "\"text\"", "42"})
    void auditEntries_nonObjectBody_isAnEmptyPage(String body) {
        server.on("/api/capsas/c/audit", StubServer.json(200, body));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getAuditEntries()).isEmpty();
        assertThat(page.getPagination()).isNotNull();
    }

    @Test
    void auditEntries_userAgentIsRead() {
        server.on("/api/capsas/c/audit", StubServer.json(200,
                "{\"auditEntries\":[{\"action\":\"soft_deleted\",\"userAgent\":\"ua/1\"}]}"));

        GetAuditEntriesResponse page = auditService(server.baseUrl(), null).getAuditEntriesAsync("c", null).join();

        assertThat(page.getAuditEntries()[0].getUserAgent()).isEqualTo("ua/1");
        assertThat(page.getAuditEntries()[0].getAction()).isEqualTo("soft_deleted");
    }

    @Test
    void missingDetails_failsBeforeAnyRequestWithStatusZero() {
        CapsaraException ex = failure(auditService(server.baseUrl(), null)
                .createAuditEntryAsync("c", new CreateAuditEntryRequest("log", Map.of())));

        assertThat(ex).isInstanceOf(CapsaraAuditException.class);
        assertThat(ex.getCode()).isEqualTo("MISSING_DETAILS");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(server.requests()).isEmpty();
    }

    @Test
    void partyKeys_serverCodePassesThrough() {
        server.on("/api/party/keys", StubServer.json(403, "{\"error\":{\"code\":\"FORBIDDEN\",\"message\":\"no\"}}"));

        CapsaraException ex = failure(keyService(server.baseUrl()).fetchPartyKeysAsync(new String[]{"p"}));

        assertThat(ex.getCode()).isEqualTo("FORBIDDEN");
        assertThat(ex.getStatusCode()).isEqualTo(403);
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>", "null", "[]"})
    void partyKeys_nonObjectBody_isInvalidResponse(String body) {
        server.on("/api/party/keys", StubServer.text(200, body));

        CapsaraException ex = failure(keyService(server.baseUrl()).fetchPartyKeysAsync(new String[]{"p"}));

        assertThat(ex.getCode()).isEqualTo("INVALID_RESPONSE");
        assertThat(ex.getStatusCode()).isZero();
    }

    @Test
    void partyKeys_missingParties_isEmpty() {
        server.on("/api/party/keys", StubServer.json(200, "{\"parties\":null}"));

        assertThat(keyService(server.baseUrl()).fetchPartyKeysAsync(new String[]{"p"}).join()).isEmpty();
    }

    @Test
    void partyKeys_sameIdInTwoSplits_isMergedWithDelegateLinksUnited() {
        String[] ids = new String[KeyService.MAX_IDS_PER_REQUEST + 1];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = "party_" + i;
        }
        server.on("/api/party/keys",
                StubServer.json(200, "{\"parties\":[{\"id\":\"party_0\",\"publicKey\":\"K\",\"isDelegate\":[\"a\"]},"
                        + "{\"id\":\"party_1\",\"publicKey\":\"K1\"}]}"),
                StubServer.json(200, "{\"parties\":[{\"id\":\"party_0\",\"publicKey\":\"K\","
                        + "\"isDelegate\":[\"a\",\"b\"]},{\"id\":\"party_1\",\"publicKey\":\"K1\",\"isDelegate\":[\"c\"]}]}"));

        PartyKey[] keys = keyService(server.baseUrl()).fetchPartyKeysAsync(ids).join();

        assertThat(keys).extracting(PartyKey::getId).containsExactly("party_0", "party_1");
        assertThat(keys[0].getIsDelegate()).containsExactly("a", "b");
        assertThat(keys[1].getIsDelegate()).containsExactly("c");
        assertThat(server.requestsTo("/api/party/keys")).hasSize(2);
    }

    private void stubDownloadUrl(String blobPath) {
        server.on("/api/capsas/c/files/f/download", StubServer.json(200,
                "{\"downloadUrl\":\"" + server.baseUrl() + blobPath + "\",\"expiresAt\":\"x\"}"));
    }

    @Test
    void download_blob403_isDownloadFailedStatusZeroWithStatusInOriginalError() {
        stubDownloadUrl("/blob/f");
        server.on("/blob/f", StubServer.text(403, "AuthenticationFailed"));

        CapsaraException ex = failure(downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(details(ex)).containsEntry("capsaId", "c").containsEntry("fileId", "f");
        assertThat(details(ex)).containsEntry("originalError", "Request failed with status code 403");
    }

    @Test
    void download_blob500_originalErrorMatchesTsText() {
        stubDownloadUrl("/blob/f");
        server.on("/blob/f", StubServer.text(500, "oops"));

        CapsaraException ex = failure(downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f"));

        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(details(ex)).containsEntry("originalError", "Request failed with status code 500");
    }

    @Test
    void download_blobConnectionDropped_isDownloadFailed() {
        stubDownloadUrl("/blob/f");
        server.on("/blob/f", StubServer.dropConnection());

        CapsaraException ex = failure(downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f"));

        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(details(ex)).containsKey("originalError");
    }

    @Test
    void download_blobTimeout_isDownloadFailed() {
        stubDownloadUrl("/blob/f");
        server.on("/blob/f", StubServer.delayed(StubServer.text(200, "late"), 1500));

        CapsaraException ex = failure(downloadService(server.baseUrl(), shortTimeout())
                .downloadEncryptedFileAsync("c", "f"));

        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
    }

    @Test
    void download_urlRequestTimeout_isNetworkErrorNotDownloadFailed() {
        server.on("/api/capsas/c/files/f/download", StubServer.delayed(StubServer.json(200, "{}"), 1500));

        assertNetworkError(failure(downloadService(server.baseUrl(), shortTimeout())
                .downloadEncryptedFileAsync("c", "f")), CapsaraCapsaException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>", "", "null", "[]"})
    void download_urlNonObjectBody_isInvalidResponseWithCapsaAndFileId(String body) {
        server.on("/api/capsas/c/files/f/download", StubServer.text(200, body));

        CapsaraException ex = failure(downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_RESPONSE");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(Map.of("capsaId", "c", "fileId", "f"));
    }

    @Test
    void download_urlWithoutDownloadUrl_isDownloadFailed() {
        server.on("/api/capsas/c/files/f/download", StubServer.json(200, "{}"));

        CapsaraException ex = failure(downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f"));

        assertThat(ex.getCode()).isEqualTo("DOWNLOAD_FAILED");
    }

    @Test
    void download_blobRedirect_isFollowed() {
        stubDownloadUrl("/blob/old");
        server.on("/blob/old", StubServer.redirect(server.baseUrl() + "/blob/new"));
        server.on("/blob/new", StubServer.text(200, "data"));

        byte[] data = downloadService(server.baseUrl(), null).downloadEncryptedFileAsync("c", "f").join();

        assertThat(new String(data, StandardCharsets.UTF_8)).isEqualTo("data");
    }

    @Test
    void defaultTimeouts_matchTheOtherSdks() {
        HttpTimeoutConfig defaults = HttpTimeoutConfig.defaults();

        assertThat(defaults.getRequestTimeout()).isEqualTo(Duration.ofMinutes(12));
        assertThat(defaults.getDownloadTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(defaults.getConnectTimeout()).isEqualTo(Duration.ofSeconds(30));
        assertThat(defaults.getUploadTimeout()).isEqualTo(Duration.ofMinutes(15));
        assertThat(HttpClientFactory.createForApi(null).connectTimeout()).contains(Duration.ofSeconds(30));
    }
}
