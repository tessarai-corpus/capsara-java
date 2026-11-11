package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpRetry;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.PartyKey;
import com.capsara.sdk.models.SendResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Refresh-on-401 behaviour for authenticated API calls against a local HTTP server. */
class TokenRefreshTest {

    private static final String CREATOR_ID = "party_creator_refresh";
    private static final String RECIPIENT_ID = "party_recipient_refresh";

    private HttpServer server;
    private String baseUrl;
    private ConcurrencyConfig concurrency;

    private volatile String loginBody;
    private volatile int refreshStatus;
    private volatile String refreshBody;
    private volatile long refreshDelayMs;
    private volatile String acceptedToken;

    private final AtomicInteger refreshCalls = new AtomicInteger();
    private final List<String> refreshRequests = Collections.synchronizedList(new ArrayList<>());
    private final List<String> protectedAuthHeaders = Collections.synchronizedList(new ArrayList<>());
    private final List<String> protectedBodies = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void startServer() throws IOException {
        loginBody = "{\"accessToken\":\"old\",\"refreshToken\":\"r1\",\"expiresIn\":900}";
        refreshStatus = 200;
        refreshBody = "{\"accessToken\":\"new\",\"refreshToken\":\"r2\",\"expiresIn\":900}";
        refreshDelayMs = 0;
        acceptedToken = "new";

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/api/auth/login", exchange -> respond(exchange, 200, loginBody));
        server.createContext("/api/auth/refresh", exchange -> {
            refreshCalls.incrementAndGet();
            refreshRequests.add(readBody(exchange));
            sleep(refreshDelayMs);
            respond(exchange, refreshStatus, refreshBody);
        });
        server.createContext("/api/party/keys", exchange -> {
            String body = readBody(exchange);
            if (body.contains(CREATOR_ID)) {
                respond(exchange, 200, partyKeysJson());
                return;
            }
            protectedEndpoint(exchange, body, "{\"parties\":[]}");
        });
        server.createContext("/api/capsas/capsa_1/audit", exchange ->
                protectedEndpoint(exchange, readBody(exchange), "{}"));
        server.createContext("/api/capsas", exchange -> protectedEndpoint(exchange, readBody(exchange), 201,
                "{\"batchId\":\"batch_1\",\"successful\":1,\"failed\":0,"
                        + "\"created\":[{\"packageId\":\"capsa_x\",\"index\":0,\"createdAt\":\"2026-01-01T00:00:00Z\"}]}"));
        server.start();

        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        concurrency = new ConcurrencyConfig();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
        concurrency.shutdown();
    }

    private void protectedEndpoint(HttpExchange exchange, String body, String okBody) throws IOException {
        protectedEndpoint(exchange, body, 200, okBody);
    }

    private void protectedEndpoint(HttpExchange exchange, String body, int okStatus, String okBody)
            throws IOException {
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        protectedAuthHeaders.add(auth);
        protectedBodies.add(body);
        if (("Bearer " + acceptedToken).equals(auth)) {
            respond(exchange, okStatus, okBody);
        } else {
            respond(exchange, 401, "{\"error\":{\"code\":\"TOKEN_EXPIRED\",\"message\":\"Token expired\"}}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void sleep(long ms) {
        if (ms <= 0) {
            return;
        }
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String partyKeysJson() {
        try {
            PartyKey[] keys = {
                    TestHelpers.createMockPartyKey(CREATOR_ID, SharedKeyFixture.getPrimaryKeyPair()),
                    TestHelpers.createMockPartyKey(RECIPIENT_ID, SharedKeyFixture.getSecondaryKeyPair())
            };
            return JsonMapper.getInstance().writeValueAsString(Map.of("parties", keys));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private AuthService loggedIn() {
        AuthService auth = new AuthService(baseUrl, null, null, null);
        auth.loginAsync(new AuthCredentials(CREATOR_ID, "pw")).join();
        return auth;
    }

    private HttpClient apiClient(AuthService auth) {
        return new TokenRefreshingHttpClient(HttpClient.newHttpClient(), auth);
    }

    private KeyService keyService(AuthService auth) {
        return new KeyService(apiClient(auth), baseUrl, auth::getToken, null, RetryConfig.defaults(), null,
                concurrency);
    }

    private static Throwable failure(Runnable call) {
        Throwable thrown = catchThrowable(call::run);
        assertThat(thrown).isInstanceOf(CompletionException.class);
        return thrown.getCause();
    }

    @Test
    void retryExecutorPath_refreshesAndRetriesWithNewToken() {
        AuthService auth = loggedIn();

        PartyKey[] keys = keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"}).join();

        assertThat(keys).isEmpty();
        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).containsExactly("Bearer old", "Bearer new");
        assertThat(auth.getToken()).isEqualTo("new");
    }

    @Test
    void directSendPath_refreshesAndResendsSameBody() {
        AuthService auth = loggedIn();
        AuditService audit = new AuditService(apiClient(auth), baseUrl, auth::getToken, null, null, concurrency);

        Boolean created = audit.createAuditEntryAsync("capsa_1",
                new CreateAuditEntryRequest("processed", Map.of("note", "done"))).join();

        assertThat(created).isTrue();
        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).containsExactly("Bearer old", "Bearer new");
        assertThat(protectedBodies).hasSize(2);
        assertThat(protectedBodies.get(0)).contains("processed").isEqualTo(protectedBodies.get(1));
    }

    @Test
    void uploadPath_refreshesAndRetriesWithNewToken() {
        AuthService auth = loggedIn();
        HttpClient client = apiClient(auth);
        KeyService keys = new KeyService(client, baseUrl, auth::getToken, null, RetryConfig.defaults(), null,
                concurrency);
        UploadService upload = new UploadService(client, baseUrl, auth::getToken, keys, 100,
                RetryConfig.defaults(), null, null, concurrency);

        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeys.getPrivateKey(), null);
        builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
        builder.addRecipient(RECIPIENT_ID).addTextFile("note.txt", "hello").withSubject("Subject");

        SendResult result = upload.sendCapsasAsync(new CapsaBuilder[]{builder}, CREATOR_ID).join();

        assertThat(result.getSuccessful()).isEqualTo(1);
        assertThat(result.getFailed()).isZero();
        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).containsExactly("Bearer old", "Bearer new");
        assertThat(protectedBodies.get(0)).isEqualTo(protectedBodies.get(1));
    }

    @Test
    void concurrentUnauthorized_shareOneRefresh() {
        refreshDelayMs = 300;
        AuthService auth = loggedIn();
        KeyService keys = keyService(auth);

        List<CompletableFuture<PartyKey[]>> calls = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            calls.add(keys.fetchPartyKeysAsync(new String[]{"party_other_" + i}));
        }
        CompletableFuture.allOf(calls.toArray(new CompletableFuture[0])).join();

        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).filteredOn("Bearer new"::equals).hasSize(8);
    }

    @Test
    void refreshFailure_surfacesRefreshErrorWithoutLooping() {
        refreshStatus = 401;
        refreshBody = "{\"error\":{\"code\":\"INVALID_REFRESH_TOKEN\",\"message\":\"Refresh token revoked\"}}";
        AuthService auth = loggedIn();

        Throwable cause = failure(() -> keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"}).join());

        assertThat(cause).isInstanceOf(CapsaraAuthException.class);
        assertThat(((CapsaraException) cause).getCode()).isEqualTo("INVALID_REFRESH_TOKEN");
        assertThat(auth.getLastRefreshError()).isSameAs(cause);
        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).containsExactly("Bearer old");
    }

    @Test
    void refreshWithoutAccessToken_isAcceptedAndTheResentRequestsAnswerStands() {
        refreshBody = "{\"refreshToken\":\"r2\"}";
        AuthService auth = loggedIn();

        Throwable cause = failure(() -> keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"}).join());

        assertThat(cause).isNotInstanceOf(CapsaraAuthException.class);
        assertThat(((CapsaraException) cause).getCode()).isEqualTo("TOKEN_EXPIRED");
        assertThat(((CapsaraException) cause).getStatusCode()).isEqualTo(401);
        assertThat(auth.getLastRefreshError()).isNull();
        assertThat(protectedAuthHeaders).containsExactly("Bearer old", "Bearer old");
    }

    @Test
    void refreshWithNullBody_failsAsAuthError() {
        refreshBody = "null";
        AuthService auth = loggedIn();

        assertThat(auth.refreshAsync().join()).isFalse();

        assertThat(auth.getLastRefreshError()).isInstanceOf(CapsaraAuthException.class);
    }

    @Test
    void refreshSupersededBySetToken_surfacesTheOriginal401NotAStaleRefreshError() throws Exception {
        refreshStatus = 401;
        refreshBody = "{\"error\":{\"code\":\"INVALID_REFRESH_TOKEN\",\"message\":\"Refresh token revoked\"}}";
        AuthService auth = loggedIn();
        assertThat(auth.refreshAsync().join()).isFalse();
        assertThat(auth.getLastRefreshError()).isNotNull();
        refreshStatus = 200;
        refreshBody = "{\"accessToken\":\"new\",\"refreshToken\":\"r2\",\"expiresIn\":900}";
        refreshDelayMs = 600;

        CompletableFuture<PartyKey[]> call = keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"});
        Thread.sleep(250);
        auth.setToken("other");
        Throwable cause = failure(call::join);

        assertThat(((CapsaraException) cause).getCode()).isEqualTo("TOKEN_EXPIRED");
        assertThat(((CapsaraException) cause).getStatusCode()).isEqualTo(401);
        assertThat(auth.getToken()).isEqualTo("other");
    }

    @Test
    void refreshValidationError_isRecordedAsAuthError() {
        refreshStatus = 400;
        refreshBody = "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"refreshToken required\"}}";
        AuthService auth = loggedIn();

        assertThat(auth.refreshAsync().join()).isFalse();

        assertThat(auth.getLastRefreshError()).isExactlyInstanceOf(CapsaraAuthException.class);
        assertThat(((CapsaraException) auth.getLastRefreshError()).getCode()).isEqualTo("VALIDATION_ERROR");
        assertThat(((CapsaraException) auth.getLastRefreshError()).getStatusCode()).isEqualTo(400);
    }

    @Test
    void refreshNetworkFailure_isRecordedAsAuthNetworkError() throws IOException {
        try (StubServer stub = new StubServer()) {
            stub.on("/api/auth/refresh", StubServer.dropConnection());
            AuthService auth = new AuthService(stub.baseUrl(), null,
                    new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)), null);
            auth.setTokens("old", "r1");

            assertThat(auth.refreshAsync().join()).isFalse();

            assertThat(auth.getLastRefreshError()).isExactlyInstanceOf(CapsaraAuthException.class);
            assertThat(((CapsaraException) auth.getLastRefreshError()).getCode()).isEqualTo("NETWORK_ERROR");
            assertThat(((CapsaraException) auth.getLastRefreshError()).getStatusCode()).isZero();
        }
    }

    @Test
    void unauthorizedAfterRefresh_isNotRetriedAgain() {
        acceptedToken = "never";
        AuthService auth = loggedIn();

        Throwable cause = failure(() -> keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"}).join());

        assertThat(cause).isInstanceOf(CapsaraException.class);
        assertThat(((CapsaraException) cause).getStatusCode()).isEqualTo(401);
        assertThat(refreshCalls.get()).isEqualTo(1);
        assertThat(protectedAuthHeaders).containsExactly("Bearer old", "Bearer new");
    }

    @Test
    void withoutRefreshToken_noRefreshIsAttempted() {
        loginBody = "{\"accessToken\":\"old\",\"expiresIn\":900}";
        AuthService auth = loggedIn();

        Throwable cause = failure(() -> keyService(auth).fetchPartyKeysAsync(new String[]{"party_other"}).join());

        assertThat(auth.canRefresh()).isFalse();
        assertThat(((CapsaraException) cause).getStatusCode()).isEqualTo(401);
        assertThat(refreshCalls.get()).isZero();
        assertThat(protectedAuthHeaders).containsExactly("Bearer old");
    }

    private static List<String> authHeaders(StubServer stub, String path) {
        List<String> headers = new ArrayList<>();
        for (StubServer.Recorded r : stub.requestsTo(path)) {
            headers.add(r.header("Authorization"));
        }
        return headers;
    }

    private static HttpResponse<String> sendWithRetry(StubServer stub) {
        AuthService auth = new AuthService(stub.baseUrl(), null, null, null);
        auth.loginAsync(new AuthCredentials(CREATOR_ID, "pw")).join();
        HttpClient client = new TokenRefreshingHttpClient(HttpClient.newHttpClient(), auth);
        HttpRequest request = HttpRequest.newBuilder(URI.create(stub.baseUrl() + "/r"))
                .header("Authorization", "Bearer " + auth.getToken()).GET().build();
        return HttpRetry.send(client, request, HttpResponse.BodyHandlers.ofString(),
                new RetryConfig(3, Duration.ofMillis(1), 2.0, Duration.ofMillis(5)), null).join();
    }

    private static StubServer authStub() throws IOException {
        StubServer stub = new StubServer();
        stub.on("/api/auth/login", StubServer.json(200,
                "{\"accessToken\":\"old\",\"refreshToken\":\"r1\",\"expiresIn\":900}"));
        stub.on("/api/auth/refresh", StubServer.json(200,
                "{\"accessToken\":\"new\",\"refreshToken\":\"r2\",\"expiresIn\":900}"));
        return stub;
    }

    @Test
    void retryBudget_isSharedAcrossTheRefresh_andLaterRetriesKeepTheNewToken() throws IOException {
        try (StubServer stub = authStub()) {
            stub.on("/r", StubServer.json(503, "{}"), StubServer.json(401, "{}"), StubServer.json(503, "{}"));

            assertThat(sendWithRetry(stub).statusCode()).isEqualTo(503);

            assertThat(authHeaders(stub, "/r"))
                    .containsExactly("Bearer old", "Bearer old", "Bearer new", "Bearer new", "Bearer new");
            assertThat(stub.requestsTo("/api/auth/refresh")).hasSize(1);
        }
    }

    @Test
    void unauthorizedOnALaterRetry_afterARefresh_isFinal() throws IOException {
        try (StubServer stub = authStub()) {
            stub.on("/r", StubServer.json(401, "{}"), StubServer.json(503, "{}"), StubServer.json(401, "{}"));

            assertThat(sendWithRetry(stub).statusCode()).isEqualTo(401);

            assertThat(authHeaders(stub, "/r")).containsExactly("Bearer old", "Bearer new", "Bearer new");
            assertThat(stub.requestsTo("/api/auth/refresh")).hasSize(1);
        }
    }

    @Test
    void refresh_sendsCurrentRefreshTokenAndKeepsItWhenNotRotated() {
        refreshBody = "{\"accessToken\":\"new\",\"expiresIn\":900}";
        AuthService auth = loggedIn();

        assertThat(auth.refreshAsync().join()).isTrue();
        assertThat(auth.refreshAsync().join()).isTrue();

        assertThat(refreshRequests).hasSize(2).allSatisfy(body -> assertThat(body).contains("\"r1\""));
        assertThat(auth.getToken()).isEqualTo("new");
        assertThat(auth.getLastRefreshError()).isNull();
    }

    @Test
    void refresh_usesRotatedRefreshTokenNextTime() {
        AuthService auth = loggedIn();

        auth.refreshAsync().join();
        auth.refreshAsync().join();

        assertThat(refreshRequests.get(0)).contains("\"r1\"");
        assertThat(refreshRequests.get(1)).contains("\"r2\"");
    }

    @Test
    void loginFailure_doesNotTriggerRefresh() {
        AuthService auth = loggedIn();
        loginBody = "{\"error\":{\"code\":\"AUTHENTICATION_FAILED\",\"message\":\"Invalid\"}}";
        server.removeContext("/api/auth/login");
        server.createContext("/api/auth/login", exchange -> respond(exchange, 401, loginBody));

        Throwable cause = failure(() -> auth.loginAsync(new AuthCredentials(CREATOR_ID, "bad")).join());

        assertThat(cause).isInstanceOf(CapsaraAuthException.class);
        assertThat(refreshCalls.get()).isZero();
    }
}
