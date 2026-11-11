package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.models.AuthCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Logout revokes the session server-side, reports the real outcome and never leaves local tokens behind. */
class AuthServiceLogoutTest {

    private static final String LOGIN_OK = "{\"party\":{\"id\":\"party_me\",\"email\":\"a@b.c\",\"name\":\"Me\","
            + "\"kind\":\"user\"},\"accessToken\":\"access-1\",\"refreshToken\":\"refresh-1\",\"expiresIn\":900}";
    private static final String REFRESH_OK = "{\"accessToken\":\"access-2\",\"refreshToken\":\"refresh-2\","
            + "\"expiresIn\":900}";
    private static final String EXPIRED = "{\"error\":{\"code\":\"INVALID_TOKEN\",\"message\":\"Token expired\"}}";

    private StubServer server;
    private AuthService service;

    @BeforeEach
    void start() throws Exception {
        startWithLogin(LOGIN_OK);
    }

    private void startWithLogin(String loginBody) throws Exception {
        if (server != null) {
            server.close();
        }
        server = new StubServer();
        server.on("/api/auth/login", StubServer.json(200, loginBody));
        service = new AuthService(server.baseUrl(), null,
                new RetryConfig(3, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)), null);
    }

    @AfterEach
    void stop() {
        server.close();
    }

    private void login() {
        service.loginAsync(new AuthCredentials("party_me", "pw")).join();
        assertThat(service.isAuthenticated()).isTrue();
    }

    private static CapsaraException failure(CompletableFuture<?> future) {
        Throwable thrown = catchThrowable(future::join);
        assertThat(thrown).isInstanceOf(CompletionException.class);
        assertThat(thrown.getCause()).isInstanceOf(CapsaraException.class);
        return (CapsaraException) thrown.getCause();
    }

    @Test
    void logout_sendsRefreshTokenWithCapturedAccessToken() {
        server.on("/api/auth/logout", StubServer.json(200, "{\"message\":\"Logged out\"}"));
        login();

        boolean result = service.logoutAsync().join();

        assertThat(result).isTrue();
        assertThat(service.isAuthenticated()).isFalse();
        StubServer.Recorded request = server.requestsTo("/api/auth/logout").get(0);
        assertThat(request.body).isEqualTo("{\"refreshToken\":\"refresh-1\"}");
        assertThat(request.header("Authorization")).isEqualTo("Bearer access-1");
    }

    @Test
    void logout_networkFailure_throwsNetworkErrorWithTokensCleared() {
        server.on("/api/auth/logout", StubServer.dropConnection());
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex).isInstanceOf(CapsaraAuthException.class);
        assertThat(ex.getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.getToken()).isNull();
    }

    @Test
    void logout_refreshValidationError_throwsAuthException() {
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED));
        server.on("/api/auth/refresh", StubServer.json(400,
                "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"refreshToken required\"}}"));
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex).isInstanceOf(CapsaraAuthException.class);
        assertThat(ex.getCode()).isEqualTo("VALIDATION_ERROR");
        assertThat(ex.getStatusCode()).isEqualTo(400);
    }

    @Test
    void logout_refreshNetworkFailure_throwsAuthNetworkError() {
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED));
        server.on("/api/auth/refresh", StubServer.dropConnection());
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex).isInstanceOf(CapsaraAuthException.class);
        assertThat(ex.getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(ex.getStatusCode()).isZero();
    }

    @Test
    void logout_locallyExpiredAccessToken_refreshesFirstWithoutStoringTheResult() throws Exception {
        startWithLogin(LOGIN_OK.replace("\"expiresIn\":900", "\"expiresIn\":20"));
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        server.on("/api/auth/logout", StubServer.json(200, "{}"));
        login();

        assertThat(service.logoutAsync().join()).isTrue();

        assertThat(server.requestsTo("/api/auth/refresh").get(0).body)
                .isEqualTo("{\"refreshToken\":\"refresh-1\"}");
        List<StubServer.Recorded> logouts = server.requestsTo("/api/auth/logout");
        assertThat(logouts).hasSize(1);
        assertThat(logouts.get(0).header("Authorization")).isEqualTo("Bearer access-2");
        assertThat(logouts.get(0).body).isEqualTo("{\"refreshToken\":\"refresh-2\"}");
        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.canRefresh()).isFalse();
    }

    @Test
    void logout_rejectedAfterAPreRefresh_doesNotRefreshAgain() throws Exception {
        startWithLogin(LOGIN_OK.replace("\"expiresIn\":900", "\"expiresIn\":20"));
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED));
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex).isInstanceOf(CapsaraAuthException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_TOKEN");
        assertThat(server.requestsTo("/api/auth/refresh")).hasSize(1);
        assertThat(server.requestsTo("/api/auth/logout")).hasSize(1);
    }

    @Test
    void logout_expiredJwtSetByTheCaller_refreshesFirst() {
        long past = System.currentTimeMillis() / 1000 - 60;
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"exp\":" + past + "}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        server.on("/api/auth/logout", StubServer.json(200, "{}"));
        service.setTokens("h." + payload + ".s", "refresh-x");

        assertThat(service.logoutAsync().join()).isTrue();

        assertThat(server.requestsTo("/api/auth/refresh")).hasSize(1);
        assertThat(server.requestsTo("/api/auth/logout").get(0).header("Authorization"))
                .isEqualTo("Bearer access-2");
    }

    @Test
    void tokenExpiry_isTrackedFromExpiresIn() {
        login();

        assertThat(service.isTokenExpired(30)).isFalse();
        assertThat(service.isTokenExpired(901)).isTrue();
    }

    @Test
    void logout_serverRejection_throwsServerCodeWithTokensCleared() {
        server.on("/api/auth/logout", StubServer.json(500,
                "{\"error\":{\"code\":\"INTERNAL_ERROR\",\"message\":\"Logout failed\"}}"));
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex).isInstanceOf(CapsaraAuthException.class);
        assertThat(ex.getCode()).isEqualTo("INTERNAL_ERROR");
        assertThat(ex.getStatusCode()).isEqualTo(500);
        assertThat(service.isAuthenticated()).isFalse();
        assertThat(server.requestsTo("/api/auth/refresh")).isEmpty();
    }

    @Test
    void logout_expiredAccessToken_refreshesOnceAndRetriesWithTheNewPair() {
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED), StubServer.json(200, "{}"));
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        login();

        assertThat(service.logoutAsync().join()).isTrue();

        assertThat(server.requestsTo("/api/auth/refresh").get(0).body)
                .isEqualTo("{\"refreshToken\":\"refresh-1\"}");
        List<StubServer.Recorded> logouts = server.requestsTo("/api/auth/logout");
        assertThat(logouts).hasSize(2);
        assertThat(logouts.get(1).header("Authorization")).isEqualTo("Bearer access-2");
        assertThat(logouts.get(1).body).isEqualTo("{\"refreshToken\":\"refresh-2\"}");
        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.canRefresh()).isFalse();
    }

    @Test
    void logout_rejectedAgainAfterRefresh_throwsWithoutAnotherRefresh() {
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED));
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex.getCode()).isEqualTo("INVALID_TOKEN");
        assertThat(ex.getStatusCode()).isEqualTo(401);
        assertThat(server.requestsTo("/api/auth/refresh")).hasSize(1);
        assertThat(server.requestsTo("/api/auth/logout")).hasSize(2);
    }

    @Test
    void logout_refreshFailure_throwsTheRefreshError() {
        server.on("/api/auth/logout", StubServer.json(401, EXPIRED));
        server.on("/api/auth/refresh", StubServer.json(401,
                "{\"error\":{\"code\":\"INVALID_REFRESH_TOKEN\",\"message\":\"Refresh token revoked\"}}"));
        login();

        CapsaraException ex = failure(service.logoutAsync());

        assertThat(ex.getCode()).isEqualTo("INVALID_REFRESH_TOKEN");
        assertThat(server.requestsTo("/api/auth/logout")).hasSize(1);
        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void logout_tokensClearedBeforeTheRequestIsSent() {
        server.on("/api/auth/logout", StubServer.json(200, "{\"message\":\"Logged out\"}"));
        login();

        CompletableFuture<Boolean> pending = service.logoutAsync();

        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.canRefresh()).isFalse();
        assertThat(pending.join()).isTrue();
    }

    @Test
    void logout_withoutSession_succeedsWithoutCallingTheServer() {
        assertThat(service.logoutAsync().join()).isTrue();
        assertThat(server.requestsTo("/api/auth/logout")).isEmpty();
    }

    @Test
    void logout_withAccessTokenOnly_revokesItWithAnEmptyBody() {
        server.on("/api/auth/logout", StubServer.json(200, "{}"));
        service.setToken("access-only");

        assertThat(service.logoutAsync().join()).isTrue();

        assertThat(service.isAuthenticated()).isFalse();
        StubServer.Recorded request = server.requestsTo("/api/auth/logout").get(0);
        assertThat(request.body).isEqualTo("{}");
        assertThat(request.header("Authorization")).isEqualTo("Bearer access-only");
    }

    @Test
    void logout_withRefreshTokenOnly_refreshesThenRevokes() {
        server.on("/api/auth/refresh", StubServer.json(200, REFRESH_OK));
        server.on("/api/auth/logout", StubServer.json(200, "{}"));
        service.setTokens(null, "refresh-only");

        assertThat(service.logoutAsync().join()).isTrue();

        assertThat(server.requestsTo("/api/auth/refresh").get(0).body)
                .isEqualTo("{\"refreshToken\":\"refresh-only\"}");
        assertThat(server.requestsTo("/api/auth/logout").get(0).header("Authorization"))
                .isEqualTo("Bearer access-2");
        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void refreshInFlight_doesNotRestoreTokensAfterLogout() {
        server.on("/api/auth/refresh", StubServer.delayed(StubServer.json(200, REFRESH_OK), 300));
        server.on("/api/auth/logout", StubServer.json(200, "{}"));
        login();

        CompletableFuture<Boolean> refresh = service.refreshAsync();
        service.logoutAsync();

        assertThat(refresh.join()).isFalse();
        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.canRefresh()).isFalse();
    }

    @Test
    void refreshInFlight_doesNotOverwriteANewLogin() {
        server.on("/api/auth/refresh", StubServer.delayed(StubServer.json(200, REFRESH_OK), 300));
        login();

        CompletableFuture<Boolean> refresh = service.refreshAsync();
        service.setTokens("access-new", "refresh-new");

        assertThat(refresh.join()).isFalse();
        assertThat(service.getToken()).isEqualTo("access-new");
    }
}
