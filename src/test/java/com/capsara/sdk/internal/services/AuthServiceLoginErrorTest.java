package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.models.AuthCredentials;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Login error mapping against a local HTTP server. */
class AuthServiceLoginErrorTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private AuthService serviceRespondingWith(int status, String body) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/auth/login", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        return new AuthService("http://127.0.0.1:" + server.getAddress().getPort(), null,
                new RetryConfig(3, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)), null);
    }

    private Throwable loginFailure(AuthService service) {
        Throwable thrown = catchThrowable(() -> service.loginAsync(new AuthCredentials("p_abc", "pw")).join());
        assertThat(thrown).isInstanceOf(CompletionException.class);
        return thrown.getCause();
    }

    @Test
    void authenticationFailed401_mapsToInvalidCredentials() throws Exception {
        AuthService service = serviceRespondingWith(401,
                "{\"error\":{\"code\":\"AUTHENTICATION_FAILED\",\"message\":\"Invalid party ID or password\"}}");

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraAuthException.class);
        CapsaraAuthException ex = (CapsaraAuthException) cause;
        assertThat(ex.getCode()).isEqualTo(CapsaraAuthException.invalidCredentials().getCode());
        assertThat(ex.getCode()).isEqualTo("AUTHENTICATION_FAILED");
        assertThat(ex.getStatusCode()).isEqualTo(401);
        assertThat(ex.getMessage()).isEqualTo("Invalid party ID or password");
        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void validationError400_mapsToValidationErrorNotAuthError() throws Exception {
        AuthService service = serviceRespondingWith(400,
                "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"Invalid request\"}}");

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraException.class);
        CapsaraException ex = (CapsaraException) cause;
        assertThat(ex.getCode()).isEqualTo("VALIDATION_ERROR");
        assertThat(ex.getStatusCode()).isEqualTo(400);
        assertThat(ex.getMessage()).isEqualTo("Invalid request");
    }

    @Test
    void otherCode401_mapsToAuthErrorWithServerCode() throws Exception {
        AuthService service = serviceRespondingWith(401,
                "{\"error\":{\"code\":\"ACCOUNT_LOCKED\",\"message\":\"Account locked\"}}");

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraAuthException.class);
        CapsaraAuthException ex = (CapsaraAuthException) cause;
        assertThat(ex.getCode()).isEqualTo("ACCOUNT_LOCKED");
        assertThat(ex.getStatusCode()).isEqualTo(401);
        assertThat(ex.getMessage()).isEqualTo("Account locked");
    }

    @Test
    void rateLimited429_mapsToAuthError() throws Exception {
        AuthService service = serviceRespondingWith(429,
                "{\"error\":{\"code\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"Too many login attempts\"}}");

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraAuthException.class);
        CapsaraAuthException ex = (CapsaraAuthException) cause;
        assertThat(ex.getCode()).isEqualTo("RATE_LIMIT_EXCEEDED");
        assertThat(ex.getStatusCode()).isEqualTo(429);
        assertThat(ex.getMessage()).isEqualTo("Too many login attempts");
    }

    @Test
    void unrecognisedErrorBody_mapsToAuthErrorWithStatus() throws Exception {
        AuthService service = serviceRespondingWith(500, "oops");

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraAuthException.class);
        assertThat(((CapsaraException) cause).getCode()).isEqualTo("HTTP_500");
        assertThat(((CapsaraException) cause).getMessage()).isEqualTo("Internal Server Error");
        assertThat(((CapsaraException) cause).getStatusCode()).isEqualTo(500);
    }

    @Test
    void rateLimited429_exposesRetryAfter() throws Exception {
        AuthService service = serviceRespondingWith(429,
                "{\"error\":{\"code\":\"AUTH_RATE_LIMIT_EXCEEDED\",\"message\":\"Slow down\",\"retryAfter\":42}}");

        CapsaraException ex = (CapsaraException) loginFailure(service);

        assertThat(ex.getCode()).isEqualTo("AUTH_RATE_LIMIT_EXCEEDED");
        assertThat(ex.getRetryAfter()).isEqualTo(42.0);
    }

    @Test
    void networkFailure_mapsToAuthNetworkError() throws Exception {
        serviceRespondingWith(200, "{}");
        int port = server.getAddress().getPort();
        server.stop(0);
        server = null;
        AuthService service = new AuthService("http://127.0.0.1:" + port, null,
                new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)), null);

        Throwable cause = loginFailure(service);

        assertThat(cause).isExactlyInstanceOf(CapsaraAuthException.class);
        assertThat(((CapsaraException) cause).getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(((CapsaraException) cause).getStatusCode()).isZero();
    }

    @Test
    void validationError400_keepsDetailsArrayRaw() throws Exception {
        AuthService service = serviceRespondingWith(400,
                "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"Invalid request\","
                        + "\"details\":[{\"path\":\"partyId\",\"message\":\"Required\"}]}}");

        CapsaraException ex = (CapsaraException) loginFailure(service);

        assertThat(ex.getDetails()).isEqualTo(
                java.util.List.of(java.util.Map.of("path", "partyId", "message", "Required")));
    }
}
