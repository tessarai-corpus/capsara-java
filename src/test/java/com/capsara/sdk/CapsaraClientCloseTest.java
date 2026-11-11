package com.capsara.sdk;

import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.models.AuthCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Closing the client logs out, swallows logout failures, and clears tokens and keys. */
class CapsaraClientCloseTest {

    private static final String LOGIN_OK = "{\"party\":{\"id\":\"party_me\",\"email\":\"a@b.c\",\"name\":\"Me\","
            + "\"kind\":\"user\"},\"accessToken\":\"access-1\",\"refreshToken\":\"refresh-1\",\"expiresIn\":900}";

    private StubServer server;
    private CapsaraClient client;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        server.on("/api/auth/login", StubServer.json(200, LOGIN_OK));
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setRetry(new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)));
        client = new CapsaraClient(server.baseUrl(), options);
        client.loginAsync(new AuthCredentials("party_me", "pw")).join();
        client.setPrivateKey(com.capsara.sdk.helpers.SharedKeyFixture.getPrimaryKeyPair().getPrivateKey());
        client.addPreviousPrivateKey(com.capsara.sdk.helpers.SharedKeyFixture.getSecondaryKeyPair().getPrivateKey());
    }

    @AfterEach
    void stop() {
        client.close();
        server.close();
    }

    private Object field(String name) throws Exception {
        Field field = CapsaraClient.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(client);
    }

    @Test
    void close_logsOutAndClearsTokensAndKeys() throws Exception {
        server.on("/api/auth/logout", StubServer.json(200, "{}"));

        client.close();

        List<StubServer.Recorded> logouts = server.requestsTo("/api/auth/logout");
        assertThat(logouts).hasSize(1);
        assertThat(logouts.get(0).header("Authorization")).isEqualTo("Bearer access-1");
        assertThat(logouts.get(0).body).isEqualTo("{\"refreshToken\":\"refresh-1\"}");
        assertThat(client.isAuthenticated()).isFalse();
        assertThat(field("creatorPrivateKey")).isNull();
        assertThat(field("creatorId")).isNull();
        assertThat((List<?>) field("previousPrivateKeys")).isEmpty();
    }

    @Test
    void close_swallowsALogoutRejection() {
        server.on("/api/auth/logout", StubServer.json(500,
                "{\"error\":{\"code\":\"INTERNAL_ERROR\",\"message\":\"Logout failed\"}}"));

        client.close();

        assertThat(server.requestsTo("/api/auth/logout")).hasSize(1);
        assertThat(client.isAuthenticated()).isFalse();
    }

    @Test
    void close_swallowsANetworkFailure() {
        server.on("/api/auth/logout", StubServer.dropConnection());

        client.close();

        assertThat(client.isAuthenticated()).isFalse();
    }

    @Test
    void close_twice_logsOutOnce() {
        server.on("/api/auth/logout", StubServer.json(200, "{}"));

        client.close();
        client.close();

        assertThat(server.requestsTo("/api/auth/logout")).hasSize(1);
    }
}
