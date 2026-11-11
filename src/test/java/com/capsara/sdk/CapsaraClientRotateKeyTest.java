package com.capsara.sdk;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.KeyRotationResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Key rotation hands the new key pair to the caller first and switches keys only once registered. */
class CapsaraClientRotateKeyTest {

    private static final String OLD_KEY =
            com.capsara.sdk.helpers.SharedKeyFixture.getPrimaryKeyPair().getPrivateKey();

    private StubServer server;
    private CapsaraClient client;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        options.setRetry(new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)));
        client = new CapsaraClient(server.baseUrl(), options);
        client.setPrivateKey(OLD_KEY);
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
    void rotate_givesTheKeyPairToTheCallerBeforeRegisteringAndSwitchesKeys() throws Exception {
        server.on("/api/account/key", StubServer.json(200,
                "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"fp\"}"));
        AtomicReference<GeneratedKeyPairResult> handed = new AtomicReference<>();
        AtomicInteger requestsWhenHanded = new AtomicInteger(-1);

        KeyRotationResult result = client.rotateKeyAsync(keyPair -> {
            handed.set(keyPair);
            requestsWhenHanded.set(server.requestsTo("/api/account/key").size());
        }).join();

        assertThat(requestsWhenHanded.get()).isZero();
        assertThat(result.getKeyPair()).isSameAs(handed.get());
        assertThat(result.getKeyPair().getKeySize()).isEqualTo(4096);
        assertThat(server.requestsTo("/api/account/key").get(0).body)
                .contains(result.getKeyPair().getFingerprint());
        assertThat(field("creatorPrivateKey")).isEqualTo(result.getKeyPair().getPrivateKey());
        assertThat((List<?>) field("previousPrivateKeys")).isEqualTo(List.of(OLD_KEY));
    }

    @Test
    void rotate_withReason_sendsItAndKeepsOnePreviousCopy() throws Exception {
        server.on("/api/account/key", StubServer.json(200,
                "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"fp\"}"));
        client.addPreviousPrivateKey(OLD_KEY);

        client.rotateKeyAsync(null, "compromised").join();

        assertThat(server.requestsTo("/api/account/key").get(0).body).contains("\"reason\":\"compromised\"");
        assertThat((List<?>) field("previousPrivateKeys")).isEqualTo(List.of(OLD_KEY));
    }

    @Test
    void rotate_withoutReason_sendsNoReason() {
        server.on("/api/account/key", StubServer.json(200,
                "{\"publicKey\":\"PEM\",\"publicKeyFingerprint\":\"fp\"}"));

        client.rotateKeyAsync(null, null).join();

        assertThat(server.requestsTo("/api/account/key").get(0).body).doesNotContain("reason");
    }

    @Test
    void addPreviousPrivateKey_twice_keepsOneCopy() throws Exception {
        String other = com.capsara.sdk.helpers.SharedKeyFixture.getSecondaryKeyPair().getPrivateKey();

        client.addPreviousPrivateKey(other);
        client.addPreviousPrivateKey(other);

        assertThat((List<?>) field("previousPrivateKeys")).isEqualTo(List.of(other));
    }

    @Test
    void rotate_networkFailure_isAccountNetworkErrorAndKeepsTheCurrentKey() throws Exception {
        server.on("/api/account/key", StubServer.dropConnection());

        Throwable thrown = catchThrowable(() -> client.rotateKeyAsync(null, "r").join());

        assertThat(thrown.getCause()).isInstanceOf(com.capsara.sdk.exceptions.CapsaraAccountException.class);
        assertThat(((CapsaraException) thrown.getCause()).getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(field("creatorPrivateKey")).isEqualTo(OLD_KEY);
    }

    @Test
    void rotate_callbackFailure_sendsNothingAndKeepsTheCurrentKey() throws Exception {
        IllegalStateException storageDown = new IllegalStateException("storage down");

        Throwable thrown = catchThrowable(() -> client.rotateKeyAsync(keyPair -> {
            throw storageDown;
        }).join());

        assertThat(thrown).isInstanceOf(CompletionException.class).hasCauseReference(storageDown);
        assertThat(server.requestsTo("/api/account/key")).isEmpty();
        assertThat(field("creatorPrivateKey")).isEqualTo(OLD_KEY);
        assertThat((List<?>) field("previousPrivateKeys")).isEmpty();
    }

    @Test
    void rotate_serverRejection_keepsTheCurrentKeyButTheCallerHasTheNewPair() throws Exception {
        server.on("/api/account/key", StubServer.json(400,
                "{\"error\":{\"code\":\"FINGERPRINT_MISMATCH\",\"message\":\"Fingerprint does not match\"}}"));
        AtomicReference<GeneratedKeyPairResult> handed = new AtomicReference<>();

        Throwable thrown = catchThrowable(() -> client.rotateKeyAsync(handed::set).join());

        assertThat(thrown.getCause()).isInstanceOf(CapsaraException.class);
        assertThat(((CapsaraException) thrown.getCause()).getCode()).isEqualTo("FINGERPRINT_MISMATCH");
        assertThat(handed.get()).isNotNull();
        assertThat(handed.get().getPrivateKey()).contains("PRIVATE KEY");
        assertThat(field("creatorPrivateKey")).isEqualTo(OLD_KEY);
        assertThat((List<?>) field("previousPrivateKeys")).isEmpty();
    }
}
