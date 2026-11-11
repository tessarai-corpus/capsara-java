package com.capsara.sdk;

import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.FileInput;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.KeychainEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Caller-reachable client failures carry an SDK code and status 0. */
class CapsaraClientCodedErrorsTest {

    private static final GeneratedKeyPairResult KEYS = SharedKeyFixture.getPrimaryKeyPair();

    private StubServer server;
    private CapsaraClient client;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        options.setRetry(new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)));
        client = new CapsaraClient(server.baseUrl(), options);
    }

    @AfterEach
    void stop() {
        client.close();
        server.close();
    }

    private static CapsaraException failure(CompletableFuture<?> future) {
        Throwable thrown = catchThrowable(future::join);
        assertThat(thrown).isInstanceOf(CompletionException.class);
        assertThat(thrown.getCause()).isInstanceOf(CapsaraException.class);
        return (CapsaraException) thrown.getCause();
    }

    private static void assertCode(CapsaraException ex, String code) {
        assertThat(ex.getCode()).isEqualTo(code);
        assertThat(ex.getStatusCode()).isZero();
    }

    private void login() {
        server.on("/api/auth/login", StubServer.json(200,
                "{\"party\":{\"id\":\"party_me\"},\"accessToken\":\"a\",\"refreshToken\":\"r\",\"expiresIn\":900}"));
        client.loginAsync(new AuthCredentials("party_me", "pw")).join();
    }

    @Test
    void getWithoutPrivateKey_isMissingPrivateKeyBeforeAnyRequest() {
        CapsaraException ex = failure(client.getDecryptedCapsaAsync("capsa_x"));

        assertThat(ex).isExactlyInstanceOf(CapsaraException.class);
        assertCode(ex, "MISSING_PRIVATE_KEY");
        assertThat(server.requests()).isEmpty();
    }

    @Test
    void downloadOnCacheMissWithoutPrivateKey_isMissingPrivateKey() {
        assertCode(failure(client.downloadFileAsync("capsa_x", "file_1")), "MISSING_PRIVATE_KEY");
    }

    @Test
    void builderOrSendBeforeLogin_isNotLoggedIn_evenWithoutAKey() {
        assertCode(failure(client.createCapsaBuilderAsync()), "NOT_LOGGED_IN");
        assertCode(failure(client.sendCapsasAsync(new CapsaBuilder[0])), "NOT_LOGGED_IN");
    }

    @Test
    void builderAfterLoginWithoutKey_isMissingPrivateKey() {
        login();

        assertCode(failure(client.createCapsaBuilderAsync()), "MISSING_PRIVATE_KEY");
    }

    @Test
    void sendWithNoCapsas_isValidationErrorWithoutDetails() {
        login();

        CapsaraException ex = failure(client.sendCapsasAsync(new CapsaBuilder[0]));

        assertCode(ex, "VALIDATION_ERROR");
        assertThat(ex.getDetails()).isNull();
    }

    @Test
    void downloadOfAFileNotInTheCapsa_isFileNotFound() throws Exception {
        String capsaId = TestHelpers.generateCapsaId();
        KeychainEntry entry = new KeychainEntry();
        entry.setParty("party_me");
        entry.setEncryptedKey(RsaProvider.encryptMasterKey(TestHelpers.generateTestMasterKey(), KEYS.getPublicKey()));
        entry.setFingerprint(KEYS.getFingerprint());
        entry.setPermissions(new String[]{"read"});
        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator("party_creator");
        capsa.setTotalSize(0L);
        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);
        TestHelpers.signAsCreator(capsa, SharedKeyFixture.getSecondaryKeyPair());
        server.on("/api/capsas/" + capsaId, StubServer.json(200,
                JsonMapper.getInstance().writeValueAsString(capsa)));
        client.setPrivateKey(KEYS.getPrivateKey());

        CapsaraException ex = failure(client.downloadFileAsync(capsaId, "file_missing"));

        assertThat(ex).isInstanceOf(CapsaraCapsaException.class);
        assertCode(ex, "FILE_NOT_FOUND");
        assertThat(ex.getDetails()).isEqualTo(Map.of("capsaId", capsaId, "fileId", "file_missing"));
    }

    @Test
    void addFileWithUnreadablePathOrNoSource_isValidationError() {
        try (CapsaBuilder builder = new CapsaBuilder("party_me", KEYS.getPrivateKey(), null)) {
            assertThatThrownBy(() -> builder.addFile("Z:/definitely/missing/file.bin"))
                    .isInstanceOf(CapsaraException.class)
                    .satisfies(e -> assertCode((CapsaraException) e, "VALIDATION_ERROR"));
            assertThatThrownBy(() -> builder.addFile(FileInput.fromData(null, "x.bin")))
                    .isInstanceOf(CapsaraException.class)
                    .satisfies(e -> assertCode((CapsaraException) e, "VALIDATION_ERROR"));
        }
    }
}
