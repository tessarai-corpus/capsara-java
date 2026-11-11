package com.capsara.sdk;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.DecryptedCapsa;
import com.capsara.sdk.models.EncryptedFile;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.KeychainEntry;
import com.capsara.sdk.models.PartyKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Receive through the client: the capsa's own creator key, no key lookups, rotated keys. */
class CapsaraClientReceiveTest {

    private static final String CREATOR = "party_creator_client";
    private static final String RECIPIENT = "party_recipient_client";

    private StubServer server;
    private CapsaraClient client;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        client = new CapsaraClient(server.baseUrl(), options);
    }

    @AfterEach
    void stop() {
        client.close();
        server.close();
    }

    /** A capsa as the API returns it to the recipient: only the recipient's own keychain entry. */
    private static String capsaJson(GeneratedKeyPairResult recipientKeys) throws Exception {
        return capsaJson(recipientKeys, true);
    }

    private static String capsaJson(GeneratedKeyPairResult recipientKeys, boolean ownEntryOnly) throws Exception {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        BuiltCapsa built;
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR, creatorKeys.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(7));
            builder.addRecipient(RECIPIENT).addTextFile("a.txt", "hello").withSubject("Quarterly report");
            built = builder.build(new PartyKey[]{
                partyKey(CREATOR, creatorKeys), partyKey(RECIPIENT, recipientKeys)});
        }

        long totalSize = 0;
        for (EncryptedFile f : built.getCapsa().getFiles()) {
            totalSize += f.getSize();
        }

        KeychainEntry own = null;
        for (KeychainEntry entry : built.getCapsa().getKeychain().getKeys()) {
            if (RECIPIENT.equals(entry.getParty())) {
                own = entry;
            }
        }
        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm(built.getCapsa().getKeychain().getAlgorithm());
        keychain.setKeys(ownEntryOnly ? new KeychainEntry[]{own} : built.getCapsa().getKeychain().getKeys());

        Capsa capsa = new Capsa();
        capsa.setId(built.getCapsa().getPackageId());
        capsa.setCreator(CREATOR);
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());
        capsa.setStatus("active");
        capsa.setSignature(built.getCapsa().getSignature());
        capsa.setKeychain(keychain);
        capsa.setFiles(built.getCapsa().getFiles());
        capsa.setEncryptedSubject(built.getCapsa().getEncryptedSubject());
        capsa.setSubjectIV(built.getCapsa().getSubjectIV());
        capsa.setSubjectAuthTag(built.getCapsa().getSubjectAuthTag());
        capsa.setTotalSize(totalSize);
        return JsonMapper.getInstance().writeValueAsString(capsa);
    }

    private static PartyKey partyKey(String id, GeneratedKeyPairResult keys) {
        PartyKey key = new PartyKey();
        key.setId(id);
        key.setPublicKey(keys.getPublicKey());
        key.setFingerprint(keys.getFingerprint());
        return key;
    }

    @Test
    void receive_verifiesWithTheCapsasCreatorKeyAndNeverLooksUpPartyKeys() throws Exception {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(recipientKeys)));
        client.setPrivateKey(recipientKeys.getPrivateKey());

        DecryptedCapsa decrypted = client.getDecryptedCapsaAsync("capsa_r").join();

        assertThat(decrypted.getSubject()).isEqualTo("Quarterly report");
        assertThat(server.requestsTo("/api/party/keys")).isEmpty();
    }

    @Test
    void receive_loggedInParty_picksItsOwnEntryFromSeveral() throws Exception {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        server.on("/api/auth/login", StubServer.json(200, "{\"party\":{\"id\":\"" + RECIPIENT + "\","
                + "\"email\":\"a@b.c\",\"name\":\"Me\",\"kind\":\"user\"},\"accessToken\":\"access-1\","
                + "\"refreshToken\":\"refresh-1\",\"expiresIn\":900}"));
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(recipientKeys, false)));
        client.loginAsync(new AuthCredentials(RECIPIENT, "pw")).join();
        client.setPrivateKey(recipientKeys.getPrivateKey());

        DecryptedCapsa decrypted = client.getDecryptedCapsaAsync("capsa_r").join();

        assertThat(decrypted.getSubject()).isEqualTo("Quarterly report");
    }

    @Test
    void receive_noPartyIdAndSeveralEntries_failsWithPrivateKeyNotAvailable() throws Exception {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(recipientKeys, false)));
        client.setPrivateKey(recipientKeys.getPrivateKey());

        Throwable thrown = catchThrowable(() -> client.getDecryptedCapsaAsync("capsa_r").join());

        assertThat(thrown).isInstanceOf(CompletionException.class);
        assertThat(((CapsaraCapsaException) thrown.getCause()).getCode()).isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
    }

    @Test
    void receive_capsaEncryptedToRotatedKey_opensWithPreviousKey() throws Exception {
        GeneratedKeyPairResult oldKeys = SharedKeyFixture.getSecondaryKeyPair();
        GeneratedKeyPairResult newKeys = SharedKeyFixture.getTertiaryKeyPair();
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(oldKeys)));
        client.setPrivateKey(newKeys.getPrivateKey());
        client.addPreviousPrivateKey(oldKeys.getPrivateKey());

        DecryptedCapsa decrypted = client.getDecryptedCapsaAsync("capsa_r").join();

        assertThat(decrypted.getSubject()).isEqualTo("Quarterly report");
    }

    @Test
    void receive_previousKeysFromOptions_areUsed() throws Exception {
        GeneratedKeyPairResult oldKeys = SharedKeyFixture.getSecondaryKeyPair();
        GeneratedKeyPairResult newKeys = SharedKeyFixture.getTertiaryKeyPair();
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        options.setPreviousPrivateKeys(List.of(oldKeys.getPrivateKey()));
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(oldKeys)));

        try (CapsaraClient withOptions = new CapsaraClient(server.baseUrl(), options)) {
            withOptions.setPrivateKey(newKeys.getPrivateKey());
            assertThat(withOptions.getDecryptedCapsaAsync("capsa_r").join().getSubject())
                    .isEqualTo("Quarterly report");
        }
    }

    @Test
    void receive_withoutTheKeyItWasEncryptedTo_failsWithPrivateKeyNotAvailable() throws Exception {
        GeneratedKeyPairResult oldKeys = SharedKeyFixture.getSecondaryKeyPair();
        server.on("/api/capsas/capsa_r", StubServer.json(200, capsaJson(oldKeys)));
        client.setPrivateKey(SharedKeyFixture.getTertiaryKeyPair().getPrivateKey());

        Throwable thrown = catchThrowable(() -> client.getDecryptedCapsaAsync("capsa_r").join());

        assertThat(thrown).isInstanceOf(CompletionException.class);
        CapsaraCapsaException ex = (CapsaraCapsaException) thrown.getCause();
        assertThat(ex.getCode()).isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
        Map<?, ?> details = (Map<?, ?>) ex.getDetails();
        assertThat(details.get("fingerprint")).isEqualTo(oldKeys.getFingerprint());
        assertThat(details.get("capsaId")).isNotNull();
    }

    @Test
    void receive_expiredCapsa_surfacesTheServerCode() {
        server.on("/api/capsas/capsa_r", StubServer.json(410,
                "{\"error\":{\"code\":\"ENVELOPE_EXPIRED\",\"message\":\"Capsa has expired\","
                        + "\"details\":{\"status\":\"expired\",\"expiredAt\":\"2026-11-01T00:00:00Z\"}}}"));
        client.setPrivateKey(SharedKeyFixture.getSecondaryKeyPair().getPrivateKey());

        Throwable thrown = catchThrowable(() -> client.getDecryptedCapsaAsync("capsa_r").join());

        CapsaraCapsaException ex = (CapsaraCapsaException) thrown.getCause();
        assertThat(ex.getCode()).isEqualTo("ENVELOPE_EXPIRED");
        assertThat(ex.getStatusCode()).isEqualTo(410);
    }

    private static void assertInvalidPrivateKey(Throwable thrown, String which) {
        assertThat(thrown).isExactlyInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class);
        com.capsara.sdk.exceptions.CapsaraException ex = (com.capsara.sdk.exceptions.CapsaraException) thrown;
        assertThat(ex.getCode()).isEqualTo("INVALID_PRIVATE_KEY");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getMessage()).contains(which);
    }

    private Object field(String name) throws Exception {
        java.lang.reflect.Field field = CapsaraClient.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(client);
    }

    @Test
    void addPreviousPrivateKey_rejectsEmptyAndUnusableKeys_withoutAddingThem() throws Exception {
        assertInvalidPrivateKey(catchThrowable(() -> client.addPreviousPrivateKey("")), "previous");
        assertInvalidPrivateKey(catchThrowable(() -> client.addPreviousPrivateKey(
                "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----")), "previous");

        assertThat((List<?>) field("previousPrivateKeys")).isEmpty();
    }

    @Test
    void setPrivateKey_rejectsAnUnusableKey_andKeepsTheCurrentOne() throws Exception {
        String current = SharedKeyFixture.getSecondaryKeyPair().getPrivateKey();
        client.setPrivateKey(current);

        assertInvalidPrivateKey(catchThrowable(() -> client.setPrivateKey("garbage")), "current");
        assertInvalidPrivateKey(catchThrowable(() -> client.setPrivateKey(null)), "current");

        assertThat(field("creatorPrivateKey")).isEqualTo(current);
    }

    @Test
    void previousKeysOption_withAnUnusableKey_isRejectedAtConstruction() {
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setPreviousPrivateKeys(List.of(SharedKeyFixture.getSecondaryKeyPair().getPrivateKey(), "garbage"));

        assertInvalidPrivateKey(catchThrowable(() -> new CapsaraClient(server.baseUrl(), options)), "previous");
    }
}
