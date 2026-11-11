package com.capsara.sdk.golden;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.models.*;
import com.capsara.sdk.models.DecryptedCapsa;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for CapsaDecryptor: wrong private key, signature validation,
 * encrypted key length, master key size, IV/authTag parsing.
 */
class ReceiveGoldenTest {

    private static GeneratedKeyPairResult creatorKeyPair;
    private static GeneratedKeyPairResult recipientKeyPair;
    private static GeneratedKeyPairResult wrongKeyPair;
    private static final String CREATOR_ID = "party_creator_receive";
    private static final String RECIPIENT_ID = "party_recipient_receive";

    @BeforeAll
    static void setUp() {
        creatorKeyPair = SharedKeyFixture.getPrimaryKeyPair();
        recipientKeyPair = SharedKeyFixture.getSecondaryKeyPair();
        wrongKeyPair = SharedKeyFixture.getTertiaryKeyPair();
    }

    // Decryption Tests

    @Test
    void decrypt_withCorrectKey_decryptsSubjectAndBody() {
        Capsa capsa = buildTestCapsa("Test Subject", "Test Body");

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID);

        assertThat(decrypted.getSubject()).isEqualTo("Test Subject");
        assertThat(decrypted.getBody()).isEqualTo("Test Body");
        decrypted.close();
    }

    @Test
    void decrypt_withWrongPrivateKey_throwsException() {
        Capsa capsa = buildTestCapsa("Secret", "Content");

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(
                        capsa, wrongKeyPair.getPrivateKey(), RECIPIENT_ID))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void decrypt_withPartyNotInKeychain_throwsNotInKeychain() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(
                        capsa, wrongKeyPair.getPrivateKey(), "party_unknown"))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(ex -> {
                    CapsaraCapsaException capsaEx = (CapsaraCapsaException) ex;
                    assertThat(capsaEx.getCode()).isEqualTo("NOT_IN_KEYCHAIN");
                });
    }

    // Signature Validation Tests

    @Test
    void decrypt_withSignatureVerification_succeeds() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID);

        assertThat(decrypted).isNotNull();
        decrypted.close();
    }

    @Test
    void decrypt_withTamperedSignature_throwsSignatureVerificationFailed() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        // Tamper with signature
        CapsaSignature sig = capsa.getSignature();
        String original = sig.getSignature();
        // Flip a character in the base64url signature (ensure it actually changes)
        char first = original.charAt(0);
        char flipped = (first == 'A') ? 'B' : 'A';
        String tampered = flipped + original.substring(1);
        sig.setSignature(tampered);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(
                        capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(ex -> {
                    CapsaraCapsaException capsaEx = (CapsaraCapsaException) ex;
                    assertThat(capsaEx.getCode()).isEqualTo("SIGNATURE_VERIFICATION_FAILED");
                });
    }

    @Test
    void decrypt_withoutCreatorPublicKey_throwsSignatureKeyMissing() {
        Capsa capsa = buildTestCapsa("Subject", "Body");
        capsa.setCreatorPublicKey(null);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(ex -> assertThat(((CapsaraCapsaException) ex).getCode())
                        .isEqualTo("SIGNATURE_KEY_MISSING"));
    }
    // Encrypted Key Length Tests

    @Test
    void build_producesRsa4096EncryptedKeyOfFiveHundredTwelveBytes() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        KeychainEntry recipientEntry = null;
        for (KeychainEntry entry : capsa.getKeychain().getKeys()) {
            if (entry.getParty().equals(RECIPIENT_ID)) {
                recipientEntry = entry;
                break;
            }
        }

        assertThat(recipientEntry).isNotNull();
        byte[] encryptedKeyBytes = Base64Url.decode(recipientEntry.getEncryptedKey());
        assertThat(encryptedKeyBytes).hasSize(512); // RSA-4096 OAEP = 512 bytes
    }

    // Master Key Size Tests

    @Test
    void decrypt_returnsMasterKeyOfThirtyTwoBytes() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID);

        assertThat(decrypted.getMasterKey()).hasSize(32);
        decrypted.close();
    }

    // DecryptedCapsa Dispose Tests

    @Test
    void decryptedCapsa_close_clearsMasterKey() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID);

        decrypted.close();

        assertThatThrownBy(decrypted::getMasterKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("disposed");
    }

    @Test
    void decryptedCapsa_clearMasterKey_nullifiesKey() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, recipientKeyPair.getPrivateKey(), RECIPIENT_ID);

        decrypted.clearMasterKey();

        assertThatThrownBy(decrypted::getMasterKey)
                .isInstanceOf(IllegalStateException.class);
    }

    // Auto-Detect Keychain Entry Tests

    @Test
    void decrypt_withNullPartyId_severalEntries_throwsPrivateKeyNotAvailable() {
        Capsa capsa = buildTestCapsa("Subject", "Body");

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, creatorKeyPair.getPrivateKey(), null))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
    }

    // Helper Methods

    private Capsa buildTestCapsa(String subject, String body) {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "file content")
                    .withSubject(subject)
                    .withBody(body);

            PartyKey creatorKey = makePartyKey(CREATOR_ID, creatorKeyPair);
            PartyKey recipientKey = makePartyKey(RECIPIENT_ID, recipientKeyPair);
            BuiltCapsa built = builder.build(new PartyKey[]{creatorKey, recipientKey});

            // Convert BuiltCapsa to Capsa (simulating API round-trip)
            // Compute totalSize from file metadata (matches what CapsaBuilder signed)
            long totalSize = 0;
            if (built.getCapsa().getFiles() != null) {
                for (EncryptedFile f : built.getCapsa().getFiles()) {
                    totalSize += f.getSize();
                }
            }

            Capsa capsa = new Capsa();
            capsa.setId(built.getCapsa().getPackageId());
            capsa.setCreator(CREATOR_ID);
            capsa.setStatus("active");
            capsa.setSignature(built.getCapsa().getSignature());
            capsa.setKeychain(built.getCapsa().getKeychain());
            capsa.setFiles(built.getCapsa().getFiles());
            capsa.setEncryptedSubject(built.getCapsa().getEncryptedSubject());
            capsa.setSubjectIV(built.getCapsa().getSubjectIV());
            capsa.setSubjectAuthTag(built.getCapsa().getSubjectAuthTag());
            capsa.setEncryptedBody(built.getCapsa().getEncryptedBody());
            capsa.setBodyIV(built.getCapsa().getBodyIV());
            capsa.setBodyAuthTag(built.getCapsa().getBodyAuthTag());
            capsa.setAccessControl(built.getCapsa().getAccessControl());
            capsa.setTotalSize(totalSize);
            capsa.setCreatorPublicKey(creatorKeyPair.getPublicKey());

            return capsa;
        }
    }

    private static PartyKey makePartyKey(String id, GeneratedKeyPairResult keyPair) {
        PartyKey pk = new PartyKey();
        pk.setId(id);
        pk.setPublicKey(keyPair.getPublicKey());
        pk.setFingerprint(keyPair.getFingerprint());
        return pk;
    }
}
