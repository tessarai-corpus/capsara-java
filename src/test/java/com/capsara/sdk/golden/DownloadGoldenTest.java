package com.capsara.sdk.golden;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.models.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for download-related edge cases: missing authTag,
 * file metadata validation, decryption with correct/incorrect keys.
 */
class DownloadGoldenTest {

    private static GeneratedKeyPairResult creatorKeyPair;
    private static GeneratedKeyPairResult recipientKeyPair;
    private static final String CREATOR_ID = "party_creator_download";
    private static final String RECIPIENT_ID = "party_recipient_download";

    @BeforeAll
    static void setUp() {
        creatorKeyPair = SharedKeyFixture.getPrimaryKeyPair();
        recipientKeyPair = SharedKeyFixture.getSecondaryKeyPair();
    }

    // Missing AuthTag Tests

    @Test
    void decryptFile_withNullAuthTag_throwsSecurityError() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                "test data".getBytes(StandardCharsets.UTF_8), masterKey, iv);

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFile(
                        encrypted.getCiphertext(), masterKey,
                        Base64Url.encode(iv), null, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR")
                .hasMessageContaining("authTag is required");
    }

    @Test
    void decryptFile_withEmptyAuthTag_throwsSecurityError() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                "test data".getBytes(StandardCharsets.UTF_8), masterKey, iv);

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFile(
                        encrypted.getCiphertext(), masterKey,
                        Base64Url.encode(iv), "", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("authTag is required");
    }

    // File Metadata Validation Tests

    @Test
    void build_setsFileMetadataCorrectly() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("report.txt", "Hello World");

            BuiltCapsa result = builder.build(createPartyKeys());
            EncryptedFile file = result.getCapsa().getFiles()[0];

            assertThat(file.getFileId()).startsWith("file_").endsWith(".enc");
            assertThat(file.getMimetype()).isEqualTo("text/plain");
            assertThat(file.getHashAlgorithm()).isEqualTo("SHA-256");
            assertThat(file.getHash()).isNotEmpty();
            assertThat(file.getHash()).hasSize(64); // SHA-256 hex = 64 chars
            assertThat(file.getIv()).isNotEmpty();
            assertThat(file.getAuthTag()).isNotEmpty();
            assertThat(file.getEncryptedFilename()).isNotEmpty();
            assertThat(file.getFilenameIV()).isNotEmpty();
            assertThat(file.getFilenameAuthTag()).isNotEmpty();
        }
    }

    // Decryption With Correct Key Tests

    @Test
    void decryptFile_withCorrectKey_recoversOriginalContent() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        byte[] plaintext = "Secret file content".getBytes(StandardCharsets.UTF_8);

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, masterKey, iv);

        byte[] decrypted = CapsaDecryptor.decryptFile(
                encrypted.getCiphertext(), masterKey,
                Base64Url.encode(iv), Base64Url.encode(encrypted.getAuthTag()), false);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void decryptFile_withIncorrectKey_throwsException() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] wrongKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        byte[] plaintext = "Secret content".getBytes(StandardCharsets.UTF_8);

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, masterKey, iv);

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFile(
                        encrypted.getCiphertext(), wrongKey,
                        Base64Url.encode(iv), Base64Url.encode(encrypted.getAuthTag()), false))
                .isInstanceOf(RuntimeException.class);
    }

    // Filename Decryption Tests

    @Test
    void decryptFilename_withCorrectKey_recoversFilename() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        byte[] filenameBytes = "secret_report.pdf".getBytes(StandardCharsets.UTF_8);

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(filenameBytes, masterKey, iv);

        String decryptedFilename = CapsaDecryptor.decryptFilename(
                Base64Url.encode(encrypted.getCiphertext()), masterKey,
                Base64Url.encode(iv), Base64Url.encode(encrypted.getAuthTag()));

        assertThat(decryptedFilename).isEqualTo("secret_report.pdf");
    }

    @Test
    void decryptFilename_withMissingAuthTag_throwsSecurityError() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFilename("encrypted_data", masterKey, "some_iv", null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR")
                .hasMessageContaining("authTag is required");
    }

    // Compressed File Decryption Tests

    @Test
    void decryptFile_withCompressedFlag_decompressesAfterDecryption() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        // Create compressible data, compress it, then encrypt
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            sb.append("Repetitive compressible data line. ");
        }
        byte[] original = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] compressed = com.capsara.sdk.internal.crypto.CompressionProvider.compress(original);

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(compressed, masterKey, iv);

        byte[] decrypted = CapsaDecryptor.decryptFile(
                encrypted.getCiphertext(), masterKey,
                Base64Url.encode(iv), Base64Url.encode(encrypted.getAuthTag()), true);

        assertThat(decrypted).isEqualTo(original);
    }

    // Helper

    private PartyKey[] createPartyKeys() {
        PartyKey creatorKey = new PartyKey();
        creatorKey.setId(CREATOR_ID);
        creatorKey.setPublicKey(creatorKeyPair.getPublicKey());
        creatorKey.setFingerprint(creatorKeyPair.getFingerprint());

        PartyKey recipientKey = new PartyKey();
        recipientKey.setId(RECIPIENT_ID);
        recipientKey.setPublicKey(recipientKeyPair.getPublicKey());
        recipientKey.setFingerprint(recipientKeyPair.getFingerprint());

        return new PartyKey[]{creatorKey, recipientKey};
    }
}
