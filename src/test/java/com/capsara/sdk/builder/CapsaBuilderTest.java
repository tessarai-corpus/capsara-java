package com.capsara.sdk.builder;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.models.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for CapsaBuilder.
 */
class CapsaBuilderTest {

    private static GeneratedKeyPairResult creatorKeyPair;
    private static GeneratedKeyPairResult recipientKeyPair;
    private static final String CREATOR_ID = "party_creator_test123";
    private static final String RECIPIENT_ID = "party_recipient_test456";

    @BeforeAll
    static void setUp() {
        creatorKeyPair = SharedKeyFixture.getPrimaryKeyPair();
        recipientKeyPair = SharedKeyFixture.getSecondaryKeyPair();
    }

    @Test
    void constructorShouldRequireCreatorId() {
        assertThatThrownBy(() -> new CapsaBuilder(null, creatorKeyPair.getPrivateKey(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Creator ID");

        assertThatThrownBy(() -> new CapsaBuilder("", creatorKeyPair.getPrivateKey(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Creator ID");
    }

    @Test
    void constructorShouldRequirePrivateKey() {
        assertThatThrownBy(() -> new CapsaBuilder(CREATOR_ID, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private key");

        assertThatThrownBy(() -> new CapsaBuilder(CREATOR_ID, "", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private key");
    }

    @Test
    void shouldBuildCapsaWithTextFile() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "Hello, World!")
                    .withSubject("Test Subject")
                    .withBody("Test Body");

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            assertThat(result).isNotNull();
            assertThat(result.getCapsa()).isNotNull();
            assertThat(result.getFiles()).hasSize(1);

            // Verify package ID format
            assertThat(result.getCapsa().getPackageId()).startsWith("capsa_");
            assertThat(result.getCapsa().getPackageId()).hasSize(28); // "capsa_" + 22 chars

            // Verify keychain
            assertThat(result.getCapsa().getKeychain()).isNotNull();
            assertThat(result.getCapsa().getKeychain().getAlgorithm()).isEqualTo("AES-256-GCM");
            assertThat(result.getCapsa().getKeychain().getKeys()).hasSize(2); // creator + recipient

            // Verify signature
            assertThat(result.getCapsa().getSignature()).isNotNull();
            assertThat(result.getCapsa().getSignature().getAlgorithm()).isEqualTo("RS256");

            // Verify encrypted subject/body
            assertThat(result.getCapsa().getEncryptedSubject()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getSubjectIV()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getSubjectAuthTag()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getEncryptedBody()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getBodyIV()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getBodyAuthTag()).isNotNull().isNotEmpty();

            // Verify file metadata
            EncryptedFile fileMetadata = result.getCapsa().getFiles()[0];
            assertThat(fileMetadata.getFileId()).startsWith("file_").endsWith(".enc");
            assertThat(fileMetadata.getMimetype()).isEqualTo("text/plain");
            assertThat(fileMetadata.getHashAlgorithm()).isEqualTo("SHA-256");
        }
    }

    @Test
    void shouldBuildCapsaWithStructuredData() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            Map<String, Object> data = new HashMap<>();
            data.put("claimNumber", "CLM-12345");
            data.put("amount", 1500.50);
            data.put("approved", true);

            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("data.txt", "test")
                    .withStructured(data);

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            assertThat(result.getCapsa().getEncryptedStructured()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getStructuredIV()).isNotNull().isNotEmpty();
            assertThat(result.getCapsa().getStructuredAuthTag()).isNotNull().isNotEmpty();
        }
    }

    @Test
    void shouldBuildCapsaWithExpiration() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            OffsetDateTime expiration = OffsetDateTime.now(ZoneOffset.UTC).plusDays(7);

            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "content")
                    .withExpiration(expiration);

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            assertThat(result.getCapsa().getAccessControl()).isNotNull();
            assertThat(result.getCapsa().getAccessControl().getExpiresAt()).isNotNull();
        }
    }

    @Test
    void shouldCompressLargeFiles() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            // Create a compressible file > 150 bytes
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                sb.append("This is repeated text for compression testing. ");
            }
            String content = sb.toString();

            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("large.txt", content);

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            EncryptedFile fileMetadata = result.getCapsa().getFiles()[0];
            assertThat(fileMetadata.getCompressed()).isTrue();
            assertThat(fileMetadata.getCompressionAlgorithm()).isEqualTo("gzip");
            assertThat(fileMetadata.getOriginalSize()).isEqualTo(content.getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Test
    void shouldNotCompressSmallFiles() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("small.txt", "tiny");

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            EncryptedFile fileMetadata = result.getCapsa().getFiles()[0];
            assertThat(fileMetadata.getCompressed()).isNull();
        }
    }

    @Test
    void shouldAllowRecipientToDecryptMasterKey() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("secret.txt", "Secret content");

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            // Find recipient's keychain entry
            KeychainEntry recipientEntry = null;
            for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
                if (entry.getParty().equals(RECIPIENT_ID)) {
                    recipientEntry = entry;
                    break;
                }
            }

            assertThat(recipientEntry).isNotNull();
            assertThat(recipientEntry.getEncryptedKey()).isNotNull().isNotEmpty();
            assertThat(recipientEntry.getPermissions()).containsExactly("read");

            // Verify recipient can decrypt the master key
            byte[] decryptedMasterKey = RsaProvider.decryptMasterKey(
                    recipientEntry.getEncryptedKey(),
                    recipientKeyPair.getPrivateKey());

            assertThat(decryptedMasterKey).hasSize(32);

            // Verify the decrypted master key can decrypt a file
            EncryptedFile file = result.getCapsa().getFiles()[0];
            byte[] fileData = result.getFiles()[0].getData();

            byte[] iv = Base64Url.decode(file.getIv());
            byte[] authTag = Base64Url.decode(file.getAuthTag());
            byte[] decryptedFile = AesGcmProvider.decrypt(fileData, decryptedMasterKey, iv, authTag);

            // Decompress if needed
            if (file.getCompressed() != null && file.getCompressed()) {
                decryptedFile = CompressionProvider.decompress(decryptedFile);
            }

            assertThat(new String(decryptedFile, StandardCharsets.UTF_8)).isEqualTo("Secret content");
        }
    }

    @Test
    void shouldVerifySignature() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "content");

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            CapsaSignature signature = result.getCapsa().getSignature();
            boolean isValid = SignatureProvider.verifyJws(
                    signature.getProtectedHeader(),
                    signature.getPayload(),
                    signature.getSignature(),
                    creatorKeyPair.getPublicKey());

            assertThat(isValid).isTrue();
        }
    }

    @Test
    void shouldEnforceFileLimits() {
        SystemLimits limits = new SystemLimits(1024 * 1024, 2, 10 * 1024 * 1024);

        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            builder.addTextFile("file1.txt", "content1")
                    .addTextFile("file2.txt", "content2");

            assertThatThrownBy(() -> builder.addTextFile("file3.txt", "content3"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("max: 2");
        }
    }

    @Test
    void shouldEnforceFileSizeLimit() {
        SystemLimits limits = new SystemLimits(50, 10, 10 * 1024 * 1024);

        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            assertThatThrownBy(() -> builder.addTextFile("large.txt", "This content is definitely more than 50 bytes long!!!"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exceeds maximum size");
        }
    }

    @Test
    void shouldBeDisposableAndClearMasterKey() {
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null);
        builder.addTextFile("test.txt", "content");

        builder.close();

        // After close, should throw on build
        assertThatThrownBy(() -> builder.build(createPartyKeys()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("disposed");
    }

    @Test
    void shouldHandleMultipleRecipients() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            String recipient2Id = "party_recipient2_test789";

            builder.addRecipients(RECIPIENT_ID, recipient2Id)
                    .addTextFile("shared.txt", "shared content");

            // Create party keys including third party
            PartyKey creatorKey = new PartyKey();
            creatorKey.setId(CREATOR_ID);
            creatorKey.setPublicKey(creatorKeyPair.getPublicKey());
            creatorKey.setFingerprint(creatorKeyPair.getFingerprint());

            PartyKey recipientKey = new PartyKey();
            recipientKey.setId(RECIPIENT_ID);
            recipientKey.setPublicKey(recipientKeyPair.getPublicKey());
            recipientKey.setFingerprint(recipientKeyPair.getFingerprint());

            PartyKey recipient2Key = new PartyKey();
            recipient2Key.setId(recipient2Id);
            recipient2Key.setPublicKey(recipientKeyPair.getPublicKey()); // Reuse key for testing
            recipient2Key.setFingerprint(recipientKeyPair.getFingerprint());

            BuiltCapsa result = builder.build(new PartyKey[]{creatorKey, recipientKey, recipient2Key});

            assertThat(result.getCapsa().getKeychain().getKeys()).hasSize(3);
        }
    }

    @Test
    void shouldSupportFluentApi() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            CapsaBuilder returned = builder
                    .addRecipient(RECIPIENT_ID)
                    .withSubject("Subject")
                    .withBody("Body")
                    .withStructured("key", "value")
                    .addTextFile("test.txt", "content")
                    .withExpiration(OffsetDateTime.now().plusDays(1));

            assertThat(returned).isSameAs(builder);
        }
    }

    @Test
    void shouldDecryptSubjectAndBody() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            String testSubject = "Test Subject Line";
            String testBody = "This is the body content.";

            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "content")
                    .withSubject(testSubject)
                    .withBody(testBody);

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            // Get recipient's master key
            KeychainEntry recipientEntry = null;
            for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
                if (entry.getParty().equals(RECIPIENT_ID)) {
                    recipientEntry = entry;
                    break;
                }
            }

            byte[] masterKey = RsaProvider.decryptMasterKey(
                    recipientEntry.getEncryptedKey(),
                    recipientKeyPair.getPrivateKey());

            // Decrypt subject
            byte[] subjectCiphertext = Base64Url.decode(result.getCapsa().getEncryptedSubject());
            byte[] subjectIv = Base64Url.decode(result.getCapsa().getSubjectIV());
            byte[] subjectAuthTag = Base64Url.decode(result.getCapsa().getSubjectAuthTag());
            byte[] decryptedSubject = AesGcmProvider.decrypt(subjectCiphertext, masterKey, subjectIv, subjectAuthTag);

            assertThat(new String(decryptedSubject, StandardCharsets.UTF_8)).isEqualTo(testSubject);

            // Decrypt body
            byte[] bodyCiphertext = Base64Url.decode(result.getCapsa().getEncryptedBody());
            byte[] bodyIv = Base64Url.decode(result.getCapsa().getBodyIV());
            byte[] bodyAuthTag = Base64Url.decode(result.getCapsa().getBodyAuthTag());
            byte[] decryptedBody = AesGcmProvider.decrypt(bodyCiphertext, masterKey, bodyIv, bodyAuthTag);

            assertThat(new String(decryptedBody, StandardCharsets.UTF_8)).isEqualTo(testBody);
        }
    }

    @Test
    void shouldAddJsonFile() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            Map<String, Object> data = new HashMap<>();
            data.put("name", "Test");
            data.put("value", 42);

            builder.addRecipient(RECIPIENT_ID)
                    .addJsonFile("data.json", data);

            PartyKey[] partyKeys = createPartyKeys();
            BuiltCapsa result = builder.build(partyKeys);

            EncryptedFile fileMetadata = result.getCapsa().getFiles()[0];
            assertThat(fileMetadata.getMimetype()).isEqualTo("application/json");
        }
    }

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
