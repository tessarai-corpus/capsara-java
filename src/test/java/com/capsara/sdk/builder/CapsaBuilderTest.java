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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
                    .isInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                    .satisfies(e -> assertThat(((com.capsara.sdk.exceptions.CapsaraException) e).getCode())
                            .isEqualTo("VALIDATION_ERROR"))
                    .hasMessageContaining("max: 2");
        }
    }

    @Test
    void shouldEnforceFileSizeLimit() {
        SystemLimits limits = new SystemLimits(50, 10, 10 * 1024 * 1024);

        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            assertThatThrownBy(() -> builder.addTextFile("large.txt", "This content is definitely more than 50 bytes long!!!"))
                    .isInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                    .satisfies(e -> assertThat(((com.capsara.sdk.exceptions.CapsaraException) e).getCode())
                            .isEqualTo("VALIDATION_ERROR"))
                    .hasMessageContaining("exceeds maximum size");
        }
    }

    @Test
    void shouldBeDisposableAndClearMasterKey() {
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null);
        builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
        builder.addTextFile("test.txt", "content");

        builder.close();

        // After close, should throw on build
        assertThatThrownBy(() -> builder.build(createPartyKeys()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("disposed");
    }

    @Test
    void shouldRejectSecondRecipient() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID);

            assertThatThrownBy(() -> builder.addRecipient("party_recipient2_test789"))
                    .isInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                    .satisfies(e -> assertThat(((com.capsara.sdk.exceptions.CapsaraException) e).getCode())
                            .isEqualTo("VALIDATION_ERROR"))
                    .hasMessageContaining("Capsa already has a recipient (\"" + RECIPIENT_ID + "\")")
                    .hasMessageContaining("exactly one recipient")
                    .hasMessageContaining("one builder per recipient");
            assertThat(builder.getRecipientIds()).containsExactly(RECIPIENT_ID);

            // The same party twice is also a second recipient
            assertThatThrownBy(() -> builder.addRecipient(RECIPIENT_ID))
                    .isInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                    .hasMessageContaining("already has a recipient");
        }
    }

    @Test
    void shouldBuildSelfSendWithCreatorsDelegates() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(CREATOR_ID).addTextFile("test.txt", "content");

            PartyKey[] keys = createPartyKeys();
            BuiltCapsa result = builder.build(new PartyKey[]{
                    keys[0],
                    keys[1],
                    delegateKey("party_creator_ams", CREATOR_ID),
                    delegateKey("party_recipient_ams", RECIPIENT_ID),
            });

            Map<String, KeychainEntry> byParty = keychainByParty(result);
            assertThat(byParty.keySet()).containsExactlyInAnyOrder(CREATOR_ID, "party_creator_ams");

            KeychainEntry creator = byParty.get(CREATOR_ID);
            assertThat(creator.getEncryptedKey()).isNotEmpty();
            assertThat(creator.getActingFor()).isNull();

            KeychainEntry delegate = byParty.get("party_creator_ams");
            assertThat(delegate.getPermissions()).containsExactly("delegate");
            assertThat(delegate.getActingFor()).containsExactly(CREATOR_ID);
            assertThat(delegate.getEncryptedKey()).isNotEmpty();
        }
    }

    @Test
    void shouldBuildSelfSendWithOnlyCreatorWhenItHasNoDelegates() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(CREATOR_ID).addTextFile("test.txt", "content");

            BuiltCapsa result = builder.build(createPartyKeys());

            KeychainEntry[] entries = result.getCapsa().getKeychain().getKeys();
            assertThat(entries).hasSize(1);
            assertThat(entries[0].getParty()).isEqualTo(CREATOR_ID);
            assertThat(entries[0].getEncryptedKey()).isNotEmpty();
            assertThat(entries[0].getActingFor()).isNull();
        }
    }

    @Test
    void shouldAllowCreatorAsDelegateOfPrincipal() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            PartyKey[] keys = createPartyKeys();
            keys[0].setIsDelegate(new String[]{RECIPIENT_ID});
            BuiltCapsa result = builder.build(keys);

            KeychainEntry creator = keychainByParty(result).get(CREATOR_ID);
            assertThat(creator.getPermissions()).containsExactly("delegate");
            assertThat(creator.getActingFor()).containsExactly(RECIPIENT_ID);
        }
    }

    @Test
    void shouldRejectBuildWithNoRecipient() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addTextFile("test.txt", "content");

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "NO_RECIPIENT"))
                    .hasMessage("Capsa has no recipient. Call addRecipient() with the party this capsa is sent to.");
        }
    }

    @Test
    void shouldScopeDelegatesToPrincipal() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            PartyKey[] keys = createPartyKeys();
            BuiltCapsa result = builder.build(new PartyKey[]{
                    keys[0],
                    keys[1],
                    delegateKey("party_shared_delegate", "party_other", RECIPIENT_ID),
                    delegateKey("party_other_delegate", "party_other"),
                    delegateKey("party_creator_delegate", CREATOR_ID),
            });

            Map<String, KeychainEntry> byParty = keychainByParty(result);
            assertThat(byParty.keySet())
                    .containsExactlyInAnyOrder(CREATOR_ID, RECIPIENT_ID, "party_shared_delegate");
            assertThat(byParty.get("party_shared_delegate").getActingFor()).containsExactly(RECIPIENT_ID);
        }
    }

    @Test
    void shouldTreatPrincipalAsPrincipalEvenIfItIsADelegateOfAnotherParty() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            PartyKey[] keys = createPartyKeys();
            keys[1].setIsDelegate(new String[]{"party_other"});
            BuiltCapsa result = builder.build(keys);

            KeychainEntry principal = keychainByParty(result).get(RECIPIENT_ID);
            assertThat(principal.getPermissions()).containsExactly("read");
            assertThat(principal.getActingFor()).isNull();
            assertThat(principal.getEncryptedKey()).isNotEmpty();
        }
    }

    @Test
    void shouldBuildValidKeychainForPrincipalAndItsDelegates() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            PartyKey[] keys = createPartyKeys();
            BuiltCapsa result = builder.build(new PartyKey[]{
                    keys[0],
                    keys[1],
                    delegateKey("party_ams", RECIPIENT_ID),
                    delegateKey("party_rater", RECIPIENT_ID),
            });

            KeychainEntry[] entries = result.getCapsa().getKeychain().getKeys();
            Map<String, KeychainEntry> byParty = keychainByParty(result);
            // Each party appears once
            assertThat(byParty).hasSize(entries.length).hasSize(4);

            KeychainEntry principal = byParty.get(RECIPIENT_ID);
            assertThat(principal.getEncryptedKey()).isNotEmpty();
            assertThat(principal.getActingFor()).isNull();

            for (String delegateId : new String[]{"party_ams", "party_rater"}) {
                KeychainEntry delegate = byParty.get(delegateId);
                assertThat(delegate.getPermissions()).containsExactly("delegate");
                assertThat(delegate.getActingFor()).containsExactly(RECIPIENT_ID);
                assertThat(delegate.getEncryptedKey()).isNotEmpty();
            }
        }
    }

    @Test
    void shouldKeepEachCapsaToItsOwnPrincipalWhenBuildersSharePartyKeys() {
        // sendCapsasAsync fetches keys once for a whole batch, so each builder sees
        // the other capsas' recipients and delegates too
        String vendorId = "party_vendor";
        PartyKey[] keys = createPartyKeys();
        PartyKey vendorKey = delegateKey(vendorId);
        PartyKey[] shared = new PartyKey[]{
                keys[0],
                keys[1],
                vendorKey,
                delegateKey("party_ams", RECIPIENT_ID),
                delegateKey("party_vendor_system", vendorId),
                delegateKey("party_shared", RECIPIENT_ID, vendorId),
        };

        try (CapsaBuilder toAgent = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null);
             CapsaBuilder toVendor = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            toAgent.withExpiration(OffsetDateTime.now().plusDays(30))
                    .addRecipient(RECIPIENT_ID).addTextFile("a.txt", "a");
            toVendor.withExpiration(OffsetDateTime.now().plusDays(30))
                    .addRecipient(vendorId).addTextFile("v.txt", "v");

            Map<String, KeychainEntry> agent = keychainByParty(toAgent.build(shared));
            Map<String, KeychainEntry> vendor = keychainByParty(toVendor.build(shared));

            assertThat(agent.keySet())
                    .containsExactlyInAnyOrder(CREATOR_ID, RECIPIENT_ID, "party_ams", "party_shared");
            assertThat(agent.get("party_shared").getActingFor()).containsExactly(RECIPIENT_ID);

            assertThat(vendor.keySet())
                    .containsExactlyInAnyOrder(CREATOR_ID, vendorId, "party_vendor_system", "party_shared");
            assertThat(vendor.get("party_shared").getActingFor()).containsExactly(vendorId);
        }
    }

    @Test
    void shouldNotOfferAddRecipients() {
        assertThat(java.util.Arrays.stream(CapsaBuilder.class.getMethods())
                .map(java.lang.reflect.Method::getName))
                .doesNotContain("addRecipients");
    }

    private PartyKey delegateKey(String id, String... actsFor) {
        PartyKey key = new PartyKey();
        key.setId(id);
        key.setPublicKey(recipientKeyPair.getPublicKey()); // Reuse key for testing
        key.setFingerprint(recipientKeyPair.getFingerprint());
        if (actsFor.length > 0) {
            key.setIsDelegate(actsFor);
        }
        return key;
    }

    private static Map<String, KeychainEntry> keychainByParty(BuiltCapsa result) {
        Map<String, KeychainEntry> byParty = new HashMap<>();
        for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
            byParty.put(entry.getParty(), entry);
        }
        return byParty;
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
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

    @Test
    void fileExpiry_sendsTheMinuteRoundedUtcValueThatWasChecked() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.setClock(FIXED_CLOCK);
            OffsetDateTime capsaExpiry = OffsetDateTime.parse("2026-12-01T10:00:00Z");
            builder.setExpiresAt(capsaExpiry);
            builder.addFile(com.capsara.sdk.models.FileInput.fromData(new byte[]{1, 2, 3}, "a.bin")
                    .withExpiration(OffsetDateTime.parse("2026-12-01T12:00:30.5+02:00")));

            BuiltCapsa built = builder.build(createPartyKeys());

            String sent = built.getFiles()[0].getMetadata().getExpiresAt();
            assertThat(OffsetDateTime.parse(sent).toInstant()).isEqualTo(capsaExpiry.toInstant());
            assertThat(sent).endsWith("Z");
        }
    }

    @Test
    void fileWithUnreadablePathAtBuild_isFileReadFailed() throws Exception {
        java.nio.file.Path temp = java.nio.file.Files.createTempFile("capsa", ".bin");
        java.nio.file.Files.write(temp, new byte[]{1, 2, 3});
        try (CapsaBuilder builder = readyBuilder()) {
            builder.addFile(temp.toString());
            java.nio.file.Files.delete(temp);

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "FILE_READ_FAILED"));
        }
    }

    @Test
    void recipientWithoutKey_keepsItsOwnCodeWithoutReason() {
        try (CapsaBuilder builder = readyBuilder()) {
            PartyKey[] onlyCreator = {createPartyKeys()[0]};

            assertThatThrownBy(() -> builder.build(onlyCreator))
                    .satisfies(e -> {
                        com.capsara.sdk.exceptions.CapsaraException error =
                                (com.capsara.sdk.exceptions.CapsaraException) e;
                        assertThat(error.getCode()).isEqualTo("RECIPIENT_KEY_NOT_FOUND");
                        assertThat(error.getDetails()).isEqualTo(java.util.Map.of("partyId", RECIPIENT_ID));
                    });
        }
    }

    @Test
    void fileExpiry_afterTheCapsaOnceRounded_isRejected() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.setClock(FIXED_CLOCK);
            builder.setExpiresAt(OffsetDateTime.parse("2026-12-01T10:00:00Z"));
            builder.addFile(com.capsara.sdk.models.FileInput.fromData(new byte[]{1, 2, 3}, "a.bin")
                    .withExpiration(OffsetDateTime.parse("2026-12-01T10:01:00Z")));

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "FILE_OUTLIVES_CAPSA"));
        }
    }

    @Test
    void partyKeyWithoutFingerprint_leavesTheEntryFingerprintUnset() {
        try (CapsaBuilder builder = readyBuilder()) {
            PartyKey[] keys = createPartyKeys();
            keys[1].setFingerprint("");

            BuiltCapsa built = builder.build(keys);

            assertThat(built.getCapsa().getKeychain().getKeys())
                    .filteredOn(e -> RECIPIENT_ID.equals(e.getParty()))
                    .extracting(KeychainEntry::getFingerprint)
                    .containsExactly((String) null);
        }
    }

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-11-09T12:00:30Z");
    private static final java.time.Clock FIXED_CLOCK =
            java.time.Clock.fixed(NOW.toInstant(), java.time.ZoneOffset.UTC);

    private CapsaBuilder clockedBuilder(Double maxExpirationDays) {
        SystemLimits limits = new SystemLimits(50L * 1024 * 1024, 500, 1024L * 1024 * 1024);
        limits.setMaxExpirationDays(maxExpirationDays);
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits);
        builder.setClock(FIXED_CLOCK);
        builder.addRecipient(RECIPIENT_ID).withSubject("s");
        return builder;
    }

    private void assertExpiryRefused(CapsaBuilder builder, String reason) {
        assertThatThrownBy(() -> builder.build(createPartyKeys()))
                .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, reason));
    }

    @Test
    void expiryInsideTheCurrentMinute_isInThePast_nextMinuteIsAccepted() {
        try (CapsaBuilder past = clockedBuilder(null); CapsaBuilder next = clockedBuilder(null)) {
            past.setExpiresAt(OffsetDateTime.parse("2026-11-09T12:00:45Z"));
            next.setExpiresAt(OffsetDateTime.parse("2026-11-09T12:01:00Z"));

            assertThatThrownBy(() -> past.build(createPartyKeys()))
                    .hasMessage("Expiration 2026-11-09T12:00:00.000Z is in the past. "
                            + "Set an expiration after the current time.")
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "EXPIRATION_IN_PAST"));
            assertThat(next.build(createPartyKeys())).isNotNull();
        }
    }

    @Test
    void expiryPastTheDefaultWindow_isTooFar_exactlyTheWindowIsAccepted() {
        try (CapsaBuilder far = clockedBuilder(null); CapsaBuilder edge = clockedBuilder(null)) {
            far.setExpiresAt(NOW.plusDays(3651));
            edge.setExpiresAt(NOW.plusDays(3650));

            assertThatThrownBy(() -> far.build(createPartyKeys()))
                    .hasMessageContaining("is more than 3650 days in the future. "
                            + "The latest allowed expiration is 3650 days from now.")
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "EXPIRATION_TOO_FAR"));
            assertThat(edge.build(createPartyKeys())).isNotNull();
        }
    }

    @Test
    void advertisedWindow_isApplied() {
        try (CapsaBuilder far = clockedBuilder(30d); CapsaBuilder near = clockedBuilder(30d)) {
            far.setExpiresAt(NOW.plusDays(31));
            near.setExpiresAt(NOW.plusDays(29));

            assertExpiryRefused(far, "EXPIRATION_TOO_FAR");
            assertThat(near.build(createPartyKeys())).isNotNull();
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(doubles = {0, -5, Double.NaN, Double.POSITIVE_INFINITY})
    void nonPositiveOrNonFiniteWindow_fallsBackTo3650Days(double days) {
        try (CapsaBuilder builder = clockedBuilder(days)) {
            builder.setExpiresAt(NOW.plusDays(3000));

            assertThat(builder.build(createPartyKeys())).isNotNull();
        }
        try (CapsaBuilder builder = clockedBuilder(days)) {
            builder.setExpiresAt(NOW.plusDays(3651));

            assertExpiryRefused(builder, "EXPIRATION_TOO_FAR");
        }
    }

    @Test
    void fileInThePast_isFileExpirationInPast() {
        try (CapsaBuilder builder = clockedBuilder(null)) {
            builder.setExpiresAt(NOW.plusDays(10));
            builder.addFile(com.capsara.sdk.models.FileInput.fromData(new byte[]{1}, "a.bin")
                    .withExpiration(NOW.minusDays(1)));

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .hasMessage("Expiration for \"a.bin\" (2026-11-08T12:00:00.000Z) is in the past. "
                            + "Set an expiration after the current time.")
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e,
                            "FILE_EXPIRATION_IN_PAST"));
        }
    }

    @Test
    void filePastTheWindow_isFileExpirationTooFarBeforeOutlivesCapsa() {
        try (CapsaBuilder builder = clockedBuilder(30d)) {
            builder.setExpiresAt(NOW.plusDays(10));
            builder.addFile(com.capsara.sdk.models.FileInput.fromData(new byte[]{1}, "a.bin")
                    .withExpiration(NOW.plusDays(40)));

            assertExpiryRefused(builder, "FILE_EXPIRATION_TOO_FAR");
        }
    }

    @Test
    void expiryChecks_runBeforeTheRecipientKeyCheck() {
        try (CapsaBuilder builder = clockedBuilder(null)) {
            builder.setExpiresAt(NOW.minusDays(1));
            PartyKey[] onlyCreator = {createPartyKeys()[0]};

            assertThatThrownBy(() -> builder.build(onlyCreator))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "EXPIRATION_IN_PAST"));
        }
    }

    @Test
    void limitsResponse_readsMaxExpirationDays() throws Exception {
        SystemLimits limits = com.capsara.sdk.internal.json.JsonMapper.getInstance()
                .readValue("{\"maxExpirationDays\":30}", SystemLimits.class);

        assertThat(limits.effectiveMaxExpirationDays()).isEqualTo(30d);
        assertThat(new SystemLimits().effectiveMaxExpirationDays()).isEqualTo(3650d);
    }

    @Test
    void tooFarMessage_printsFractionalDaysLikeJs() {
        try (CapsaBuilder builder = clockedBuilder(0.0001)) {
            builder.setExpiresAt(OffsetDateTime.parse("2026-11-09T12:02:00Z"));

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .hasMessage("Expiration 2026-11-09T12:02:00.000Z is more than 0.0001 days in the future. "
                            + "The latest allowed expiration is 0.0001 days from now.");
        }
    }

    @Test
    void tooFarMessage_printsYearsAbove9999LikeToIsoString() {
        try (CapsaBuilder builder = clockedBuilder(null)) {
            builder.setExpiresAt(OffsetDateTime.parse("+12000-01-02T03:04:00Z"));

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .hasMessageStartingWith("Expiration +012000-01-02T03:04:00.000Z is more than 3650 days");
        }
    }

    @Test
    void hugeWindow_doesNotOverflow_andAcceptsAFarExpiry() {
        try (CapsaBuilder builder = clockedBuilder(1e300)) {
            builder.setExpiresAt(OffsetDateTime.parse("+12000-01-02T03:04:00Z"));

            assertThat(builder.build(createPartyKeys())).isNotNull();
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "3650, 3650", "0.0001, 0.0001", "12345678.5, 12345678.5", "1.5, 1.5", "0.5, 0.5",
            "0.000001, 0.000001", "0.0000001, 1e-7", "1e21, 1e+21", "1e20, 100000000000000000000",
            "1.25e-10, 1.25e-10", "1e300, 1e+300", "123456789012345680000, 123456789012345680000"})
    void formatDays_matchesJsNumberToString(double value, String expected) {
        assertThat(CapsaBuilder.formatDays(value)).isEqualTo(expected);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "2026-11-09T12:00:00Z, 2026-11-09T12:00:00.000Z",
            "0001-01-01T00:00:00Z, 0001-01-01T00:00:00.000Z",
            "9999-12-31T23:59:59.999Z, 9999-12-31T23:59:59.999Z",
            "+10000-01-01T00:00:00Z, +010000-01-01T00:00:00.000Z",
            "+275760-09-13T00:00:00Z, +275760-09-13T00:00:00.000Z",
            "-0001-06-01T00:00:00Z, -000001-06-01T00:00:00.000Z",
            "2026-11-09T14:00:00+02:00, 2026-11-09T12:00:00.000Z"})
    void formatMillis_matchesToIsoString(String input, String expected) {
        assertThat(CapsaBuilder.formatMillis(OffsetDateTime.parse(input))).isEqualTo(expected);
    }

    private CapsaBuilder readyBuilder() {
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null);
        builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
        builder.addRecipient(RECIPIENT_ID).withSubject("s");
        return builder;
    }

    @Test
    void signature_bindsTheCreatorAndItsKeyFingerprint() {
        try (CapsaBuilder builder = readyBuilder()) {
            BuiltCapsa built = builder.build(createPartyKeys());

            String payload = new String(Base64Url.decode(built.getCapsa().getSignature().getPayload()),
                    StandardCharsets.UTF_8);

            assertThat(payload).startsWith(built.getCapsa().getPackageId() + "|1.0.0|0|AES-256-GCM|"
                    + CREATOR_ID + "|" + creatorKeyPair.getFingerprint() + "|");
        }
    }

    @Test
    void fingerprintFromPrivateKey_matchesThePublicKeyFingerprint() {
        assertThat(KeyGenerator.calculateFingerprintFromPrivateKey(creatorKeyPair.getPrivateKey()))
                .isEqualTo(KeyGenerator.calculateFingerprint(creatorKeyPair.getPublicKey()));
    }

    @Test
    void recipientMissingFromPartyKeys_failsWithRecipientKeyNotFound() {
        try (CapsaBuilder builder = readyBuilder()) {
            PartyKey[] creatorOnly = {createPartyKeys()[0]};

            Throwable thrown = catchThrowable(() -> builder.build(creatorOnly));

            assertThat(thrown).isInstanceOf(com.capsara.sdk.exceptions.CapsaraCapsaException.class);
            com.capsara.sdk.exceptions.CapsaraException ex = (com.capsara.sdk.exceptions.CapsaraException) thrown;
            assertThat(ex.getCode()).isEqualTo("RECIPIENT_KEY_NOT_FOUND");
            assertThat(ex.getMessage()).isEqualTo("Recipient " + RECIPIENT_ID + " has no registered public key");
            assertThat(ex.getDetails()).isEqualTo(Map.of("partyId", RECIPIENT_ID));
        }
    }

    @Test
    void recipientWithEmptyPublicKey_failsWithRecipientKeyNotFound() {
        try (CapsaBuilder builder = readyBuilder()) {
            PartyKey[] keys = createPartyKeys();
            keys[1].setPublicKey("");

            assertThatThrownBy(() -> builder.build(keys))
                    .isInstanceOf(com.capsara.sdk.exceptions.CapsaraCapsaException.class)
                    .extracting(e -> ((com.capsara.sdk.exceptions.CapsaraException) e).getCode())
                    .isEqualTo("RECIPIENT_KEY_NOT_FOUND");
        }
    }

    @Test
    void delegateWithoutPublicKey_failsTheBuild() {
        try (CapsaBuilder builder = readyBuilder()) {
            PartyKey delegate = new PartyKey();
            delegate.setId("party_delegate_nokey");
            delegate.setPublicKey("");
            delegate.setIsDelegate(new String[]{RECIPIENT_ID});
            PartyKey[] keys = createPartyKeys();
            PartyKey[] withDelegate = {keys[0], keys[1], delegate};

            assertThatThrownBy(() -> builder.build(withDelegate))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void emptyFile_isRejectedAtBuild() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.addFile(new byte[0], "empty.bin");

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "EMPTY_FILE"))
                    .hasMessage("File \"empty.bin\" is empty");
        }
    }

    @Test
    void oneByteFile_builds() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.addFile(new byte[]{1}, "one.bin");

            assertThat(builder.build(createPartyKeys()).getFiles()).hasSize(1);
        }
    }

    @Test
    void capsaJsonOverOneMebibyte_isRejectedAtBuild() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.withBody("b".repeat(700_000)).withStructured("s", "x".repeat(700_000));

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .satisfies(e -> com.capsara.sdk.helpers.TestHelpers.assertBuildFailed(e, "CAPSA_JSON_TOO_LARGE"))
                    .hasMessageContaining("exceeds the server limit of 1048576 bytes per JSON field");
        }
    }

    @Test
    void capsaJsonUnderOneMebibyte_builds() {
        try (CapsaBuilder builder = readyBuilder()) {
            builder.withBody("b".repeat(700_000));

            assertThat(builder.build(createPartyKeys()).getCapsa().getEncryptedBody()).isNotEmpty();
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
