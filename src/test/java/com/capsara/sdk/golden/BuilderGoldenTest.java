package com.capsara.sdk.golden;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.models.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

/**
 * Golden tests for CapsaBuilder: master key generation, limits enforcement,
 * IV uniqueness, file validation, expiration, signature, compression, delegation.
 */
class BuilderGoldenTest {

    private static GeneratedKeyPairResult creatorKeyPair;
    private static GeneratedKeyPairResult recipientKeyPair;
    private static GeneratedKeyPairResult tertiaryKeyPair;
    private static final String CREATOR_ID = "party_creator_golden";
    private static final String RECIPIENT_ID = "party_recipient_golden";
    private static final String TERTIARY_ID = "party_tertiary_golden";

    @BeforeAll
    static void setUp() {
        creatorKeyPair = SharedKeyFixture.getPrimaryKeyPair();
        recipientKeyPair = SharedKeyFixture.getSecondaryKeyPair();
        tertiaryKeyPair = SharedKeyFixture.getTertiaryKeyPair();
    }

    // Master Key Generation Tests

    @Test
    void build_generatesMasterKeyThatDecryptsToThirtyTwoBytes() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            KeychainEntry creatorEntry = findEntry(result, CREATOR_ID);
            byte[] masterKey = RsaProvider.decryptMasterKey(
                    creatorEntry.getEncryptedKey(), creatorKeyPair.getPrivateKey());

            assertThat(masterKey).hasSize(32);
        }
    }

    @Test
    void build_differentBuildersGenerateDifferentMasterKeys() {
        byte[] masterKey1;
        byte[] masterKey2;

        try (CapsaBuilder builder1 = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder1.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result1 = builder1.build(createPartyKeys());
            KeychainEntry entry1 = findEntry(result1, CREATOR_ID);
            masterKey1 = RsaProvider.decryptMasterKey(entry1.getEncryptedKey(), creatorKeyPair.getPrivateKey());
        }

        try (CapsaBuilder builder2 = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder2.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result2 = builder2.build(createPartyKeys());
            KeychainEntry entry2 = findEntry(result2, CREATOR_ID);
            masterKey2 = RsaProvider.decryptMasterKey(entry2.getEncryptedKey(), creatorKeyPair.getPrivateKey());
        }

        assertThat(masterKey1).isNotEqualTo(masterKey2);
    }

    // Limits Enforcement Tests

    @Test
    void addFile_enforcesMaxFilesPerCapsa() {
        SystemLimits limits = new SystemLimits(1024 * 1024, 3, 10 * 1024 * 1024);
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            builder.addTextFile("f1.txt", "a")
                    .addTextFile("f2.txt", "b")
                    .addTextFile("f3.txt", "c");

            assertThatThrownBy(() -> builder.addTextFile("f4.txt", "d"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("max: 3");
        }
    }

    @Test
    void addFile_enforcesMaxFileSize() {
        SystemLimits limits = new SystemLimits(10, 100, 10 * 1024 * 1024);
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            assertThatThrownBy(() -> builder.addTextFile("big.txt", "This is way more than ten bytes"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exceeds maximum size");
        }
    }

    @Test
    void build_enforcesMaxTotalSize() {
        SystemLimits limits = new SystemLimits(1024 * 1024, 100, 20);
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), limits)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("f1.txt", "data that will be larger than 20 bytes when encrypted");

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exceeds maximum");
        }
    }

    @Test
    void builder_usesDefaultLimitsWhenNull() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            // Should not throw - default limits are generous
            BuiltCapsa result = builder.build(createPartyKeys());
            assertThat(result).isNotNull();
        }
    }

    // IV Uniqueness Tests

    @Test
    void build_generatesUniqueIvPerFile() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("f1.txt", "content1")
                    .addTextFile("f2.txt", "content2")
                    .addTextFile("f3.txt", "content3");

            BuiltCapsa result = builder.build(createPartyKeys());

            Set<String> contentIVs = new HashSet<>();
            Set<String> filenameIVs = new HashSet<>();
            for (EncryptedFile file : result.getCapsa().getFiles()) {
                contentIVs.add(file.getIv());
                filenameIVs.add(file.getFilenameIV());
            }

            assertThat(contentIVs).hasSize(3);
            assertThat(filenameIVs).hasSize(3);
        }
    }

    @Test
    void build_subjectBodyStructuredHaveUniqueIVs() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("f.txt", "content")
                    .withSubject("Subject")
                    .withBody("Body")
                    .withStructured("key", "value");

            BuiltCapsa result = builder.build(createPartyKeys());

            Set<String> ivs = new HashSet<>();
            ivs.add(result.getCapsa().getSubjectIV());
            ivs.add(result.getCapsa().getBodyIV());
            ivs.add(result.getCapsa().getStructuredIV());

            assertThat(ivs).hasSize(3);
        }
    }

    // File Size and Count Validation Tests

    @Test
    void getFileCount_returnsCorrectCount() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            assertThat(builder.getFileCount()).isEqualTo(0);

            builder.addTextFile("f1.txt", "a");
            assertThat(builder.getFileCount()).isEqualTo(1);

            builder.addTextFile("f2.txt", "b");
            assertThat(builder.getFileCount()).isEqualTo(2);
        }
    }

    @Test
    void build_setsFileSizeToEncryptedSize() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "Hello");
            BuiltCapsa result = builder.build(createPartyKeys());

            EncryptedFile file = result.getCapsa().getFiles()[0];
            assertThat(file.getSize()).isGreaterThan(0);
        }
    }

    // Expiration Normalization Tests

    @Test
    void withExpiration_roundsToMinuteGranularity() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            OffsetDateTime withSeconds = OffsetDateTime.of(2030, 6, 15, 10, 30, 45, 123456789, ZoneOffset.UTC);
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "content")
                    .withExpiration(withSeconds);

            BuiltCapsa result = builder.build(createPartyKeys());

            String expiresAt = result.getCapsa().getAccessControl().getExpiresAt();
            assertThat(expiresAt).isNotNull();
            // Seconds and nanos should be zeroed out
            assertThat(expiresAt).contains("10:30");
            assertThat(expiresAt).doesNotContain(":45");
        }
    }

    @Test
    void withExpiration_null_clearsExpiration() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID)
                    .addTextFile("test.txt", "content")
                    .withExpiration(OffsetDateTime.now().plusDays(7))
                    .withExpiration(null);

            BuiltCapsa result = builder.build(createPartyKeys());

            assertThat(result.getCapsa().getAccessControl().getExpiresAt()).isNull();
        }
    }

    // Signature Generation Tests

    @Test
    void build_generatesRS256Signature() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            CapsaSignature sig = result.getCapsa().getSignature();
            assertThat(sig.getAlgorithm()).isEqualTo("RS256");
            assertThat(sig.getProtectedHeader()).isNotEmpty();
            assertThat(sig.getPayload()).isNotEmpty();
            assertThat(sig.getSignature()).isNotEmpty();
        }
    }

    @Test
    void build_signatureIsVerifiable() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            CapsaSignature sig = result.getCapsa().getSignature();
            boolean valid = SignatureProvider.verifyJws(
                    sig.getProtectedHeader(), sig.getPayload(),
                    sig.getSignature(), creatorKeyPair.getPublicKey());

            assertThat(valid).isTrue();
        }
    }

    @Test
    void build_signatureFailsVerificationWithWrongKey() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            CapsaSignature sig = result.getCapsa().getSignature();
            boolean valid = SignatureProvider.verifyJws(
                    sig.getProtectedHeader(), sig.getPayload(),
                    sig.getSignature(), recipientKeyPair.getPublicKey());

            assertThat(valid).isFalse();
        }
    }

    // Compression Threshold Tests

    @Test
    void build_compressesFilesAboveThreshold() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                sb.append("Repetitive text for compression. ");
            }

            builder.addRecipient(RECIPIENT_ID).addTextFile("large.txt", sb.toString());
            BuiltCapsa result = builder.build(createPartyKeys());

            EncryptedFile file = result.getCapsa().getFiles()[0];
            assertThat(file.getCompressed()).isTrue();
            assertThat(file.getCompressionAlgorithm()).isEqualTo("gzip");
            assertThat(file.getOriginalSize()).isGreaterThan(0);
        }
    }

    @Test
    void build_doesNotCompressSmallFiles() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("small.txt", "tiny");
            BuiltCapsa result = builder.build(createPartyKeys());

            EncryptedFile file = result.getCapsa().getFiles()[0];
            assertThat(file.getCompressed()).isNull();
            assertThat(file.getCompressionAlgorithm()).isNull();
        }
    }

    // Delegation Keychain Tests

    @Test
    void build_delegateGetsEncryptedKeyWithActingFor() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");

            PartyKey creatorKey = makePartyKey(CREATOR_ID, creatorKeyPair);
            PartyKey recipientKey = makePartyKey(RECIPIENT_ID, recipientKeyPair);

            // Delegate acts for recipient
            PartyKey delegateKey = makePartyKey(TERTIARY_ID, tertiaryKeyPair);
            delegateKey.setIsDelegate(new String[]{RECIPIENT_ID});

            BuiltCapsa result = builder.build(new PartyKey[]{creatorKey, recipientKey, delegateKey});

            // Delegate should have encrypted key and actingFor
            KeychainEntry delegateEntry = findEntry(result, TERTIARY_ID);
            assertThat(delegateEntry).isNotNull();
            assertThat(delegateEntry.getEncryptedKey()).isNotEmpty();
            assertThat(delegateEntry.getActingFor()).contains(RECIPIENT_ID);
            assertThat(delegateEntry.getPermissions()).containsExactly("delegate");
        }
    }

    @Test
    void build_creatorKeychainEntryHasNoPermissions() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            KeychainEntry creatorEntry = findEntry(result, CREATOR_ID);
            assertThat(creatorEntry.getPermissions()).isEmpty();
            assertThat(creatorEntry.getEncryptedKey()).isNotEmpty();
        }
    }

    @Test
    void build_recipientKeychainEntryHasReadPermission() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            KeychainEntry recipientEntry = findEntry(result, RECIPIENT_ID);
            assertThat(recipientEntry.getPermissions()).containsExactly("read");
        }
    }

    // Constructor Validation Tests

    @Test
    void constructor_rejectsNullCreatorId() {
        assertThatThrownBy(() -> new CapsaBuilder(null, creatorKeyPair.getPrivateKey(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Creator ID");
    }

    @Test
    void constructor_rejectsEmptyCreatorId() {
        assertThatThrownBy(() -> new CapsaBuilder("", creatorKeyPair.getPrivateKey(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Creator ID");
    }

    @Test
    void constructor_rejectsNullPrivateKey() {
        assertThatThrownBy(() -> new CapsaBuilder(CREATOR_ID, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private key");
    }

    // Package ID Format Tests

    @Test
    void build_generatesPackageIdWithCapsaPrefix() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("test.txt", "content");
            BuiltCapsa result = builder.build(createPartyKeys());

            assertThat(result.getCapsa().getPackageId()).startsWith("capsa_");
            assertThat(result.getCapsa().getPackageId()).hasSize(28);
        }
    }

    // Dispose Tests

    @Test
    void close_preventsFurtherBuilds() {
        CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null);
        builder.addTextFile("test.txt", "content");
        builder.close();

        assertThatThrownBy(() -> builder.build(createPartyKeys()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("disposed");
    }

    // ========================================================================
    // Defense-in-Depth: Server-Aligned Pre-Flight Validations
    // ========================================================================

    // Recipient Count Limits (server: max 100 keychain entries)

    @Test
    void addRecipient_rejectsWhenKeychainWouldExceedLimit() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            // Add 99 recipients (+1 creator = 100 total, at limit, still valid)
            for (int i = 0; i < 99; i++) {
                builder.addRecipient("party_" + i);
            }

            // 100th recipient would make 101 (100 + creator) = over limit
            assertThatThrownBy(() -> builder.addRecipient("one_too_many"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("100");
        }
    }

    @Test
    void addRecipients_rejectsBatchThatWouldExceedLimit() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient("existing_1");

            String[] tooMany = new String[100];
            for (int i = 0; i < 100; i++) {
                tooMany[i] = "batch_" + i;
            }

            assertThatThrownBy(() -> builder.addRecipients(tooMany))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("100");
        }
    }

    // Encrypted Field Size Limits (server-aligned)

    @Test
    void build_rejectsEncryptedSubjectExceedingSixtyFourKB() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            // 60KB of text + base64url overhead will exceed 65536 chars
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 60_000; i++) {
                sb.append('x');
            }
            builder.withSubject(sb.toString());

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("subject")
                    .hasMessageContaining("server limit");
        }
    }

    @Test
    void build_acceptsSubjectWithinLimit() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");
            builder.withSubject("Normal subject line");

            BuiltCapsa result = builder.build(createPartyKeys());
            assertThat(result.getCapsa().getEncryptedSubject()).isNotEmpty();
        }
    }

    @Test
    void build_rejectsEncryptedBodyExceedingOneMB() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 900_000; i++) {
                sb.append('x');
            }
            builder.withBody(sb.toString());

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("body")
                    .hasMessageContaining("server limit");
        }
    }

    @Test
    void build_rejectsEncryptedStructuredExceedingOneMB() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 900_000; i++) {
                sb.append('x');
            }
            builder.withStructured("bigField", sb.toString());

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("structured")
                    .hasMessageContaining("server limit");
        }
    }

    // Metadata Field Size Limits (server-aligned)

    @Test
    void build_rejectsMetadataLabelExceedingFiveHundredTwelveChars() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            StringBuilder label = new StringBuilder();
            for (int i = 0; i < 513; i++) {
                label.append('x');
            }
            builder.getMetadata().setLabel(label.toString());

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("label")
                    .hasMessageContaining("512");
        }
    }

    @Test
    void build_rejectsMoreThanOneHundredTags() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            String[] tags = new String[101];
            for (int i = 0; i < 101; i++) {
                tags[i] = "tag_" + i;
            }
            builder.getMetadata().setTags(tags);

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("tags count")
                    .hasMessageContaining("100");
        }
    }

    @Test
    void build_rejectsIndividualTagExceedingOneHundredChars() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            StringBuilder longTag = new StringBuilder();
            for (int i = 0; i < 101; i++) {
                longTag.append('x');
            }
            builder.getMetadata().setTags(new String[]{longTag.toString()});

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("tag")
                    .hasMessageContaining("100 chars");
        }
    }

    @Test
    void build_rejectsMetadataNotesExceedingTenKB() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            StringBuilder notes = new StringBuilder();
            for (int i = 0; i < 10_241; i++) {
                notes.append('x');
            }
            builder.getMetadata().setNotes(notes.toString());

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("notes")
                    .hasMessageContaining("10240");
        }
    }

    @Test
    void build_rejectsMoreThanFiftyRelatedPackages() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID).addTextFile("f.txt", "data");

            String[] pkgs = new String[51];
            for (int i = 0; i < 51; i++) {
                pkgs[i] = "pkg_" + i;
            }
            builder.getMetadata().setRelatedPackages(pkgs);

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Related packages")
                    .hasMessageContaining("50");
        }
    }

    // Duplicate IV Detection (defense-in-depth)

    @Test
    void build_producesGloballyUniqueIVsAcrossAllFields() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.withSubject("test")
                    .withBody("test body")
                    .withStructured("key", "val")
                    .addRecipient(RECIPIENT_ID)
                    .addTextFile("a.txt", "file1")
                    .addTextFile("b.txt", "file2");

            BuiltCapsa result = builder.build(createPartyKeys());

            // Collect ALL IVs
            Set<String> allIVs = new HashSet<>();
            if (result.getCapsa().getSubjectIV() != null) allIVs.add(result.getCapsa().getSubjectIV());
            if (result.getCapsa().getBodyIV() != null) allIVs.add(result.getCapsa().getBodyIV());
            if (result.getCapsa().getStructuredIV() != null) allIVs.add(result.getCapsa().getStructuredIV());
            for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
                if (entry.getIv() != null) allIVs.add(entry.getIv());
            }
            int ivCount = (result.getCapsa().getSubjectIV() != null ? 1 : 0)
                    + (result.getCapsa().getBodyIV() != null ? 1 : 0)
                    + (result.getCapsa().getStructuredIV() != null ? 1 : 0);
            for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
                if (entry.getIv() != null) ivCount++;
            }
            for (EncryptedFile file : result.getCapsa().getFiles()) {
                allIVs.add(file.getIv());
                allIVs.add(file.getFilenameIV());
                ivCount += 2;
            }

            // All IVs must be globally unique
            assertThat(allIVs).hasSize(ivCount);
            // 2 files * 2 IVs (content + filename) + 3 metadata + 2 keychain = 9 IVs
            assertThat(ivCount).isGreaterThanOrEqualTo(9);
        }
    }

    // Server Constants Validation

    @Test
    void serverLimitsConstantsMatchZodSchema() {
        assertThat(CapsaBuilder.MAX_KEYCHAIN_KEYS).isEqualTo(100);
        assertThat(CapsaBuilder.MAX_ENCRYPTED_SUBJECT).isEqualTo(65_536);
        assertThat(CapsaBuilder.MAX_ENCRYPTED_BODY).isEqualTo(1_048_576);
        assertThat(CapsaBuilder.MAX_ENCRYPTED_STRUCTURED).isEqualTo(1_048_576);
        assertThat(CapsaBuilder.MAX_METADATA_LABEL).isEqualTo(512);
        assertThat(CapsaBuilder.MAX_METADATA_TAGS).isEqualTo(100);
        assertThat(CapsaBuilder.MAX_TAG_LENGTH).isEqualTo(100);
        assertThat(CapsaBuilder.MAX_METADATA_NOTES).isEqualTo(10_240);
        assertThat(CapsaBuilder.MAX_RELATED_PACKAGES).isEqualTo(50);
    }

    // Party ID Validation

    @Test
    void addRecipient_rejectsEmptyPartyId() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            assertThatThrownBy(() -> builder.addRecipient(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("empty");
        }
    }

    @Test
    void addRecipient_rejectsNullPartyId() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            assertThatThrownBy(() -> builder.addRecipient(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("empty");
        }
    }

    @Test
    void addRecipient_rejectsPartyIdExceeding100Chars() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            StringBuilder longId = new StringBuilder();
            for (int i = 0; i < 101; i++) longId.append('x');
            assertThatThrownBy(() -> builder.addRecipient(longId.toString()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("100");
        }
    }

    @Test
    void addRecipients_rejectsEmptyPartyIdInBatch() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            assertThatThrownBy(() -> builder.addRecipients("valid_id", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("empty");
        }
    }

    // No-Content Guard

    @Test
    void build_rejectsEmptyCapsaWithNoFilesOrMessage() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID);
            // Only structured data, no files or subject/body
            builder.withStructured("key", "val");

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("files")
                    .hasMessageContaining("message");
        }
    }

    @Test
    void build_allowsSubjectOnlyWithNoFiles() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID);
            builder.withSubject("Just a message");

            BuiltCapsa result = builder.build(createPartyKeys());
            assertThat(result).isNotNull();
            assertThat(result.getCapsa().getEncryptedSubject()).isNotNull();
            assertThat(result.getCapsa().getFiles()).isEmpty();
        }
    }

    // Encrypted Filename Length Limit

    @Test
    void build_rejectsLongFilenameExceedingEncryptedLimit() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            // 1540 + 4 (.txt) = 1544 bytes → AES-GCM → 1544 bytes → base64url → 2059 chars > 2048
            StringBuilder longName = new StringBuilder();
            for (int i = 0; i < 1540; i++) longName.append('a');
            longName.append(".txt");
            builder.addFile(new byte[10], longName.toString());
            builder.addRecipient(RECIPIENT_ID);

            assertThatThrownBy(() -> builder.build(createPartyKeys()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Encrypted filename")
                    .hasMessageContaining("2048");
        }
    }

    // Constants Verification

    @Test
    void serverLimitsConstants_includeNewValidationLimits() {
        assertThat(CapsaBuilder.MAX_PARTY_ID_LENGTH).isEqualTo(100);
        assertThat(CapsaBuilder.MAX_ENCRYPTED_FILENAME).isEqualTo(2048);
        assertThat(CapsaBuilder.MAX_SIGNATURE_PAYLOAD).isEqualTo(65536);
        assertThat(CapsaBuilder.MAX_ACTING_FOR).isEqualTo(10);
    }

    // Helper Methods

    private PartyKey[] createPartyKeys() {
        return new PartyKey[]{
                makePartyKey(CREATOR_ID, creatorKeyPair),
                makePartyKey(RECIPIENT_ID, recipientKeyPair)
        };
    }

    private static PartyKey makePartyKey(String id, GeneratedKeyPairResult keyPair) {
        PartyKey pk = new PartyKey();
        pk.setId(id);
        pk.setPublicKey(keyPair.getPublicKey());
        pk.setFingerprint(keyPair.getFingerprint());
        return pk;
    }

    private static KeychainEntry findEntry(BuiltCapsa result, String partyId) {
        for (KeychainEntry entry : result.getCapsa().getKeychain().getKeys()) {
            if (entry.getParty().equals(partyId)) {
                return entry;
            }
        }
        return null;
    }
}
