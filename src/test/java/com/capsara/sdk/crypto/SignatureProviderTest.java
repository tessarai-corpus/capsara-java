package com.capsara.sdk.crypto;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for SignatureProvider JWS RS256 signature operations.
 */
class SignatureProviderTest {

    // buildCanonicalString Tests

    @Test
    void buildCanonicalString_withBasicParams_buildsCorrectString() {
        String packageId = "pkg_123";
        long totalSize = 1024;
        String algorithm = "AES-256-GCM";
        FileHashData[] files = new FileHashData[0];

        String result = SignatureProvider.buildCanonicalString(
                packageId, totalSize, algorithm, "party_c", "fp", files, null, null, null);

        assertThat(result).isEqualTo("pkg_123|1.0.0|1024|AES-256-GCM|party_c|fp");
    }

    @Test
    void buildCanonicalString_putsCreatorAndKeyFingerprintRightAfterAlgorithm() {
        FileHashData[] files = {new FileHashData("file_1", "hash1", 100, "iv1", "fnIv1")};

        String result = SignatureProvider.buildCanonicalString(
                "pkg_123", 100, "AES-256-GCM", "party_creator", "ab12", files, "sIV", "subIV", "bIV");

        assertThat(result).isEqualTo(
                "pkg_123|1.0.0|100|AES-256-GCM|party_creator|ab12|hash1|iv1|fnIv1|structured:sIV|subject:subIV|body:bIV");
    }

    @Test
    void buildCanonicalString_withFiles_includesFileData() {
        String packageId = "pkg_123";
        FileHashData[] files = new FileHashData[]{
                new FileHashData("file_1", "hash1", 100, "iv1", "fnIv1"),
                new FileHashData("file_2", "hash2", 200, "iv2", "fnIv2")
        };

        String result = SignatureProvider.buildCanonicalString(
                packageId, 300, "AES-256-GCM", "party_c", "fp", files, null, null, null);

        // Should include hashes, then IVs, then filename IVs in order
        assertThat(result).contains("|hash1|hash2|");
        assertThat(result).contains("|iv1|iv2|");
        assertThat(result).contains("|fnIv1|fnIv2");
    }

    @Test
    void buildCanonicalString_withOptionalIVs_includesThemInOrder() {
        String packageId = "pkg_123";
        FileHashData[] files = new FileHashData[0];

        String result = SignatureProvider.buildCanonicalString(
                packageId, 0, "AES-256-GCM", "party_c", "fp", files,
                "structuredIV", "subjectIV", "bodyIV");

        assertThat(result).endsWith("|structured:structuredIV|subject:subjectIV|body:bodyIV");
    }

    @Test
    void buildCanonicalString_labelsEachOptionalIvOnItsOwn() {
        FileHashData[] files = new FileHashData[0];

        String subjectOnly = SignatureProvider.buildCanonicalString(
                "pkg_123", 0, "AES-256-GCM", "party_c", "fp", files, null, "iv", null);
        String bodyOnly = SignatureProvider.buildCanonicalString(
                "pkg_123", 0, "AES-256-GCM", "party_c", "fp", files, null, null, "iv");

        assertThat(subjectOnly).endsWith("|subject:iv");
        assertThat(bodyOnly).endsWith("|body:iv");
        assertThat(subjectOnly).isNotEqualTo(bodyOnly);
    }

    @Test
    void buildCanonicalString_withNullOptionalIVs_omitsThem() {
        String packageId = "pkg_123";
        FileHashData[] files = new FileHashData[0];

        String result = SignatureProvider.buildCanonicalString(
                packageId, 0, "AES-256-GCM", "party_c", "fp", files, null, null, null);

        // Should not have trailing pipes for null IVs
        assertThat(result).doesNotContain("||");
        assertThat(result.split("\\|")).hasSize(6);
    }

    @Test
    void buildCanonicalString_withEmptyOptionalIVs_omitsThem() {
        String packageId = "pkg_123";
        FileHashData[] files = new FileHashData[0];

        String result = SignatureProvider.buildCanonicalString(
                packageId, 0, "AES-256-GCM", "party_c", "fp", files, "", "", "");

        assertThat(result.split("\\|")).hasSize(6);
    }

    @Test
    void buildCanonicalString_preservesFileOrder() {
        FileHashData[] files = new FileHashData[]{
                new FileHashData("file_c", "hashC", 100, "ivC", "fnIvC"),
                new FileHashData("file_a", "hashA", 200, "ivA", "fnIvA"),
                new FileHashData("file_b", "hashB", 300, "ivB", "fnIvB")
        };

        String result = SignatureProvider.buildCanonicalString(
                "pkg_123", 600, "AES-256-GCM", "party_c", "fp", files, null, null, null);

        // Files should not be sorted - preserve original order
        int hashCPos = result.indexOf("hashC");
        int hashAPos = result.indexOf("hashA");
        int hashBPos = result.indexOf("hashB");

        assertThat(hashCPos).isLessThan(hashAPos);
        assertThat(hashAPos).isLessThan(hashBPos);
    }

    @Test
    void buildCanonicalString_includesVersionNumber() {
        String result = SignatureProvider.buildCanonicalString(
                "pkg_123", 0, "AES-256-GCM", "party_c", "fp", new FileHashData[0], null, null, null);

        assertThat(result).contains("|1.0.0|");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.NullAndEmptySource
    void buildCanonicalString_withoutCreatorPartyId_throws(String creatorPartyId) {
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 0, "AES-256-GCM", creatorPartyId, "fp", new FileHashData[0], null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("creatorPartyId");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.NullAndEmptySource
    void buildCanonicalString_withoutCreatorKeyFingerprint_throws(String fingerprint) {
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 0, "AES-256-GCM", "party_c", fingerprint, new FileHashData[0], null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("creatorKeyFingerprint");
    }

    @Test
    void buildCanonicalString_fileWithoutHash_throwsInsteadOfRenderingNull() {
        FileHashData[] files = {new FileHashData("file_1", null, 1, "iv1", "fnIv1")};

        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 1, "AES-256-GCM", "party_c", "fp", files, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("File at index 0 missing required field: hash");
    }

    @Test
    void buildCanonicalString_fileWithoutIvs_throws() {
        FileHashData[] noIv = {new FileHashData("file_1", "h", 1, "", "fnIv1")};
        FileHashData[] noFilenameIv = {new FileHashData("file_1", "h", 1, "iv1", null)};

        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 1, "AES-256-GCM", "party_c", "fp", noIv, null, null, null))
                .hasMessage("File at index 0 missing required field: iv");
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 1, "AES-256-GCM", "party_c", "fp", noFilenameIv, null, null, null))
                .hasMessage("File at index 0 missing required field: filenameIV");
    }

    @Test
    void buildCanonicalString_missingOrNegativeTotalSize_throws() {
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", (Long) null, "AES-256-GCM", "party_c", "fp", new FileHashData[0], null, null, null))
                .hasMessageContaining("totalSize");
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", -1, "AES-256-GCM", "party_c", "fp", new FileHashData[0], null, null, null))
                .hasMessageContaining("totalSize");
    }

    @Test
    void buildCanonicalString_withoutPackageIdOrAlgorithm_throws() {
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "", 0, "AES-256-GCM", "party_c", "fp", new FileHashData[0], null, null, null))
                .hasMessageContaining("packageId");
        assertThatThrownBy(() -> SignatureProvider.buildCanonicalString(
                "pkg_1", 0, null, "party_c", "fp", new FileHashData[0], null, null, null))
                .hasMessageContaining("algorithm");
    }

    @Test
    void buildCanonicalString_integralFloatTotalSize_rendersAsInteger() throws Exception {
        com.capsara.sdk.models.Capsa capsa = com.capsara.sdk.internal.json.JsonMapper.getInstance()
                .readValue("{\"id\":\"pkg_1\",\"totalSize\":1024.0}", com.capsara.sdk.models.Capsa.class);

        assertThat(SignatureProvider.buildCanonicalString(capsa.getId(), capsa.getTotalSize(), "AES-256-GCM",
                "party_c", "fp", new FileHashData[0], null, null, null))
                .isEqualTo("pkg_1|1.0.0|1024|AES-256-GCM|party_c|fp");
    }

    // createJws Tests

    @Test
    void createJws_createsValidSignature() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "pkg_123|1.0.0|1024|AES-256-GCM";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        assertThat(signature).isNotNull();
        assertThat(signature.getAlgorithm()).isEqualTo("RS256");
        assertThat(signature.getProtectedHeader()).isNotEmpty();
        assertThat(signature.getPayload()).isNotEmpty();
        assertThat(signature.getSignature()).isNotEmpty();
    }

    @Test
    void createJws_payloadContainsCanonicalString() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test_canonical_string";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        String decodedPayload = new String(Base64Url.decode(signature.getPayload()), StandardCharsets.UTF_8);
        assertThat(decodedPayload).isEqualTo(canonicalString);
    }

    @Test
    void createJws_protectedHeaderContainsAlgorithm() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        String decodedHeader = new String(Base64Url.decode(signature.getProtectedHeader()), StandardCharsets.UTF_8);
        assertThat(decodedHeader).contains("RS256");
        assertThat(decodedHeader).contains("JWT");
    }

    @Test
    void createJws_signatureIs512Bytes() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        byte[] signatureBytes = Base64Url.decode(signature.getSignature());
        assertThat(signatureBytes).hasSize(512); // RSA-4096 produces 512-byte signature
    }

    @Test
    void createJws_withNullCanonicalString_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        assertThatThrownBy(() -> SignatureProvider.createJws(null, keyPair.getPrivateKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Canonical string");
    }

    @Test
    void createJws_withEmptyCanonicalString_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        assertThatThrownBy(() -> SignatureProvider.createJws("", keyPair.getPrivateKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Canonical string");
    }

    @Test
    void createJws_withNullPrivateKey_throwsException() {
        assertThatThrownBy(() -> SignatureProvider.createJws("test", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Private key");
    }

    @Test
    void createJws_withEmptyPrivateKey_throwsException() {
        assertThatThrownBy(() -> SignatureProvider.createJws("test", ""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Private key");
    }

    // verifyJws Tests

    @Test
    void verifyJws_withValidSignature_returnsTrue() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test_data";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyJws(
                signature.getProtectedHeader(),
                signature.getPayload(),
                signature.getSignature(),
                keyPair.getPublicKey());

        assertThat(result).isTrue();
    }

    @Test
    void verifyJws_withInvalidSignature_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test_data";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        // Tamper with signature
        byte[] signatureBytes = Base64Url.decode(signature.getSignature());
        signatureBytes[0] ^= 0xFF;
        String tamperedSignature = Base64Url.encode(signatureBytes);

        boolean result = SignatureProvider.verifyJws(
                signature.getProtectedHeader(),
                signature.getPayload(),
                tamperedSignature,
                keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withWrongPublicKey_returnsFalse() {
        GeneratedKeyPairResult keyPair1 = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult keyPair2 = SharedKeyFixture.getSecondaryKeyPair();
        String canonicalString = "test_data";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair1.getPrivateKey());

        boolean result = SignatureProvider.verifyJws(
                signature.getProtectedHeader(),
                signature.getPayload(),
                signature.getSignature(),
                keyPair2.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withTamperedPayload_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test_data";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        // Tamper with payload
        String tamperedPayload = Base64Url.encode("tampered_data".getBytes(StandardCharsets.UTF_8));

        boolean result = SignatureProvider.verifyJws(
                signature.getProtectedHeader(),
                tamperedPayload,
                signature.getSignature(),
                keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withNullProtectedHeader_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        boolean result = SignatureProvider.verifyJws(null, "payload", "signature", keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withNullPayload_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        boolean result = SignatureProvider.verifyJws("header", null, "signature", keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withNullSignature_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        boolean result = SignatureProvider.verifyJws("header", "payload", null, keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withNullPublicKey_returnsFalse() {
        boolean result = SignatureProvider.verifyJws("header", "payload", "signature", null);

        assertThat(result).isFalse();
    }

    @Test
    void verifyJws_withEmptyPublicKey_returnsFalse() {
        boolean result = SignatureProvider.verifyJws("header", "payload", "signature", "");

        assertThat(result).isFalse();
    }

    // verifyCapsaSignature Tests

    @Test
    void verifyCapsaSignature_withMatchingCanonicalString_returnsTrue() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "pkg_123|1.0.0|1024|AES-256-GCM";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, canonicalString, keyPair.getPublicKey());

        assertThat(result).isTrue();
    }

    @Test
    void verifyCapsaSignature_withNonMatchingCanonicalString_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "pkg_123|1.0.0|1024|AES-256-GCM";
        String differentCanonicalString = "pkg_456|1.0.0|2048|AES-256-GCM";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, differentCanonicalString, keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyCapsaSignature_withNullSignature_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        boolean result = SignatureProvider.verifyCapsaSignature(
                null, "canonical_string", keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyCapsaSignature_withNullCanonicalString_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        CapsaSignature signature = SignatureProvider.createJws("test", keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, null, keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    @Test
    void verifyCapsaSignature_withEmptyCanonicalString_returnsFalse() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        CapsaSignature signature = SignatureProvider.createJws("test", keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, "", keyPair.getPublicKey());

        assertThat(result).isFalse();
    }

    // Roundtrip Tests

    @Test
    void createAndVerify_roundtripWithComplexCanonicalString_succeeds() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String capsaId = TestHelpers.generateCapsaId();

        FileHashData[] files = new FileHashData[]{
                new FileHashData("file_1", "abc123hash", 1024, "iv1base64", "fniv1base64"),
                new FileHashData("file_2", "def456hash", 2048, "iv2base64", "fniv2base64")
        };

        String canonicalString = SignatureProvider.buildCanonicalString(
                capsaId, 3072, "AES-256-GCM", "party_c", "fp", files,
                "structuredIV", "subjectIV", "bodyIV");

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, canonicalString, keyPair.getPublicKey());

        assertThat(result).isTrue();
    }

    @Test
    void createAndVerify_multipleSignaturesAreDeterministic() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "test_deterministic";

        CapsaSignature signature1 = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());
        CapsaSignature signature2 = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        // Protected header and payload should be identical
        assertThat(signature1.getProtectedHeader()).isEqualTo(signature2.getProtectedHeader());
        assertThat(signature1.getPayload()).isEqualTo(signature2.getPayload());

        // Both signatures should verify correctly
        assertThat(SignatureProvider.verifyCapsaSignature(signature1, canonicalString, keyPair.getPublicKey())).isTrue();
        assertThat(SignatureProvider.verifyCapsaSignature(signature2, canonicalString, keyPair.getPublicKey())).isTrue();
    }

    @Test
    void verifyJws_withUnicodeCanonicalString_works() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String canonicalString = "pkg_123|1.0.0|日本語テスト|AES-256-GCM";

        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        boolean result = SignatureProvider.verifyCapsaSignature(
                signature, canonicalString, keyPair.getPublicKey());

        assertThat(result).isTrue();
    }
}
