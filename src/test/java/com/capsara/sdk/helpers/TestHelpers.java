package com.capsara.sdk.helpers;

import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.EncryptedFile;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.PartyKey;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

/**
 * Test helper utilities for SDK tests.
 */
public final class TestHelpers {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestHelpers() {
        // Utility class
    }

    /**
     * Generate a test AES-256 master key.
     */
    public static byte[] generateTestMasterKey() {
        return SecureMemory.generateMasterKey();
    }

    /**
     * Generate a test IV (12 bytes for AES-GCM).
     */
    public static byte[] generateTestIV() {
        return SecureMemory.generateIv();
    }

    /**
     * Generate a test party ID.
     */
    public static String generatePartyId() {
        return "party_" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    /**
     * Generate a test capsa ID.
     */
    public static String generateCapsaId() {
        return "capsa_" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    /**
     * Generate a test file ID.
     */
    public static String generateFileId() {
        return "file_" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    /**
     * Create a mock PartyKey.
     */
    public static PartyKey createMockPartyKey(String partyId, GeneratedKeyPairResult keyPair) {
        PartyKey partyKey = new PartyKey();
        partyKey.setId(partyId);
        partyKey.setPublicKey(keyPair.getPublicKey());
        partyKey.setFingerprint(keyPair.getFingerprint());
        return partyKey;
    }

    /**
     * Create a mock PartyKey using shared fixtures.
     */
    public static PartyKey createMockPartyKey(String partyId) {
        return createMockPartyKey(partyId, SharedKeyFixture.getPrimaryKeyPair());
    }

    /**
     * Sign a capsa as its creator would and attach the creator's public key, the way
     * the server returns it.
     */
    public static Capsa signAsCreator(Capsa capsa, GeneratedKeyPairResult creatorKeys) {
        EncryptedFile[] files = capsa.getFiles() != null ? capsa.getFiles() : new EncryptedFile[0];
        FileHashData[] hashData = Arrays.stream(files)
                .map(f -> new FileHashData(f.getFileId(), f.getHash(), f.getSize(), f.getIv(), f.getFilenameIV()))
                .toArray(FileHashData[]::new);
        String canonical = SignatureProvider.buildCanonicalString(
                capsa.getId(), capsa.getTotalSize(), capsa.getKeychain().getAlgorithm(), capsa.getCreator(),
                creatorKeys.getFingerprint(), hashData,
                capsa.getStructuredIV(), capsa.getSubjectIV(), capsa.getBodyIV());
        CapsaSignature signature = SignatureProvider.createJws(canonical, creatorKeys.getPrivateKey());
        capsa.setSignature(signature);
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());
        return capsa;
    }

    /**
     * Generate random bytes.
     */
    public static void assertBuildFailed(Throwable thrown, String reason) {
        org.assertj.core.api.Assertions.assertThat(thrown)
                .isExactlyInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class);
        com.capsara.sdk.exceptions.CapsaraException error = (com.capsara.sdk.exceptions.CapsaraException) thrown;
        org.assertj.core.api.Assertions.assertThat(error.getCode()).isEqualTo("BUILD_FAILED");
        org.assertj.core.api.Assertions.assertThat(error.getStatusCode()).isZero();
        org.assertj.core.api.Assertions.assertThat(error.getDetails()).isEqualTo(java.util.Map.of("reason", reason));
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
