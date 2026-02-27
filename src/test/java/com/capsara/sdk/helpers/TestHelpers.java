package com.capsara.sdk.helpers;

import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.PartyKey;

import java.security.SecureRandom;
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
        partyKey.setEmail("test@example.com");
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
     * Generate random bytes.
     */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
