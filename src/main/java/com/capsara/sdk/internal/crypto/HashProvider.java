package com.capsara.sdk.internal.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 hashing utilities.
 */
public final class HashProvider {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private HashProvider() {
        // Utility class
    }

    /**
     * Compute SHA-256 hash of data.
     *
     * @param data data to hash
     * @return lowercase hex-encoded hash
     */
    public static String computeHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Compute SHA-256 fingerprint of a public key.
     *
     * @param publicKeyBytes DER-encoded public key bytes
     * @return lowercase hex-encoded fingerprint
     */
    public static String computeFingerprint(byte[] publicKeyBytes) {
        return computeHash(publicKeyBytes);
    }

    /**
     * Constant-time comparison of two byte arrays.
     *
     * @param a first array
     * @param b second array
     * @return true if arrays are equal
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }
}
