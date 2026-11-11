package com.capsara.sdk.internal.crypto;

import java.security.SecureRandom;
import java.util.Arrays;

/** Secure memory operations and CSPRNG random byte generation. */
public final class SecureMemory {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureMemory() {
    }

    /** Securely clear a byte array by filling it with zeros. */
    public static void clear(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    /** Securely clear a char array by filling it with zeros. */
    public static void clear(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, '\0');
        }
    }

    /** Generate cryptographically secure random bytes. */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** Generate a 256-bit (32 byte) AES master key. */
    public static byte[] generateMasterKey() {
        return generateRandomBytes(32);
    }

    /** Generate a 96-bit (12 byte) IV for AES-GCM. */
    public static byte[] generateIv() {
        return generateRandomBytes(12);
    }
}
