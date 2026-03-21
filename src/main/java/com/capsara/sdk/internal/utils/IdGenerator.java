package com.capsara.sdk.internal.utils;

import com.capsara.sdk.internal.crypto.SecureMemory;

/** Cryptographically secure ID generator using rejection sampling. */
public final class IdGenerator {

    private static final char[] ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();

    private IdGenerator() {
    }

    // Largest multiple of 36 that fits in a byte (252 = 36 * 7)
    private static final int REJECTION_THRESHOLD = 256 - (256 % ALPHABET.length);

    /** Generates a random alphanumeric ID of the specified length. */
    public static String generate(int length) {
        char[] result = new char[length];
        int filled = 0;

        while (filled < length) {
            byte[] randomBytes = SecureMemory.generateRandomBytes(length - filled);
            for (int i = 0; i < randomBytes.length && filled < length; i++) {
                int value = randomBytes[i] & 0xFF;
                if (value < REJECTION_THRESHOLD) {
                    result[filled++] = ALPHABET[value % ALPHABET.length];
                }
            }
        }

        return new String(result);
    }

    public static String generate() {
        return generate(22);
    }
}
