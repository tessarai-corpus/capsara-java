package com.capsara.sdk.helpers;

import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.models.GeneratedKeyPairResult;

/**
 * Shared RSA key fixtures for tests.
 * RSA-4096 key generation is expensive, so we generate keys once and reuse them.
 */
public final class SharedKeyFixture {

    private static volatile GeneratedKeyPairResult primaryKeyPair;
    private static volatile GeneratedKeyPairResult secondaryKeyPair;
    private static volatile GeneratedKeyPairResult tertiaryKeyPair;

    private static final Object LOCK = new Object();

    private SharedKeyFixture() {
        // Utility class
    }

    /**
     * Get the primary test key pair (lazy initialization).
     */
    public static GeneratedKeyPairResult getPrimaryKeyPair() {
        if (primaryKeyPair == null) {
            synchronized (LOCK) {
                if (primaryKeyPair == null) {
                    primaryKeyPair = KeyGenerator.generateKeyPair();
                }
            }
        }
        return primaryKeyPair;
    }

    /**
     * Get the secondary test key pair (lazy initialization).
     */
    public static GeneratedKeyPairResult getSecondaryKeyPair() {
        if (secondaryKeyPair == null) {
            synchronized (LOCK) {
                if (secondaryKeyPair == null) {
                    secondaryKeyPair = KeyGenerator.generateKeyPair();
                }
            }
        }
        return secondaryKeyPair;
    }

    /**
     * Get the tertiary test key pair (lazy initialization).
     */
    public static GeneratedKeyPairResult getTertiaryKeyPair() {
        if (tertiaryKeyPair == null) {
            synchronized (LOCK) {
                if (tertiaryKeyPair == null) {
                    tertiaryKeyPair = KeyGenerator.generateKeyPair();
                }
            }
        }
        return tertiaryKeyPair;
    }
}
