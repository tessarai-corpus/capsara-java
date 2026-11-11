package com.capsara.sdk.internal.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * AES-256-GCM encryption/decryption provider.
 */
public final class AesGcmProvider {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    private AesGcmProvider() {
    }

    /** Encrypt data using AES-256-GCM. */
    public static EncryptionResult encrypt(byte[] plaintext, byte[] key, byte[] iv) {
        validateKeySize(key);
        validateIvSize(iv);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);

            // Java AES-GCM appends the auth tag to the ciphertext
            byte[] ciphertext = Arrays.copyOfRange(ciphertextWithTag, 0, ciphertextWithTag.length - TAG_LENGTH_BYTES);
            byte[] authTag = Arrays.copyOfRange(
                    ciphertextWithTag, ciphertextWithTag.length - TAG_LENGTH_BYTES, ciphertextWithTag.length);

            return new EncryptionResult(ciphertext, authTag);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypt data using AES-256-GCM.
     *
     * @throws RuntimeException if decryption or authentication fails
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] authTag) {
        validateKeySize(key);
        validateIvSize(iv);
        validateAuthTagSize(authTag);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            // Java AES-GCM expects ciphertext + authTag concatenated
            byte[] ciphertextWithTag = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
            System.arraycopy(authTag, 0, ciphertextWithTag, ciphertext.length, authTag.length);

            return cipher.doFinal(ciphertextWithTag);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }

    private static void validateKeySize(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes (256 bits)");
        }
    }

    private static void validateIvSize(byte[] iv) {
        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("IV must be 12 bytes (96 bits)");
        }
    }

    private static void validateAuthTagSize(byte[] authTag) {
        if (authTag == null || authTag.length != TAG_LENGTH_BYTES) {
            throw new IllegalArgumentException("Auth tag must be 16 bytes (128 bits)");
        }
    }

    /** Result of AES-GCM encryption. */
    public static final class EncryptionResult {
        private final byte[] ciphertext;
        private final byte[] authTag;

        public EncryptionResult(byte[] ciphertext, byte[] authTag) {
            this.ciphertext = ciphertext;
            this.authTag = authTag;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getAuthTag() {
            return authTag;
        }
    }
}
