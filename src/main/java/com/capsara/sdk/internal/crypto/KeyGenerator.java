package com.capsara.sdk.internal.crypto;

import com.capsara.sdk.models.GeneratedKeyPairResult;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CompletableFuture;

/**
 * RSA key pair generation with fingerprint calculation.
 */
public final class KeyGenerator {

    /** Default key size in bits. */
    public static final int DEFAULT_KEY_SIZE = 4096;

    private KeyGenerator() {
    }

    /** Generate an RSA-4096 key pair. */
    public static GeneratedKeyPairResult generateKeyPair() {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }

    /**
     * Generate an RSA key pair with specified key size.
     *
     * @param keySize key size in bits (minimum 2048)
     */
    public static GeneratedKeyPairResult generateKeyPair(int keySize) {
        if (keySize < 2048) {
            throw new IllegalArgumentException("Key size must be at least 2048 bits");
        }

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            String publicKeyPem = PemHelper.exportPublicKeyPem(keyPair.getPublic());
            String privateKeyPem = PemHelper.exportPrivateKeyPem(keyPair.getPrivate());
            String fingerprint = calculateFingerprint(keyPair.getPublic());

            return new GeneratedKeyPairResult(publicKeyPem, privateKeyPem, fingerprint, keySize);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available", e);
        }
    }

    /**
     * Generate an RSA-4096 key pair asynchronously.
     * Key generation is CPU-intensive, so this runs on a separate thread.
     */
    public static CompletableFuture<GeneratedKeyPairResult> generateKeyPairAsync() {
        return generateKeyPairAsync(DEFAULT_KEY_SIZE);
    }

    /** Generate an RSA key pair asynchronously with specified key size. */
    public static CompletableFuture<GeneratedKeyPairResult> generateKeyPairAsync(int keySize) {
        return CompletableFuture.supplyAsync(() -> generateKeyPair(keySize));
    }

    /** Calculate SHA-256 fingerprint of a public key. Returns lowercase hex (64 characters). */
    private static String calculateFingerprint(java.security.PublicKey publicKey) {
        byte[] derBytes = PemHelper.exportSubjectPublicKeyInfo(publicKey);
        return HashProvider.computeHash(derBytes);
    }

    /** Calculate fingerprint from a PEM-encoded public key. Returns lowercase hex (64 characters). */
    public static String calculateFingerprint(String publicKeyPem) {
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Public key PEM cannot be null or empty");
        }

        RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
        return calculateFingerprint(publicKey);
    }

    /** Validate that a public key meets minimum size requirements. */
    public static boolean validateKeySize(String publicKeyPem, int minimumKeySize) {
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            return false;
        }

        try {
            RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
            return publicKey.getModulus().bitLength() >= minimumKeySize;
        } catch (Exception e) {
            return false;
        }
    }

    /** Validate that a public key meets the default minimum size (4096 bits). */
    public static boolean validateKeySize(String publicKeyPem) {
        return validateKeySize(publicKeyPem, DEFAULT_KEY_SIZE);
    }

    /** Get the key size of a PEM-encoded public key, or -1 if invalid. */
    public static int getKeySize(String publicKeyPem) {
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            return -1;
        }

        try {
            RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
            return publicKey.getModulus().bitLength();
        } catch (Exception e) {
            return -1;
        }
    }
}
