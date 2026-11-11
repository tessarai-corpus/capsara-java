package com.capsara.sdk.internal.crypto;

import com.capsara.sdk.models.GeneratedKeyPairResult;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.CompletableFuture;

/**
 * RSA key pair generation with fingerprint calculation.
 */
public final class KeyGenerator {

    /** Default key size in bits. */
    public static final int DEFAULT_KEY_SIZE = 4096;

    private KeyGenerator() {
    }

    /**
     * Generate an RSA-4096 key pair with public exponent 65537.
     *
     * @return the key pair and its fingerprint
     */
    public static GeneratedKeyPairResult generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(new RSAKeyGenParameterSpec(DEFAULT_KEY_SIZE, RSAKeyGenParameterSpec.F4));
            KeyPair keyPair = keyGen.generateKeyPair();

            String publicKeyPem = PemHelper.exportPublicKeyPem(keyPair.getPublic());
            String privateKeyPem = PemHelper.exportPrivateKeyPem(keyPair.getPrivate());
            String fingerprint = calculateFingerprint(publicKeyPem);

            return new GeneratedKeyPairResult(publicKeyPem, privateKeyPem, fingerprint, DEFAULT_KEY_SIZE);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("RSA-4096 key generation not available", e);
        }
    }

    /**
     * Generate an RSA-4096 key pair on a separate thread.
     *
     * @return the key pair and its fingerprint
     */
    public static CompletableFuture<GeneratedKeyPairResult> generateKeyPairAsync() {
        return CompletableFuture.supplyAsync(KeyGenerator::generateKeyPair);
    }

    /**
     * Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo of an SPKI PEM key.
     *
     * @param publicKeyPem SPKI PEM public key
     * @return fingerprint
     */
    public static String calculateFingerprint(String publicKeyPem) {
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Public key PEM cannot be null or empty");
        }

        return HashProvider.computeHash(PemHelper.importPublicKey(publicKeyPem).getEncoded());
    }

    /**
     * Fingerprint of the public half of an RSA private key, as {@link #calculateFingerprint(String)} computes it.
     *
     * @param privateKeyPem PKCS#8 PEM private key carrying its public exponent
     * @return fingerprint
     */
    public static String calculateFingerprintFromPrivateKey(String privateKeyPem) {
        Object imported = PemHelper.importPrivateKey(privateKeyPem);
        if (!(imported instanceof RSAPrivateCrtKey)) {
            throw new IllegalArgumentException("Private key does not carry its public exponent");
        }
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) imported;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return HashProvider.computeHash(publicKey.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot derive the public key from the private key", e);
        }
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
