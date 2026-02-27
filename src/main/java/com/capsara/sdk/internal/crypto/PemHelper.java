package com.capsara.sdk.internal.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * PEM encoding/decoding utilities for RSA keys.
 */
public final class PemHelper {

    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";

    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final int PEM_LINE_LENGTH = 64;

    private PemHelper() {
        // Utility class
    }

    /**
     * Import a public key from PEM format.
     *
     * @param pem PEM-encoded public key (SPKI format)
     * @return RSA public key
     */
    public static RSAPublicKey importPublicKey(String pem) {
        if (pem == null || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty");
        }

        String base64 = extractBase64(pem, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER);
        byte[] derBytes = Base64.getDecoder().decode(base64);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derBytes);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to import public key", e);
        }
    }

    /**
     * Import a private key from PEM format.
     *
     * @param pem PEM-encoded private key (PKCS#8 format)
     * @return RSA private key
     */
    public static RSAPrivateKey importPrivateKey(String pem) {
        if (pem == null || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty");
        }

        String base64 = extractBase64(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        byte[] derBytes = Base64.getDecoder().decode(base64);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to import private key", e);
        }
    }

    /**
     * Export a public key to PEM format (SPKI / X.509 SubjectPublicKeyInfo).
     *
     * @param publicKey RSA public key
     * @return PEM-encoded public key
     */
    public static String exportPublicKeyPem(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        byte[] encoded = publicKey.getEncoded();
        return formatPem(encoded, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER);
    }

    /**
     * Export a private key to PEM format (PKCS#8).
     *
     * @param privateKey RSA private key
     * @return PEM-encoded private key
     */
    public static String exportPrivateKeyPem(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        byte[] encoded = privateKey.getEncoded();
        return formatPem(encoded, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
    }

    /**
     * Get the DER-encoded SubjectPublicKeyInfo bytes for fingerprint calculation.
     *
     * @param publicKey RSA public key
     * @return DER-encoded bytes
     */
    public static byte[] exportSubjectPublicKeyInfo(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        return publicKey.getEncoded();
    }

    private static String extractBase64(String pem, String header, String footer) {
        String trimmed = pem.trim();

        if (!trimmed.startsWith(header)) {
            throw new IllegalArgumentException("Invalid PEM format: missing header '" + header + "'");
        }
        if (!trimmed.endsWith(footer)) {
            throw new IllegalArgumentException("Invalid PEM format: missing footer '" + footer + "'");
        }

        String content = trimmed
                .substring(header.length(), trimmed.length() - footer.length());

        return WHITESPACE.matcher(content).replaceAll("");
    }

    private static String formatPem(byte[] der, String header, String footer) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append(header).append("\n");

        for (int i = 0; i < base64.length(); i += PEM_LINE_LENGTH) {
            int end = Math.min(i + PEM_LINE_LENGTH, base64.length());
            sb.append(base64, i, end).append("\n");
        }

        sb.append(footer);
        return sb.toString();
    }
}
