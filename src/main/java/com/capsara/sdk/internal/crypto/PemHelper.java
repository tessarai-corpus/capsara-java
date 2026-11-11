package com.capsara.sdk.internal.crypto;

import java.io.ByteArrayOutputStream;
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
    private static final String RSA_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String RSA_PRIVATE_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";
    private static final byte[] RSA_ALGORITHM_IDENTIFIER = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    };

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
     * @param pem PEM-encoded private key, PKCS#8 ({@code BEGIN PRIVATE KEY}) or PKCS#1 ({@code BEGIN RSA PRIVATE KEY})
     * @return RSA private key
     */
    public static RSAPrivateKey importPrivateKey(String pem) {
        if (pem == null || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty");
        }

        byte[] derBytes;
        if (pem.trim().startsWith(RSA_PRIVATE_KEY_HEADER)) {
            String base64 = extractBase64(pem, RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_FOOTER);
            derBytes = wrapPkcs1(Base64.getDecoder().decode(base64));
        } else {
            String base64 = extractBase64(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
            derBytes = Base64.getDecoder().decode(base64);
        }

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

    private static byte[] wrapPkcs1(byte[] pkcs1) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x02);
        body.write(0x01);
        body.write(0x00);
        body.writeBytes(RSA_ALGORITHM_IDENTIFIER);
        body.write(0x04);
        writeLength(body, pkcs1.length);
        body.writeBytes(pkcs1);
        byte[] content = body.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        int bytes = 0;
        for (int value = length; value > 0; value >>= 8) {
            bytes++;
        }
        out.write(0x80 | bytes);
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
            out.write((length >> shift) & 0xff);
        }
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
