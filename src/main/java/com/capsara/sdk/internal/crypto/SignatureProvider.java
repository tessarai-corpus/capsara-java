package com.capsara.sdk.internal.crypto;

import com.capsara.sdk.models.CapsaSignature;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * JWS RS256 signature creation and verification.
 */
public final class SignatureProvider {

    private static final String VERSION = "1.0.0";

    private SignatureProvider() {
    }

    /**
     * Build canonical string for signature.
     * Format: packageId|version|totalSize|algorithm|hashes...|ivs...|filenameIVs...|structuredIV|subjectIV|bodyIV
     */
    public static String buildCanonicalString(
            String packageId,
            long totalSize,
            String algorithm,
            FileHashData[] files,
            String structuredIV,
            String subjectIV,
            String bodyIV) {

        List<String> parts = new ArrayList<>();
        parts.add(packageId);
        parts.add(VERSION);
        parts.add(String.valueOf(totalSize));
        parts.add(algorithm);

        // Preserve file order - DO NOT SORT (for deterministic signatures)
        if (files != null && files.length > 0) {
            for (FileHashData file : files) {
                parts.add(file.getHash());
            }
            for (FileHashData file : files) {
                parts.add(file.getIv());
            }
            for (FileHashData file : files) {
                parts.add(file.getFilenameIV());
            }
        }

        // Skip empty/undefined optional IVs
        if (structuredIV != null && !structuredIV.isEmpty()) {
            parts.add(structuredIV);
        }
        if (subjectIV != null && !subjectIV.isEmpty()) {
            parts.add(subjectIV);
        }
        if (bodyIV != null && !bodyIV.isEmpty()) {
            parts.add(bodyIV);
        }

        return String.join("|", parts);
    }

    /** Create JWS RS256 signature. */
    public static CapsaSignature createJws(String canonicalString, String privateKeyPem) {
        if (canonicalString == null || canonicalString.isEmpty()) {
            throw new IllegalArgumentException("Canonical string cannot be null or empty");
        }
        if (privateKeyPem == null || privateKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Private key PEM cannot be null or empty");
        }

        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String protectedHeader = Base64Url.encode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64Url.encode(canonicalString.getBytes(StandardCharsets.UTF_8));
        String signingInput = protectedHeader + "." + payload;
        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.UTF_8);

        RSAPrivateKey privateKey = PemHelper.importPrivateKey(privateKeyPem);
        byte[] signatureBytes = sign(signingInputBytes, privateKey);
        String signature = Base64Url.encode(signatureBytes);

        CapsaSignature result = new CapsaSignature();
        result.setAlgorithm("RS256");
        result.setProtectedHeader(protectedHeader);
        result.setPayload(payload);
        result.setSignature(signature);

        return result;
    }

    /** Verify JWS RS256 signature. */
    public static boolean verifyJws(String protectedHeader, String payload, String signature, String publicKeyPem) {
        if (protectedHeader == null || protectedHeader.isEmpty()) {
            return false;
        }
        if (payload == null || payload.isEmpty()) {
            return false;
        }
        if (signature == null || signature.isEmpty()) {
            return false;
        }
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            return false;
        }

        try {
            String signingInput = protectedHeader + "." + payload;
            byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64Url.decode(signature);

            RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
            return verify(signingInputBytes, signatureBytes, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    /** Verify a capsa signature against the expected canonical string. */
    public static boolean verifyCapsaSignature(
            CapsaSignature capsaSignature,
            String expectedCanonicalString,
            String publicKeyPem) {
        if (capsaSignature == null) {
            return false;
        }
        if (expectedCanonicalString == null || expectedCanonicalString.isEmpty()) {
            return false;
        }

        // Verify the payload matches expected canonical string
        String expectedPayload = Base64Url.encode(expectedCanonicalString.getBytes(StandardCharsets.UTF_8));
        if (!HashProvider.constantTimeEquals(
                expectedPayload.getBytes(StandardCharsets.UTF_8),
                capsaSignature.getPayload().getBytes(StandardCharsets.UTF_8))) {
            return false;
        }

        return verifyJws(
                capsaSignature.getProtectedHeader(),
                capsaSignature.getPayload(),
                capsaSignature.getSignature(),
                publicKeyPem
        );
    }

    private static byte[] sign(byte[] data, RSAPrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signature", e);
        }
    }

    private static boolean verify(byte[] data, byte[] signatureBytes, RSAPublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
