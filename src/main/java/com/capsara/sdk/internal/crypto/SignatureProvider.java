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
     * Build the canonical signed string for a known total size.
     *
     * @param packageId             capsa ID
     * @param totalSize             total encrypted file bytes
     * @param algorithm             keychain algorithm
     * @param creatorPartyId        party that signs the capsa
     * @param creatorKeyFingerprint fingerprint of the signing party's public key
     * @param files                 file hashes and IVs, in capsa order
     * @param structuredIV          structured data IV, may be null
     * @param subjectIV             subject IV, may be null
     * @param bodyIV                body IV, may be null
     * @return the canonical string
     */
    public static String buildCanonicalString(
            String packageId,
            long totalSize,
            String algorithm,
            String creatorPartyId,
            String creatorKeyFingerprint,
            FileHashData[] files,
            String structuredIV,
            String subjectIV,
            String bodyIV) {
        return buildCanonicalString(packageId, Long.valueOf(totalSize), algorithm, creatorPartyId,
                creatorKeyFingerprint, files, structuredIV, subjectIV, bodyIV);
    }

    /**
     * Build the canonical signed string: packageId|version|totalSize|algorithm|creatorPartyId|creatorKeyFingerprint|
     * hashes...|ivs...|filenameIVs...|structured:IV|subject:IV|body:IV.
     *
     * @param packageId             capsa ID
     * @param totalSize             total encrypted file bytes
     * @param algorithm             keychain algorithm
     * @param creatorPartyId        party that signs the capsa
     * @param creatorKeyFingerprint fingerprint of the signing party's public key
     * @param files                 file hashes and IVs, in capsa order
     * @param structuredIV          structured data IV, may be null
     * @param subjectIV             subject IV, may be null
     * @param bodyIV                body IV, may be null
     * @return the canonical string
     * @throws IllegalArgumentException if a required part is missing or empty
     */
    public static String buildCanonicalString(
            String packageId,
            Long totalSize,
            String algorithm,
            String creatorPartyId,
            String creatorKeyFingerprint,
            FileHashData[] files,
            String structuredIV,
            String subjectIV,
            String bodyIV) {

        requireNonEmpty(packageId, "packageId");
        if (totalSize == null || totalSize < 0) {
            throw new IllegalArgumentException(
                    "Invalid canonicalString: totalSize must be a non-negative number");
        }
        requireNonEmpty(algorithm, "algorithm");
        requireNonEmpty(creatorPartyId, "creatorPartyId");
        requireNonEmpty(creatorKeyFingerprint, "creatorKeyFingerprint");
        if (files == null) {
            throw new IllegalArgumentException("Invalid canonicalString: files must be an array");
        }
        for (int i = 0; i < files.length; i++) {
            validateFile(files[i], i);
        }

        List<String> parts = new ArrayList<>();
        parts.add(packageId);
        parts.add(VERSION);
        parts.add(String.valueOf(totalSize));
        parts.add(algorithm);
        parts.add(creatorPartyId);
        parts.add(creatorKeyFingerprint);

        if (files.length > 0) {
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

        if (structuredIV != null && !structuredIV.isEmpty()) {
            parts.add("structured:" + structuredIV);
        }
        if (subjectIV != null && !subjectIV.isEmpty()) {
            parts.add("subject:" + subjectIV);
        }
        if (bodyIV != null && !bodyIV.isEmpty()) {
            parts.add("body:" + bodyIV);
        }

        return String.join("|", parts);
    }

    private static void requireNonEmpty(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(
                    "Invalid canonicalString: " + name + " must be a non-empty string");
        }
    }

    private static void validateFile(FileHashData file, int index) {
        if (file == null) {
            throw new IllegalArgumentException("File at index " + index + " is missing");
        }
        requireFileField(file.getHash(), "hash", index);
        requireFileField(file.getIv(), "iv", index);
        requireFileField(file.getFilenameIV(), "filenameIV", index);
    }

    private static void requireFileField(String value, String name, int index) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("File at index " + index + " missing required field: " + name);
        }
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
        if (capsaSignature == null || capsaSignature.getPayload() == null) {
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
