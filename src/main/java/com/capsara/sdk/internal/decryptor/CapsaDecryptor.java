package com.capsara.sdk.internal.decryptor;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.CompressionProvider;
import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaStatus;
import com.capsara.sdk.models.KeychainEntry;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/** Capsa decryption utilities for client-side decryption of API responses. */
public final class CapsaDecryptor {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private CapsaDecryptor() {
    }

    /**
     * Decrypt capsa using party's private key.
     *
     * @param capsa              encrypted capsa from API
     * @param privateKeyPem      party's RSA private key in PEM format
     * @param partyId            party ID (optional - auto-detected from keychain if null)
     * @param creatorPublicKeyPem creator's RSA public key for signature verification
     * @param verifySignature    whether to verify signature (default: true)
     * @return decrypted capsa data
     */
    public static DecryptedCapsa decrypt(
            Capsa capsa,
            String privateKeyPem,
            String partyId,
            String creatorPublicKeyPem,
            boolean verifySignature) {

        if (verifySignature) {
            if (creatorPublicKeyPem == null || creatorPublicKeyPem.isEmpty()) {
                throw new IllegalStateException(
                        "creatorPublicKeyPem is required for signature verification. "
                                + "Pass verifySignature=false to skip (not recommended).");
            }

            verifySignature(capsa, creatorPublicKeyPem);
        }

        KeychainEntry keychainEntry = findKeychainEntry(capsa, partyId);

        if (keychainEntry.getEncryptedKey() == null || keychainEntry.getEncryptedKey().isEmpty()) {
            throw CapsaraCapsaException.notInKeychain(
                    partyId != null ? partyId : keychainEntry.getParty());
        }

        byte[] masterKey = RsaProvider.decryptMasterKey(keychainEntry.getEncryptedKey(), privateKeyPem);

        // AES-256 requires exactly 32 bytes
        if (masterKey.length != 32) {
            SecureMemory.clear(masterKey);
            throw new IllegalStateException(
                    String.format("Master key size validation failed: expected 32 bytes (AES-256), got %d bytes.",
                            masterKey.length));
        }

        String subject = null;
        String body = null;
        Map<String, Object> structured = null;

        if (hasValue(capsa.getEncryptedSubject())
                && hasValue(capsa.getSubjectIV())
                && hasValue(capsa.getSubjectAuthTag())) {
            byte[] subjectBytes = AesGcmProvider.decrypt(
                    Base64Url.decode(capsa.getEncryptedSubject()),
                    masterKey,
                    Base64Url.decode(capsa.getSubjectIV()),
                    Base64Url.decode(capsa.getSubjectAuthTag()));
            subject = new String(subjectBytes, StandardCharsets.UTF_8);
        }

        if (hasValue(capsa.getEncryptedBody())
                && hasValue(capsa.getBodyIV())
                && hasValue(capsa.getBodyAuthTag())) {
            byte[] bodyBytes = AesGcmProvider.decrypt(
                    Base64Url.decode(capsa.getEncryptedBody()),
                    masterKey,
                    Base64Url.decode(capsa.getBodyIV()),
                    Base64Url.decode(capsa.getBodyAuthTag()));
            body = new String(bodyBytes, StandardCharsets.UTF_8);
        }

        if (hasValue(capsa.getEncryptedStructured())
                && hasValue(capsa.getStructuredIV())
                && hasValue(capsa.getStructuredAuthTag())) {
            byte[] structuredBytes = AesGcmProvider.decrypt(
                    Base64Url.decode(capsa.getEncryptedStructured()),
                    masterKey,
                    Base64Url.decode(capsa.getStructuredIV()),
                    Base64Url.decode(capsa.getStructuredAuthTag()));
            String json = new String(structuredBytes, StandardCharsets.UTF_8);
            try {
                structured = OBJECT_MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new RuntimeException("Failed to parse decrypted structured data", e);
            }
        }

        DecryptedCapsa decryptedCapsa = new DecryptedCapsa();
        decryptedCapsa.setId(capsa.getId());
        decryptedCapsa.setCreator(capsa.getCreator());
        decryptedCapsa.setCreatedAt(capsa.getCreatedAt());
        decryptedCapsa.setUpdatedAt(capsa.getUpdatedAt());
        decryptedCapsa.setStatus(CapsaStatus.fromString(capsa.getStatus()));
        decryptedCapsa.setSubject(subject);
        decryptedCapsa.setBody(body);
        decryptedCapsa.setStructured(structured);
        decryptedCapsa.setFiles(capsa.getFiles());
        decryptedCapsa.setAccessControl(capsa.getAccessControl());
        decryptedCapsa.setKeychain(capsa.getKeychain());
        decryptedCapsa.setSignature(capsa.getSignature());
        decryptedCapsa.setMetadata(capsa.getMetadata());
        decryptedCapsa.setTotalSize(capsa.getTotalSize());
        decryptedCapsa.setEncryptedCapsa(capsa);
        decryptedCapsa.setMasterKey(masterKey);

        return decryptedCapsa;
    }

    /**
     * Decrypt a file from a capsa.
     *
     * @param encryptedData encrypted file data
     * @param masterKey     decrypted master key
     * @param iv            initialization vector (base64url)
     * @param authTag       authentication tag (base64url)
     * @param compressed    whether file was compressed before encryption
     * @return decrypted file data
     */
    public static byte[] decryptFile(
            byte[] encryptedData,
            byte[] masterKey,
            String iv,
            String authTag,
            boolean compressed) {

        if (authTag == null || authTag.isEmpty()) {
            throw new IllegalStateException(
                    "SECURITY ERROR: authTag is required for file decryption. "
                            + "Missing authTag indicates potential tampering.");
        }

        byte[] decrypted = AesGcmProvider.decrypt(
                encryptedData,
                masterKey,
                Base64Url.decode(iv),
                Base64Url.decode(authTag));

        if (compressed) {
            return CompressionProvider.decompress(decrypted);
        }

        return decrypted;
    }

    /**
     * Decrypt filename from capsa.
     *
     * @param encryptedFilename encrypted filename (base64url)
     * @param masterKey         decrypted master key
     * @param iv                initialization vector (base64url)
     * @param authTag           authentication tag (base64url)
     * @return decrypted filename
     */
    public static String decryptFilename(
            String encryptedFilename,
            byte[] masterKey,
            String iv,
            String authTag) {

        if (authTag == null || authTag.isEmpty()) {
            throw new IllegalStateException(
                    "SECURITY ERROR: authTag is required for filename decryption. "
                            + "Missing authTag indicates potential tampering.");
        }

        byte[] decrypted = AesGcmProvider.decrypt(
                Base64Url.decode(encryptedFilename),
                masterKey,
                Base64Url.decode(iv),
                Base64Url.decode(authTag));

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static KeychainEntry findKeychainEntry(Capsa capsa, String partyId) {
        KeychainEntry[] keys = capsa.getKeychain().getKeys();

        if (partyId != null) {
            for (KeychainEntry key : keys) {
                if (partyId.equals(key.getParty())) {
                    return key;
                }
            }

            for (KeychainEntry key : keys) {
                if (key.getActingFor() != null) {
                    for (String actingFor : key.getActingFor()) {
                        if (partyId.equals(actingFor)) {
                            return key;
                        }
                    }
                }
            }

            throw CapsaraCapsaException.notInKeychain(partyId);
        }

        // No partyId - use first keychain entry with an encrypted key
        if (keys.length == 0) {
            throw new IllegalStateException("No keychain entries found in capsa. Cannot decrypt.");
        }

        for (KeychainEntry key : keys) {
            if (hasValue(key.getEncryptedKey())) {
                return key;
            }
        }

        return keys[0];
    }

    private static void verifySignature(Capsa capsa, String creatorPublicKeyPem) {
        if (capsa.getSignature() == null
                || capsa.getSignature().getSignature() == null
                || capsa.getSignature().getSignature().isEmpty()) {
            throw CapsaraCapsaException.signatureVerificationFailed();
        }

        // Validate signature length (RSA-4096-SHA256 = 512 bytes)
        byte[] signatureBytes = Base64Url.decode(capsa.getSignature().getSignature());
        if (signatureBytes.length != 512) {
            throw CapsaraCapsaException.signatureVerificationFailed();
        }

        FileHashData[] fileHashData = Arrays.stream(capsa.getFiles())
                .map(f -> new FileHashData(
                        f.getFileId(), f.getHash(), f.getSize(), f.getIv(), f.getFilenameIV()))
                .toArray(FileHashData[]::new);

        String canonicalString = SignatureProvider.buildCanonicalString(
                capsa.getId(),
                capsa.getTotalSize(),
                capsa.getKeychain().getAlgorithm(),
                fileHashData,
                capsa.getStructuredIV(),
                capsa.getSubjectIV(),
                capsa.getBodyIV());

        boolean isValid = SignatureProvider.verifyCapsaSignature(
                capsa.getSignature(),
                canonicalString,
                creatorPublicKeyPem);

        if (!isValid) {
            throw CapsaraCapsaException.signatureVerificationFailed();
        }
    }

    private static boolean hasValue(String value) {
        return value != null && !value.isEmpty();
    }
}
