package com.capsara.sdk.internal.decryptor;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.CompressionProvider;
import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.HashProvider;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.PrivateKeyRing;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.DecryptedCapsa;
import com.capsara.sdk.models.KeychainEntry;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Capsa decryption utilities for client-side decryption of API responses. */
public final class CapsaDecryptor {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private CapsaDecryptor() {
    }

    /**
     * Verify and decrypt a capsa with a single private key.
     *
     * @param capsa         encrypted capsa from API
     * @param privateKeyPem party's RSA private key in PEM format
     * @param partyId       party ID (optional - auto-detected from keychain if null)
     * @return decrypted capsa data
     */
    public static DecryptedCapsa decrypt(Capsa capsa, String privateKeyPem, String partyId) {
        if (privateKeyPem == null || privateKeyPem.isEmpty()) {
            verifyCreatorSignature(capsa);
            throw CapsaraException.invalidPrivateKey("current", capsa.getId());
        }
        return decrypt(capsa, new PrivateKeyRing(privateKeyPem, null), partyId);
    }

    /**
     * Verify the creator's signature and decrypt a capsa.
     *
     * @param capsa   encrypted capsa from API
     * @param keys    current and previous private keys
     * @param partyId party ID (optional - auto-detected from keychain if null)
     * @return decrypted capsa data
     */
    public static DecryptedCapsa decrypt(Capsa capsa, PrivateKeyRing keys, String partyId) {
        verifyCreatorSignature(capsa);

        KeychainEntry keychainEntry = findKeychainEntry(capsa, partyId);

        if (keychainEntry.getEncryptedKey() == null || keychainEntry.getEncryptedKey().isEmpty()) {
            throw CapsaraCapsaException.noEncryptedKey(capsa.getId(), keychainEntry.getParty());
        }

        int encryptedKeyLength = encryptedKeyLength(keychainEntry.getEncryptedKey());
        if (encryptedKeyLength != 512) {
            throw CapsaraCapsaException.invalidEncryptedKey(capsa.getId(), encryptedKeyLength);
        }

        String privateKeyPem = keys.selectFor(capsa.getId(), keychainEntry.getFingerprint());
        byte[] masterKey;
        try {
            masterKey = RsaProvider.decryptMasterKey(keychainEntry.getEncryptedKey(), privateKeyPem);
        } catch (RuntimeException e) {
            throw CapsaraCapsaException.keyDecryptionFailed(capsa.getId(), e);
        }

        if (masterKey.length != 32) {
            int length = masterKey.length;
            SecureMemory.clear(masterKey);
            throw CapsaraCapsaException.keyDecryptionFailed(capsa.getId(),
                    new IllegalStateException("expected a 32-byte master key, got " + length + " bytes"));
        }

        try {
            return decryptContent(capsa, masterKey);
        } catch (RuntimeException e) {
            SecureMemory.clear(masterKey);
            throw CapsaraCapsaException.contentDecryptionFailed(capsa.getId(), e);
        }
    }

    private static int encryptedKeyLength(String encryptedKey) {
        try {
            return Base64Url.decode(encryptedKey).length;
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static DecryptedCapsa decryptContent(Capsa capsa, byte[] masterKey) {
        String subject = null;
        String body = null;
        Object structured = null;

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
                structured = OBJECT_MAPPER.readValue(json, Object.class);
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException("Decrypted structured data is not valid JSON", e);
            }
        }

        DecryptedCapsa decryptedCapsa = new DecryptedCapsa();
        decryptedCapsa.setId(capsa.getId());
        decryptedCapsa.setCreator(capsa.getCreator());
        decryptedCapsa.setCreatedAt(capsa.getCreatedAt());
        decryptedCapsa.setUpdatedAt(capsa.getUpdatedAt());
        decryptedCapsa.setStatus(capsa.getStatus());
        decryptedCapsa.setSubject(subject);
        decryptedCapsa.setBody(body);
        decryptedCapsa.setStructured(structured);
        decryptedCapsa.setFiles(capsa.getFiles());
        decryptedCapsa.setAccessControl(capsa.getAccessControl());
        decryptedCapsa.setKeychain(capsa.getKeychain());
        decryptedCapsa.setSignature(capsa.getSignature());
        decryptedCapsa.setMetadata(capsa.getMetadata());
        decryptedCapsa.setTotalSize(capsa.getTotalSize() != null ? capsa.getTotalSize() : 0L);
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
        KeychainEntry[] keys = capsa.getKeychain() == null || capsa.getKeychain().getKeys() == null
                ? new KeychainEntry[0]
                : capsa.getKeychain().getKeys();

        if (keys.length == 0) {
            throw CapsaraCapsaException.notInKeychain(capsa.getId(), hasValue(partyId) ? partyId : null);
        }

        if (hasValue(partyId)) {
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

            throw CapsaraCapsaException.notInKeychain(capsa.getId(), partyId);
        }

        if (keys.length != 1) {
            throw CapsaraCapsaException.callerEntryAmbiguous(capsa.getId(), keys.length);
        }

        return keys[0];
    }

    /** Verify the creator's signature against the public key stored on the capsa. */
    private static void verifyCreatorSignature(Capsa capsa) {
        String creatorPublicKeyPem = capsa.getCreatorPublicKey();
        if (creatorPublicKeyPem == null || creatorPublicKeyPem.isEmpty()) {
            throw CapsaraCapsaException.signatureKeyMissing(capsa.getId());
        }

        KeychainEntry creatorEntry = findCreatorEntry(capsa);
        if (creatorEntry != null && hasValue(creatorEntry.getFingerprint())) {
            String actual;
            try {
                actual = KeyGenerator.calculateFingerprint(creatorPublicKeyPem);
            } catch (RuntimeException e) {
                throw signatureFailure(capsa, "creator public key cannot be parsed");
            }
            boolean matches = HashProvider.constantTimeEquals(
                    actual.getBytes(StandardCharsets.UTF_8),
                    creatorEntry.getFingerprint().getBytes(StandardCharsets.UTF_8));
            if (!matches) {
                throw CapsaraCapsaException.signatureKeyMismatch(capsa.getId(), creatorEntry.getFingerprint(),
                        actual);
            }
        }

        verifySignature(capsa, creatorPublicKeyPem);
    }

    private static CapsaraCapsaException signatureFailure(Capsa capsa, String reason) {
        return CapsaraCapsaException.signatureVerificationFailed(capsa.getId(), capsa.getCreator(), reason);
    }

    private static KeychainEntry findCreatorEntry(Capsa capsa) {
        if (capsa.getKeychain() == null || capsa.getKeychain().getKeys() == null || capsa.getCreator() == null) {
            return null;
        }
        for (KeychainEntry key : capsa.getKeychain().getKeys()) {
            if (capsa.getCreator().equals(key.getParty())) {
                return key;
            }
        }
        return null;
    }

    private static void verifySignature(Capsa capsa, String creatorPublicKeyPem) {
        if (capsa.getSignature() == null
                || capsa.getSignature().getSignature() == null
                || capsa.getSignature().getSignature().isEmpty()) {
            throw signatureFailure(capsa, "signature is missing");
        }

        byte[] signatureBytes;
        try {
            signatureBytes = Base64Url.decode(capsa.getSignature().getSignature());
        } catch (RuntimeException e) {
            throw signatureFailure(capsa, "signature is not valid base64url");
        }
        if (signatureBytes.length != 512) {
            throw signatureFailure(capsa, "expected a 512-byte signature, got " + signatureBytes.length + " bytes");
        }

        boolean isValid;
        try {
            FileHashData[] fileHashData = capsa.getFiles() == null ? null : Arrays.stream(capsa.getFiles())
                    .map(f -> new FileHashData(
                            f.getFileId(), f.getHash(), f.getSize(), f.getIv(), f.getFilenameIV()))
                    .toArray(FileHashData[]::new);

            String canonicalString = SignatureProvider.buildCanonicalString(
                    capsa.getId(),
                    capsa.getTotalSize(),
                    capsa.getKeychain() == null ? null : capsa.getKeychain().getAlgorithm(),
                    capsa.getCreator(),
                    KeyGenerator.calculateFingerprint(creatorPublicKeyPem),
                    fileHashData,
                    capsa.getStructuredIV(),
                    capsa.getSubjectIV(),
                    capsa.getBodyIV());

            isValid = SignatureProvider.verifyCapsaSignature(
                    capsa.getSignature(),
                    canonicalString,
                    creatorPublicKeyPem);
        } catch (RuntimeException e) {
            throw signatureFailure(capsa, e.getMessage() != null ? e.getMessage() : e.toString());
        }

        if (!isValid) {
            throw signatureFailure(capsa, "capsa data does not match the signature");
        }
    }

    private static boolean hasValue(String value) {
        return value != null && !value.isEmpty();
    }
}
