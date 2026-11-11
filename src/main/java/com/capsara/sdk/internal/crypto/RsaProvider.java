package com.capsara.sdk.internal.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;

/**
 * RSA-OAEP-SHA256 encryption/decryption provider.
 * Requires RSA-4096 keys per cryptographic specification.
 */
public final class RsaProvider {

    private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /** Minimum required RSA key size in bits (4096). */
    private static final int MIN_KEY_SIZE_BITS = 4096;

    // OAEP parameters: SHA-256 for hashing, MGF1 with SHA-256
    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
    );

    private RsaProvider() {
    }

    /** @throws IllegalArgumentException if key is smaller than 4096 bits */
    private static void validateKeySize(int keySizeBits, String keyType) {
        if (keySizeBits < MIN_KEY_SIZE_BITS) {
            throw new IllegalArgumentException(
                    String.format("%s key size %d bits is below minimum required %d bits. Use RSA-4096.",
                            keyType, keySizeBits, MIN_KEY_SIZE_BITS));
        }
    }

    /** Encrypt a master key with an RSA public key using OAEP-SHA256. */
    public static String encryptMasterKey(byte[] masterKey, String publicKeyPem) {
        if (masterKey == null || masterKey.length != 32) {
            throw new IllegalArgumentException("Master key must be 32 bytes");
        }
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Public key PEM cannot be null or empty");
        }

        try {
            RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
            return encryptMasterKey(masterKey, publicKey);
        } catch (RuntimeException e) {
            throw new RuntimeException("Failed to encrypt master key", e);
        }
    }

    /**
     * Encrypt a master key with an RSA public key using OAEP-SHA256.
     *
     * @throws IllegalArgumentException if key is smaller than 4096 bits
     */
    public static String encryptMasterKey(byte[] masterKey, RSAPublicKey publicKey) {
        if (masterKey == null || masterKey.length != 32) {
            throw new IllegalArgumentException("Master key must be 32 bytes");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        validateKeySize(publicKey.getModulus().bitLength(), "Public");

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_PARAMS);
            byte[] encrypted = cipher.doFinal(masterKey);
            return Base64Url.encode(encrypted);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("RSA encryption failed", e);
        }
    }

    /** Decrypt a master key with an RSA private key using OAEP-SHA256. */
    public static byte[] decryptMasterKey(String encryptedKey, String privateKeyPem) {
        if (encryptedKey == null || encryptedKey.isEmpty()) {
            throw new IllegalArgumentException("Encrypted key cannot be null or empty");
        }
        if (privateKeyPem == null || privateKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Private key PEM cannot be null or empty");
        }

        try {
            RSAPrivateKey privateKey = PemHelper.importPrivateKey(privateKeyPem);
            return decryptMasterKey(encryptedKey, privateKey);
        } catch (RuntimeException e) {
            throw new RuntimeException("Failed to decrypt master key", e);
        }
    }

    /**
     * Decrypt a master key with an RSA private key using OAEP-SHA256.
     *
     * @throws IllegalArgumentException if key is smaller than 4096 bits
     */
    public static byte[] decryptMasterKey(String encryptedKey, RSAPrivateKey privateKey) {
        if (encryptedKey == null || encryptedKey.isEmpty()) {
            throw new IllegalArgumentException("Encrypted key cannot be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        validateKeySize(privateKey.getModulus().bitLength(), "Private");

        try {
            byte[] encrypted = Base64Url.decode(encryptedKey);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_PARAMS);
            return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("RSA decryption failed", e);
        }
    }

    /**
     * Encrypt arbitrary data with an RSA public key using OAEP-SHA256.
     * Data must be smaller than key size minus OAEP overhead.
     *
     * @throws IllegalArgumentException if key is smaller than 4096 bits
     */
    public static byte[] encrypt(byte[] data, String publicKeyPem) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (publicKeyPem == null || publicKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Public key PEM cannot be null or empty");
        }

        try {
            RSAPublicKey publicKey = PemHelper.importPublicKey(publicKeyPem);
            validateKeySize(publicKey.getModulus().bitLength(), "Public");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_PARAMS);
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("RSA encryption failed", e);
        }
    }

    /**
     * Decrypt data with an RSA private key using OAEP-SHA256.
     *
     * @throws IllegalArgumentException if key is smaller than 4096 bits
     */
    public static byte[] decrypt(byte[] encrypted, String privateKeyPem) {
        if (encrypted == null) {
            throw new IllegalArgumentException("Encrypted data cannot be null");
        }
        if (privateKeyPem == null || privateKeyPem.isEmpty()) {
            throw new IllegalArgumentException("Private key PEM cannot be null or empty");
        }

        try {
            RSAPrivateKey privateKey = PemHelper.importPrivateKey(privateKeyPem);
            validateKeySize(privateKey.getModulus().bitLength(), "Private");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_PARAMS);
            return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("RSA decryption failed", e);
        }
    }
}
