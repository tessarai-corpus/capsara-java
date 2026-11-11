package com.capsara.sdk.golden;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for cryptographic primitives: AES-GCM, RSA, KeyGen,
 * signatures, IV uniqueness, and hashing.
 */
class CryptoGoldenTest {

    private static GeneratedKeyPairResult keyPair1;
    private static GeneratedKeyPairResult keyPair2;

    @BeforeAll
    static void setUp() {
        keyPair1 = SharedKeyFixture.getPrimaryKeyPair();
        keyPair2 = SharedKeyFixture.getSecondaryKeyPair();
    }

    // AES-GCM Roundtrip Tests

    @Test
    void aesGcm_encryptDecrypt_roundtrip() {
        byte[] plaintext = "Hello, cryptographic world!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] decrypted = AesGcmProvider.decrypt(encrypted.getCiphertext(), key, iv, encrypted.getAuthTag());

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void aesGcm_wrongKey_throwsException() {
        byte[] plaintext = "Secret data".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] wrongKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), wrongKey, iv, encrypted.getAuthTag()))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void aesGcm_wrongIv_throwsException() {
        byte[] plaintext = "test".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        byte[] wrongIv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), key, wrongIv, encrypted.getAuthTag()))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void aesGcm_authTagIsAlwaysSixteenBytes() {
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult result = AesGcmProvider.encrypt(
                "test".getBytes(StandardCharsets.UTF_8), key, iv);

        assertThat(result.getAuthTag()).hasSize(16);
    }

    @Test
    void aesGcm_tamperedAuthTag_throwsException() {
        byte[] plaintext = "data".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] tamperedTag = encrypted.getAuthTag().clone();
        tamperedTag[0] ^= 0xFF;

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), key, iv, tamperedTag))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void aesGcm_tamperedCiphertext_throwsException() {
        byte[] plaintext = "data".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] tamperedCiphertext = encrypted.getCiphertext().clone();
        tamperedCiphertext[0] ^= 0xFF;

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(tamperedCiphertext, key, iv, encrypted.getAuthTag()))
                .isInstanceOf(RuntimeException.class);
    }

    // RSA Roundtrip Tests

    @Test
    void rsa_encryptDecryptMasterKey_roundtrip() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair1.getPublicKey());
        byte[] decrypted = RsaProvider.decryptMasterKey(encrypted, keyPair1.getPrivateKey());

        assertThat(decrypted).isEqualTo(masterKey);
    }

    @Test
    void rsa_wrongPrivateKey_throwsException() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair1.getPublicKey());

        assertThatThrownBy(() ->
                RsaProvider.decryptMasterKey(encrypted, keyPair2.getPrivateKey()))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void rsa_encryptedOutputIsFiveHundredTwelveBytes() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair1.getPublicKey());
        byte[] encryptedBytes = Base64Url.decode(encrypted);

        assertThat(encryptedBytes).hasSize(512); // RSA-4096 = 512 bytes
    }

    @Test
    void rsa_rejectsMasterKeyNotThirtyTwoBytes() {
        byte[] badKey = new byte[16];

        assertThatThrownBy(() ->
                RsaProvider.encryptMasterKey(badKey, keyPair1.getPublicKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    // KeyGenerator Tests

    @Test
    void keyGenerator_producesRsa4096Keys() {
        assertThat(keyPair1.getKeySize()).isEqualTo(4096);
        assertThat(KeyGenerator.validateKeySize(keyPair1.getPublicKey())).isTrue();
    }

    @Test
    void keyGenerator_fingerprintIsSixtyFourHexChars() {
        assertThat(keyPair1.getFingerprint()).hasSize(64);
        assertThat(keyPair1.getFingerprint()).matches("[0-9a-f]{64}");
    }

    @Test
    void keyGenerator_differentKeyPairsHaveDifferentFingerprints() {
        assertThat(keyPair1.getFingerprint()).isNotEqualTo(keyPair2.getFingerprint());
    }

    // Signature Tests

    @Test
    void signature_createAndVerify_roundtrip() {
        String canonical = "capsa_abc|1.0.0|1024|AES-256-GCM|hash1|iv1|fnIv1";

        CapsaSignature sig = SignatureProvider.createJws(canonical, keyPair1.getPrivateKey());

        boolean valid = SignatureProvider.verifyJws(
                sig.getProtectedHeader(), sig.getPayload(),
                sig.getSignature(), keyPair1.getPublicKey());

        assertThat(valid).isTrue();
    }

    @Test
    void signature_tamperedPayload_failsVerification() {
        String canonical = "capsa_abc|1.0.0|1024|AES-256-GCM|hash1";
        CapsaSignature sig = SignatureProvider.createJws(canonical, keyPair1.getPrivateKey());

        // Tamper with payload
        String tampered = Base64Url.encode("tampered_data".getBytes(StandardCharsets.UTF_8));

        boolean valid = SignatureProvider.verifyJws(
                sig.getProtectedHeader(), tampered,
                sig.getSignature(), keyPair1.getPublicKey());

        assertThat(valid).isFalse();
    }

    @Test
    void signature_wrongVerificationKey_failsVerification() {
        String canonical = "capsa_abc|1.0.0|1024|AES-256-GCM";
        CapsaSignature sig = SignatureProvider.createJws(canonical, keyPair1.getPrivateKey());

        boolean valid = SignatureProvider.verifyJws(
                sig.getProtectedHeader(), sig.getPayload(),
                sig.getSignature(), keyPair2.getPublicKey());

        assertThat(valid).isFalse();
    }

    // IV Uniqueness Tests

    @Test
    void secureMemory_generateIv_producesUniqueValues() {
        Set<String> ivs = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] iv = SecureMemory.generateIv();
            ivs.add(Base64Url.encode(iv));
        }

        assertThat(ivs).hasSize(100);
    }

    // Hash SHA-256 Tests

    @Test
    void hashProvider_computeHash_producesSha256Hex() {
        byte[] data = "Hello, World!".getBytes(StandardCharsets.UTF_8);

        String hash = HashProvider.computeHash(data);

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]{64}");
    }

    @Test
    void hashProvider_computeHash_deterministicForSameInput() {
        byte[] data = "Deterministic test".getBytes(StandardCharsets.UTF_8);

        String hash1 = HashProvider.computeHash(data);
        String hash2 = HashProvider.computeHash(data);

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void hashProvider_computeHash_differesForDifferentInput() {
        String hash1 = HashProvider.computeHash("input1".getBytes(StandardCharsets.UTF_8));
        String hash2 = HashProvider.computeHash("input2".getBytes(StandardCharsets.UTF_8));

        assertThat(hash1).isNotEqualTo(hash2);
    }
}
