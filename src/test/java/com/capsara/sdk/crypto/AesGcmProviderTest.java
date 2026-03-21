package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmProviderTest {

    @Test
    void encrypt_shouldProduceCiphertextAndAuthTag() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult result = AesGcmProvider.encrypt(plaintext, key, iv);

        assertThat(result.getCiphertext()).isNotEmpty();
        assertThat(result.getAuthTag()).hasSize(16);
        assertThat(result.getCiphertext()).isNotEqualTo(plaintext);
    }

    @Test
    void decrypt_shouldRecoverOriginalPlaintext() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] decrypted = AesGcmProvider.decrypt(
                encrypted.getCiphertext(),
                key,
                iv,
                encrypted.getAuthTag()
        );

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void decrypt_shouldFailWithWrongKey() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] wrongKey = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), wrongKey, iv, encrypted.getAuthTag())
        ).isInstanceOf(RuntimeException.class);
    }

    @Test
    void decrypt_shouldFailWithWrongIv() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();
        byte[] wrongIv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), key, wrongIv, encrypted.getAuthTag())
        ).isInstanceOf(RuntimeException.class);
    }

    @Test
    void decrypt_shouldFailWithTamperedAuthTag() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] tamperedTag = encrypted.getAuthTag().clone();
        tamperedTag[0] ^= 0xFF;

        assertThatThrownBy(() ->
                AesGcmProvider.decrypt(encrypted.getCiphertext(), key, iv, tamperedTag)
        ).isInstanceOf(RuntimeException.class);
    }

    @Test
    void encrypt_shouldRejectInvalidKeySize() {
        byte[] plaintext = "test".getBytes();
        byte[] invalidKey = new byte[16]; // 128-bit instead of 256-bit
        byte[] iv = SecureMemory.generateIv();

        assertThatThrownBy(() ->
                AesGcmProvider.encrypt(plaintext, invalidKey, iv)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encrypt_shouldRejectInvalidIvSize() {
        byte[] plaintext = "test".getBytes();
        byte[] key = SecureMemory.generateMasterKey();
        byte[] invalidIv = new byte[16]; // Should be 12 bytes

        assertThatThrownBy(() ->
                AesGcmProvider.encrypt(plaintext, key, invalidIv)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encrypt_shouldProduceDifferentCiphertextForSameDataWithDifferentIv() {
        byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv1 = SecureMemory.generateIv();
        byte[] iv2 = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult result1 = AesGcmProvider.encrypt(plaintext, key, iv1);
        AesGcmProvider.EncryptionResult result2 = AesGcmProvider.encrypt(plaintext, key, iv2);

        assertThat(result1.getCiphertext()).isNotEqualTo(result2.getCiphertext());
    }

    @Test
    void encrypt_shouldHandleLargeData() {
        byte[] plaintext = new byte[1024 * 1024]; // 1MB
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) i;
        }
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] decrypted = AesGcmProvider.decrypt(
                encrypted.getCiphertext(),
                key,
                iv,
                encrypted.getAuthTag()
        );

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encrypt_shouldHandleEmptyData() {
        byte[] plaintext = new byte[0];
        byte[] key = SecureMemory.generateMasterKey();
        byte[] iv = SecureMemory.generateIv();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(plaintext, key, iv);
        byte[] decrypted = AesGcmProvider.decrypt(
                encrypted.getCiphertext(),
                key,
                iv,
                encrypted.getAuthTag()
        );

        assertThat(decrypted).isEqualTo(plaintext);
    }
}
