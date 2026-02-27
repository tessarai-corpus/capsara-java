package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyGeneratorTest {

    @Test
    void generateKeyPair_shouldReturn4096BitKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getKeySize()).isEqualTo(4096);
    }

    @Test
    void generateKeyPair_shouldReturnPemEncodedPublicKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getPublicKey()).startsWith("-----BEGIN PUBLIC KEY-----");
        assertThat(result.getPublicKey()).endsWith("-----END PUBLIC KEY-----");
    }

    @Test
    void generateKeyPair_shouldReturnPemEncodedPrivateKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getPrivateKey()).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(result.getPrivateKey()).endsWith("-----END PRIVATE KEY-----");
    }

    @Test
    void generateKeyPair_shouldReturn64CharFingerprint() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getFingerprint()).hasSize(64);
        assertThat(result.getFingerprint()).matches("[a-f0-9]+");
    }

    @Test
    void generateKeyPair_shouldGenerateDifferentKeysEachTime() {
        GeneratedKeyPairResult result1 = KeyGenerator.generateKeyPair();
        GeneratedKeyPairResult result2 = KeyGenerator.generateKeyPair();

        assertThat(result1.getPublicKey()).isNotEqualTo(result2.getPublicKey());
        assertThat(result1.getFingerprint()).isNotEqualTo(result2.getFingerprint());
    }

    @Test
    void generateKeyPair_withCustomSize_shouldRespectSize() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair(2048);

        assertThat(result.getKeySize()).isEqualTo(2048);
    }

    @Test
    void generateKeyPair_shouldRejectKeySizeUnder2048() {
        assertThatThrownBy(() -> KeyGenerator.generateKeyPair(1024))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("2048");
    }

    @Test
    void generateKeyPairAsync_shouldWorkCorrectly() throws ExecutionException, InterruptedException {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPairAsync().get();

        assertThat(result.getKeySize()).isEqualTo(4096);
        assertThat(result.getPublicKey()).isNotEmpty();
        assertThat(result.getPrivateKey()).isNotEmpty();
        assertThat(result.getFingerprint()).hasSize(64);
    }

    @Test
    void calculateFingerprint_shouldMatchGeneratedFingerprint() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        String recalculatedFingerprint = KeyGenerator.calculateFingerprint(result.getPublicKey());

        assertThat(recalculatedFingerprint).isEqualTo(result.getFingerprint());
    }

    @Test
    void validateKeySize_shouldReturnTrueForSufficientSize() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(KeyGenerator.validateKeySize(result.getPublicKey())).isTrue();
    }

    @Test
    void validateKeySize_shouldReturnFalseForSmallKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair(2048);

        assertThat(KeyGenerator.validateKeySize(result.getPublicKey(), 4096)).isFalse();
    }

    @Test
    void validateKeySize_shouldReturnFalseForNullInput() {
        assertThat(KeyGenerator.validateKeySize(null)).isFalse();
    }

    @Test
    void getKeySize_shouldReturnCorrectSize() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        int keySize = KeyGenerator.getKeySize(result.getPublicKey());

        assertThat(keySize).isEqualTo(4096);
    }

    @Test
    void getKeySize_shouldReturnNegativeOneForInvalidKey() {
        assertThat(KeyGenerator.getKeySize("invalid")).isEqualTo(-1);
        assertThat(KeyGenerator.getKeySize(null)).isEqualTo(-1);
    }
}
