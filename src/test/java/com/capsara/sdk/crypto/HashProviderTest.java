package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.HashProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HashProviderTest {

    @Test
    void computeHash_shouldReturnCorrectSha256() {
        byte[] data = "hello".getBytes();
        String hash = HashProvider.computeHash(data);

        // SHA-256 of "hello" is well-known
        assertThat(hash).isEqualTo("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    @Test
    void computeHash_shouldReturnLowercaseHex() {
        byte[] data = "test".getBytes();
        String hash = HashProvider.computeHash(data);
        assertThat(hash).isEqualTo(hash.toLowerCase());
    }

    @Test
    void computeHash_shouldReturn64Characters() {
        byte[] data = "any data".getBytes();
        String hash = HashProvider.computeHash(data);
        assertThat(hash).hasSize(64);
    }

    @Test
    void computeHash_shouldProduceDifferentHashesForDifferentInputs() {
        String hash1 = HashProvider.computeHash("data1".getBytes());
        String hash2 = HashProvider.computeHash("data2".getBytes());
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void constantTimeEquals_shouldReturnTrueForEqualArrays() {
        byte[] a = {1, 2, 3, 4, 5};
        byte[] b = {1, 2, 3, 4, 5};
        assertThat(HashProvider.constantTimeEquals(a, b)).isTrue();
    }

    @Test
    void constantTimeEquals_shouldReturnFalseForDifferentArrays() {
        byte[] a = {1, 2, 3, 4, 5};
        byte[] b = {1, 2, 3, 4, 6};
        assertThat(HashProvider.constantTimeEquals(a, b)).isFalse();
    }

    @Test
    void constantTimeEquals_shouldReturnFalseForDifferentLengths() {
        byte[] a = {1, 2, 3};
        byte[] b = {1, 2, 3, 4};
        assertThat(HashProvider.constantTimeEquals(a, b)).isFalse();
    }
}
