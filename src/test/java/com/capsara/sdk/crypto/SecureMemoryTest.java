package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.SecureMemory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecureMemoryTest {

    @Test
    void clearByteArray_shouldZeroAllBytes() {
        byte[] buffer = {1, 2, 3, 4, 5};
        SecureMemory.clear(buffer);
        assertThat(buffer).containsOnly((byte) 0);
    }

    @Test
    void clearByteArray_shouldHandleNullSafely() {
        SecureMemory.clear((byte[]) null);
        // Should not throw
    }

    @Test
    void clearCharArray_shouldZeroAllChars() {
        char[] buffer = {'a', 'b', 'c'};
        SecureMemory.clear(buffer);
        assertThat(buffer).containsOnly('\0');
    }

    @Test
    void clearCharArray_shouldHandleNullSafely() {
        SecureMemory.clear((char[]) null);
        // Should not throw
    }

    @Test
    void generateRandomBytes_shouldReturnCorrectLength() {
        byte[] bytes = SecureMemory.generateRandomBytes(32);
        assertThat(bytes).hasSize(32);
    }

    @Test
    void generateRandomBytes_shouldReturnDifferentValuesEachTime() {
        byte[] bytes1 = SecureMemory.generateRandomBytes(32);
        byte[] bytes2 = SecureMemory.generateRandomBytes(32);
        assertThat(bytes1).isNotEqualTo(bytes2);
    }

    @Test
    void generateMasterKey_shouldReturn32Bytes() {
        byte[] key = SecureMemory.generateMasterKey();
        assertThat(key).hasSize(32);
    }

    @Test
    void generateIv_shouldReturn12Bytes() {
        byte[] iv = SecureMemory.generateIv();
        assertThat(iv).hasSize(12);
    }
}
