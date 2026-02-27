package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.CompressionProvider;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CompressionProviderTest {

    @Test
    void shouldCompress_shouldReturnFalseForSmallData() {
        assertThat(CompressionProvider.shouldCompress(100)).isFalse();
        assertThat(CompressionProvider.shouldCompress(149)).isFalse();
    }

    @Test
    void shouldCompress_shouldReturnTrueForLargeData() {
        assertThat(CompressionProvider.shouldCompress(150)).isTrue();
        assertThat(CompressionProvider.shouldCompress(1000)).isTrue();
    }

    @Test
    void compress_shouldReduceDataSize() {
        // Create compressible data (repeated pattern)
        byte[] data = new byte[1000];
        Arrays.fill(data, (byte) 'a');

        byte[] compressed = CompressionProvider.compress(data);

        assertThat(compressed.length).isLessThan(data.length);
    }

    @Test
    void decompress_shouldRecoverOriginalData() {
        byte[] original = "This is test data that should be compressed and decompressed correctly.".getBytes();

        byte[] compressed = CompressionProvider.compress(original);
        byte[] decompressed = CompressionProvider.decompress(compressed);

        assertThat(decompressed).isEqualTo(original);
    }

    @Test
    void compressIfBeneficial_shouldNotCompressSmallData() {
        byte[] data = new byte[50];
        Arrays.fill(data, (byte) 'a');

        CompressionProvider.CompressionResult result = CompressionProvider.compressIfBeneficial(data);

        assertThat(result.wasCompressed()).isFalse();
        assertThat(result.getData()).isEqualTo(data);
        assertThat(result.getCompressionAlgorithm()).isNull();
    }

    @Test
    void compressIfBeneficial_shouldCompressLargeRepetitiveData() {
        byte[] data = new byte[1000];
        Arrays.fill(data, (byte) 'a');

        CompressionProvider.CompressionResult result = CompressionProvider.compressIfBeneficial(data);

        assertThat(result.wasCompressed()).isTrue();
        assertThat(result.getData().length).isLessThan(data.length);
        assertThat(result.getCompressionAlgorithm()).isEqualTo("gzip");
        assertThat(result.getOriginalSize()).isEqualTo(data.length);
    }

    @Test
    void compressIfBeneficial_shouldNotCompressIncompressibleData() {
        // Create random (incompressible) data
        byte[] data = new byte[200];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (Math.random() * 256);
        }

        CompressionProvider.CompressionResult result = CompressionProvider.compressIfBeneficial(data);

        // If compression doesn't help, original data is returned
        if (result.wasCompressed()) {
            assertThat(result.getData().length).isLessThan(data.length);
        } else {
            assertThat(result.getData()).isEqualTo(data);
        }
    }

    @Test
    void compress_shouldRejectNullInput() {
        assertThatThrownBy(() -> CompressionProvider.compress(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decompress_shouldRejectNullInput() {
        assertThatThrownBy(() -> CompressionProvider.decompress(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void roundTrip_shouldWorkWithVariousDataSizes() {
        int[] sizes = {150, 500, 1000, 10000, 100000};

        for (int size : sizes) {
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) (i % 256);
            }

            byte[] compressed = CompressionProvider.compress(data);
            byte[] decompressed = CompressionProvider.decompress(compressed);

            assertThat(decompressed).isEqualTo(data);
        }
    }
}
