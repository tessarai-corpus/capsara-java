package com.capsara.sdk.golden;

import com.capsara.sdk.internal.crypto.CompressionProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for compression: roundtrip, threshold checks, invalid data handling.
 */
class CompressionGoldenTest {

    // Roundtrip Tests

    @Test
    void compressDecompress_roundtrip_recoversOriginalData() {
        byte[] original = "This is a test string for compression roundtrip verification."
                .getBytes(StandardCharsets.UTF_8);

        byte[] compressed = CompressionProvider.compress(original);
        byte[] decompressed = CompressionProvider.decompress(compressed);

        assertThat(decompressed).isEqualTo(original);
    }

    @Test
    void compressIfBeneficial_largeRepetitiveData_compresses() {
        byte[] data = new byte[2000];
        Arrays.fill(data, (byte) 'x');

        CompressionProvider.CompressionResult result = CompressionProvider.compressIfBeneficial(data);

        assertThat(result.wasCompressed()).isTrue();
        assertThat(result.getCompressionAlgorithm()).isEqualTo("gzip");
        assertThat(result.getOriginalSize()).isEqualTo(2000);
        assertThat(result.getData().length).isLessThan(data.length);

        // Verify roundtrip
        byte[] decompressed = CompressionProvider.decompress(result.getData());
        assertThat(decompressed).isEqualTo(data);
    }

    // Threshold Tests

    @Test
    void shouldCompress_belowThreshold_returnsFalse() {
        assertThat(CompressionProvider.shouldCompress(0)).isFalse();
        assertThat(CompressionProvider.shouldCompress(50)).isFalse();
        assertThat(CompressionProvider.shouldCompress(149)).isFalse();
    }

    @Test
    void shouldCompress_atAndAboveThreshold_returnsTrue() {
        assertThat(CompressionProvider.shouldCompress(150)).isTrue();
        assertThat(CompressionProvider.shouldCompress(151)).isTrue();
        assertThat(CompressionProvider.shouldCompress(10000)).isTrue();
    }

    @Test
    void compressIfBeneficial_smallData_doesNotCompress() {
        byte[] data = "tiny".getBytes(StandardCharsets.UTF_8);

        CompressionProvider.CompressionResult result = CompressionProvider.compressIfBeneficial(data);

        assertThat(result.wasCompressed()).isFalse();
        assertThat(result.getData()).isEqualTo(data);
        assertThat(result.getCompressionAlgorithm()).isNull();
    }

    // Invalid Data Handling Tests

    @Test
    void compress_withNullInput_throwsIllegalArgument() {
        assertThatThrownBy(() -> CompressionProvider.compress(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decompress_withNullInput_throwsIllegalArgument() {
        assertThatThrownBy(() -> CompressionProvider.decompress(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
