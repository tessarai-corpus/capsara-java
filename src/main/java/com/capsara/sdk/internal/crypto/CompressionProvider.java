package com.capsara.sdk.internal.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Gzip compression/decompression provider.
 */
public final class CompressionProvider {

    /**
     * Minimum file size for compression to be beneficial (gzip header overhead breakeven).
     */
    public static final int COMPRESSION_THRESHOLD = 150;

    private CompressionProvider() {
    }

    /** Check if a file should be compressed based on its size. */
    public static boolean shouldCompress(long size) {
        return size >= COMPRESSION_THRESHOLD;
    }

    /** Compress data using gzip. */
    public static byte[] compress(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(data);
            gzos.finish();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Compression failed", e);
        }
    }

    /** Compress data if beneficial, otherwise return original data. */
    public static CompressionResult compressIfBeneficial(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        if (!shouldCompress(data.length)) {
            return new CompressionResult(data, false, null, data.length);
        }

        byte[] compressed = compress(data);

        // Only use compressed if it's actually smaller
        if (compressed.length < data.length) {
            return new CompressionResult(compressed, true, "gzip", data.length);
        }

        return new CompressionResult(data, false, null, data.length);
    }

    /** Decompress gzip data. */
    public static byte[] decompress(byte[] compressedData) {
        if (compressedData == null) {
            throw new IllegalArgumentException("Compressed data cannot be null");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
                GZIPInputStream gzis = new GZIPInputStream(bais);
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int len;
            while ((len = gzis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Decompression failed", e);
        }
    }

    /** Result of compression operation. */
    public static final class CompressionResult {
        private final byte[] data;
        private final boolean wasCompressed;
        private final String compressionAlgorithm;
        private final long originalSize;

        /** @param compressionAlgorithm the algorithm used, or null if not compressed */
        public CompressionResult(byte[] data, boolean wasCompressed, String compressionAlgorithm, long originalSize) {
            this.data = data;
            this.wasCompressed = wasCompressed;
            this.compressionAlgorithm = compressionAlgorithm;
            this.originalSize = originalSize;
        }

        public byte[] getData() {
            return data;
        }

        public boolean wasCompressed() {
            return wasCompressed;
        }

        public String getCompressionAlgorithm() {
            return compressionAlgorithm;
        }

        public long getOriginalSize() {
            return originalSize;
        }
    }
}
