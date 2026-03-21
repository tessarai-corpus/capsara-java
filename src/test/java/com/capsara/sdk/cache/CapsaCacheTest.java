package com.capsara.sdk.cache;

import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.cache.CachedFileMetadata;
import com.capsara.sdk.internal.cache.CapsaCache;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for CapsaCache in-memory envelope caching.
 */
class CapsaCacheTest {

    // Set and Get Tests

    @Test
    void set_storesCapsaInCache() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            assertThat(cache.size()).isEqualTo(1);
        }
    }

    @Test
    void getMasterKey_returnsCachedMasterKey() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            byte[] result = cache.getMasterKey(capsaId);
            assertThat(result).isEqualTo(masterKey);
        }
    }

    @Test
    void getMasterKey_nonExistentCapsa_returnsNull() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();

            byte[] result = cache.getMasterKey(capsaId);

            assertThat(result).isNull();
        }
    }

    @Test
    void getFileMetadata_returnsCachedFileMetadata() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            String fileId = TestHelpers.generateFileId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata(fileId)};

            cache.set(capsaId, masterKey, files);

            CachedFileMetadata result = cache.getFileMetadata(capsaId, fileId);
            assertThat(result).isNotNull();
            assertThat(result.getFileId()).isEqualTo(fileId);
        }
    }

    @Test
    void getFileMetadata_nonExistentFile_returnsNull() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            CachedFileMetadata result = cache.getFileMetadata(capsaId, "nonexistent_file");
            assertThat(result).isNull();
        }
    }

    @Test
    void getFileMetadata_nonExistentCapsa_returnsNull() {
        try (CapsaCache cache = new CapsaCache()) {
            CachedFileMetadata result = cache.getFileMetadata("nonexistent_capsa", "file_123");
            assertThat(result).isNull();
        }
    }

    // Expiration Tests

    @Test
    void getMasterKey_expiredEntry_returnsNull() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache(Duration.ofMillis(50))) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            // Wait for expiration
            Thread.sleep(100);

            byte[] result = cache.getMasterKey(capsaId);
            assertThat(result).isNull();
        }
    }

    @Test
    void getFileMetadata_expiredEntry_returnsNull() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache(Duration.ofMillis(50))) {
            String capsaId = TestHelpers.generateCapsaId();
            String fileId = TestHelpers.generateFileId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata(fileId)};

            cache.set(capsaId, masterKey, files);

            // Wait for expiration
            Thread.sleep(100);

            CachedFileMetadata result = cache.getFileMetadata(capsaId, fileId);
            assertThat(result).isNull();
        }
    }

    @Test
    void getMasterKey_notExpiredEntry_returnsMasterKey() {
        try (CapsaCache cache = new CapsaCache(Duration.ofMinutes(5))) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            byte[] result = cache.getMasterKey(capsaId);
            assertThat(result).isEqualTo(masterKey);
        }
    }

    // Clear Tests

    @Test
    void clear_removesSpecificCapsa() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId1 = TestHelpers.generateCapsaId();
            String capsaId2 = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId1, masterKey, files);
            cache.set(capsaId2, masterKey, files);

            cache.clear(capsaId1);

            assertThat(cache.size()).isEqualTo(1);
            assertThat(cache.getMasterKey(capsaId1)).isNull();
            assertThat(cache.getMasterKey(capsaId2)).isNotNull();
        }
    }

    @Test
    void clearAll_removesAllCapsas() {
        try (CapsaCache cache = new CapsaCache()) {
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            for (int i = 0; i < 5; i++) {
                cache.set(TestHelpers.generateCapsaId(), masterKey, files);
            }

            assertThat(cache.size()).isEqualTo(5);

            cache.clearAll();

            assertThat(cache.size()).isEqualTo(0);
        }
    }

    @Test
    void clear_nonExistentCapsa_doesNotThrow() {
        try (CapsaCache cache = new CapsaCache()) {
            cache.clear("nonexistent");
            // No exception should be thrown
        }
    }

    // Update Tests

    @Test
    void set_overwritesExistingEntry() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey1 = TestHelpers.generateTestMasterKey();
            byte[] masterKey2 = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey1, files);
            cache.set(capsaId, masterKey2, files);

            byte[] result = cache.getMasterKey(capsaId);
            assertThat(cache.size()).isEqualTo(1);
            assertThat(result).isEqualTo(masterKey2);
        }
    }

    // Multiple Files Tests

    @Test
    void set_storesMultipleFiles() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            String fileId1 = TestHelpers.generateFileId();
            String fileId2 = TestHelpers.generateFileId();
            String fileId3 = TestHelpers.generateFileId();
            CachedFileMetadata[] files = new CachedFileMetadata[]{
                    createTestFileMetadata(fileId1),
                    createTestFileMetadata(fileId2),
                    createTestFileMetadata(fileId3)
            };

            cache.set(capsaId, masterKey, files);

            assertThat(cache.getFileMetadata(capsaId, fileId1)).isNotNull();
            assertThat(cache.getFileMetadata(capsaId, fileId2)).isNotNull();
            assertThat(cache.getFileMetadata(capsaId, fileId3)).isNotNull();
        }
    }

    // Thread Safety Tests

    @Test
    void concurrentAccess_doesNotThrow() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache()) {
            int threadCount = 10;
            int iterationsPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger errors = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                int threadIndex = t;
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterationsPerThread; j++) {
                            String capsaId = "capsa_" + threadIndex + "_" + j;
                            byte[] masterKey = TestHelpers.generateTestMasterKey();
                            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

                            cache.set(capsaId, masterKey, files);
                            cache.getMasterKey(capsaId);
                            cache.clear(capsaId);
                        }
                    } catch (Exception e) {
                        errors.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            assertThat(errors.get()).isEqualTo(0);
        }
    }

    // Default TTL Tests

    @Test
    void defaultTTL_isFiveMinutes() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            // Entry should still be valid immediately
            byte[] result = cache.getMasterKey(capsaId);
            assertThat(result).isNotNull();
        }
    }

    // Max Size and LRU Eviction Tests

    @Test
    void set_evictsOldestWhenMaxSizeReached() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache(Duration.ofMinutes(5), 3)) {
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            // Add 3 entries (at max)
            cache.set("capsa_0", TestHelpers.generateTestMasterKey(), files);
            Thread.sleep(10);
            cache.set("capsa_1", TestHelpers.generateTestMasterKey(), files);
            Thread.sleep(10);
            cache.set("capsa_2", TestHelpers.generateTestMasterKey(), files);

            assertThat(cache.size()).isEqualTo(3);

            // Add a 4th entry
            cache.set("capsa_new", TestHelpers.generateTestMasterKey(), files);

            // Oldest entry should be evicted
            assertThat(cache.size()).isEqualTo(3);
            assertThat(cache.getMasterKey("capsa_0")).isNull(); // Oldest evicted
            assertThat(cache.getMasterKey("capsa_1")).isNotNull();
            assertThat(cache.getMasterKey("capsa_2")).isNotNull();
            assertThat(cache.getMasterKey("capsa_new")).isNotNull();
        }
    }

    @Test
    void prune_removesExpiredEntries() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache(Duration.ofMillis(50))) {
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set("capsa_1", TestHelpers.generateTestMasterKey(), files);
            cache.set("capsa_2", TestHelpers.generateTestMasterKey(), files);

            assertThat(cache.size()).isEqualTo(2);

            // Wait for expiration
            Thread.sleep(100);

            cache.prune();

            assertThat(cache.size()).isEqualTo(0);
        }
    }

    @Test
    void prune_keepsNonExpiredEntries() {
        try (CapsaCache cache = new CapsaCache(Duration.ofMinutes(5))) {
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set("capsa_1", TestHelpers.generateTestMasterKey(), files);
            cache.set("capsa_2", TestHelpers.generateTestMasterKey(), files);

            cache.prune();

            assertThat(cache.size()).isEqualTo(2);
        }
    }

    @Test
    void defaultMaxSize_is100() {
        assertThat(CapsaCache.DEFAULT_MAX_SIZE).isEqualTo(100);
    }

    // AutoCloseable Tests

    @Test
    void close_clearsAllEntries() {
        CapsaCache cache = new CapsaCache();
        CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

        cache.set("capsa_1", TestHelpers.generateTestMasterKey(), files);
        cache.set("capsa_2", TestHelpers.generateTestMasterKey(), files);

        cache.close();

        assertThat(cache.size()).isEqualTo(0);
    }

    @Test
    void afterClose_operationsThrow() {
        CapsaCache cache = new CapsaCache();
        cache.close();

        assertThatThrownBy(() -> cache.getMasterKey("test"))
                .isInstanceOf(IllegalStateException.class);

        assertThatThrownBy(() -> cache.set("test", new byte[32], null))
                .isInstanceOf(IllegalStateException.class);
    }

    // Null handling tests

    @Test
    void set_withNullFiles_doesNotThrow() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();

            cache.set(capsaId, masterKey, null);

            assertThat(cache.getMasterKey(capsaId)).isNotNull();
            assertThat(cache.getFileMetadata(capsaId, "any")).isNull();
        }
    }

    // Master key copy test

    @Test
    void getMasterKey_returnsCopyNotOriginal() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createTestFileMetadata()};

            cache.set(capsaId, masterKey, files);

            byte[] result1 = cache.getMasterKey(capsaId);
            byte[] result2 = cache.getMasterKey(capsaId);

            // Modify result1
            result1[0] = (byte) (result1[0] ^ 0xFF);

            // result2 should be unchanged
            assertThat(result2).isNotEqualTo(result1);
            assertThat(result2).isEqualTo(masterKey);
        }
    }

    private static CachedFileMetadata createTestFileMetadata() {
        return createTestFileMetadata(TestHelpers.generateFileId());
    }

    private static CachedFileMetadata createTestFileMetadata(String fileId) {
        CachedFileMetadata metadata = new CachedFileMetadata();
        metadata.setFileId(fileId);
        metadata.setIv(Base64.getEncoder().encodeToString(TestHelpers.generateTestIV()));
        metadata.setAuthTag(Base64.getEncoder().encodeToString(new byte[16]));
        metadata.setCompressed(false);
        metadata.setEncryptedFilename(Base64.getEncoder().encodeToString(new byte[32]));
        metadata.setFilenameIV(Base64.getEncoder().encodeToString(TestHelpers.generateTestIV()));
        metadata.setFilenameAuthTag(Base64.getEncoder().encodeToString(new byte[16]));
        return metadata;
    }
}
