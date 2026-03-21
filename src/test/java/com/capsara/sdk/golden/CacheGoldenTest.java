package com.capsara.sdk.golden;

import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.cache.CachedFileMetadata;
import com.capsara.sdk.internal.cache.CapsaCache;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for CapsaCache: set/get, TTL expiry, clear, file metadata lookup.
 */
class CacheGoldenTest {

    // Set/Get Tests

    @Test
    void setAndGet_masterKeyRoundtrip() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();

            cache.set(capsaId, masterKey, null);

            byte[] retrieved = cache.getMasterKey(capsaId);
            assertThat(retrieved).isEqualTo(masterKey);
        }
    }

    @Test
    void get_nonExistent_returnsNull() {
        try (CapsaCache cache = new CapsaCache()) {
            assertThat(cache.getMasterKey("capsa_doesnotexist")).isNull();
        }
    }

    @Test
    void set_overwritesExistingEntry() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] key1 = TestHelpers.generateTestMasterKey();
            byte[] key2 = TestHelpers.generateTestMasterKey();

            cache.set(capsaId, key1, null);
            cache.set(capsaId, key2, null);

            assertThat(cache.getMasterKey(capsaId)).isEqualTo(key2);
            assertThat(cache.size()).isEqualTo(1);
        }
    }

    // TTL Expiry Tests

    @Test
    void getMasterKey_afterExpiry_returnsNull() throws InterruptedException {
        try (CapsaCache cache = new CapsaCache(Duration.ofMillis(50))) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();

            cache.set(capsaId, masterKey, null);
            Thread.sleep(100);

            assertThat(cache.getMasterKey(capsaId)).isNull();
        }
    }

    @Test
    void getMasterKey_beforeExpiry_returnsMasterKey() {
        try (CapsaCache cache = new CapsaCache(Duration.ofMinutes(10))) {
            String capsaId = TestHelpers.generateCapsaId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();

            cache.set(capsaId, masterKey, null);

            assertThat(cache.getMasterKey(capsaId)).isEqualTo(masterKey);
        }
    }

    // Clear Specific/All Tests

    @Test
    void clear_removesSpecificEntry() {
        try (CapsaCache cache = new CapsaCache()) {
            String id1 = TestHelpers.generateCapsaId();
            String id2 = TestHelpers.generateCapsaId();

            cache.set(id1, TestHelpers.generateTestMasterKey(), null);
            cache.set(id2, TestHelpers.generateTestMasterKey(), null);

            cache.clear(id1);

            assertThat(cache.getMasterKey(id1)).isNull();
            assertThat(cache.getMasterKey(id2)).isNotNull();
            assertThat(cache.size()).isEqualTo(1);
        }
    }

    @Test
    void clearAll_removesEveryEntry() {
        try (CapsaCache cache = new CapsaCache()) {
            for (int i = 0; i < 5; i++) {
                cache.set(TestHelpers.generateCapsaId(), TestHelpers.generateTestMasterKey(), null);
            }

            cache.clearAll();

            assertThat(cache.size()).isEqualTo(0);
        }
    }

    // File Metadata Lookup Tests

    @Test
    void getFileMetadata_returnsCorrectFile() {
        try (CapsaCache cache = new CapsaCache()) {
            String capsaId = TestHelpers.generateCapsaId();
            String fileId = TestHelpers.generateFileId();
            byte[] masterKey = TestHelpers.generateTestMasterKey();
            CachedFileMetadata[] files = new CachedFileMetadata[]{createFileMetadata(fileId)};

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
            cache.set(capsaId, TestHelpers.generateTestMasterKey(),
                    new CachedFileMetadata[]{createFileMetadata("file_exists")});

            assertThat(cache.getFileMetadata(capsaId, "file_missing")).isNull();
        }
    }

    @Test
    void close_preventsSubsequentOperations() {
        CapsaCache cache = new CapsaCache();
        cache.close();

        assertThatThrownBy(() -> cache.getMasterKey("test"))
                .isInstanceOf(IllegalStateException.class);
    }

    // Helper

    private static CachedFileMetadata createFileMetadata(String fileId) {
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
