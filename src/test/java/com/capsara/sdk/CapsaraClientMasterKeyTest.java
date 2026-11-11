package com.capsara.sdk;

import com.capsara.sdk.internal.cache.CachedFileMetadata;
import com.capsara.sdk.internal.cache.CapsaCache;
import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.models.DecryptedFileResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Downloads decrypt with their own master key copy and zero it whatever the outcome. */
class CapsaraClientMasterKeyTest {

    private static byte[] lastCiphertext;

    private static byte[] key() {
        return SecureMemory.generateMasterKey();
    }

    private static CachedFileMetadata encryptedFile(byte[] key, byte[] content, String filename) {
        byte[] iv = SecureMemory.generateIv();
        byte[] nameIv = SecureMemory.generateIv();
        AesGcmProvider.EncryptionResult body = AesGcmProvider.encrypt(content, key, iv);
        AesGcmProvider.EncryptionResult name = AesGcmProvider.encrypt(
                filename.getBytes(StandardCharsets.UTF_8), key, nameIv);
        CachedFileMetadata file = new CachedFileMetadata();
        file.setFileId("file_1.enc");
        file.setIv(Base64Url.encode(iv));
        file.setAuthTag(Base64Url.encode(body.getAuthTag()));
        file.setEncryptedFilename(Base64Url.encode(name.getCiphertext()));
        file.setFilenameIV(Base64Url.encode(nameIv));
        file.setFilenameAuthTag(Base64Url.encode(name.getAuthTag()));
        file.setCompressed(false);
        lastCiphertext = body.getCiphertext();
        return file;
    }

    @Test
    void successfulDownload_decryptsAndZeroesTheKeyCopy() {
        byte[] key = key();
        byte[] content = "hello".getBytes(StandardCharsets.UTF_8);
        CachedFileMetadata file = encryptedFile(key, content, "a.txt");
        byte[] ciphertext = lastCiphertext;

        DecryptedFileResult result = CapsaraClient.decryptDownload(
                CompletableFuture.completedFuture(ciphertext), "capsa_1", key, file).join();

        assertThat(result.getData()).isEqualTo(content);
        assertThat(result.getFilename()).isEqualTo("a.txt");
        assertThat(key).containsOnly(0);
    }

    @Test
    void failedDownload_zeroesTheKeyCopy() {
        byte[] key = key();
        CachedFileMetadata file = encryptedFile(key, new byte[]{1}, "a.txt");

        Throwable thrown = catchThrowable(() -> CapsaraClient.decryptDownload(
                CompletableFuture.failedFuture(new IOException("reset")), "capsa_1", key, file).join());

        assertThat(thrown).hasRootCauseInstanceOf(IOException.class);
        assertThat(key).containsOnly(0);
    }

    @Test
    void failedDecryption_zeroesTheKeyCopy() {
        byte[] key = key();
        CachedFileMetadata file = encryptedFile(key, new byte[]{1}, "a.txt");

        Throwable thrown = catchThrowable(() -> CapsaraClient.decryptDownload(
                CompletableFuture.completedFuture(new byte[]{9, 9, 9}), "capsa_1", key, file).join());

        assertThat(thrown).hasCauseInstanceOf(com.capsara.sdk.exceptions.CapsaraCapsaException.class);
        com.capsara.sdk.exceptions.CapsaraCapsaException error =
                (com.capsara.sdk.exceptions.CapsaraCapsaException) thrown.getCause();
        assertThat(error.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(error.getStatusCode()).isZero();
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> details = (java.util.Map<String, Object>) error.getDetails();
        assertThat(details)
                .containsEntry("capsaId", "capsa_1")
                .containsEntry("fileId", file.getFileId())
                .containsKey("originalError");
        assertThat(key).containsOnly(0);
    }

    @Test
    void cacheContains_doesNotHandOutTheKey() {
        try (CapsaCache cache = new CapsaCache()) {
            byte[] key = key();
            CachedFileMetadata file = new CachedFileMetadata();
            file.setFileId("file_1.enc");
            cache.set("capsa_1", key, new CachedFileMetadata[]{file});

            assertThat(cache.contains("capsa_1", "file_1.enc")).isTrue();
            assertThat(cache.contains("capsa_1", "file_2.enc")).isFalse();
            assertThat(cache.contains("capsa_2", "file_1.enc")).isFalse();
            assertThat(cache.getMasterKey("capsa_1")).isEqualTo(key).isNotSameAs(key);
        }
    }
}
