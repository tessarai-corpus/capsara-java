package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpRetry;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** File download service for downloading encrypted files from capsas. */
public final class DownloadService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final HttpClient blobDownloadClient;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final RetryConfig retryConfig;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;
    private final RetryExecutor retryExecutor;

    /**
     * Constructs a DownloadService with the specified configuration.
     *
     * @param apiHttpClient     HTTP client for API requests
     * @param blobHttpClient    HTTP client for blob storage downloads
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retryConfig       retry configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public DownloadService(HttpClient apiHttpClient, HttpClient blobHttpClient, String baseUrl,
                           Supplier<String> tokenSupplier, HttpTimeoutConfig timeout,
                           RetryConfig retryConfig, String userAgent, ConcurrencyConfig concurrencyConfig) {
        this.blobDownloadClient = blobHttpClient;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.retryConfig = retryConfig != null ? retryConfig : RetryConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
        this.retryExecutor = new RetryExecutor(apiHttpClient,
                this.retryConfig, concurrencyConfig, CapsaraCapsaException::fromApiError,
                CapsaraCapsaException::networkError);
    }

    /**
     * Get download URL for encrypted file.
     *
     * @param capsaId          capsa ID
     * @param fileId           file ID
     * @param expiresInMinutes URL expiration in minutes (default: 60)
     * @return download URL and expiration
     */
    public CompletableFuture<DownloadUrlResult> getFileDownloadUrlAsync(String capsaId, String fileId,
                                                                         int expiresInMinutes) {
        String url = String.format("/api/capsas/%s/files/%s/download?expires=%d",
                capsaId, fileId, expiresInMinutes);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + url))
                .timeout(timeout.getRequestTimeout())
                .GET();

        addHeaders(builder);

        return retryExecutor.sendWithRetry(builder.build(), response -> {
            JsonNode root;
            try {
                root = OBJECT_MAPPER.readTree(response.body());
            } catch (Exception e) {
                root = null;
            }
            if (root == null || !root.isObject()) {
                throw CapsaraCapsaException.invalidResponse(capsaId, fileId);
            }
            return new DownloadUrlResult(text(root.get("downloadUrl")), text(root.get("expiresAt")));
        });
    }

    private static String text(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    /**
     * Download encrypted file from blob storage.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @return encrypted file data; API failures keep their code, blob failures are DOWNLOAD_FAILED
     */
    public CompletableFuture<byte[]> downloadEncryptedFileAsync(String capsaId, String fileId) {
        return getFileDownloadUrlAsync(capsaId, fileId, 60)
                .thenCompose(result -> downloadBlobAsync(capsaId, fileId, result.getDownloadUrl()));
    }

    private CompletableFuture<byte[]> downloadBlobAsync(String capsaId, String fileId, String downloadUrl) {
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder()
                    .uri(URI.create(downloadUrl))
                    .timeout(timeout.getDownloadTimeout())
                    .GET()
                    .build();
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(CapsaraCapsaException.downloadFailed(capsaId, fileId, e));
        }

        return HttpRetry.send(blobDownloadClient, request, HttpResponse.BodyHandlers.ofByteArray(),
                        retryConfig, concurrencyConfig)
                .handle((response, error) -> {
                    if (error != null) {
                        throw CapsaraCapsaException.downloadFailed(capsaId, fileId, HttpRetry.unwrap(error));
                    }
                    if (response.statusCode() >= 200 && response.statusCode() < 300) {
                        return response.body();
                    }
                    throw CapsaraCapsaException.downloadFailed(capsaId, fileId,
                            new IllegalStateException("Request failed with status code " + response.statusCode()));
                });
    }

    private void addHeaders(HttpRequest.Builder builder) {
        if (userAgent != null && !userAgent.isEmpty()) {
            builder.header("User-Agent", userAgent);
        }

        String token = tokenSupplier != null ? tokenSupplier.get() : null;
        if (token != null && !token.isEmpty()) {
            builder.header("Authorization", "Bearer " + token);
        }
    }

    /** Result containing a download URL and its expiration timestamp. */
    public static class DownloadUrlResult {
        private final String downloadUrl;
        private final String expiresAt;

        public DownloadUrlResult(String downloadUrl, String expiresAt) {
            this.downloadUrl = downloadUrl;
            this.expiresAt = expiresAt;
        }

        public String getDownloadUrl() {
            return downloadUrl;
        }

        public String getExpiresAt() {
            return expiresAt;
        }
    }
}
