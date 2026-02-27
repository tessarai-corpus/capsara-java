package com.capsara.sdk.internal.services;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/** File download service for downloading encrypted files from capsas. */
public final class DownloadService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final Random RANDOM = new Random();

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
                this.retryConfig, concurrencyConfig);
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
            try {
                DownloadUrlResponse result = OBJECT_MAPPER.readValue(response.body(), DownloadUrlResponse.class);
                return new DownloadUrlResult(result.downloadUrl, result.expiresAt);
            } catch (Exception e) {
                throw CapsaraException.networkError(e);
            }
        });
    }

    /**
     * Download encrypted file from blob storage.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @return encrypted file data
     */
    public CompletableFuture<byte[]> downloadEncryptedFileAsync(String capsaId, String fileId) {
        return getFileDownloadUrlAsync(capsaId, fileId, 60)
                .thenCompose(result -> downloadFileWithRetryAsync(result.getDownloadUrl(), 0));
    }

    private CompletableFuture<byte[]> downloadFileWithRetryAsync(String downloadUrl, int retryCount) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(downloadUrl))
                .timeout(timeout.getDownloadTimeout())
                .GET()
                .build();

        return HttpClientFactory.sendAsyncWithLimit(blobDownloadClient, request,
                HttpResponse.BodyHandlers.ofByteArray(), concurrencyConfig)
                .thenComposeAsync(response -> {
                    if (response.statusCode() >= 200 && response.statusCode() < 300) {
                        return CompletableFuture.completedFuture(response.body());
                    }

                    int status = response.statusCode();
                    boolean isRetryable = status == 503 || status == 429;

                    if (isRetryable && retryCount < retryConfig.getMaxRetries()) {
                        return delayedRetry(downloadUrl, retryCount);
                    }

                    throw CapsaraCapsaException.downloadFailed("", "",
                            new RuntimeException("Download failed with status " + status));
                }, concurrencyConfig.getResponseExecutor())
                .exceptionallyCompose(error -> {
                    // Unwrap CompletionException if needed
                    Throwable cause = error.getCause() != null ? error.getCause() : error;

                    if (cause instanceof CapsaraException) {
                        return CompletableFuture.failedFuture(cause);
                    }

                    if (retryCount < retryConfig.getMaxRetries()) {
                        return delayedRetry(downloadUrl, retryCount);
                    }

                    return CompletableFuture.failedFuture(CapsaraException.networkError(cause));
                });
    }

    /** Schedule a retry after a delay using non-blocking approach. */
    private CompletableFuture<byte[]> delayedRetry(String downloadUrl, int retryCount) {
        Duration delay = calculateRetryDelay(retryCount);
        Executor delayedExecutor = CompletableFuture.delayedExecutor(delay.toMillis(), TimeUnit.MILLISECONDS);
        return CompletableFuture.supplyAsync(() -> null, delayedExecutor)
                .thenCompose(ignored -> downloadFileWithRetryAsync(downloadUrl, retryCount + 1));
    }

    private Duration calculateRetryDelay(int retryCount) {
        Duration delay = retryConfig.getDelayForAttempt(retryCount);
        double jitter = RANDOM.nextDouble() * 0.3 * delay.toMillis();
        return Duration.ofMillis(delay.toMillis() + (long) jitter);
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

    private static final class DownloadUrlResponse {
        @JsonProperty("fileId")
        public String fileId;

        @JsonProperty("downloadUrl")
        public String downloadUrl;

        @JsonProperty("expiresAt")
        public String expiresAt;
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
