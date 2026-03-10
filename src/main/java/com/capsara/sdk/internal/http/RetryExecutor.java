package com.capsara.sdk.internal.http;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/** Retry executor for HTTP requests with exponential backoff and server-suggested delays. */
public final class RetryExecutor {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final Random RANDOM = new Random();

    private final HttpClient httpClient;
    private final RetryConfig retryConfig;
    private final ConcurrencyConfig concurrencyConfig;

    /** Creates a retry executor with the given HTTP client, retry, and concurrency configs. */
    public RetryExecutor(HttpClient httpClient, RetryConfig retryConfig, ConcurrencyConfig concurrencyConfig) {
        this.httpClient = httpClient;
        this.retryConfig = retryConfig != null ? retryConfig : RetryConfig.defaults();
        this.concurrencyConfig = concurrencyConfig;
    }

    public <T> CompletableFuture<T> sendWithRetry(
            HttpRequest request,
            Function<HttpResponse<String>, T> responseHandler) {
        return sendWithRetryInternal(request, responseHandler, 0);
    }

    public CompletableFuture<HttpResponse<String>> sendWithRetryRaw(HttpRequest request) {
        return sendWithRetryRawInternal(request, 0);
    }

    private <T> CompletableFuture<T> sendWithRetryInternal(
            HttpRequest request,
            Function<HttpResponse<String>, T> responseHandler,
            int retryCount) {

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenComposeAsync(response -> {
                    int status = response.statusCode();

                    if (status >= 200 && status < 300) {
                        try {
                            T result = responseHandler.apply(response);
                            return CompletableFuture.completedFuture(result);
                        } catch (Exception e) {
                            return CompletableFuture.failedFuture(e);
                        }
                    }

                    boolean isRetryable = status == 503 || status == 429;
                    if (isRetryable && retryCount < retryConfig.getMaxRetries()) {
                        Duration delay = calculateRetryDelay(response, retryCount);
                        return delayedRetry(request, responseHandler, retryCount, delay);
                    }

                    return CompletableFuture.failedFuture(
                            CapsaraException.fromHttpResponse(status, response.body(), null));
                }, concurrencyConfig.getResponseExecutor())
                .exceptionallyCompose(error -> {
                    Throwable cause = error.getCause() != null ? error.getCause() : error;

                    if (cause instanceof CapsaraException) {
                        return CompletableFuture.failedFuture(cause);
                    }

                    if (retryCount < retryConfig.getMaxRetries()) {
                        Duration delay = calculateExponentialBackoff(retryCount);
                        return delayedRetry(request, responseHandler, retryCount, delay);
                    }

                    return CompletableFuture.failedFuture(CapsaraException.networkError(cause));
                });
    }

    private CompletableFuture<HttpResponse<String>> sendWithRetryRawInternal(
            HttpRequest request,
            int retryCount) {

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenComposeAsync(response -> {
                    int status = response.statusCode();

                    if (status >= 200 && status < 300) {
                        return CompletableFuture.completedFuture(response);
                    }

                    boolean isRetryable = status == 503 || status == 429;
                    if (isRetryable && retryCount < retryConfig.getMaxRetries()) {
                        Duration delay = calculateRetryDelay(response, retryCount);
                        return delayedRetryRaw(request, retryCount, delay);
                    }

                    return CompletableFuture.completedFuture(response);
                }, concurrencyConfig.getResponseExecutor())
                .exceptionallyCompose(error -> {
                    Throwable cause = error.getCause() != null ? error.getCause() : error;

                    if (retryCount < retryConfig.getMaxRetries()) {
                        Duration delay = calculateExponentialBackoff(retryCount);
                        return delayedRetryRaw(request, retryCount, delay);
                    }

                    return CompletableFuture.failedFuture(CapsaraException.networkError(cause));
                });
    }

    private <T> CompletableFuture<T> delayedRetry(
            HttpRequest request,
            Function<HttpResponse<String>, T> responseHandler,
            int retryCount,
            Duration delay) {
        Executor delayedExecutor = CompletableFuture.delayedExecutor(delay.toMillis(), TimeUnit.MILLISECONDS);
        return CompletableFuture.supplyAsync(() -> null, delayedExecutor)
                .thenCompose(ignored -> sendWithRetryInternal(request, responseHandler, retryCount + 1));
    }

    private CompletableFuture<HttpResponse<String>> delayedRetryRaw(
            HttpRequest request,
            int retryCount,
            Duration delay) {
        Executor delayedExecutor = CompletableFuture.delayedExecutor(delay.toMillis(), TimeUnit.MILLISECONDS);
        return CompletableFuture.supplyAsync(() -> null, delayedExecutor)
                .thenCompose(ignored -> sendWithRetryRawInternal(request, retryCount + 1));
    }

    // Delay priority: JSON body retryAfter -> Retry-After header -> exponential backoff
    private Duration calculateRetryDelay(HttpResponse<String> response, int retryCount) {
        String responseBody = response.body();
        if (responseBody != null && !responseBody.isEmpty()) {
            try {
                JsonNode doc = OBJECT_MAPPER.readTree(responseBody);

                JsonNode retryAfterNode = doc.get("retryAfter");
                if (retryAfterNode != null && retryAfterNode.isNumber()) {
                    Duration serverDelay = Duration.ofSeconds(retryAfterNode.asLong());
                    return capDelay(serverDelay);
                }

                JsonNode errorNode = doc.get("error");
                if (errorNode != null && errorNode.isObject()) {
                    retryAfterNode = errorNode.get("retryAfter");
                    if (retryAfterNode != null && retryAfterNode.isNumber()) {
                        Duration serverDelay = Duration.ofSeconds(retryAfterNode.asLong());
                        return capDelay(serverDelay);
                    }
                }
            } catch (Exception ignored) {
            }
        }

        Duration headerDelay = parseRetryAfterHeader(response);
        if (headerDelay != null) {
            return capDelay(headerDelay);
        }

        return calculateExponentialBackoff(retryCount);
    }

    private Duration parseRetryAfterHeader(HttpResponse<String> response) {
        var retryAfterHeader = response.headers().firstValue("Retry-After");
        if (retryAfterHeader.isEmpty()) {
            return null;
        }

        String value = retryAfterHeader.get();

        try {
            long seconds = Long.parseLong(value);
            return Duration.ofSeconds(seconds);
        } catch (NumberFormatException ignored) {
        }

        // RFC 7231 date format
        try {
            java.time.ZonedDateTime date = java.time.ZonedDateTime.parse(value,
                    java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration delay = Duration.between(java.time.Instant.now(), date.toInstant());
            return delay.isNegative() ? Duration.ZERO : delay;
        } catch (Exception ignored) {
        }

        return null;
    }

    private Duration capDelay(Duration delay) {
        if (delay.compareTo(retryConfig.getMaxDelay()) > 0) {
            return retryConfig.getMaxDelay();
        }
        return delay;
    }

    private Duration calculateExponentialBackoff(int retryCount) {
        Duration baseDelay = retryConfig.getDelayForAttempt(retryCount);
        double jitter = RANDOM.nextDouble() * 0.3 * baseDelay.toMillis();
        Duration totalDelay = Duration.ofMillis((long) (baseDelay.toMillis() + jitter));

        if (totalDelay.compareTo(retryConfig.getMaxDelay()) > 0) {
            return retryConfig.getMaxDelay();
        }
        return totalDelay;
    }
}
