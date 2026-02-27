package com.capsara.sdk.internal.services;

import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.SystemLimits;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** System limits management with caching. */
public final class LimitsService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final Duration CACHE_TTL = Duration.ofDays(7);

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;

    private volatile SystemLimits cachedLimits;
    private volatile Instant cachedAt;

    /**
     * Constructs a LimitsService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public LimitsService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                         HttpTimeoutConfig timeout, String userAgent, ConcurrencyConfig concurrencyConfig) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
    }

    /**
     * Get system limits (from cache or fetch from API).
     *
     * @return system limits
     */
    public CompletableFuture<SystemLimits> getLimitsAsync() {
        if (cachedLimits != null && cachedAt != null) {
            Duration age = Duration.between(cachedAt, Instant.now());
            if (age.compareTo(CACHE_TTL) < 0) {
                return CompletableFuture.completedFuture(cachedLimits);
            }
            cachedLimits = null;
            cachedAt = null;
        }

        return fetchLimitsAsync()
                .thenApply(limits -> {
                    cachedLimits = limits;
                    cachedAt = Instant.now();
                    return limits;
                });
    }

    /** Fetch system limits from API. */
    private CompletableFuture<SystemLimits> fetchLimitsAsync() {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/limits"))
                .timeout(timeout.getRequestTimeout())
                .GET();

        if (userAgent != null && !userAgent.isEmpty()) {
            requestBuilder.header("User-Agent", userAgent);
        }

        String token = tokenSupplier != null ? tokenSupplier.get() : null;
        if (token != null && !token.isEmpty()) {
            requestBuilder.header("Authorization", "Bearer " + token);
        }

        HttpRequest request = requestBuilder.build();

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenApplyAsync(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        return SystemLimits.DEFAULT;
                    }

                    try {
                        return OBJECT_MAPPER.readValue(response.body(), SystemLimits.class);
                    } catch (Exception e) {
                        return SystemLimits.DEFAULT;
                    }
                }, concurrencyConfig.getResponseExecutor())
                .exceptionally(e -> SystemLimits.DEFAULT);
    }

    /** Clear the limits cache. */
    public void clearCache() {
        cachedLimits = null;
        cachedAt = null;
    }
}
