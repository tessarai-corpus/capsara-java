package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpRetry;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.SystemLimits;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalDouble;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** System limits management with caching. */
public final class LimitsService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final Duration CACHE_TTL = Duration.ofDays(7);
    private static final double FALLBACK_MAX_EXPIRATION_DAYS = 3650d;

    /** How long fallback limits are cached after a failed fetch. */
    static final Duration FALLBACK_TTL = Duration.ofMinutes(1);

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;
    private final Duration fallbackTtl;
    private final RetryConfig retryConfig;

    private volatile SystemLimits cachedLimits;
    private volatile Instant cachedAt;
    private volatile Duration cachedTtl;

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
        this(httpClient, baseUrl, tokenSupplier, timeout, null, userAgent, concurrencyConfig, FALLBACK_TTL);
    }

    /**
     * Constructs a LimitsService with a retry configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retry             retry configuration, null for defaults
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public LimitsService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                         HttpTimeoutConfig timeout, RetryConfig retry, String userAgent,
                         ConcurrencyConfig concurrencyConfig) {
        this(httpClient, baseUrl, tokenSupplier, timeout, retry, userAgent, concurrencyConfig, FALLBACK_TTL);
    }

    LimitsService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                  HttpTimeoutConfig timeout, String userAgent, ConcurrencyConfig concurrencyConfig,
                  Duration fallbackTtl) {
        this(httpClient, baseUrl, tokenSupplier, timeout, null, userAgent, concurrencyConfig, fallbackTtl);
    }

    LimitsService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                  HttpTimeoutConfig timeout, RetryConfig retry, String userAgent,
                  ConcurrencyConfig concurrencyConfig, Duration fallbackTtl) {
        this.retryConfig = retry != null ? retry : RetryConfig.defaults();
        this.fallbackTtl = fallbackTtl;
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
            if (age.compareTo(cachedTtl) < 0) {
                return CompletableFuture.completedFuture(cachedLimits);
            }
            cachedLimits = null;
            cachedAt = null;
        }

        return fetchLimitsAsync()
                .thenApply(limits -> {
                    cachedTtl = limits == SystemLimits.DEFAULT ? fallbackTtl : CACHE_TTL;
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

        return HttpRetry.send(httpClient, request, HttpResponse.BodyHandlers.ofString(), retryConfig,
                        concurrencyConfig)
                .thenApplyAsync(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        return SystemLimits.DEFAULT;
                    }

                    return parseLimits(response.body());
                }, concurrencyConfig.getResponseExecutor())
                .exceptionally(e -> SystemLimits.DEFAULT);
    }

    /**
     * Parse a /api/limits body field by field. A field is used only when it is a finite JSON number above zero,
     * otherwise that field's fallback; a body that is not an object gives {@link SystemLimits#DEFAULT}.
     * Fractions keep the comparisons the builder and request planner make: floor for {@code >} limits, ceil
     * for the file count ({@code >=}), and at least 1 for the request limits.
     */
    static SystemLimits parseLimits(String body) {
        JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(body);
        } catch (Exception e) {
            return SystemLimits.DEFAULT;
        }
        if (root == null || !root.isObject()) {
            return SystemLimits.DEFAULT;
        }
        SystemLimits d = SystemLimits.DEFAULT;
        SystemLimits limits = new SystemLimits(
                floorOr(root, "maxFileSize", d.getMaxFileSize(), 0),
                (int) Math.min(Integer.MAX_VALUE,
                        ceilOr(root, "maxFilesPerCapsa", d.getMaxFilesPerCapsa())),
                floorOr(root, "maxTotalSize", d.getMaxTotalSize(), 0),
                floorOr(root, "maxRequestSize", d.getMaxRequestSize(), 1),
                floorOr(root, "maxRequestFieldBytes", d.getMaxRequestFieldBytes(), 1));
        OptionalDouble days = positive(root, "maxExpirationDays");
        limits.setMaxExpirationDays(days.isPresent() ? days.getAsDouble() : FALLBACK_MAX_EXPIRATION_DAYS);
        limits.setMaxFilesPerRequest((int) Math.min(Integer.MAX_VALUE,
                floorOr(root, "maxFilesPerRequest", d.getMaxFilesPerRequest(), 1)));
        return limits;
    }

    private static OptionalDouble positive(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isNumber()) {
            return OptionalDouble.empty();
        }
        double value = node.doubleValue();
        return Double.isFinite(value) && value > 0 ? OptionalDouble.of(value) : OptionalDouble.empty();
    }

    private static long floorOr(JsonNode root, String field, long fallback, long min) {
        OptionalDouble value = positive(root, field);
        if (value.isEmpty()) {
            return fallback;
        }
        double v = value.getAsDouble();
        return v >= Long.MAX_VALUE ? Long.MAX_VALUE : Math.max(min, (long) Math.floor(v));
    }

    private static long ceilOr(JsonNode root, String field, long fallback) {
        OptionalDouble value = positive(root, field);
        if (value.isEmpty()) {
            return fallback;
        }
        double v = value.getAsDouble();
        return v >= Long.MAX_VALUE ? Long.MAX_VALUE : (long) Math.ceil(v);
    }

    /** Clear the limits cache. */
    public void clearCache() {
        cachedLimits = null;
        cachedAt = null;
    }
}
