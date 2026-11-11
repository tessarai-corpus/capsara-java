package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ApiError;
import com.capsara.sdk.internal.http.ApiErrorParser;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpRetry;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.AuthResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Service for authentication operations. */
public final class AuthService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final long EXPIRY_BUFFER_MS = 30_000L;

    private final String baseUrl;
    private final HttpClient httpClient;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final RetryConfig retryConfig;

    private volatile String accessToken;
    private volatile String refreshToken;
    private volatile Throwable lastRefreshError;
    private volatile Long tokenExpiresAt;

    private final AtomicReference<CompletableFuture<Boolean>> inFlightRefresh = new AtomicReference<>();
    private final AtomicLong generation = new AtomicLong();
    private final Object tokenLock = new Object();

    /**
     * Constructs an AuthService with the specified configuration.
     *
     * @param baseUrl   base URL for the API
     * @param timeout   timeout configuration
     * @param retry     retry configuration
     * @param userAgent user agent string
     */
    public AuthService(String baseUrl, HttpTimeoutConfig timeout, RetryConfig retry, String userAgent) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.httpClient = HttpClientFactory.create(timeout);
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.retryConfig = retry != null ? retry : RetryConfig.defaults();
        this.userAgent = userAgent;
    }

    private CompletableFuture<HttpResponse<String>> send(HttpRequest request) {
        return HttpRetry.send(httpClient, request, HttpResponse.BodyHandlers.ofString(), retryConfig, null)
                .exceptionallyCompose(error -> {
                    Throwable cause = HttpRetry.unwrap(error);
                    return CompletableFuture.failedFuture(
                            cause instanceof CapsaraException || cause instanceof CancellationException
                                    ? cause
                                    : CapsaraAuthException.networkError(cause));
                });
    }

    /**
     * Login with credentials.
     *
     * @param credentials authentication credentials
     * @return auth response
     */
    public CompletableFuture<AuthResponse> loginAsync(AuthCredentials credentials) {
        HttpRequest request = HttpClientFactory.buildPostRequest(
                baseUrl + "/api/auth/login",
                credentials,
                null,
                userAgent,
                timeout.getRequestTimeout()
        );

        return send(request)
                .thenApply(raw -> {
                    if (raw.statusCode() < 200 || raw.statusCode() >= 300) {
                        throw loginError(raw);
                    }
                    AuthResponse response;
                    try {
                        response = OBJECT_MAPPER.readValue(raw.body(), AuthResponse.class);
                    } catch (Exception e) {
                        throw new CapsaraException("Failed to parse response", e);
                    }
                    synchronized (tokenLock) {
                        generation.incrementAndGet();
                        this.accessToken = response.getAccessToken();
                        this.refreshToken = response.getRefreshToken();
                        this.tokenExpiresAt = expiresAt(response);
                    }
                    return response;
                });
    }

    private CompletableFuture<AuthResponse> requestRefresh(String currentRefreshToken,
            Function<HttpResponse<String>, CapsaraException> errorFactory) {
        HttpRequest request = HttpClientFactory.buildPostRequest(
                baseUrl + "/api/auth/refresh",
                Map.of("refreshToken", currentRefreshToken),
                null,
                userAgent,
                timeout.getRequestTimeout()
        );

        return send(request)
                .thenApply(raw -> {
                    if (raw.statusCode() < 200 || raw.statusCode() >= 300) {
                        throw errorFactory.apply(raw);
                    }
                    try {
                        return OBJECT_MAPPER.readValue(raw.body(), AuthResponse.class);
                    } catch (Exception e) {
                        throw new CapsaraException("Failed to parse response", e);
                    }
                });
    }

    private static Long expiresAt(AuthResponse response) {
        if (response.getExpiresIn() > 0) {
            return System.currentTimeMillis() + response.getExpiresIn() * 1000L;
        }
        return response.getAccessToken() != null ? jwtExpiry(response.getAccessToken()) : null;
    }

    private static Long jwtExpiry(String token) {
        if (token == null) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        try {
            JsonNode exp = OBJECT_MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1])).get("exp");
            return exp != null && exp.isNumber() && exp.asDouble() != 0 ? (long) (exp.asDouble() * 1000) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Whether the access token is missing an expiry or expires within the buffer.
     *
     * @param bufferSeconds seconds before expiry that already count as expired
     * @return true when the token has no known expiry or is (nearly) expired
     */
    public boolean isTokenExpired(int bufferSeconds) {
        Long expires = tokenExpiresAt;
        return expires == null || System.currentTimeMillis() >= expires - bufferSeconds * 1000L;
    }

    /**
     * Exchange the refresh token for a new access token.
     * Concurrent calls share one in-flight request. On failure the error is
     * recorded for {@link #getLastRefreshError()} and the future completes with false.
     *
     * @return true if new tokens were obtained
     */
    public CompletableFuture<Boolean> refreshAsync() {
        String currentRefreshToken = refreshToken;
        if (currentRefreshToken == null || currentRefreshToken.isEmpty()) {
            return CompletableFuture.completedFuture(false);
        }

        CompletableFuture<Boolean> created = new CompletableFuture<>();
        CompletableFuture<Boolean> existing = inFlightRefresh.compareAndExchange(null, created);
        if (existing != null) {
            return existing;
        }

        long startedIn = generation.get();
        requestRefresh(currentRefreshToken, AuthService::authError)
                .whenComplete((response, error) -> {
                    boolean refreshed = false;
                    synchronized (tokenLock) {
                        if (generation.get() != startedIn) {
                            this.lastRefreshError = null;
                        } else if (error == null && response != null) {
                            String issued = response.getAccessToken();
                            if (issued != null && !issued.isEmpty()) {
                                this.accessToken = issued;
                                this.tokenExpiresAt = expiresAt(response);
                            }
                            String rotated = response.getRefreshToken();
                            if (rotated != null && !rotated.isEmpty()) {
                                this.refreshToken = rotated;
                            }
                            this.lastRefreshError = null;
                            refreshed = true;
                        } else {
                            this.lastRefreshError = refreshFailure(error != null ? error
                                    : new CapsaraException("Failed to parse response"));
                        }
                    }
                    inFlightRefresh.set(null);
                    created.complete(refreshed);
                });

        return created;
    }

    private static Throwable refreshFailure(Throwable error) {
        Throwable cause = HttpRetry.unwrap(error);
        if (cause instanceof CapsaraAuthException || cause instanceof CancellationException) {
            return cause;
        }
        return cause instanceof CapsaraException
                ? new CapsaraAuthException(cause.getMessage(), cause)
                : CapsaraAuthException.networkError(cause);
    }

    /**
     * Get the error from the most recent failed refresh, cleared on success.
     *
     * @return last refresh error, or null
     */
    public Throwable getLastRefreshError() {
        return lastRefreshError;
    }

    /**
     * Whether a refresh token is available.
     *
     * @return true if {@link #refreshAsync()} can be attempted
     */
    public boolean canRefresh() {
        String token = refreshToken;
        return token != null && !token.isEmpty();
    }

    private static CapsaraException loginError(HttpResponse<String> raw) {
        ApiError error = ApiErrorParser.parse(raw.statusCode(), raw.body(), raw.headers());
        if (error.getStatusCode() == 400 && "VALIDATION_ERROR".equals(error.getCode())) {
            return CapsaraException.fromApiError(error);
        }
        return CapsaraAuthException.fromApiError(error);
    }

    /**
     * Clear local tokens, then revoke the session server-side, refreshing once first if the access token is
     * missing or expired, or once after the server rejects it.
     *
     * @return true once the server confirms; fails with {@link CapsaraAuthException} carrying the server's error,
     *         the refresh error, or NETWORK_ERROR otherwise
     */
    public CompletableFuture<Boolean> logoutAsync() {
        String currentAccessToken;
        String currentRefreshToken;
        Long expiresAt;
        synchronized (tokenLock) {
            currentAccessToken = accessToken;
            currentRefreshToken = refreshToken;
            expiresAt = tokenExpiresAt;
            clearTokens();
        }

        boolean hasAccess = currentAccessToken != null && !currentAccessToken.isEmpty();
        boolean hasRefresh = currentRefreshToken != null && !currentRefreshToken.isEmpty();
        if (!hasAccess && !hasRefresh) {
            return CompletableFuture.completedFuture(true);
        }

        boolean accessExpired = expiresAt != null && System.currentTimeMillis() >= expiresAt - EXPIRY_BUFFER_MS;
        CompletableFuture<Boolean> outcome;
        if (hasRefresh && (!hasAccess || accessExpired)) {
            outcome = refreshThenLogout(currentRefreshToken);
        } else {
            outcome = postLogout(currentAccessToken, hasRefresh ? currentRefreshToken : null)
                    .thenCompose(raw -> {
                        if (isSuccess(raw)) {
                            return CompletableFuture.completedFuture(true);
                        }
                        if (raw.statusCode() == 401 && hasRefresh) {
                            return refreshThenLogout(currentRefreshToken);
                        }
                        return CompletableFuture.failedFuture(authError(raw));
                    });
        }

        return outcome.exceptionallyCompose(error -> {
            Throwable cause = HttpRetry.unwrap(error);
            if (cause instanceof CapsaraAuthException || cause instanceof CancellationException) {
                return CompletableFuture.failedFuture(cause);
            }
            return CompletableFuture.failedFuture(cause instanceof CapsaraException
                    ? new CapsaraAuthException(cause.getMessage(), cause)
                    : CapsaraAuthException.networkError(cause));
        });
    }

    private CompletableFuture<Boolean> refreshThenLogout(String currentRefreshToken) {
        return requestRefresh(currentRefreshToken, AuthService::authError).thenCompose(response -> {
            String rotated = response.getRefreshToken();
            String newRefreshToken = rotated != null && !rotated.isEmpty() ? rotated : currentRefreshToken;
            return postLogout(response.getAccessToken(), newRefreshToken).thenApply(raw -> {
                if (!isSuccess(raw)) {
                    throw authError(raw);
                }
                return true;
            });
        });
    }

    private CompletableFuture<HttpResponse<String>> postLogout(String bearer, String revokedRefreshToken) {
        HttpRequest request = HttpClientFactory.buildPostRequest(
                baseUrl + "/api/auth/logout",
                revokedRefreshToken != null
                        ? Collections.singletonMap("refreshToken", revokedRefreshToken)
                        : Collections.emptyMap(),
                () -> bearer,
                userAgent,
                timeout.getRequestTimeout()
        );
        return send(request);
    }

    private static boolean isSuccess(HttpResponse<String> raw) {
        return raw.statusCode() >= 200 && raw.statusCode() < 300;
    }

    private static CapsaraException authError(HttpResponse<String> raw) {
        return CapsaraAuthException.fromApiError(ApiErrorParser.parse(raw.statusCode(), raw.body(), raw.headers()));
    }

    public String getToken() {
        return accessToken;
    }

    /**
     * Set the access token, superseding any refresh in flight.
     *
     * @param token access token
     */
    public void setToken(String token) {
        synchronized (tokenLock) {
            generation.incrementAndGet();
            this.accessToken = token;
            this.tokenExpiresAt = jwtExpiry(token);
        }
    }

    /**
     * Set both tokens, superseding any refresh in flight.
     *
     * @param newAccessToken  access token
     * @param newRefreshToken refresh token
     */
    public void setTokens(String newAccessToken, String newRefreshToken) {
        synchronized (tokenLock) {
            generation.incrementAndGet();
            this.accessToken = newAccessToken;
            this.refreshToken = newRefreshToken;
            this.tokenExpiresAt = jwtExpiry(newAccessToken);
        }
    }

    public boolean isAuthenticated() {
        return accessToken != null && !accessToken.isEmpty();
    }

    /** Clear both tokens; a refresh in flight will not restore them. */
    public void clearTokens() {
        synchronized (tokenLock) {
            generation.incrementAndGet();
            this.accessToken = null;
            this.refreshToken = null;
            this.tokenExpiresAt = null;
        }
    }
}
