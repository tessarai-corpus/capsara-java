package com.capsara.sdk.internal.services;

import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.AuthResponse;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;

/** Service for authentication operations. */
public final class AuthService {

    private final String baseUrl;
    private final HttpClient httpClient;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;

    private volatile String accessToken;
    private volatile String refreshToken;

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
        this.userAgent = userAgent;
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

        return HttpClientFactory.sendAsync(httpClient, request, AuthResponse.class)
                .thenApply(response -> {
                    this.accessToken = response.getAccessToken();
                    this.refreshToken = response.getRefreshToken();
                    return response;
                });
    }

    /**
     * Logout and clear tokens.
     *
     * @return true if server-side logout succeeded
     */
    public CompletableFuture<Boolean> logoutAsync() {
        if (accessToken == null) {
            return CompletableFuture.completedFuture(true);
        }

        HttpRequest request = HttpClientFactory.buildPostRequest(
                baseUrl + "/api/auth/logout",
                Collections.emptyMap(),
                this::getToken,
                userAgent,
                timeout.getRequestTimeout()
        );

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    this.accessToken = null;
                    this.refreshToken = null;
                    return response.statusCode() >= 200 && response.statusCode() < 300;
                });
    }

    public String getToken() {
        return accessToken;
    }

    public void setToken(String token) {
        this.accessToken = token;
    }

    public boolean isAuthenticated() {
        return accessToken != null && !accessToken.isEmpty();
    }

    public void clearTokens() {
        this.accessToken = null;
        this.refreshToken = null;
    }
}
