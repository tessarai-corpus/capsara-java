package com.capsara.sdk.internal.services;

import com.capsara.sdk.internal.http.HttpRetry;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

/**
 * API client that, on a 401, refreshes the access token once and resends the request
 * with the new bearer token. Concurrent refreshes share one in-flight request.
 */
public final class TokenRefreshingHttpClient extends HttpClient implements HttpRetry.AttemptSender {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";

    private final HttpClient delegate;
    private final AuthService authService;

    /**
     * Wraps an HTTP client used for authenticated API calls.
     *
     * @param delegate    underlying HTTP client
     * @param authService source of the current token and refresh
     */
    public TokenRefreshingHttpClient(HttpClient delegate, AuthService authService) {
        this.delegate = delegate;
        this.authService = authService;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler) {
        return sendAttempt(new HttpRetry.Attempt(request), responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler)
                .thenCompose(response -> retryRequest(request, response.statusCode())
                        .thenCompose(retry -> retry == null
                                ? CompletableFuture.completedFuture(response)
                                : delegate.sendAsync(retry, responseBodyHandler, pushPromiseHandler)));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAttempt(HttpRetry.Attempt attempt,
            HttpResponse.BodyHandler<T> responseBodyHandler) {
        HttpRequest request = attempt.getRequest();
        return delegate.sendAsync(request, responseBodyHandler)
                .thenCompose(response -> {
                    if (attempt.isRefreshed()) {
                        return CompletableFuture.completedFuture(response);
                    }
                    return retryRequest(request, response.statusCode())
                            .thenCompose(retry -> {
                                if (retry == null) {
                                    return CompletableFuture.completedFuture(response);
                                }
                                attempt.markRefreshed(retry);
                                return delegate.sendAsync(retry, responseBodyHandler);
                            });
                });
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        HttpResponse<T> response = delegate.send(request, responseBodyHandler);
        HttpRequest retry;
        try {
            retry = retryRequest(request, response.statusCode()).join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            }
            throw e;
        }
        return retry == null ? response : delegate.send(retry, responseBodyHandler);
    }

    /**
     * Resolve the request to resend after a 401.
     *
     * @param request the request that was sent
     * @param status  the response status
     * @return the rebuilt request, null if the response stands, or the refresh error
     */
    private CompletableFuture<HttpRequest> retryRequest(HttpRequest request, int status) {
        if (status != 401 || !authService.canRefresh()) {
            return CompletableFuture.completedFuture(null);
        }

        String currentToken = authService.getToken();
        if (currentToken != null && !currentToken.isEmpty() && !currentToken.equals(bearerToken(request))) {
            return CompletableFuture.completedFuture(withBearerToken(request, currentToken));
        }

        return authService.refreshAsync().thenCompose(refreshed -> {
            String newToken = authService.getToken();
            if (refreshed && newToken != null && !newToken.isEmpty()) {
                return CompletableFuture.completedFuture(withBearerToken(request, newToken));
            }
            Throwable refreshError = authService.getLastRefreshError();
            return refreshError != null
                    ? CompletableFuture.failedFuture(refreshError)
                    : CompletableFuture.completedFuture(null);
        });
    }

    private static String bearerToken(HttpRequest request) {
        return request.headers().firstValue(AUTHORIZATION)
                .filter(value -> value.startsWith(BEARER))
                .map(value -> value.substring(BEARER.length()))
                .orElse(null);
    }

    /**
     * Copy a request, replacing its bearer token.
     *
     * @param original request to copy
     * @param token    access token to send
     * @return the rebuilt request
     */
    static HttpRequest withBearerToken(HttpRequest original, String token) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(original.uri())
                .method(original.method(), original.bodyPublisher().orElseGet(HttpRequest.BodyPublishers::noBody))
                .expectContinue(original.expectContinue());
        original.timeout().ifPresent(builder::timeout);
        original.version().ifPresent(builder::version);
        original.headers().map().forEach((name, values) -> {
            if (!AUTHORIZATION.equalsIgnoreCase(name)) {
                values.forEach(value -> builder.header(name, value));
            }
        });
        return builder.header(AUTHORIZATION, BEARER + token).build();
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    @Override
    public WebSocket.Builder newWebSocketBuilder() {
        return delegate.newWebSocketBuilder();
    }
}
