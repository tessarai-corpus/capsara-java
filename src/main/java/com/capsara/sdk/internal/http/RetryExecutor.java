package com.capsara.sdk.internal.http;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/** Sends API requests under the shared retry policy and maps failures to SDK exceptions. */
public final class RetryExecutor {

    private final HttpClient httpClient;
    private final RetryConfig retryConfig;
    private final ConcurrencyConfig concurrencyConfig;
    private final Function<ApiError, ? extends CapsaraException> errorFactory;
    private final Function<Throwable, ? extends CapsaraException> networkErrorFactory;

    /** Creates a retry executor that reports API failures as {@link CapsaraException}. */
    public RetryExecutor(HttpClient httpClient, RetryConfig retryConfig, ConcurrencyConfig concurrencyConfig) {
        this(httpClient, retryConfig, concurrencyConfig, CapsaraException::fromApiError,
                CapsaraException::networkError);
    }

    /**
     * Creates a retry executor.
     *
     * @param httpClient        HTTP client
     * @param retryConfig       retry configuration
     * @param concurrencyConfig concurrency configuration
     * @param errorFactory      builds the calling service's exception type from a parsed API error
     * @param networkErrorFactory builds the calling service's NETWORK_ERROR from a transport failure
     */
    public RetryExecutor(HttpClient httpClient, RetryConfig retryConfig, ConcurrencyConfig concurrencyConfig,
            Function<ApiError, ? extends CapsaraException> errorFactory,
            Function<Throwable, ? extends CapsaraException> networkErrorFactory) {
        this.httpClient = httpClient;
        this.retryConfig = retryConfig != null ? retryConfig : RetryConfig.defaults();
        this.concurrencyConfig = concurrencyConfig;
        this.errorFactory = errorFactory;
        this.networkErrorFactory = networkErrorFactory;
    }

    /**
     * Send a request and convert a 2xx response.
     *
     * @param request         request to send
     * @param responseHandler converts a 2xx response
     * @param <T>             result type
     * @return the converted result, or the mapped API or network error
     */
    public <T> CompletableFuture<T> sendWithRetry(
            HttpRequest request,
            Function<HttpResponse<String>, T> responseHandler) {
        return sendWithRetryRaw(request).thenApply(response -> {
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                throw errorFactory.apply(ApiErrorParser.parse(status, response.body(), response.headers()));
            }
            return responseHandler.apply(response);
        });
    }

    /**
     * Send a request and return the final response whatever its status.
     *
     * @param request request to send
     * @return the final response, or a network error once retries are exhausted
     */
    public CompletableFuture<HttpResponse<String>> sendWithRetryRaw(HttpRequest request) {
        return HttpRetry.send(httpClient, request, HttpResponse.BodyHandlers.ofString(), retryConfig,
                        concurrencyConfig)
                .exceptionallyCompose(error -> {
                    Throwable cause = HttpRetry.unwrap(error);
                    return CompletableFuture.failedFuture(cause instanceof CapsaraException
                            ? cause
                            : networkErrorFactory.apply(cause));
                });
    }
}
