package com.capsara.sdk.internal.http;

import com.capsara.sdk.RetryConfig;
import javax.net.ssl.SSLException;
import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/** Retry policy shared by every HTTP call: 429/503, dropped connections, and timeouts except on POST. */
public final class HttpRetry {

    private static final Duration MAX_HINT = Duration.ofSeconds(30);
    private static final String[] DROP_MESSAGES = {
        "received no bytes", "connection reset", "broken pipe", "forcibly closed", "connection closed",
        "eof reached",
    };

    private HttpRetry() {
    }

    /**
     * Send a request, retrying under the shared policy.
     *
     * @param client      HTTP client
     * @param request     request to send
     * @param handler     response body handler
     * @param retryConfig retry configuration, null for defaults
     * @param concurrency concurrency limits, may be null
     * @param <T>         response body type
     * @return the final response (any status), or the last transport failure
     */
    public static <T> CompletableFuture<HttpResponse<T>> send(HttpClient client, HttpRequest request,
            HttpResponse.BodyHandler<T> handler, RetryConfig retryConfig, ConcurrencyConfig concurrency) {
        return attempt(client, new Attempt(request), handler,
                retryConfig != null ? retryConfig : RetryConfig.defaults(), concurrency, 0);
    }

    private static <T> CompletableFuture<HttpResponse<T>> attempt(HttpClient client, Attempt state,
            HttpResponse.BodyHandler<T> handler, RetryConfig config, ConcurrencyConfig concurrency, int retryCount) {
        CompletableFuture<HttpResponse<T>> sent = concurrency != null
                ? HttpClientFactory.sendAsyncWithLimit(() -> dispatch(client, state, handler), concurrency)
                : dispatch(client, state, handler);

        return sent.handle((response, error) -> {
            boolean canRetry = retryCount < config.getMaxRetries();
            if (error != null) {
                Throwable cause = unwrap(error);
                if (canRetry && isRetryableFailure(cause, state.getRequest().method())) {
                    return retryAfter(client, state, handler, config, concurrency, retryCount,
                            backoff(config, retryCount));
                }
                return CompletableFuture.<HttpResponse<T>>failedFuture(cause);
            }
            if (canRetry && isRetryableStatus(response.statusCode())) {
                Duration hint = ApiErrorParser.parse(response.statusCode(), bodyText(response.body()),
                        response.headers()).getRetryDelay();
                return retryAfter(client, state, handler, config, concurrency, retryCount,
                        delay(config, hint, retryCount));
            }
            return CompletableFuture.completedFuture(response);
        }).thenCompose(next -> next);
    }

    private static <T> CompletableFuture<HttpResponse<T>> dispatch(HttpClient client, Attempt state,
            HttpResponse.BodyHandler<T> handler) {
        return client instanceof AttemptSender
                ? ((AttemptSender) client).sendAttempt(state, handler)
                : client.sendAsync(state.getRequest(), handler);
    }

    private static <T> CompletableFuture<HttpResponse<T>> retryAfter(HttpClient client, Attempt state,
            HttpResponse.BodyHandler<T> handler, RetryConfig config, ConcurrencyConfig concurrency, int retryCount,
            Duration delay) {
        return CompletableFuture.supplyAsync(() -> null,
                        CompletableFuture.delayedExecutor(delay.toMillis(), TimeUnit.MILLISECONDS))
                .thenCompose(ignored -> attempt(client, state, handler, config, concurrency, retryCount + 1));
    }

    /** One logical request across its retries: the request to send next and whether its token was refreshed. */
    public static final class Attempt {
        private volatile HttpRequest request;
        private volatile boolean refreshed;

        /**
         * Starts tracking a request.
         *
         * @param request the request as first built
         */
        public Attempt(HttpRequest request) {
            this.request = request;
        }

        public HttpRequest getRequest() {
            return request;
        }

        public boolean isRefreshed() {
            return refreshed;
        }

        /**
         * Record the token refresh; later retries send the rebuilt request and never refresh again.
         *
         * @param rebuilt request carrying the new token
         */
        public void markRefreshed(HttpRequest rebuilt) {
            this.request = rebuilt;
            this.refreshed = true;
        }
    }

    /** A client that sends one attempt of a retried request and may update its state. */
    public interface AttemptSender {
        /**
         * Send the attempt's current request.
         *
         * @param attempt the request's retry state
         * @param handler response body handler
         * @param <T>     response body type
         * @return the response
         */
        <T> CompletableFuture<HttpResponse<T>> sendAttempt(Attempt attempt, HttpResponse.BodyHandler<T> handler);
    }

    /**
     * Whether a status is retried.
     *
     * @param status HTTP status
     * @return true for 429 and 503
     */
    public static boolean isRetryableStatus(int status) {
        return status == 429 || status == 503;
    }

    /**
     * Whether a transport failure is retried.
     *
     * @param cause  the failure, unwrapped
     * @param method HTTP method of the request
     * @return true for reset, dropped or refused connections, unresolved or unreachable hosts, and for
     *         timeouts unless the method is POST; false for TLS failures, cancellation and anything else
     */
    public static boolean isRetryableFailure(Throwable cause, String method) {
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return false;
            }
        }
        if (cause instanceof HttpTimeoutException) {
            return !"POST".equalsIgnoreCase(method);
        }
        for (Throwable t = cause; t != null && t != t.getCause(); t = t.getCause()) {
            if (isNetworkDrop(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNetworkDrop(Throwable t) {
        if (t instanceof SocketException || t instanceof UnknownHostException || t instanceof EOFException) {
            return true;
        }
        if (!(t instanceof IOException) || t.getMessage() == null) {
            return false;
        }
        String message = t.getMessage().toLowerCase(Locale.ROOT);
        for (String marker : DROP_MESSAGES) {
            if (message.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Delay before the next attempt.
     *
     * @param config     retry configuration
     * @param hint       server hint, may be null
     * @param retryCount retries made so far
     * @return the server hint capped at the maximum delay and 30 seconds, else exponential backoff
     */
    public static Duration delay(RetryConfig config, Duration hint, int retryCount) {
        if (hint != null) {
            Duration cap = config.getMaxDelay().compareTo(MAX_HINT) < 0 ? config.getMaxDelay() : MAX_HINT;
            return hint.compareTo(cap) > 0 ? cap : hint;
        }
        return backoff(config, retryCount);
    }

    /**
     * Exponential backoff with up to 30% jitter, capped at the maximum delay.
     *
     * @param config     retry configuration
     * @param retryCount retries made so far
     * @return the delay
     */
    public static Duration backoff(RetryConfig config, int retryCount) {
        long base = config.getDelayForAttempt(retryCount).toMillis();
        long jitter = (long) (ThreadLocalRandom.current().nextDouble() * 0.3 * base);
        Duration total = Duration.ofMillis(base + jitter);
        return total.compareTo(config.getMaxDelay()) > 0 ? config.getMaxDelay() : total;
    }

    /**
     * Strip future wrappers from a failure.
     *
     * @param error the failure
     * @return the underlying cause
     */
    public static Throwable unwrap(Throwable error) {
        Throwable cause = error;
        while ((cause instanceof CompletionException || cause instanceof ExecutionException)
                && cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    private static String bodyText(Object body) {
        if (body instanceof String) {
            return (String) body;
        }
        if (body instanceof byte[]) {
            return new String((byte[]) body, StandardCharsets.UTF_8);
        }
        return null;
    }
}
