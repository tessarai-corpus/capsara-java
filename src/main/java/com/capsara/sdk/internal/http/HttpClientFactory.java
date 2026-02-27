package com.capsara.sdk.internal.http;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

/** Factory for creating configured HTTP clients. */
public final class HttpClientFactory {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private HttpClientFactory() {
    }

    /** Creates an HTTP client with the given timeout configuration. */
    public static HttpClient create(HttpTimeoutConfig timeout) {
        return HttpClient.newBuilder()
                .connectTimeout(timeout != null ? timeout.getConnectTimeout() : Duration.ofSeconds(10))
                .build();
    }

    /** Creates an HTTP client configured for API requests. */
    public static HttpClient createForApi(HttpTimeoutConfig timeout) {
        return HttpClient.newBuilder()
                .connectTimeout(timeout != null ? timeout.getConnectTimeout() : Duration.ofSeconds(10))
                .build();
    }

    /** Creates an HTTP client configured for blob storage downloads. */
    public static HttpClient createForBlob(HttpTimeoutConfig timeout) {
        return HttpClient.newBuilder()
                .connectTimeout(timeout != null ? timeout.getConnectTimeout() : Duration.ofSeconds(10))
                .build();
    }

    public static HttpClient createDefault() {
        return create(HttpTimeoutConfig.defaults());
    }

    public static ObjectMapper getObjectMapper() {
        return OBJECT_MAPPER;
    }

    /** Builds an authenticated GET request with optional user agent and timeout. */
    public static HttpRequest buildGetRequest(String url, Supplier<String> tokenSupplier,
            String userAgent, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .header("Accept", "application/json");

        if (timeout != null) {
            builder.timeout(timeout);
        }

        if (tokenSupplier != null) {
            String token = tokenSupplier.get();
            if (token != null && !token.isEmpty()) {
                builder.header("Authorization", "Bearer " + token);
            }
        }

        if (userAgent != null && !userAgent.isEmpty()) {
            builder.header("User-Agent", userAgent);
        }

        return builder.build();
    }

    /** Builds an authenticated POST request with JSON body serialization. */
    public static HttpRequest buildPostRequest(String url, Object body,
            Supplier<String> tokenSupplier, String userAgent, Duration timeout) {
        try {
            String json = OBJECT_MAPPER.writeValueAsString(body);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json");

            if (timeout != null) {
                builder.timeout(timeout);
            }

            if (tokenSupplier != null) {
                String token = tokenSupplier.get();
                if (token != null && !token.isEmpty()) {
                    builder.header("Authorization", "Bearer " + token);
                }
            }

            if (userAgent != null && !userAgent.isEmpty()) {
                builder.header("User-Agent", userAgent);
            }

            return builder.build();
        } catch (Exception e) {
            throw new CapsaraException("Failed to serialize request body", e);
        }
    }

    /** Builds an authenticated DELETE request with optional user agent and timeout. */
    public static HttpRequest buildDeleteRequest(String url, Supplier<String> tokenSupplier,
            String userAgent, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .DELETE()
                .header("Accept", "application/json");

        if (timeout != null) {
            builder.timeout(timeout);
        }

        if (tokenSupplier != null) {
            String token = tokenSupplier.get();
            if (token != null && !token.isEmpty()) {
                builder.header("Authorization", "Bearer " + token);
            }
        }

        if (userAgent != null && !userAgent.isEmpty()) {
            builder.header("User-Agent", userAgent);
        }

        return builder.build();
    }

    /** Sends an async HTTP request and deserializes the JSON response. */
    public static <T> CompletableFuture<T> sendAsync(HttpClient client, HttpRequest request, Class<T> responseType) {
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() >= 200 && response.statusCode() < 300) {
                        try {
                            if (responseType == Void.class) {
                                return null;
                            }
                            return OBJECT_MAPPER.readValue(response.body(), responseType);
                        } catch (Exception e) {
                            throw new CapsaraException("Failed to parse response", e);
                        }
                    } else {
                        throw CapsaraException.fromHttpResponse(response.statusCode(), response.body(), null);
                    }
                });
    }

    public static CompletableFuture<HttpResponse<String>> sendRawAsync(HttpClient client, HttpRequest request) {
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sends request with semaphore-based concurrency limiting.
     * Uses dedicated executor for semaphore acquisition to prevent ForkJoinPool starvation.
     */
    public static <T> CompletableFuture<HttpResponse<T>> sendAsyncWithLimit(
            HttpClient client,
            HttpRequest request,
            HttpResponse.BodyHandler<T> handler,
            ConcurrencyConfig config) {

        Semaphore sem = config.getRequestSemaphore();

        return CompletableFuture.runAsync(() -> {
            try {
                sem.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CompletionException(e);
            }
        }, config.getResponseExecutor())
                .thenCompose(v -> client.sendAsync(request, handler))
                .whenComplete((response, ex) -> sem.release());
    }
}
