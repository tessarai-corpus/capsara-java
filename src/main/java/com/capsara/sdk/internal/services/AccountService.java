package com.capsara.sdk.internal.services;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.KeyHistoryEntry;
import com.capsara.sdk.models.KeyRotationResult;
import com.capsara.sdk.models.PublicKeyInfo;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Account management service for key rotation and account operations. */
public final class AccountService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;

    /**
     * Constructs an AccountService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public AccountService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                          HttpTimeoutConfig timeout, String userAgent, ConcurrencyConfig concurrencyConfig) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
    }

    /**
     * Get current active public key.
     *
     * @return current public key info or null if not set
     */
    public CompletableFuture<PublicKeyInfo> getCurrentPublicKeyAsync() {
        HttpRequest request = buildGetRequest("/api/account/key");

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenApplyAsync(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        return null;
                    }

                    try {
                        // API returns publicKeyFingerprint, not keyFingerprint
                        GetKeyResponse result = OBJECT_MAPPER.readValue(response.body(), GetKeyResponse.class);
                        if (result.publicKey == null) {
                            return null;
                        }

                        PublicKeyInfo info = new PublicKeyInfo();
                        info.setPublicKey(result.publicKey);
                        info.setKeyFingerprint(result.publicKeyFingerprint != null ? result.publicKeyFingerprint : "");
                        info.setActive(true);
                        return info;
                    } catch (Exception e) {
                        return null;
                    }
                }, concurrencyConfig.getResponseExecutor())
                .exceptionally(e -> null);
    }

    /**
     * Add new public key (auto-rotates: moves current to history).
     *
     * @param publicKey   new public key in PEM format
     * @param fingerprint SHA-256 fingerprint of the public key
     * @param reason      optional reason for key rotation
     * @return updated public key info
     */
    public CompletableFuture<PublicKeyInfo> addPublicKeyAsync(String publicKey, String fingerprint, String reason) {
        try {
            AddKeyRequest requestBody = new AddKeyRequest();
            requestBody.publicKey = publicKey;
            requestBody.publicKeyFingerprint = fingerprint;
            requestBody.reason = reason;

            String jsonBody = OBJECT_MAPPER.writeValueAsString(requestBody);
            HttpRequest request = buildPostRequest("/api/account/key", jsonBody);

            return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                    HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                    .thenApplyAsync(response -> {
                        if (response.statusCode() < 200 || response.statusCode() >= 300) {
                            throw CapsaraException.fromHttpResponse(response.statusCode(), response.body());
                        }

                        try {
                            AddKeyResponse result = OBJECT_MAPPER.readValue(response.body(), AddKeyResponse.class);

                            PublicKeyInfo info = new PublicKeyInfo();
                            info.setPublicKey(result.publicKey != null ? result.publicKey : publicKey);
                            info.setKeyFingerprint(
                                    result.publicKeyFingerprint != null
                                            ? result.publicKeyFingerprint : fingerprint);
                            info.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC).toString());
                            info.setActive(true);
                            return info;
                        } catch (CapsaraException e) {
                            throw e;
                        } catch (Exception e) {
                            throw CapsaraException.networkError(e);
                        }
                    }, concurrencyConfig.getResponseExecutor());
        } catch (Exception e) {
            return CompletableFuture.failedFuture(CapsaraException.networkError(e));
        }
    }

    /**
     * Get key history (all previous keys).
     *
     * @return array of historical keys (including current active key)
     */
    public CompletableFuture<KeyHistoryEntry[]> getKeyHistoryAsync() {
        HttpRequest request = buildGetRequest("/api/account/key/history");

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenApplyAsync(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        return new KeyHistoryEntry[0];
                    }

                    try {
                        KeyHistoryResponse result = OBJECT_MAPPER.readValue(response.body(), KeyHistoryResponse.class);
                        return result.keys != null ? result.keys : new KeyHistoryEntry[0];
                    } catch (Exception e) {
                        return new KeyHistoryEntry[0];
                    }
                }, concurrencyConfig.getResponseExecutor())
                .exceptionally(e -> new KeyHistoryEntry[0]);
    }

    /**
     * Rotate key: generate new key pair and update on server.
     * Application must store the returned private key securely.
     * The private key is never sent to the server.
     *
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync() {
        return KeyGenerator.generateKeyPairAsync()
                .thenCompose(keyPair ->
                        addPublicKeyAsync(keyPair.getPublicKey(), keyPair.getFingerprint(), null)
                                .thenApply(serverInfo -> {
                                    KeyRotationResult result = new KeyRotationResult();
                                    result.setKeyPair(keyPair);
                                    result.setServerInfo(serverInfo);
                                    return result;
                                })
                );
    }

    private HttpRequest buildGetRequest(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout.getRequestTimeout())
                .GET();

        addHeaders(builder);
        return builder.build();
    }

    private HttpRequest buildPostRequest(String path, String jsonBody) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout.getRequestTimeout())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));

        addHeaders(builder);
        return builder.build();
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

    private static final class GetKeyResponse {
        @JsonProperty("publicKey")
        public String publicKey;

        @JsonProperty("publicKeyFingerprint")
        public String publicKeyFingerprint;
    }

    private static final class AddKeyRequest {
        @JsonProperty("publicKey")
        public String publicKey;

        @JsonProperty("publicKeyFingerprint")
        public String publicKeyFingerprint;

        @JsonProperty("reason")
        public String reason;
    }

    private static final class AddKeyResponse {
        @JsonProperty("publicKey")
        public String publicKey;

        @JsonProperty("publicKeyFingerprint")
        public String publicKeyFingerprint;

        @JsonProperty("message")
        public String message;
    }

    private static final class KeyHistoryResponse {
        @JsonProperty("keys")
        public KeyHistoryEntry[] keys;
    }
}
