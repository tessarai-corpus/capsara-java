package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAccountException;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.KeyHistoryEntry;
import com.capsara.sdk.models.KeyRotationResult;
import com.capsara.sdk.models.PublicKeyInfo;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Account management service for key rotation and account operations. */
public final class AccountService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final RetryExecutor retryExecutor;

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
        this(httpClient, baseUrl, tokenSupplier, timeout, null, userAgent, concurrencyConfig);
    }

    /**
     * Constructs an AccountService with a retry configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retry             retry configuration, null for defaults
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public AccountService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                          HttpTimeoutConfig timeout, RetryConfig retry, String userAgent,
                          ConcurrencyConfig concurrencyConfig) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.retryExecutor = new RetryExecutor(httpClient, retry != null ? retry : RetryConfig.defaults(),
                concurrencyConfig, CapsaraAccountException::fromApiError, CapsaraAccountException::networkError);
    }

    /**
     * Get current active public key; failures throw rather than report no key.
     *
     * @return current public key info, or null if the party has no key
     */
    public CompletableFuture<PublicKeyInfo> getCurrentPublicKeyAsync() {
        HttpRequest request = buildGetRequest("/api/account/key");

        return retryExecutor.sendWithRetry(request, response -> {
            GetKeyResponse result = parse(response.body(), GetKeyResponse.class);
            if (result.publicKey == null || result.publicKey.isEmpty()) {
                return null;
            }

            PublicKeyInfo info = new PublicKeyInfo();
            info.setPublicKey(result.publicKey);
            info.setKeyFingerprint(result.publicKeyFingerprint != null ? result.publicKeyFingerprint : "");
            info.setActive(true);
            return info;
        });
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
            requestBody.reason = reason != null && !reason.isEmpty() ? reason : null;

            String jsonBody = OBJECT_MAPPER.writeValueAsString(requestBody);
            HttpRequest request = buildPostRequest("/api/account/key", jsonBody);

            return retryExecutor.sendWithRetry(request, response -> {
                AddKeyResponse result = parse(response.body(), AddKeyResponse.class);
                PublicKeyInfo info = new PublicKeyInfo();
                info.setPublicKey(result.publicKey != null ? result.publicKey : publicKey);
                info.setKeyFingerprint(
                        result.publicKeyFingerprint != null
                                ? result.publicKeyFingerprint : fingerprint);
                info.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC).toString());
                info.setActive(true);
                return info;
            });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(new CapsaraAccountException("Failed to serialize request body",
                    "ACCOUNT_ERROR", 0, null, null));
        }
    }

    /**
     * Get keys this party rotated away from, newest first (current key excluded).
     *
     * @return historical keys
     */
    public CompletableFuture<KeyHistoryEntry[]> getKeyHistoryAsync() {
        HttpRequest request = buildGetRequest("/api/account/key/history");

        return retryExecutor.sendWithRetry(request, response -> {
            KeyHistoryResponse result = parse(response.body(), KeyHistoryResponse.class);
            return result.keyHistory != null ? result.keyHistory : new KeyHistoryEntry[0];
        });
    }

    /**
     * Rotate key: generate a new key pair and register its public key.
     *
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync() {
        return rotateKeyAsync(null, null);
    }

    /**
     * Rotate key, handing the new key pair to the caller before its public key is registered.
     *
     * @param onKeyPairGenerated receives the new key pair before the request; if it throws, nothing is sent
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync(Consumer<GeneratedKeyPairResult> onKeyPairGenerated) {
        return rotateKeyAsync(onKeyPairGenerated, null);
    }

    /**
     * Rotate key, handing the new key pair to the caller before its public key is registered.
     *
     * @param onKeyPairGenerated receives the new key pair before the request; if it throws, nothing is sent
     * @param reason             rotation reason recorded in key history, may be null
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync(Consumer<GeneratedKeyPairResult> onKeyPairGenerated,
            String reason) {
        return KeyGenerator.generateKeyPairAsync()
                .thenCompose(keyPair -> {
                    if (onKeyPairGenerated != null) {
                        onKeyPairGenerated.accept(keyPair);
                    }
                    return addPublicKeyAsync(keyPair.getPublicKey(), keyPair.getFingerprint(), reason)
                            .thenApply(serverInfo -> {
                                KeyRotationResult result = new KeyRotationResult();
                                result.setKeyPair(keyPair);
                                result.setServerInfo(serverInfo);
                                return result;
                            });
                });
    }

    private static <T> T parse(String body, Class<T> type) {
        JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(body);
        } catch (Exception e) {
            throw CapsaraAccountException.invalidResponse(body);
        }
        if (root == null || !root.isObject()) {
            throw CapsaraAccountException.invalidResponse(body);
        }
        try {
            return OBJECT_MAPPER.treeToValue(root, type);
        } catch (Exception e) {
            throw CapsaraAccountException.invalidResponse(body);
        }
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
        @JsonProperty("keyHistory")
        public KeyHistoryEntry[] keyHistory;
    }
}
