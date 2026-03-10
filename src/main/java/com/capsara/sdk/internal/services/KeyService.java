package com.capsara.sdk.internal.services;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.PartyKey;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Party key management for fetching public keys. */
public final class KeyService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final RetryExecutor retryExecutor;

    /**
     * Constructs a KeyService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retry             retry configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public KeyService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                      HttpTimeoutConfig timeout, RetryConfig retry, String userAgent,
                      ConcurrencyConfig concurrencyConfig) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.retryExecutor = new RetryExecutor(httpClient,
                retry != null ? retry : RetryConfig.defaults(), concurrencyConfig);
    }

    /**
     * Fetch a single party key by exact ID (excludes delegates).
     *
     * @param partyId party ID to fetch
     * @return party key or null if not found
     */
    public CompletableFuture<PartyKey> fetchExplicitPartyKeyAsync(String partyId) {
        return fetchPartyKeysAsync(new String[]{partyId})
                .thenApply(parties -> {
                    for (PartyKey party : parties) {
                        if (party.getId().equals(partyId)) {
                            return party;
                        }
                    }
                    return null;
                });
    }

    /**
     * Fetch party keys from API (includes delegates).
     * Uses POST to avoid URL length limits with large batches.
     *
     * @param partyIds array of party IDs
     * @return array of party keys
     */
    public CompletableFuture<PartyKey[]> fetchPartyKeysAsync(String[] partyIds) {
        try {
            PartyIdsRequest requestBody = new PartyIdsRequest();
            requestBody.ids = partyIds;
            String jsonBody = OBJECT_MAPPER.writeValueAsString(requestBody);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/party/keys"))
                    .timeout(timeout.getRequestTimeout())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));

            addHeaders(builder);

            return retryExecutor.sendWithRetry(builder.build(), response -> {
                try {
                    PartyKeysResponse result = OBJECT_MAPPER.readValue(response.body(), PartyKeysResponse.class);
                    return result.parties != null ? result.parties : new PartyKey[0];
                } catch (CapsaraException e) {
                    throw e;
                } catch (Exception e) {
                    throw CapsaraException.networkError(e);
                }
            });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(CapsaraException.networkError(e));
        }
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

    private static final class PartyIdsRequest {
        @JsonProperty("ids")
        public String[] ids;
    }

    private static final class PartyKeysResponse {
        @JsonProperty("parties")
        public PartyKey[] parties;
    }
}
