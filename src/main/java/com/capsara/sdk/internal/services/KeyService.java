package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.PartyKey;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Party key management for fetching public keys. */
public final class KeyService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    /** Server cap on ids per party-keys request. */
    static final int MAX_IDS_PER_REQUEST = 500;

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
     * Fetch party keys (with delegates), one request per 500 distinct ids, sent in sequence.
     *
     * @param partyIds array of party IDs
     * @return one party key per party ID across every request, delegate links merged, in first-seen order
     */
    public CompletableFuture<PartyKey[]> fetchPartyKeysAsync(String[] partyIds) {
        List<String> distinct = new ArrayList<>(new LinkedHashSet<>(Arrays.asList(partyIds)));
        CompletableFuture<Map<String, PartyKey>> all = CompletableFuture.completedFuture(new LinkedHashMap<>());
        for (int start = 0; start < Math.max(distinct.size(), 1); start += MAX_IDS_PER_REQUEST) {
            String[] chunk = distinct.subList(start, Math.min(start + MAX_IDS_PER_REQUEST, distinct.size()))
                    .toArray(new String[0]);
            all = all.thenCompose(collected -> fetchChunkAsync(chunk).thenApply(keys -> {
                for (PartyKey key : keys) {
                    collected.merge(key.getId(), key, KeyService::mergePartyKey);
                }
                return collected;
            }));
        }
        return all.thenApply(keys -> keys.values().toArray(new PartyKey[0]));
    }

    private static PartyKey mergePartyKey(PartyKey existing, PartyKey next) {
        LinkedHashSet<String> actingFor = new LinkedHashSet<>();
        if (existing.getIsDelegate() != null) {
            actingFor.addAll(Arrays.asList(existing.getIsDelegate()));
        }
        if (next.getIsDelegate() != null) {
            actingFor.addAll(Arrays.asList(next.getIsDelegate()));
        }
        if (actingFor.isEmpty()) {
            if (existing.getIsDelegate() == null && next.getIsDelegate() != null) {
                existing.setIsDelegate(next.getIsDelegate());
            }
            return existing;
        }
        existing.setIsDelegate(actingFor.toArray(new String[0]));
        return existing;
    }

    private CompletableFuture<PartyKey[]> fetchChunkAsync(String[] partyIds) {
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

            return retryExecutor.sendWithRetry(builder.build(), response -> parseParties(response.body()));
        } catch (Exception e) {
            return CompletableFuture.failedFuture(
                    new CapsaraException("Failed to serialize request body", "INVALID_REQUEST", 0, null, null));
        }
    }

    private static PartyKey[] parseParties(String body) {
        JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(body);
        } catch (Exception e) {
            root = null;
        }
        if (root == null || !root.isObject()) {
            throw invalidResponse(body);
        }
        try {
            PartyKeysResponse result = OBJECT_MAPPER.treeToValue(root, PartyKeysResponse.class);
            return result.parties != null ? result.parties : new PartyKey[0];
        } catch (Exception e) {
            throw invalidResponse(body);
        }
    }

    private static CapsaraException invalidResponse(String body) {
        return new CapsaraException("Invalid response from the API.", "INVALID_RESPONSE", 0, null, body);
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
