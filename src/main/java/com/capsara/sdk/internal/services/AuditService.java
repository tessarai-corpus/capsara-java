package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraAuditException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuditActions;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import com.capsara.sdk.models.GetAuditEntriesResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Audit trail service for audit entry operations. */
public final class AuditService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final RetryExecutor retryExecutor;

    /**
     * Constructs an AuditService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public AuditService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                        HttpTimeoutConfig timeout, String userAgent, ConcurrencyConfig concurrencyConfig) {
        this(httpClient, baseUrl, tokenSupplier, timeout, null, userAgent, concurrencyConfig);
    }

    /**
     * Constructs an AuditService with a retry configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retry             retry configuration, null for defaults
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public AuditService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                        HttpTimeoutConfig timeout, RetryConfig retry, String userAgent,
                        ConcurrencyConfig concurrencyConfig) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.retryExecutor = new RetryExecutor(httpClient, retry != null ? retry : RetryConfig.defaults(),
                concurrencyConfig, CapsaraAuditException::fromApiError, CapsaraAuditException::networkError);
    }

    /**
     * Get audit trail for a capsa.
     *
     * @param capsaId capsa ID
     * @param filters optional filters
     * @return paginated audit entries; an unreadable 2xx body gives an empty page
     */
    public CompletableFuture<GetAuditEntriesResponse> getAuditEntriesAsync(String capsaId,
                                                                            GetAuditEntriesFilters filters) {
        String queryString = buildQueryString(filters);
        String url = queryString.isEmpty()
                ? String.format("/api/capsas/%s/audit", capsaId)
                : String.format("/api/capsas/%s/audit?%s", capsaId, queryString);

        return retryExecutor.sendWithRetry(buildGetRequest(url), response -> {
            try {
                JsonNode root = OBJECT_MAPPER.readTree(response.body());
                if (root == null || !root.isObject()) {
                    return new GetAuditEntriesResponse();
                }
                if (!root.path("pagination").isObject()) {
                    ((ObjectNode) root).remove("pagination");
                }
                GetAuditEntriesResponse result = OBJECT_MAPPER.treeToValue(root, GetAuditEntriesResponse.class);
                return result != null ? result : new GetAuditEntriesResponse();
            } catch (JsonProcessingException | IllegalArgumentException e) {
                return new GetAuditEntriesResponse();
            }
        });
    }

    /**
     * Create audit entry for a capsa.
     *
     * @param capsaId capsa ID
     * @param entry   audit entry request
     * @return true on success
     */
    public CompletableFuture<Boolean> createAuditEntryAsync(String capsaId, CreateAuditEntryRequest entry) {
        if (AuditActions.LOG.equals(entry.getAction())
                && (entry.getDetails() == null || entry.getDetails().isEmpty())) {
            return CompletableFuture.failedFuture(CapsaraAuditException.missingDetails());
        }

        String jsonBody;
        try {
            jsonBody = OBJECT_MAPPER.writeValueAsString(entry);
        } catch (JsonProcessingException e) {
            return CompletableFuture.failedFuture(new CapsaraAuditException(
                    "Failed to serialize audit entry", "AUDIT_ERROR", 0, null, null));
        }
        String url = String.format("/api/capsas/%s/audit", capsaId);
        return retryExecutor.sendWithRetry(buildPostRequest(url, jsonBody), response -> true);
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

    private String buildQueryString(GetAuditEntriesFilters filters) {
        if (filters == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        appendParam(sb, "action", filters.getAction());
        appendParam(sb, "party", filters.getParty());
        if (filters.getPage() != null) {
            appendParam(sb, "page", filters.getPage().toString());
        }
        if (filters.getLimit() != null) {
            appendParam(sb, "limit", filters.getLimit().toString());
        }

        return sb.toString();
    }

    private void appendParam(StringBuilder sb, String key, String value) {
        if (value == null) {
            return;
        }
        if (sb.length() > 0) {
            sb.append('&');
        }
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
        sb.append('=');
        sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    }
}
