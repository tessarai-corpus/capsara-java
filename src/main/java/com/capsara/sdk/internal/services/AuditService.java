package com.capsara.sdk.internal.services;

import com.capsara.sdk.exceptions.CapsaraAuditException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuditActions;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import com.capsara.sdk.models.GetAuditEntriesResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Audit trail service for audit entry operations. */
public final class AuditService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final HttpClient httpClient;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;

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
        this.httpClient = httpClient;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
    }

    /**
     * Get audit trail for a capsa.
     *
     * @param capsaId capsa ID
     * @param filters optional filters
     * @return paginated audit entries
     */
    public CompletableFuture<GetAuditEntriesResponse> getAuditEntriesAsync(String capsaId,
                                                                            GetAuditEntriesFilters filters) {
        String queryString = buildQueryString(filters);
        String url = queryString.isEmpty()
                ? String.format("/api/capsas/%s/audit", capsaId)
                : String.format("/api/capsas/%s/audit?%s", capsaId, queryString);

        HttpRequest request = buildGetRequest(url);

        return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                .thenApplyAsync(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        throw CapsaraAuditException.fromHttpResponse(response.statusCode(), response.body());
                    }

                    try {
                        GetAuditEntriesResponse result =
                                OBJECT_MAPPER.readValue(response.body(), GetAuditEntriesResponse.class);
                        return result != null ? result : new GetAuditEntriesResponse();
                    } catch (CapsaraException e) {
                        throw e;
                    } catch (Exception e) {
                        throw CapsaraException.networkError(e);
                    }
                }, concurrencyConfig.getResponseExecutor());
    }

    /**
     * Create audit entry for a capsa.
     *
     * @param capsaId capsa ID
     * @param entry   audit entry request
     * @return true on success
     */
    public CompletableFuture<Boolean> createAuditEntryAsync(String capsaId, CreateAuditEntryRequest entry) {
        // Client-side validation: 'log' action requires details
        if (AuditActions.LOG.equals(entry.getAction()) &&
                (entry.getDetails() == null || entry.getDetails().isEmpty())) {
            return CompletableFuture.failedFuture(CapsaraAuditException.missingDetails());
        }

        try {
            String jsonBody = OBJECT_MAPPER.writeValueAsString(entry);
            String url = String.format("/api/capsas/%s/audit", capsaId);

            HttpRequest request = buildPostRequest(url, jsonBody);

            return HttpClientFactory.sendAsyncWithLimit(httpClient, request,
                    HttpResponse.BodyHandlers.ofString(), concurrencyConfig)
                    .thenApplyAsync(response -> {
                        if (response.statusCode() < 200 || response.statusCode() >= 300) {
                            throw CapsaraAuditException.fromHttpResponse(response.statusCode(), response.body());
                        }

                        return true;
                    }, concurrencyConfig.getResponseExecutor());
        } catch (Exception e) {
            return CompletableFuture.failedFuture(CapsaraException.networkError(e));
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
        if (value == null || value.isEmpty()) {
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
