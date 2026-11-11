package com.capsara.sdk.internal.services;

import com.capsara.sdk.HttpTimeoutConfig;
import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CapsaSummary;
import com.capsara.sdk.models.CursorPagination;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Capsa CRUD operations service. */
public final class CapsaService {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String baseUrl;
    private final Supplier<String> tokenSupplier;
    private final HttpTimeoutConfig timeout;
    private final String userAgent;
    private final ConcurrencyConfig concurrencyConfig;
    private final RetryExecutor retryExecutor;

    /**
     * Constructs a CapsaService with the specified configuration.
     *
     * @param httpClient        HTTP client for making requests
     * @param baseUrl           base URL for the API
     * @param tokenSupplier     supplier for authentication tokens
     * @param timeout           timeout configuration
     * @param retryConfig       retry configuration for 503/429 errors
     * @param userAgent         user agent string
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public CapsaService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                        HttpTimeoutConfig timeout, RetryConfig retryConfig, String userAgent,
                        ConcurrencyConfig concurrencyConfig) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.concurrencyConfig = concurrencyConfig;
        this.retryExecutor = new RetryExecutor(httpClient,
                retryConfig != null ? retryConfig : RetryConfig.defaults(), concurrencyConfig,
                CapsaraCapsaException::fromApiError, CapsaraCapsaException::networkError);
    }

    /**
     * Get capsa by ID (encrypted).
     *
     * @param capsaId capsa ID
     * @return encrypted capsa; a 2xx body that is not a JSON object fails with INVALID_RESPONSE
     */
    public CompletableFuture<Capsa> getCapsaAsync(String capsaId) {
        HttpRequest request = buildGetRequest("/api/capsas/" + capsaId);

        return retryExecutor.sendWithRetry(request, response -> {
            JsonNode root = readObject(response.body());
            if (root == null) {
                throw CapsaraCapsaException.invalidResponse(capsaId);
            }
            try {
                return OBJECT_MAPPER.treeToValue(root, Capsa.class);
            } catch (Exception e) {
                throw CapsaraCapsaException.invalidResponse(capsaId);
            }
        });
    }

    /**
     * List capsas with cursor-based pagination.
     *
     * @param filters query filters
     * @return paginated capsa list
     */
    public CompletableFuture<CapsaListResponse> listCapsasAsync(CapsaListFilters filters) {
        String queryString = buildQueryString(filters);
        String url = queryString.isEmpty() ? "/api/capsas" : "/api/capsas?" + queryString;

        HttpRequest request = buildGetRequest(url);

        return retryExecutor.sendWithRetry(request, response -> toListResponse(readObject(response.body()), filters));
    }

    private static CapsaListResponse toListResponse(JsonNode root, CapsaListFilters filters) {
        CapsaListResponse result = new CapsaListResponse();
        result.setCapsas(new CapsaSummary[0]);
        CapsaListResponse data = null;
        if (root != null) {
            try {
                data = OBJECT_MAPPER.treeToValue(root, CapsaListResponse.class);
            } catch (Exception e) {
                data = null;
            }
        }
        if (data != null && data.getCapsas() != null) {
            result.setCapsas(data.getCapsas());
        }

        CursorPagination pagination = new CursorPagination();
        JsonNode page = root != null ? root.get("pagination") : null;
        JsonNode limit = page != null ? page.get("limit") : null;
        if (limit != null && limit.isNumber()) {
            pagination.setLimit(limit.asInt());
        } else if (filters != null && filters.getLimit() != null) {
            pagination.setLimit(filters.getLimit());
        }
        if (data != null && data.getPagination() != null && page != null && page.isObject()) {
            pagination.setHasMore(data.getPagination().isHasMore());
            pagination.setNextCursor(data.getPagination().getNextCursor());
            pagination.setPrevCursor(data.getPagination().getPrevCursor());
        }
        result.setPagination(pagination);
        return result;
    }

    private static JsonNode readObject(String body) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(body);
            return root != null && root.isObject() ? root : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Soft delete a capsa.
     *
     * @param capsaId capsa ID
     */
    public CompletableFuture<Void> deleteCapsaAsync(String capsaId) {
        HttpRequest request = buildDeleteRequest("/api/capsas/" + capsaId);

        return retryExecutor.sendWithRetry(request, response -> (Void) null);
    }


    private HttpRequest buildGetRequest(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout.getRequestTimeout())
                .GET();

        addHeaders(builder);
        return builder.build();
    }

    private HttpRequest buildDeleteRequest(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout.getRequestTimeout())
                .DELETE();

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

    private String buildQueryString(CapsaListFilters filters) {
        if (filters == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        appendParam(sb, "status", filters.getStatus() != null ? filters.getStatus().toApiString() : null);
        appendParam(sb, "createdBy", filters.getCreatedBy());
        appendParam(sb, "startDate", filters.getStartDate());
        appendParam(sb, "endDate", filters.getEndDate());
        appendParam(sb, "expiringBefore", filters.getExpiringBefore());
        if (filters.getLimit() != null) {
            appendParam(sb, "limit", filters.getLimit().toString());
        }
        appendParam(sb, "after", filters.getAfter());
        appendParam(sb, "before", filters.getBefore());

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
