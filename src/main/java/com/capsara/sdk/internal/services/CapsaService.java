package com.capsara.sdk.internal.services;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.http.RetryExecutor;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CapsaSummary;
import com.capsara.sdk.models.CursorPagination;
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
    private final KeyService keyService;
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
     * @param keyService        key service for fetching public keys
     * @param concurrencyConfig concurrency configuration for limiting parallel requests
     */
    public CapsaService(HttpClient httpClient, String baseUrl, Supplier<String> tokenSupplier,
                        HttpTimeoutConfig timeout, RetryConfig retryConfig, String userAgent,
                        KeyService keyService, ConcurrencyConfig concurrencyConfig) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.tokenSupplier = tokenSupplier;
        this.timeout = timeout != null ? timeout : HttpTimeoutConfig.defaults();
        this.userAgent = userAgent;
        this.keyService = keyService;
        this.concurrencyConfig = concurrencyConfig;
        this.retryExecutor = new RetryExecutor(httpClient,
                retryConfig != null ? retryConfig : RetryConfig.defaults(), concurrencyConfig);
    }

    /**
     * Get capsa by ID (encrypted).
     *
     * @param capsaId capsa ID
     * @return encrypted capsa
     */
    public CompletableFuture<Capsa> getCapsaAsync(String capsaId) {
        HttpRequest request = buildGetRequest("/api/capsas/" + capsaId);

        return retryExecutor.sendWithRetry(request, response -> {
            try {
                Capsa result = OBJECT_MAPPER.readValue(response.body(), Capsa.class);
                return result;
            } catch (CapsaraException e) {
                throw e;
            } catch (Exception e) {
                throw CapsaraException.networkError(e);
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

        return retryExecutor.sendWithRetry(request, response -> {
            try {
                CapsaListResponse data = OBJECT_MAPPER.readValue(response.body(), CapsaListResponse.class);

                // Defensive handling for null response data
                CapsaListResponse result = new CapsaListResponse();
                result.setCapsas(data != null && data.getCapsas() != null ? data.getCapsas() : new CapsaSummary[0]);

                CursorPagination pagination = new CursorPagination();
                if (data != null && data.getPagination() != null) {
                    pagination.setLimit(data.getPagination().getLimit());
                    pagination.setHasMore(data.getPagination().isHasMore());
                    pagination.setNextCursor(data.getPagination().getNextCursor());
                    pagination.setPrevCursor(data.getPagination().getPrevCursor());
                } else if (filters != null && filters.getLimit() != null) {
                    pagination.setLimit(filters.getLimit());
                }
                result.setPagination(pagination);

                return result;
            } catch (CapsaraException e) {
                throw e;
            } catch (Exception e) {
                throw CapsaraException.networkError(e);
            }
        });
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

    /**
     * Get creator's public key for signature verification.
     */
    public CompletableFuture<String> getCreatorPublicKeyAsync(String creatorId) {
        return keyService.fetchExplicitPartyKeyAsync(creatorId)
                .thenApply(key -> key != null ? key.getPublicKey() : null);
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
        if (filters.getHasLegalHold() != null) {
            appendParam(sb, "hasLegalHold", filters.getHasLegalHold().toString().toLowerCase());
        }
        if (filters.getLimit() != null) {
            appendParam(sb, "limit", filters.getLimit().toString());
        }
        appendParam(sb, "after", filters.getAfter());
        appendParam(sb, "before", filters.getBefore());

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
