package com.capsara.sdk.internal.http;

import java.time.Duration;

/** An API error response, reduced to the fields every service reports. */
public final class ApiError {

    private final int statusCode;
    private final String code;
    private final String message;
    private final Object details;
    private final Double retryAfter;
    private final Duration retryDelay;
    private final String responseBody;
    private final String requestId;

    /**
     * Creates a parsed API error.
     *
     * @param statusCode   HTTP status code
     * @param code         server error code, or HTTP_status when the body has none
     * @param message      server message, or the HTTP reason phrase
     * @param details      raw details value (map, list, string or number), or null
     * @param retryAfter   seconds (fractions kept) the server asked the client to wait, or null
     * @param retryDelay   exact wait the retry policy uses, or null
     * @param responseBody raw response body
     */
    public ApiError(int statusCode, String code, String message, Object details,
            Double retryAfter, Duration retryDelay, String responseBody) {
        this(statusCode, code, message, details, retryAfter, retryDelay, responseBody, null);
    }

    /**
     * Creates a parsed API error with the server request ID.
     *
     * @param statusCode   HTTP status code
     * @param code         server error code, or HTTP_status when the body has none
     * @param message      server message, or the HTTP reason phrase
     * @param details      raw details value (map, list, string or number), or null
     * @param retryAfter   seconds (fractions kept) the server asked the client to wait, or null
     * @param retryDelay   exact wait the retry policy uses, or null
     * @param responseBody raw response body
     * @param requestId    server request ID, or null
     */
    public ApiError(int statusCode, String code, String message, Object details,
            Double retryAfter, Duration retryDelay, String responseBody, String requestId) {
        this.statusCode = statusCode;
        this.code = code;
        this.message = message;
        this.details = details;
        this.retryAfter = retryAfter;
        this.retryDelay = retryDelay;
        this.responseBody = responseBody;
        this.requestId = requestId;
    }

    public String getRequestId() {
        return requestId;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public Object getDetails() {
        return details;
    }

    public Double getRetryAfter() {
        return retryAfter;
    }

    /**
     * Exact wait the server asked for, at millisecond precision.
     *
     * @return the server retry hint, or null
     */
    public Duration getRetryDelay() {
        return retryDelay;
    }

    public String getResponseBody() {
        return responseBody;
    }
}
