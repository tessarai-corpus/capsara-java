package com.capsara.sdk.exceptions;

import com.capsara.sdk.internal.http.ApiError;
import com.capsara.sdk.internal.http.ApiErrorParser;

import java.util.HashMap;
import java.util.Map;

/** Base exception for all Capsara SDK errors; API failures carry the server code verbatim. */
public class CapsaraException extends RuntimeException {

    private static final int MAX_RESPONSE_BODY_LENGTH = 1024;

    private final String code;
    private final int statusCode;
    private final transient Object details;
    private final String responseBody;
    private final Double retryAfter;
    private final String requestId;

    public CapsaraException(String message) {
        this(message, "SDK_ERROR", 0, null, null);
    }

    public CapsaraException(String message, Throwable cause) {
        this(message, "SDK_ERROR", 0, null, null, null, cause);
    }

    /**
     * Constructs a CapsaraException with detailed information.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details (map, list or string), may be null
     * @param responseBody raw response body
     */
    public CapsaraException(String message, String code, int statusCode,
            Object details, String responseBody) {
        this(message, code, statusCode, details, responseBody, null, null);
    }

    /**
     * Constructs a CapsaraException with every field.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details (map, list or string), may be null
     * @param responseBody raw response body
     * @param retryAfter   seconds the server asked the client to wait, may be null
     * @param cause        the cause of the exception, may be null
     */
    public CapsaraException(String message, String code, int statusCode,
            Object details, String responseBody, Double retryAfter, Throwable cause) {
        this(message, code, statusCode, details, responseBody, retryAfter, null, cause);
    }

    /**
     * Constructs a CapsaraException with every field, including the server request ID.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details (map, list or string), may be null
     * @param responseBody raw response body
     * @param retryAfter   seconds the server asked the client to wait, may be null
     * @param requestId    server request ID, may be null
     * @param cause        the cause of the exception, may be null
     */
    public CapsaraException(String message, String code, int statusCode, Object details, String responseBody,
            Double retryAfter, String requestId, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        this.responseBody = truncateResponseBody(responseBody);
        this.retryAfter = retryAfter;
        this.requestId = requestId;
    }

    /**
     * Copies a parsed API error into an exception of any SDK type.
     *
     * @param error parsed API error
     */
    protected CapsaraException(ApiError error) {
        this(error.getMessage(), error.getCode(), error.getStatusCode(), error.getDetails(),
                error.getResponseBody(), error.getRetryAfter(), error.getRequestId(), null);
    }

    /**
     * Builds a NETWORK_ERROR exception of any SDK type.
     *
     * @param cause the transport failure
     */
    protected CapsaraException(Throwable cause) {
        this("Network error: " + describe(cause), "NETWORK_ERROR", 0, originalError(cause), null, null,
                null, cause);
    }

    public String getCode() {
        return code;
    }

    /** HTTP status code, or 0 for client-side errors. */
    public int getStatusCode() {
        return statusCode;
    }

    /** Server details as sent: a Map, List, String or null. */
    public Object getDetails() {
        return details;
    }

    /** Server request ID from the error body, or null. */
    public String getRequestId() {
        return requestId;
    }

    public String getResponseBody() {
        return responseBody;
    }

    /** Seconds (fractions kept) the server asked the client to wait before retrying (429/503), or null. */
    public Double getRetryAfter() {
        return retryAfter;
    }

    /**
     * An API request failed before the server answered (connection failure or timeout).
     *
     * @param cause the transport failure
     * @return exception with code NETWORK_ERROR, status 0 and {@code details.originalError}
     */
    public static CapsaraException networkError(Throwable cause) {
        return new CapsaraException(cause);
    }

    /**
     * Details for an SDK-local failure.
     *
     * @param cause the underlying failure, may be null
     * @return a map with {@code originalError}, the cause's message
     */
    protected static Map<String, Object> originalError(Throwable cause) {
        Map<String, Object> details = new HashMap<>();
        details.put("originalError", describe(cause));
        return details;
    }

    /**
     * Message of a failure, or its type name when it has none.
     *
     * @param cause the failure, may be null
     * @return a non-null description
     */
    protected static String describe(Throwable cause) {
        if (cause == null) {
            return "Unknown error";
        }
        String message = cause.getMessage();
        return message != null && !message.isEmpty() ? message : cause.getClass().getSimpleName();
    }

    /**
     * A configured private key is not a usable RSA private key.
     *
     * @param which "current" or "previous"
     * @return exception with code INVALID_PRIVATE_KEY and status 0
     */
    public static CapsaraException invalidPrivateKey(String which) {
        return invalidPrivateKey(which, null);
    }

    /**
     * A configured private key is not usable while decrypting a capsa.
     *
     * @param which   "current" or "previous"
     * @param capsaId capsa being decrypted, or null when no capsa is involved
     * @return exception with code INVALID_PRIVATE_KEY, status 0 and {@code details.capsaId} when given
     */
    public static CapsaraException invalidPrivateKey(String which, String capsaId) {
        Map<String, Object> details = null;
        if (capsaId != null) {
            details = new HashMap<>();
            details.put("capsaId", capsaId);
        }
        return new CapsaraException("The " + which + " private key is not a usable RSA private key in PEM format.",
                "INVALID_PRIVATE_KEY", 0, details, null);
    }

    /**
     * No current private key is set for an operation that needs one.
     *
     * @return exception with code MISSING_PRIVATE_KEY and status 0
     */
    public static CapsaraException missingPrivateKey() {
        return new CapsaraException("Private key required. Call setPrivateKey() first.", "MISSING_PRIVATE_KEY", 0,
                null, null);
    }

    /**
     * The client has no logged-in party for an operation that needs one.
     *
     * @return exception with code NOT_LOGGED_IN and status 0
     */
    public static CapsaraException notLoggedIn() {
        return new CapsaraException("Creator identity not set. Call loginAsync() and setPrivateKey() first.",
                "NOT_LOGGED_IN", 0, null, null);
    }

    /**
     * A capsa cannot be built from the builder's content.
     *
     * @param message what was wrong
     * @param reason  machine-readable reason, such as NO_RECIPIENT or TOTAL_SIZE_EXCEEDED
     * @return exception with code BUILD_FAILED, status 0 and {@code details.reason}
     */
    public static CapsaraException buildFailed(String message, String reason) {
        Map<String, Object> details = new HashMap<>();
        details.put("reason", reason);
        return new CapsaraException(message, "BUILD_FAILED", 0, details, null);
    }

    /**
     * A caller-supplied value was rejected before any request.
     *
     * @param message what was wrong
     * @param details extra details, may be null
     * @return exception with code VALIDATION_ERROR and status 0
     */
    public static CapsaraException validationError(String message, Object details) {
        return new CapsaraException(message, "VALIDATION_ERROR", 0, details, null);
    }

    /** Creates an exception from a parsed API error. */
    public static CapsaraException fromApiError(ApiError error) {
        return new CapsaraException(error);
    }

    /** Creates an exception from an HTTP error response. */
    public static CapsaraException fromHttpResponse(int statusCode, String responseBody) {
        return fromApiError(ApiErrorParser.parse(statusCode, responseBody));
    }

    private static String truncateResponseBody(String body) {
        if (body == null || body.length() <= MAX_RESPONSE_BODY_LENGTH) {
            return body;
        }
        return body.substring(0, MAX_RESPONSE_BODY_LENGTH) + "...[truncated]";
    }
}
