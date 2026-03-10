package com.capsara.sdk.exceptions;

import java.util.Map;

/** Base exception for all Capsara SDK errors. */
public class CapsaraException extends RuntimeException {

    private final String code;
    private final int statusCode;
    private final Map<String, Object> details;
    private final String responseBody;

    public CapsaraException(String message) {
        this(message, "SDK_ERROR", 0, null, null);
    }

    public CapsaraException(String message, Throwable cause) {
        this(message, "SDK_ERROR", 0, null, null, cause);
    }

    /**
     * Constructs a CapsaraException with detailed information.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details
     * @param responseBody raw response body
     */
    public CapsaraException(String message, String code, int statusCode,
            Map<String, Object> details, String responseBody) {
        super(message);
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        this.responseBody = truncateResponseBody(responseBody);
    }

    /**
     * Constructs a CapsaraException with detailed information and cause.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details
     * @param responseBody raw response body
     * @param cause        the cause of the exception
     */
    public CapsaraException(String message, String code, int statusCode,
            Map<String, Object> details, String responseBody, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        this.responseBody = truncateResponseBody(responseBody);
    }

    public String getCode() {
        return code;
    }

    /** HTTP status code, or 0 for client-side errors. */
    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public static CapsaraException networkError(Throwable cause) {
        return new CapsaraException("Network error: " + cause.getMessage(), "NETWORK_ERROR", 0, null, null, cause);
    }

    /** Creates an exception from an HTTP error response. */
    public static CapsaraException fromHttpResponse(int statusCode, String responseBody) {
        String message = "HTTP " + statusCode;
        if (responseBody != null && !responseBody.isEmpty()) {
            message += ": " + responseBody;
        }
        return new CapsaraException(message, "HTTP_ERROR", statusCode, null, responseBody);
    }

    /** Creates an exception from an HTTP error response with a cause. */
    public static CapsaraException fromHttpResponse(int statusCode, String responseBody, Throwable cause) {
        String message = "HTTP " + statusCode;
        if (responseBody != null && !responseBody.isEmpty()) {
            message += ": " + responseBody;
        }
        return new CapsaraException(message, "HTTP_ERROR", statusCode, null, responseBody, cause);
    }

    private static final int MAX_RESPONSE_BODY_LENGTH = 1024;

    private static String truncateResponseBody(String body) {
        if (body == null || body.length() <= MAX_RESPONSE_BODY_LENGTH) {
            return body;
        }
        return body.substring(0, MAX_RESPONSE_BODY_LENGTH) + "...[truncated]";
    }
}
