package com.capsara.sdk.exceptions;

import com.capsara.sdk.internal.http.ApiError;
import com.capsara.sdk.internal.http.ApiErrorParser;

/** Exception for audit-related errors. */
public class CapsaraAuditException extends CapsaraException {

    public CapsaraAuditException(String message) {
        super(message, "AUDIT_ERROR", 0, null, null);
    }

    public CapsaraAuditException(String message, String code, int statusCode,
            Object details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    public CapsaraAuditException(String message, Throwable cause) {
        super(message, cause);
    }

    private CapsaraAuditException(ApiError error) {
        super(error);
    }

    private CapsaraAuditException(Throwable networkCause) {
        super(networkCause);
    }

    /**
     * An audit request failed before the server answered (connection failure or timeout).
     *
     * @param cause the transport failure
     * @return exception with code NETWORK_ERROR, status 0 and {@code details.originalError}
     */
    public static CapsaraAuditException networkError(Throwable cause) {
        return new CapsaraAuditException(cause);
    }

    /** Creates an audit exception from a parsed API error. */
    public static CapsaraAuditException fromApiError(ApiError error) {
        return new CapsaraAuditException(error);
    }

    /** Creates an audit exception from an HTTP error response. */
    public static CapsaraAuditException fromHttpResponse(int statusCode, String responseBody) {
        return fromApiError(ApiErrorParser.parse(statusCode, responseBody));
    }

    /**
     * A 'log' entry was created without details; checked before any request.
     *
     * @return exception with code MISSING_DETAILS and status 0
     */
    public static CapsaraAuditException missingDetails() {
        return new CapsaraAuditException("Details field is required for log action", "MISSING_DETAILS", 0,
                null, null);
    }

    public static CapsaraAuditException createFailed(String capsaId) {
        return new CapsaraAuditException("Failed to create audit entry for capsa: " + capsaId);
    }

    public static CapsaraAuditException invalidAction(String action) {
        return new CapsaraAuditException("Invalid audit action: " + action, "INVALID_ACTION", 400, null, null);
    }
}
