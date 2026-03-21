package com.capsara.sdk.exceptions;

import java.util.Map;

/** Exception for audit-related errors. */
public class CapsaraAuditException extends CapsaraException {

    public CapsaraAuditException(String message) {
        super(message, "AUDIT_ERROR", 0, null, null);
    }

    public CapsaraAuditException(String message, String code, int statusCode,
            Map<String, Object> details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    public CapsaraAuditException(String message, Throwable cause) {
        super(message, cause);
    }

    /** Creates an audit exception from an HTTP error response. */
    public static CapsaraAuditException fromHttpResponse(int statusCode, String responseBody) {
        String message = "Audit HTTP " + statusCode;
        if (responseBody != null && !responseBody.isEmpty()) {
            message += ": " + responseBody;
        }
        return new CapsaraAuditException(message, "HTTP_ERROR", statusCode, null, responseBody);
    }

    public static CapsaraAuditException missingDetails() {
        return new CapsaraAuditException("'log' action requires details", "MISSING_DETAILS", 400, null, null);
    }

    public static CapsaraAuditException createFailed(String capsaId) {
        return new CapsaraAuditException("Failed to create audit entry for capsa: " + capsaId);
    }

    public static CapsaraAuditException invalidAction(String action) {
        return new CapsaraAuditException("Invalid audit action: " + action, "INVALID_ACTION", 400, null, null);
    }
}
