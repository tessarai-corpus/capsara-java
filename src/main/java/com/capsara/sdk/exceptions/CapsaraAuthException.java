package com.capsara.sdk.exceptions;

import java.util.Map;

/** Exception for authentication and authorization errors. */
public class CapsaraAuthException extends CapsaraException {

    public CapsaraAuthException(String message) {
        super(message, "AUTH_ERROR", 401, null, null);
    }

    public CapsaraAuthException(String message, String code, int statusCode,
            Map<String, Object> details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    public CapsaraAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    public static CapsaraAuthException invalidCredentials() {
        return new CapsaraAuthException("Invalid email or password", "INVALID_CREDENTIALS", 401, null, null);
    }

    public static CapsaraAuthException tokenExpired() {
        return new CapsaraAuthException("Access token has expired", "TOKEN_EXPIRED", 401, null, null);
    }

    public static CapsaraAuthException notAuthenticated() {
        return new CapsaraAuthException("Not authenticated. Call loginAsync() first.",
                "NOT_AUTHENTICATED", 0, null, null);
    }
}
