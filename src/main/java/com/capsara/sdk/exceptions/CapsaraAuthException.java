package com.capsara.sdk.exceptions;

import com.capsara.sdk.internal.http.ApiError;

/** Exception for authentication and authorization errors. */
public class CapsaraAuthException extends CapsaraException {

    public CapsaraAuthException(String message) {
        super(message, "AUTH_ERROR", 401, null, null);
    }

    public CapsaraAuthException(String message, String code, int statusCode,
            Object details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    public CapsaraAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    private CapsaraAuthException(ApiError error) {
        super(error);
    }

    private CapsaraAuthException(Throwable networkCause) {
        super(networkCause);
    }

    /**
     * An auth request failed before the server answered.
     *
     * @param cause the transport failure
     * @return exception with code NETWORK_ERROR, status 0 and {@code details.originalError}
     */
    public static CapsaraAuthException networkError(Throwable cause) {
        return new CapsaraAuthException(cause);
    }

    /** Creates an auth exception from a parsed API error. */
    public static CapsaraAuthException fromApiError(ApiError error) {
        return new CapsaraAuthException(error);
    }

    public static CapsaraAuthException invalidCredentials() {
        return new CapsaraAuthException("Invalid party ID or password", "AUTHENTICATION_FAILED", 401, null, null);
    }

    public static CapsaraAuthException tokenExpired() {
        return new CapsaraAuthException("Access token is invalid or has expired", "INVALID_TOKEN", 401, null, null);
    }

    public static CapsaraAuthException notAuthenticated() {
        return new CapsaraAuthException("Not authenticated. Call loginAsync() first.",
                "NOT_AUTHENTICATED", 0, null, null);
    }
}
