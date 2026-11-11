package com.capsara.sdk.exceptions;

import com.capsara.sdk.internal.http.ApiError;

/** Exception for account operations: public keys, key history and key rotation. */
public class CapsaraAccountException extends CapsaraException {

    /**
     * Constructs an account exception.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code, or 0 for client-side errors
     * @param details      additional error details, may be null
     * @param responseBody raw response body, may be null
     */
    public CapsaraAccountException(String message, String code, int statusCode,
            Object details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    private CapsaraAccountException(ApiError error) {
        super(error);
    }

    private CapsaraAccountException(Throwable networkCause) {
        super(networkCause);
    }

    /**
     * Creates an account exception from a parsed API error.
     *
     * @param error parsed API error
     * @return exception carrying the server code, status, details and request ID
     */
    public static CapsaraAccountException fromApiError(ApiError error) {
        return new CapsaraAccountException(error);
    }

    /**
     * An account request failed before the server answered (connection failure or timeout).
     *
     * @param cause the transport failure
     * @return exception with code NETWORK_ERROR, status 0 and {@code details.originalError}
     */
    public static CapsaraAccountException networkError(Throwable cause) {
        return new CapsaraAccountException(cause);
    }

    /**
     * The server answered 2xx with a body that is not a JSON object.
     *
     * @param responseBody raw response body, may be null
     * @return exception with code INVALID_RESPONSE and status 0
     */
    public static CapsaraAccountException invalidResponse(String responseBody) {
        return new CapsaraAccountException("Invalid response from the API.", "INVALID_RESPONSE", 0, null,
                responseBody);
    }
}
