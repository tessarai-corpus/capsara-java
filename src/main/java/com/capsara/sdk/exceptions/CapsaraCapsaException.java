package com.capsara.sdk.exceptions;

import java.util.Map;

/** Exception for capsa-related errors. */
public class CapsaraCapsaException extends CapsaraException {

    public CapsaraCapsaException(String message) {
        super(message, "CAPSA_ERROR", 0, null, null);
    }

    public CapsaraCapsaException(String message, String code, int statusCode,
            Map<String, Object> details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    public CapsaraCapsaException(String message, Throwable cause) {
        super(message, cause);
    }

    /** Creates a capsa exception from an HTTP error response. */
    public static CapsaraCapsaException fromHttpResponse(int statusCode, String responseBody) {
        String message = "Capsa HTTP " + statusCode;
        if (responseBody != null && !responseBody.isEmpty()) {
            message += ": " + responseBody;
        }
        return new CapsaraCapsaException(message, "HTTP_ERROR", statusCode, null, responseBody);
    }

    public static CapsaraCapsaException capsaNotFound(String capsaId) {
        return new CapsaraCapsaException("Capsa not found: " + capsaId, "CAPSA_NOT_FOUND", 404, null, null);
    }

    public static CapsaraCapsaException fileNotFound(String fileId) {
        return new CapsaraCapsaException("File not found: " + fileId, "FILE_NOT_FOUND", 404, null, null);
    }

    public static CapsaraCapsaException accessDenied(Map<String, Object> details) {
        return new CapsaraCapsaException("Access denied to capsa", "ACCESS_DENIED", 403, details, null);
    }

    /** Creates an exception for authenticated-vs-claimed creator identity mismatch. */
    public static CapsaraCapsaException creatorMismatch(String authenticated, String claimed) {
        return new CapsaraCapsaException(
                String.format("Creator mismatch: authenticated as '%s' but creating as '%s'", authenticated, claimed),
                "CREATOR_MISMATCH", 403, null, null
        );
    }

    public static CapsaraCapsaException capsaDeleted(Map<String, Object> details) {
        return new CapsaraCapsaException("Capsa has been deleted", "CAPSA_DELETED", 410, details, null);
    }

    public static CapsaraCapsaException invalidContentType() {
        return new CapsaraCapsaException("Invalid content type", "INVALID_CONTENT_TYPE", 415, null, null);
    }

    /** Creates an exception for missing required parameters. */
    public static CapsaraCapsaException missingParams(String... parameters) {
        return new CapsaraCapsaException(
                "Missing required parameters: " + String.join(", ", parameters),
                "MISSING_PARAMS", 400, null, null
        );
    }

    /** Creates an exception for a failed file download. */
    public static CapsaraCapsaException downloadFailed(String capsaId, String fileId, Throwable cause) {
        return new CapsaraCapsaException(
                String.format("Failed to download file '%s' from capsa '%s'", fileId, capsaId),
                "DOWNLOAD_FAILED", 0, null, null
        );
    }

    public static CapsaraCapsaException decryptionFailed(String message, Throwable cause) {
        CapsaraCapsaException ex = new CapsaraCapsaException(message, cause);
        return ex;
    }

    public static CapsaraCapsaException signatureVerificationFailed() {
        return new CapsaraCapsaException("Signature verification failed", "SIGNATURE_INVALID", 0, null, null);
    }

    /** Creates an exception when a party is not found in the keychain. */
    public static CapsaraCapsaException notInKeychain(String partyId) {
        return new CapsaraCapsaException(
                "Party '" + partyId + "' not found in keychain",
                "NOT_IN_KEYCHAIN", 403, null, null
        );
    }
}
