package com.capsara.sdk.exceptions;

import com.capsara.sdk.internal.http.ApiError;
import com.capsara.sdk.internal.http.ApiErrorParser;

import java.util.HashMap;
import java.util.Map;

/** Exception for capsa-related errors. */
public class CapsaraCapsaException extends CapsaraException {

    public CapsaraCapsaException(String message) {
        super(message, "CAPSA_ERROR", 0, null, null);
    }

    public CapsaraCapsaException(String message, String code, int statusCode,
            Object details, String responseBody) {
        super(message, code, statusCode, details, responseBody);
    }

    /**
     * Constructs a capsa exception with every field.
     *
     * @param message      error message
     * @param code         error code
     * @param statusCode   HTTP status code
     * @param details      additional error details, may be null
     * @param responseBody raw response body
     * @param retryAfter   seconds the server asked the client to wait, may be null
     * @param cause        the cause of the exception, may be null
     */
    public CapsaraCapsaException(String message, String code, int statusCode,
            Object details, String responseBody, Double retryAfter, Throwable cause) {
        super(message, code, statusCode, details, responseBody, retryAfter, cause);
    }

    public CapsaraCapsaException(String message, Throwable cause) {
        super(message, cause);
    }

    private CapsaraCapsaException(ApiError error) {
        super(error);
    }

    private CapsaraCapsaException(Throwable networkCause) {
        super(networkCause);
    }

    /** Creates a capsa exception from a parsed API error. */
    public static CapsaraCapsaException fromApiError(ApiError error) {
        return new CapsaraCapsaException(error);
    }

    /**
     * A capsa request failed before the server answered (connection failure or timeout).
     *
     * @param cause the transport failure
     * @return exception with code NETWORK_ERROR, status 0 and {@code details.originalError}
     */
    public static CapsaraCapsaException networkError(Throwable cause) {
        return new CapsaraCapsaException(cause);
    }

    /**
     * The server answered 2xx with a body that is not a JSON object.
     *
     * @param capsaId capsa requested
     * @return exception with code INVALID_RESPONSE, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException invalidResponse(String capsaId) {
        return new CapsaraCapsaException("Invalid response from the API for capsa " + capsaId + ".",
                "INVALID_RESPONSE", 0, capsaDetails(capsaId), null);
    }

    /**
     * The download-URL request answered 2xx with a body that is not a JSON object.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @return exception with code INVALID_RESPONSE, status 0 and details capsaId and fileId
     */
    public static CapsaraCapsaException invalidResponse(String capsaId, String fileId) {
        return new CapsaraCapsaException("Invalid download response from the API for file " + fileId
                + " in capsa " + capsaId + ".", "INVALID_RESPONSE", 0, fileDetails(capsaId, fileId), null);
    }

    /** Creates a capsa exception from an HTTP error response. */
    public static CapsaraCapsaException fromHttpResponse(int statusCode, String responseBody) {
        return fromApiError(ApiErrorParser.parse(statusCode, responseBody));
    }

    /**
     * The capsa's recipient has no registered public key.
     *
     * @param partyId recipient party ID
     * @return exception with code RECIPIENT_KEY_NOT_FOUND
     */
    public static CapsaraCapsaException recipientKeyNotFound(String partyId) {
        Map<String, Object> details = new HashMap<>();
        details.put("partyId", partyId);
        return new CapsaraCapsaException("Recipient " + partyId + " has no registered public key",
                "RECIPIENT_KEY_NOT_FOUND", 0, details, null);
    }

    public static CapsaraCapsaException capsaNotFound(String capsaId) {
        return new CapsaraCapsaException("Capsa not found: " + capsaId, "ENVELOPE_NOT_FOUND", 404, null, null);
    }

    /**
     * The requested file is not part of the capsa.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @return exception with code FILE_NOT_FOUND, status 0 and details capsaId and fileId
     */
    public static CapsaraCapsaException fileNotFound(String capsaId, String fileId) {
        return new CapsaraCapsaException("File " + fileId + " not found in capsa " + capsaId,
                "FILE_NOT_FOUND", 0, fileDetails(capsaId, fileId), null);
    }

    /**
     * The caller's encrypted key does not have the RSA-4096 length.
     *
     * @param capsaId capsa being decrypted
     * @param length  decoded length in bytes
     * @return exception with code INVALID_ENCRYPTED_KEY, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException invalidEncryptedKey(String capsaId, int length) {
        return new CapsaraCapsaException("Encrypted key for capsa " + capsaId + " is " + length
                + " bytes; expected 512 (RSA-4096).", "INVALID_ENCRYPTED_KEY", 0, capsaDetails(capsaId), null);
    }

    /**
     * The master key could not be decrypted with the selected private key, or is not 32 bytes.
     *
     * @param capsaId capsa being decrypted
     * @param cause   the underlying failure, may be null
     * @return exception with code KEY_DECRYPTION_FAILED, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException keyDecryptionFailed(String capsaId, Throwable cause) {
        return new CapsaraCapsaException("Master key decryption failed for capsa " + capsaId + ": "
                + describe(cause), "KEY_DECRYPTION_FAILED", 0, capsaDetails(capsaId), null, null, cause);
    }

    /**
     * The subject, body or structured data could not be decrypted or parsed.
     *
     * @param capsaId capsa being decrypted
     * @param cause   the underlying failure
     * @return exception with code CONTENT_DECRYPTION_FAILED, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException contentDecryptionFailed(String capsaId, Throwable cause) {
        return new CapsaraCapsaException("Content decryption failed for capsa " + capsaId + ": "
                + describe(cause), "CONTENT_DECRYPTION_FAILED", 0, capsaDetails(capsaId), null, null, cause);
    }

    private static Map<String, Object> fileDetails(String capsaId, String fileId) {
        Map<String, Object> details = capsaDetails(capsaId);
        details.put("fileId", fileId);
        return details;
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
        return new CapsaraCapsaException("Capsa has been deleted", "ENVELOPE_DELETED", 410, details, null);
    }

    public static CapsaraCapsaException capsaExpired(Map<String, Object> details) {
        return new CapsaraCapsaException("Capsa has expired", "ENVELOPE_EXPIRED", 410, details, null);
    }

    public static CapsaraCapsaException invalidContentType() {
        return new CapsaraCapsaException("Invalid content type", "INVALID_CONTENT_TYPE", 400, null, null);
    }

    /** Creates an exception for missing required parameters. */
    public static CapsaraCapsaException missingParams(String... parameters) {
        return new CapsaraCapsaException(
                "Missing required parameters: " + String.join(", ", parameters),
                "MISSING_PARAMS", 400, null, null
        );
    }

    /**
     * Fetching, decrypting or decompressing a file failed after its download URL was issued.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @param cause   the underlying failure
     * @return exception with code DOWNLOAD_FAILED, status 0 and details capsaId, fileId and originalError
     */
    public static CapsaraCapsaException downloadFailed(String capsaId, String fileId, Throwable cause) {
        String reason = describe(cause);
        Map<String, Object> details = capsaDetails(capsaId);
        details.put("fileId", fileId);
        details.put("originalError", reason);
        return new CapsaraCapsaException(
                "Failed to download file " + fileId + " from capsa " + capsaId + ": " + reason,
                "DOWNLOAD_FAILED", 0, details, null, null, cause);
    }

    public static CapsaraCapsaException decryptionFailed(String message, Throwable cause) {
        return new CapsaraCapsaException(message, cause);
    }

    /**
     * The creator's signature, or its binding to this capsa, did not verify.
     *
     * @param capsaId capsa being verified
     * @param creator capsa creator, may be null
     * @param reason  why verification failed
     * @return the exception, with {@code details.capsaId}
     */
    public static CapsaraCapsaException signatureVerificationFailed(String capsaId, String creator, String reason) {
        return new CapsaraCapsaException(
                "Signature verification failed: " + reason + " (capsa: " + capsaId + ", creator: " + creator + ").",
                "SIGNATURE_VERIFICATION_FAILED", 0, capsaDetails(capsaId), null);
    }

    /**
     * The capsa carries no creator public key to verify its signature with.
     *
     * @param capsaId capsa being verified
     * @return the exception, with {@code details.capsaId}
     */
    public static CapsaraCapsaException signatureKeyMissing(String capsaId) {
        return new CapsaraCapsaException(
                "Capsa " + capsaId + " has no creator public key; its signature cannot be verified.",
                "SIGNATURE_KEY_MISSING", 0, capsaDetails(capsaId), null);
    }

    /**
     * The creator public key on the capsa is not the key the creator's keychain entry names.
     *
     * @param capsaId  capsa being verified
     * @param expected fingerprint on the creator's keychain entry
     * @param actual   fingerprint of the capsa's creator public key
     * @return the exception, with {@code details.capsaId}, {@code details.expected} and {@code details.actual}
     */
    public static CapsaraCapsaException signatureKeyMismatch(String capsaId, String expected, String actual) {
        Map<String, Object> details = capsaDetails(capsaId);
        details.put("expected", expected);
        details.put("actual", actual);
        return new CapsaraCapsaException(
                "Creator public key on capsa " + capsaId + " does not match the creator's keychain fingerprint.",
                "SIGNATURE_KEY_MISMATCH", 0, details, null);
    }

    private static Map<String, Object> capsaDetails(String capsaId) {
        Map<String, Object> details = new HashMap<>();
        details.put("capsaId", capsaId);
        return details;
    }

    /**
     * None of the configured private keys matches the key the capsa was encrypted to.
     *
     * @param capsaId     capsa being decrypted
     * @param fingerprint fingerprint named by the caller's keychain entry, may be null
     * @return the exception, with {@code details.capsaId} and {@code details.fingerprint}
     */
    public static CapsaraCapsaException privateKeyNotAvailable(String capsaId, String fingerprint) {
        return new CapsaraCapsaException(
                "No configured private key matches the key capsa " + capsaId + " was encrypted to. "
                        + "Add the previous private key with addPreviousPrivateKey().",
                "PRIVATE_KEY_NOT_AVAILABLE", 0, keyDetails(capsaId, fingerprint), null);
    }

    /**
     * The caller's keychain entry cannot be picked because no party ID was given and the keychain has several.
     *
     * @param capsaId    capsa being decrypted
     * @param entryCount number of keychain entries
     * @return the exception, with {@code details.capsaId} and a null {@code details.fingerprint}
     */
    public static CapsaraCapsaException callerEntryAmbiguous(String capsaId, int entryCount) {
        return new CapsaraCapsaException(
                "Capsa keychain has " + entryCount + " entries and no party ID was given. "
                        + "Cannot pick the caller's entry.",
                "PRIVATE_KEY_NOT_AVAILABLE", 0, keyDetails(capsaId, null), null);
    }

    private static Map<String, Object> keyDetails(String capsaId, String fingerprint) {
        Map<String, Object> details = new HashMap<>();
        details.put("capsaId", capsaId);
        details.put("fingerprint", fingerprint);
        return details;
    }

    /**
     * The capsa keychain has no entry for the caller.
     *
     * @param capsaId capsa being decrypted
     * @param partyId caller's party ID, may be null
     * @return exception with code NOT_IN_KEYCHAIN, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException notInKeychain(String capsaId, String partyId) {
        String who = partyId != null ? "Party " + partyId : "The caller";
        return new CapsaraCapsaException(who + " has no entry in the keychain of capsa " + capsaId + ".",
                "NOT_IN_KEYCHAIN", 0, capsaDetails(capsaId), null);
    }

    /**
     * The caller's keychain entry carries no encrypted key, as for a delegated recipient.
     *
     * @param capsaId capsa being decrypted
     * @param partyId party of the entry
     * @return exception with code NO_ENCRYPTED_KEY, status 0 and {@code details.capsaId}
     */
    public static CapsaraCapsaException noEncryptedKey(String capsaId, String partyId) {
        return new CapsaraCapsaException("Party " + partyId + " has no encrypted key in the keychain of capsa "
                + capsaId + ". It may be a delegated recipient without direct access.",
                "NO_ENCRYPTED_KEY", 0, capsaDetails(capsaId), null);
    }
}
