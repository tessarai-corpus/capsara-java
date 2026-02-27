package com.capsara.sdk.exceptions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for SDK exception classes and error handling.
 */
class ExceptionTest {

    // CapsaraException Constructor Tests

    @Test
    void capsaraException_withMessage_setsMessage() {
        CapsaraException exception = new CapsaraException("Test error message");

        assertThat(exception.getMessage()).isEqualTo("Test error message");
        assertThat(exception.getCode()).isEqualTo("SDK_ERROR");
        assertThat(exception.getStatusCode()).isEqualTo(0);
    }

    @Test
    void capsaraException_withEmptyMessage_setsEmptyMessage() {
        CapsaraException exception = new CapsaraException("");

        assertThat(exception.getMessage()).isEmpty();
        assertThat(exception.getCode()).isEqualTo("SDK_ERROR");
    }

    @Test
    void capsaraException_withSpecialCharacters_preservesMessage() {
        CapsaraException exception = new CapsaraException("Error: <script>alert('xss')</script> & \"quotes\"");

        assertThat(exception.getMessage()).isEqualTo("Error: <script>alert('xss')</script> & \"quotes\"");
    }

    @Test
    void capsaraException_withUnicodeMessage_preservesMessage() {
        CapsaraException exception = new CapsaraException("Error: こんにちは");

        assertThat(exception.getMessage()).isEqualTo("Error: こんにちは");
    }

    @Test
    void capsaraException_withInnerException_setsInnerException() {
        Exception innerException = new IllegalStateException("Inner error");

        CapsaraException exception = new CapsaraException("Outer error", innerException);

        assertThat(exception.getMessage()).isEqualTo("Outer error");
        assertThat(exception.getCause()).isSameAs(innerException);
        assertThat(exception.getCode()).isEqualTo("SDK_ERROR");
    }

    @Test
    void capsaraException_withFullDetails_setsAllProperties() {
        Map<String, Object> details = new HashMap<>();
        details.put("key", "value");

        CapsaraException exception = new CapsaraException(
                "Error message",
                "ERROR_CODE",
                500,
                details,
                "{\"error\": \"raw response\"}"
        );

        assertThat(exception.getMessage()).isEqualTo("Error message");
        assertThat(exception.getCode()).isEqualTo("ERROR_CODE");
        assertThat(exception.getStatusCode()).isEqualTo(500);
        assertThat(exception.getDetails()).isNotNull();
        assertThat(exception.getDetails().get("key")).isEqualTo("value");
        assertThat(exception.getResponseBody()).isEqualTo("{\"error\": \"raw response\"}");
    }

    @Test
    void capsaraException_withNullDetails_setsNullDetails() {
        CapsaraException exception = new CapsaraException("Error", "CODE", 500, null, null);

        assertThat(exception.getDetails()).isNull();
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 400, 401, 403, 404, 500, 503})
    void capsaraException_withVariousStatusCodes_setsStatusCode(int statusCode) {
        CapsaraException exception = new CapsaraException("Error", "CODE", statusCode, null, null);

        assertThat(exception.getStatusCode()).isEqualTo(statusCode);
    }

    // CapsaraException NetworkError Tests

    @Test
    void networkError_createsNetworkException() {
        Exception innerException = new RuntimeException("Connection refused");

        CapsaraException exception = CapsaraException.networkError(innerException);

        assertThat(exception.getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(exception.getMessage()).contains("Network error");
        assertThat(exception.getCause()).isSameAs(innerException);
    }

    @Test
    void networkError_preservesInnerExceptionMessage() {
        Exception innerException = new RuntimeException("DNS resolution failed");

        CapsaraException exception = CapsaraException.networkError(innerException);

        assertThat(exception.getMessage()).contains("DNS resolution failed");
    }

    // CapsaraException FromHttpResponse Tests

    @Test
    void fromHttpResponse_withBody_createsException() {
        CapsaraException exception = CapsaraException.fromHttpResponse(400, "Bad Request");

        assertThat(exception.getCode()).isEqualTo("HTTP_ERROR");
        assertThat(exception.getMessage()).contains("400");
        assertThat(exception.getMessage()).contains("Bad Request");
        assertThat(exception.getStatusCode()).isEqualTo(400);
    }

    @Test
    void fromHttpResponse_withNullBody_createsException() {
        CapsaraException exception = CapsaraException.fromHttpResponse(404, null);

        assertThat(exception.getCode()).isEqualTo("HTTP_ERROR");
        assertThat(exception.getMessage()).contains("404");
        assertThat(exception.getStatusCode()).isEqualTo(404);
    }

    @Test
    void fromHttpResponse_withEmptyBody_createsException() {
        CapsaraException exception = CapsaraException.fromHttpResponse(500, "");

        assertThat(exception.getCode()).isEqualTo("HTTP_ERROR");
        assertThat(exception.getMessage()).contains("500");
    }

    // CapsaraAuthException Factory Method Tests

    @Test
    void invalidCredentials_returnsCorrectException() {
        CapsaraAuthException exception = CapsaraAuthException.invalidCredentials();

        assertThat(exception.getCode()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(exception.getStatusCode()).isEqualTo(401);
        assertThat(exception.getMessage()).contains("Invalid email or password");
    }

    @Test
    void tokenExpired_returnsCorrectException() {
        CapsaraAuthException exception = CapsaraAuthException.tokenExpired();

        assertThat(exception.getCode()).isEqualTo("TOKEN_EXPIRED");
        assertThat(exception.getStatusCode()).isEqualTo(401);
    }

    @Test
    void notAuthenticated_returnsCorrectException() {
        CapsaraAuthException exception = CapsaraAuthException.notAuthenticated();

        assertThat(exception.getCode()).isEqualTo("NOT_AUTHENTICATED");
        assertThat(exception.getMessage()).contains("Not authenticated");
    }

    // CapsaraCapsaException Factory Method Tests

    @Test
    void capsaNotFound_withId_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.capsaNotFound("pkg_123");

        assertThat(exception.getCode()).isEqualTo("CAPSA_NOT_FOUND");
        assertThat(exception.getStatusCode()).isEqualTo(404);
        assertThat(exception.getMessage()).contains("pkg_123");
    }

    @Test
    void fileNotFound_withId_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.fileNotFound("file_456");

        assertThat(exception.getCode()).isEqualTo("FILE_NOT_FOUND");
        assertThat(exception.getStatusCode()).isEqualTo(404);
        assertThat(exception.getMessage()).contains("file_456");
    }

    @Test
    void accessDenied_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.accessDenied(null);

        assertThat(exception.getCode()).isEqualTo("ACCESS_DENIED");
        assertThat(exception.getStatusCode()).isEqualTo(403);
    }

    @Test
    void creatorMismatch_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.creatorMismatch("party_actual", "party_claimed");

        assertThat(exception.getCode()).isEqualTo("CREATOR_MISMATCH");
        assertThat(exception.getStatusCode()).isEqualTo(403);
        assertThat(exception.getMessage()).contains("party_actual");
        assertThat(exception.getMessage()).contains("party_claimed");
    }

    @Test
    void capsaDeleted_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.capsaDeleted(null);

        assertThat(exception.getCode()).isEqualTo("CAPSA_DELETED");
        assertThat(exception.getStatusCode()).isEqualTo(410);
    }

    @Test
    void invalidContentType_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.invalidContentType();

        assertThat(exception.getCode()).isEqualTo("INVALID_CONTENT_TYPE");
        assertThat(exception.getStatusCode()).isEqualTo(415);
    }

    @Test
    void missingParams_withParams_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.missingParams("fileId", "capsaId");

        assertThat(exception.getCode()).isEqualTo("MISSING_PARAMS");
        assertThat(exception.getStatusCode()).isEqualTo(400);
        assertThat(exception.getMessage()).contains("fileId");
        assertThat(exception.getMessage()).contains("capsaId");
    }

    @Test
    void downloadFailed_returnsCorrectException() {
        Exception innerException = new RuntimeException("Storage error");

        CapsaraCapsaException exception = CapsaraCapsaException.downloadFailed("pkg_123", "file_456", innerException);

        assertThat(exception.getCode()).isEqualTo("DOWNLOAD_FAILED");
        assertThat(exception.getMessage()).contains("pkg_123");
        assertThat(exception.getMessage()).contains("file_456");
    }

    @Test
    void signatureVerificationFailed_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.signatureVerificationFailed();

        assertThat(exception.getCode()).isEqualTo("SIGNATURE_INVALID");
        assertThat(exception.getMessage()).contains("Signature verification failed");
    }

    @Test
    void notInKeychain_returnsCorrectException() {
        CapsaraCapsaException exception = CapsaraCapsaException.notInKeychain("party_123");

        assertThat(exception.getCode()).isEqualTo("NOT_IN_KEYCHAIN");
        assertThat(exception.getStatusCode()).isEqualTo(403);
        assertThat(exception.getMessage()).contains("party_123");
    }

    @Test
    void capsaException_fromHttpResponse_createsException() {
        CapsaraCapsaException exception = CapsaraCapsaException.fromHttpResponse(404, "Not Found");

        assertThat(exception.getStatusCode()).isEqualTo(404);
        assertThat(exception.getMessage()).contains("404");
    }

    // CapsaraAuditException Factory Method Tests

    @Test
    void missingDetails_returnsCorrectException() {
        CapsaraAuditException exception = CapsaraAuditException.missingDetails();

        assertThat(exception.getCode()).isEqualTo("MISSING_DETAILS");
        assertThat(exception.getStatusCode()).isEqualTo(400);
    }

    @Test
    void invalidAction_returnsCorrectException() {
        CapsaraAuditException exception = CapsaraAuditException.invalidAction("unknown_action");

        assertThat(exception.getCode()).isEqualTo("INVALID_ACTION");
        assertThat(exception.getStatusCode()).isEqualTo(400);
        assertThat(exception.getMessage()).contains("unknown_action");
    }

    @Test
    void createFailed_returnsCorrectException() {
        CapsaraAuditException exception = CapsaraAuditException.createFailed("pkg_123");

        assertThat(exception.getMessage()).contains("pkg_123");
    }

    @Test
    void auditException_fromHttpResponse_createsException() {
        CapsaraAuditException exception = CapsaraAuditException.fromHttpResponse(400, "Bad Request");

        assertThat(exception.getStatusCode()).isEqualTo(400);
        assertThat(exception.getMessage()).contains("400");
    }

    // Exception Inheritance Tests

    @Test
    void capsaraAuthException_inheritsFromCapsaraException() {
        CapsaraAuthException exception = CapsaraAuthException.invalidCredentials();

        assertThat(exception).isInstanceOf(CapsaraException.class);
    }

    @Test
    void capsaraCapsaException_inheritsFromCapsaraException() {
        CapsaraCapsaException exception = CapsaraCapsaException.capsaNotFound("test");

        assertThat(exception).isInstanceOf(CapsaraException.class);
    }

    @Test
    void capsaraAuditException_inheritsFromCapsaraException() {
        CapsaraAuditException exception = CapsaraAuditException.missingDetails();

        assertThat(exception).isInstanceOf(CapsaraException.class);
    }

    // Exception Types Are RuntimeExceptions

    @Test
    void allExceptionTypes_areRuntimeExceptions() {
        CapsaraException baseException = new CapsaraException("Test");
        CapsaraAuthException authException = CapsaraAuthException.invalidCredentials();
        CapsaraCapsaException capsaException = CapsaraCapsaException.capsaNotFound("test");
        CapsaraAuditException auditException = CapsaraAuditException.missingDetails();

        assertThat(baseException).isInstanceOf(RuntimeException.class);
        assertThat(authException).isInstanceOf(RuntimeException.class);
        assertThat(capsaException).isInstanceOf(RuntimeException.class);
        assertThat(auditException).isInstanceOf(RuntimeException.class);
    }

    // Exception Types Can Be Caught As Base Type

    @Test
    void exceptionTypes_canBeCaughtAsBaseType() {
        CapsaraException caught = null;

        try {
            throw CapsaraAuthException.invalidCredentials();
        } catch (CapsaraException ex) {
            caught = ex;
        }

        assertThat(caught).isNotNull();
        assertThat(caught.getCode()).isEqualTo("INVALID_CREDENTIALS");
    }

    // Status Code Consistency Tests

    @Test
    void authExceptions_have401StatusCode() {
        assertThat(CapsaraAuthException.invalidCredentials().getStatusCode()).isEqualTo(401);
        assertThat(CapsaraAuthException.tokenExpired().getStatusCode()).isEqualTo(401);
    }

    @Test
    void notFoundExceptions_have404StatusCode() {
        assertThat(CapsaraCapsaException.capsaNotFound("test").getStatusCode()).isEqualTo(404);
        assertThat(CapsaraCapsaException.fileNotFound("test").getStatusCode()).isEqualTo(404);
    }

    @Test
    void forbiddenExceptions_have403StatusCode() {
        assertThat(CapsaraCapsaException.accessDenied(null).getStatusCode()).isEqualTo(403);
        assertThat(CapsaraCapsaException.creatorMismatch("a", "b").getStatusCode()).isEqualTo(403);
    }

    @Test
    void badRequestExceptions_have400StatusCode() {
        assertThat(CapsaraCapsaException.missingParams("test").getStatusCode()).isEqualTo(400);
        assertThat(CapsaraAuditException.missingDetails().getStatusCode()).isEqualTo(400);
        assertThat(CapsaraAuditException.invalidAction("test").getStatusCode()).isEqualTo(400);
    }

    // ToString Tests

    @Test
    void exception_toString_containsMessage() {
        CapsaraException exception = new CapsaraException("Test error message");

        assertThat(exception.toString()).contains("Test error message");
    }

    @Test
    void exception_toString_containsExceptionType() {
        CapsaraException exception = new CapsaraException("Test");

        assertThat(exception.toString()).contains("CapsaraException");
    }
}
