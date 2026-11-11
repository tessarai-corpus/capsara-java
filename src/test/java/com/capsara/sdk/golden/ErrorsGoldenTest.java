package com.capsara.sdk.golden;

import com.capsara.sdk.exceptions.CapsaraAuditException;
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden tests for exception hierarchy, factory methods, error messages, status codes.
 */
class ErrorsGoldenTest {

    // Exception Hierarchy Tests

    @Test
    void allExceptionTypes_extendCapsaraException() {
        assertThat(CapsaraAuthException.invalidCredentials()).isInstanceOf(CapsaraException.class);
        assertThat(CapsaraCapsaException.capsaNotFound("test")).isInstanceOf(CapsaraException.class);
        assertThat(CapsaraAuditException.missingDetails()).isInstanceOf(CapsaraException.class);
    }

    @Test
    void allExceptionTypes_extendRuntimeException() {
        assertThat(new CapsaraException("test")).isInstanceOf(RuntimeException.class);
        assertThat(CapsaraAuthException.tokenExpired()).isInstanceOf(RuntimeException.class);
        assertThat(CapsaraCapsaException.accessDenied(null)).isInstanceOf(RuntimeException.class);
        assertThat(CapsaraAuditException.invalidAction("test")).isInstanceOf(RuntimeException.class);
    }

    // Factory Method Tests

    @Test
    void networkError_setsCodeAndPreservesInner() {
        RuntimeException inner = new RuntimeException("Connection refused");
        CapsaraException ex = CapsaraException.networkError(inner);

        assertThat(ex.getCode()).isEqualTo("NETWORK_ERROR");
        assertThat(ex.getMessage()).contains("Connection refused");
        assertThat(ex.getCause()).isSameAs(inner);
    }

    @Test
    void fromHttpResponse_setsStatusCodeAndMessage() {
        CapsaraException ex = CapsaraException.fromHttpResponse(503, "Service Unavailable");

        assertThat(ex.getCode()).isEqualTo("HTTP_503");
        assertThat(ex.getStatusCode()).isEqualTo(503);
        assertThat(ex.getMessage()).isEqualTo("Service Unavailable");
    }

    // Error Message and Code Tests

    @Test
    void authExceptions_haveCorrectCodesAndStatuses() {
        CapsaraAuthException invalid = CapsaraAuthException.invalidCredentials();
        assertThat(invalid.getCode()).isEqualTo("AUTHENTICATION_FAILED");
        assertThat(invalid.getStatusCode()).isEqualTo(401);

        CapsaraAuthException expired = CapsaraAuthException.tokenExpired();
        assertThat(expired.getCode()).isEqualTo("INVALID_TOKEN");
        assertThat(expired.getStatusCode()).isEqualTo(401);

        CapsaraAuthException notAuth = CapsaraAuthException.notAuthenticated();
        assertThat(notAuth.getCode()).isEqualTo("NOT_AUTHENTICATED");
        assertThat(notAuth.getMessage()).contains("Not authenticated");
    }

    @Test
    void capsaExceptions_haveCorrectCodesAndStatuses() {
        CapsaraCapsaException notFound = CapsaraCapsaException.capsaNotFound("capsa_abc");
        assertThat(notFound.getCode()).isEqualTo("ENVELOPE_NOT_FOUND");
        assertThat(notFound.getStatusCode()).isEqualTo(404);
        assertThat(notFound.getMessage()).contains("capsa_abc");

        CapsaraCapsaException denied = CapsaraCapsaException.accessDenied(null);
        assertThat(denied.getCode()).isEqualTo("ACCESS_DENIED");
        assertThat(denied.getStatusCode()).isEqualTo(403);

        CapsaraCapsaException deleted = CapsaraCapsaException.capsaDeleted(null);
        assertThat(deleted.getCode()).isEqualTo("ENVELOPE_DELETED");
        assertThat(deleted.getStatusCode()).isEqualTo(410);

        CapsaraCapsaException sigFailed = CapsaraCapsaException.signatureVerificationFailed("capsa_1", "party_c", "x");
        assertThat(sigFailed.getCode()).isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    // Status Code Consistency Tests

    @Test
    void statusCodes_matchHttpSemantics() {
        // 400 - Bad Request
        assertThat(CapsaraCapsaException.missingParams("id").getStatusCode()).isEqualTo(400);
        assertThat(CapsaraAuditException.missingDetails().getStatusCode()).isZero();
        assertThat(CapsaraAuditException.invalidAction("bad").getStatusCode()).isEqualTo(400);

        // 401 - Unauthorized
        assertThat(CapsaraAuthException.invalidCredentials().getStatusCode()).isEqualTo(401);
        assertThat(CapsaraAuthException.tokenExpired().getStatusCode()).isEqualTo(401);

        // 403 - Forbidden
        assertThat(CapsaraCapsaException.accessDenied(null).getStatusCode()).isEqualTo(403);
        assertThat(CapsaraCapsaException.notInKeychain("capsa_x", "party_x").getStatusCode()).isZero();

        // 404 - Not Found
        assertThat(CapsaraCapsaException.capsaNotFound("id").getStatusCode()).isEqualTo(404);

        // 410 - Gone
        assertThat(CapsaraCapsaException.capsaDeleted(null).getStatusCode()).isEqualTo(410);

        // The API answers a non-multipart upload with 400 INVALID_CONTENT_TYPE
        assertThat(CapsaraCapsaException.invalidContentType().getStatusCode()).isEqualTo(400);
    }

    // Full Constructor Test

    @Test
    void fullConstructor_setsAllFields() {
        Map<String, Object> details = new HashMap<>();
        details.put("field", "value");

        CapsaraException ex = new CapsaraException(
                "Full error", "CUSTOM_CODE", 422, details, "{\"error\":\"detail\"}");

        assertThat(ex.getMessage()).isEqualTo("Full error");
        assertThat(ex.getCode()).isEqualTo("CUSTOM_CODE");
        assertThat(ex.getStatusCode()).isEqualTo(422);
        assertThat(ex.getDetails()).isEqualTo(Map.of("field", "value"));
        assertThat(ex.getResponseBody()).isEqualTo("{\"error\":\"detail\"}");
    }

    // Catch-as-Base-Type Test

    @Test
    void subExceptions_catchableAsBaseType() {
        CapsaraException caught = null;

        try {
            throw CapsaraCapsaException.capsaNotFound("capsa_test");
        } catch (CapsaraException ex) {
            caught = ex;
        }

        assertThat(caught).isNotNull();
        assertThat(caught).isInstanceOf(CapsaraCapsaException.class);
        assertThat(caught.getCode()).isEqualTo("ENVELOPE_NOT_FOUND");
    }
}
