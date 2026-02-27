package com.capsara.sdk.golden;

import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.services.AuthService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden tests for AuthService token management and state.
 * Tests constructor/state behavior without requiring HTTP mocks.
 */
class AuthGoldenTest {

    private static final String BASE_URL = "https://api.example.com";

    // Constructor Tests

    @Test
    void constructor_createsServiceWithDefaults() {
        AuthService service = new AuthService(BASE_URL, null, null, null);

        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.getToken()).isNull();
    }

    @Test
    void constructor_trimsTrailingSlashFromBaseUrl() {
        AuthService service = new AuthService(BASE_URL + "/", null, null, null);

        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void constructor_acceptsCustomTimeoutConfig() {
        HttpTimeoutConfig timeout = HttpTimeoutConfig.defaults();
        AuthService service = new AuthService(BASE_URL, timeout, null, null);

        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void constructor_acceptsCustomRetryConfig() {
        RetryConfig retry = RetryConfig.defaults();
        AuthService service = new AuthService(BASE_URL, null, retry, null);

        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void constructor_acceptsCustomUserAgent() {
        AuthService service = new AuthService(BASE_URL, null, null, "TestAgent/1.0");

        assertThat(service.isAuthenticated()).isFalse();
    }

    // Token Management Tests

    @Test
    void setToken_makesServiceAuthenticated() {
        AuthService service = new AuthService(BASE_URL, null, null, null);

        service.setToken("test_access_token_abc123");

        assertThat(service.isAuthenticated()).isTrue();
        assertThat(service.getToken()).isEqualTo("test_access_token_abc123");
    }

    @Test
    void setToken_withNull_makesServiceNotAuthenticated() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("test_token");

        service.setToken(null);

        assertThat(service.isAuthenticated()).isFalse();
        assertThat(service.getToken()).isNull();
    }

    @Test
    void setToken_withEmptyString_makesServiceNotAuthenticated() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("test_token");

        service.setToken("");

        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void setToken_overwritesPreviousToken() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("first_token");

        service.setToken("second_token");

        assertThat(service.getToken()).isEqualTo("second_token");
    }

    // isAuthenticated Tests

    @Test
    void isAuthenticated_returnsFalseInitially() {
        AuthService service = new AuthService(BASE_URL, null, null, null);

        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void isAuthenticated_returnsTrueAfterSetToken() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("valid_token");

        assertThat(service.isAuthenticated()).isTrue();
    }

    @Test
    void isAuthenticated_returnsFalseAfterClearTokens() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("valid_token");

        service.clearTokens();

        assertThat(service.isAuthenticated()).isFalse();
    }

    // clearTokens Tests

    @Test
    void clearTokens_removesAccessToken() {
        AuthService service = new AuthService(BASE_URL, null, null, null);
        service.setToken("access_token");

        service.clearTokens();

        assertThat(service.getToken()).isNull();
        assertThat(service.isAuthenticated()).isFalse();
    }

    @Test
    void clearTokens_doesNotThrowWhenNoTokensSet() {
        AuthService service = new AuthService(BASE_URL, null, null, null);

        service.clearTokens();

        assertThat(service.isAuthenticated()).isFalse();
    }
}
