package com.capsara.sdk;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** Client options carry only settings the client acts on; login stays an explicit call. */
class CapsaraClientOptionsTest {

    @Test
    void options_haveNoCredentialsSetting() {
        assertThat(Arrays.stream(CapsaraClientOptions.class.getMethods()).map(Method::getName))
                .doesNotContain("getCredentials", "setCredentials");
    }

    @Test
    void accessTokenOption_authenticatesTheClientImmediately() {
        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        options.setRetry(new com.capsara.sdk.RetryConfig(0, java.time.Duration.ofMillis(1), 1.0,
                java.time.Duration.ofMillis(1)));

        try (CapsaraClient client = new CapsaraClient("http://127.0.0.1:1", options)) {
            assertThat(client.isAuthenticated()).isTrue();
        }
    }

    @Test
    void noAccessToken_leavesTheClientUnauthenticated() {
        try (CapsaraClient client = new CapsaraClient("http://127.0.0.1:1", new CapsaraClientOptions())) {
            assertThat(client.isAuthenticated()).isFalse();
        }
    }
}
