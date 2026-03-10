package com.capsara.sdk.golden;

import com.capsara.sdk.internal.http.RetryConfig;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden tests for RetryConfig: construction, validation, backoff calculation.
 */
class RetryGoldenTest {

    // Default Construction Tests

    @Test
    void defaults_hasExpectedValues() {
        RetryConfig config = RetryConfig.defaults();

        assertThat(config.getMaxRetries()).isEqualTo(3);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofMillis(100));
        assertThat(config.getBackoffMultiplier()).isEqualTo(2.0);
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void noArgConstructor_matchesDefaults() {
        RetryConfig config = new RetryConfig();

        assertThat(config.getMaxRetries()).isEqualTo(3);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofMillis(100));
        assertThat(config.getBackoffMultiplier()).isEqualTo(2.0);
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofSeconds(30));
    }

    // Custom Construction Tests

    @Test
    void threeArgConstructor_setsValues() {
        RetryConfig config = new RetryConfig(5, Duration.ofMillis(200), 3.0);

        assertThat(config.getMaxRetries()).isEqualTo(5);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofMillis(200));
        assertThat(config.getBackoffMultiplier()).isEqualTo(3.0);
        // maxDelay should remain default
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void fourArgConstructor_setsAllValues() {
        RetryConfig config = new RetryConfig(
                10, Duration.ofMillis(500), 1.5, Duration.ofMinutes(1));

        assertThat(config.getMaxRetries()).isEqualTo(10);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofMillis(500));
        assertThat(config.getBackoffMultiplier()).isEqualTo(1.5);
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofMinutes(1));
    }

    // Setter Tests

    @Test
    void setters_overrideValues() {
        RetryConfig config = new RetryConfig();

        config.setMaxRetries(7);
        config.setInitialDelay(Duration.ofMillis(250));
        config.setBackoffMultiplier(4.0);
        config.setMaxDelay(Duration.ofMinutes(2));

        assertThat(config.getMaxRetries()).isEqualTo(7);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofMillis(250));
        assertThat(config.getBackoffMultiplier()).isEqualTo(4.0);
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofMinutes(2));
    }

    // Backoff Calculation Tests

    @Test
    void getDelayForAttempt_calculatesExponentialBackoff() {
        RetryConfig config = new RetryConfig(3, Duration.ofMillis(100), 2.0);

        // attempt 0: 100ms * 2^0 = 100ms
        assertThat(config.getDelayForAttempt(0)).isEqualTo(Duration.ofMillis(100));

        // attempt 1: 100ms * 2^1 = 200ms
        assertThat(config.getDelayForAttempt(1)).isEqualTo(Duration.ofMillis(200));

        // attempt 2: 100ms * 2^2 = 400ms
        assertThat(config.getDelayForAttempt(2)).isEqualTo(Duration.ofMillis(400));

        // attempt 3: 100ms * 2^3 = 800ms
        assertThat(config.getDelayForAttempt(3)).isEqualTo(Duration.ofMillis(800));
    }

    @Test
    void getDelayForAttempt_withCustomMultiplier() {
        RetryConfig config = new RetryConfig(3, Duration.ofMillis(50), 3.0);

        // attempt 0: 50ms * 3^0 = 50ms
        assertThat(config.getDelayForAttempt(0)).isEqualTo(Duration.ofMillis(50));

        // attempt 1: 50ms * 3^1 = 150ms
        assertThat(config.getDelayForAttempt(1)).isEqualTo(Duration.ofMillis(150));

        // attempt 2: 50ms * 3^2 = 450ms
        assertThat(config.getDelayForAttempt(2)).isEqualTo(Duration.ofMillis(450));
    }

    @Test
    void getDelayForAttempt_zeroAttempt_returnsInitialDelay() {
        RetryConfig config = new RetryConfig(3, Duration.ofSeconds(1), 2.0);

        assertThat(config.getDelayForAttempt(0)).isEqualTo(Duration.ofSeconds(1));
    }
}
