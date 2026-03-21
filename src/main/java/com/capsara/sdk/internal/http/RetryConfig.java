package com.capsara.sdk.internal.http;

import java.time.Duration;

/** Retry configuration for HTTP requests. */
public final class RetryConfig {

    private int maxRetries = 3;
    private Duration initialDelay = Duration.ofMillis(100);
    private double backoffMultiplier = 2.0;
    private Duration maxDelay = Duration.ofSeconds(30);

    public RetryConfig() {
    }

    /** Creates a retry config with custom retries, delay, and backoff multiplier. */
    public RetryConfig(int maxRetries, Duration initialDelay, double backoffMultiplier) {
        this.maxRetries = maxRetries;
        this.initialDelay = initialDelay;
        this.backoffMultiplier = backoffMultiplier;
    }

    /** Creates a retry config with custom retries, delay, backoff multiplier, and max delay. */
    public RetryConfig(int maxRetries, Duration initialDelay, double backoffMultiplier,
            Duration maxDelay) {
        this.maxRetries = maxRetries;
        this.initialDelay = initialDelay;
        this.backoffMultiplier = backoffMultiplier;
        this.maxDelay = maxDelay;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public Duration getInitialDelay() {
        return initialDelay;
    }

    public void setInitialDelay(Duration initialDelay) {
        this.initialDelay = initialDelay;
    }

    public double getBackoffMultiplier() {
        return backoffMultiplier;
    }

    public void setBackoffMultiplier(double backoffMultiplier) {
        this.backoffMultiplier = backoffMultiplier;
    }

    public Duration getMaxDelay() {
        return maxDelay;
    }

    public void setMaxDelay(Duration maxDelay) {
        this.maxDelay = maxDelay;
    }

    public static RetryConfig defaults() {
        return new RetryConfig();
    }

    /** Calculate delay for a specific retry attempt using exponential backoff. */
    public Duration getDelayForAttempt(int attempt) {
        // initialDelay * backoffMultiplier^attempt
        long delayMs = (long) (initialDelay.toMillis() * Math.pow(backoffMultiplier, attempt));
        return Duration.ofMillis(delayMs);
    }
}
