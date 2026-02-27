package com.capsara.sdk;

import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.models.AuthCredentials;

import java.time.Duration;
import java.util.function.Consumer;

/** Configuration options for CapsaraClient. */
public final class CapsaraClientOptions {

    private AuthCredentials credentials;
    private String accessToken;
    private String expectedIssuer;
    private String expectedAudience;
    private HttpTimeoutConfig timeout;
    private RetryConfig retry;
    private int maxBatchSize = 150;
    private String userAgent;
    private Duration cacheTTL;
    private boolean enableLogging;
    private Consumer<String> logger;

    /** Get authentication credentials. */
    public AuthCredentials getCredentials() {
        return credentials;
    }

    /** Set authentication credentials. */
    public void setCredentials(AuthCredentials credentials) {
        this.credentials = credentials;
    }

    /** Get pre-authenticated access token. */
    public String getAccessToken() {
        return accessToken;
    }

    /** Set pre-authenticated access token. */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /** Get expected JWT issuer for token validation. */
    public String getExpectedIssuer() {
        return expectedIssuer;
    }

    /** Set expected JWT issuer for token validation. */
    public void setExpectedIssuer(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
    }

    /** Get expected JWT audience for token validation. */
    public String getExpectedAudience() {
        return expectedAudience;
    }

    /** Set expected JWT audience for token validation. */
    public void setExpectedAudience(String expectedAudience) {
        this.expectedAudience = expectedAudience;
    }

    /** Get HTTP timeout configuration. */
    public HttpTimeoutConfig getTimeout() {
        return timeout;
    }

    /** Set HTTP timeout configuration. */
    public void setTimeout(HttpTimeoutConfig timeout) {
        this.timeout = timeout;
    }

    /** Get retry configuration. */
    public RetryConfig getRetry() {
        return retry;
    }

    /** Set retry configuration. */
    public void setRetry(RetryConfig retry) {
        this.retry = retry;
    }

    /** Get maximum batch size for bulk operations. */
    public int getMaxBatchSize() {
        return maxBatchSize;
    }

    /** Set maximum batch size for bulk operations. */
    public void setMaxBatchSize(int maxBatchSize) {
        this.maxBatchSize = maxBatchSize;
    }

    /** Appended to the default SDK user agent string. */
    public String getUserAgent() {
        return userAgent;
    }

    /** Set custom user agent suffix. */
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    /** Get cache time-to-live duration. */
    public Duration getCacheTTL() {
        return cacheTTL;
    }

    /** Set cache time-to-live duration. */
    public void setCacheTTL(Duration cacheTTL) {
        this.cacheTTL = cacheTTL;
    }

    /** Check if logging is enabled. */
    public boolean isEnableLogging() {
        return enableLogging;
    }

    /** Set whether logging is enabled. */
    public void setEnableLogging(boolean enableLogging) {
        this.enableLogging = enableLogging;
    }

    /** Get custom logger. */
    public Consumer<String> getLogger() {
        return logger;
    }

    /** Set custom logger. */
    public void setLogger(Consumer<String> logger) {
        this.logger = logger;
    }
}
