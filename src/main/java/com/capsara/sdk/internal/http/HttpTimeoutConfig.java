package com.capsara.sdk.internal.http;

import java.time.Duration;

/** HTTP timeout configuration. */
public final class HttpTimeoutConfig {

    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration requestTimeout = Duration.ofMinutes(5);
    private Duration downloadTimeout = Duration.ofMinutes(10);

    public HttpTimeoutConfig() {
    }

    public HttpTimeoutConfig(Duration connectTimeout, Duration requestTimeout) {
        this.connectTimeout = connectTimeout;
        this.requestTimeout = requestTimeout;
    }

    /** Creates a timeout config with connect, request, and download timeouts. */
    public HttpTimeoutConfig(Duration connectTimeout, Duration requestTimeout,
            Duration downloadTimeout) {
        this.connectTimeout = connectTimeout;
        this.requestTimeout = requestTimeout;
        this.downloadTimeout = downloadTimeout;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    public void setRequestTimeout(Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
    }

    public Duration getDownloadTimeout() {
        return downloadTimeout;
    }

    public void setDownloadTimeout(Duration downloadTimeout) {
        this.downloadTimeout = downloadTimeout;
    }

    public static HttpTimeoutConfig defaults() {
        return new HttpTimeoutConfig();
    }
}
