package com.capsara.sdk;

import java.time.Duration;

/** HTTP timeout configuration. */
public final class HttpTimeoutConfig {

    private Duration connectTimeout = Duration.ofSeconds(30);
    private Duration requestTimeout = Duration.ofMinutes(12);
    private Duration downloadTimeout = Duration.ofSeconds(60);
    private Duration uploadTimeout = Duration.ofMinutes(15);

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

    /** Time allowed for one whole capsa upload request (sending every file and the response), not idle time. */
    public Duration getUploadTimeout() {
        return uploadTimeout;
    }

    public void setUploadTimeout(Duration uploadTimeout) {
        this.uploadTimeout = uploadTimeout;
    }

    public static HttpTimeoutConfig defaults() {
        return new HttpTimeoutConfig();
    }
}
