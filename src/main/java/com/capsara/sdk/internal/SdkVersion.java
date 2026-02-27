package com.capsara.sdk.internal;

/** SDK version information. */
public final class SdkVersion {

    public static final String VERSION = "1.0.0";
    public static final String SDK_NAME = "Capsara-SDK-java";
    public static final String DEFAULT_USER_AGENT = SDK_NAME + "/" + VERSION;

    private SdkVersion() {
    }

    /** Builds a user agent string, appending the custom agent if provided. */
    public static String buildUserAgent(String customAgent) {
        if (customAgent != null && !customAgent.isEmpty()) {
            return DEFAULT_USER_AGENT + " " + customAgent;
        }
        return DEFAULT_USER_AGENT;
    }
}
