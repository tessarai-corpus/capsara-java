package com.capsara.sdk.internal;

import java.io.InputStream;
import java.util.Properties;

/** SDK version information, read from the build's project version. */
public final class SdkVersion {

    private static final String VERSION_RESOURCE = "/com/capsara/sdk/sdk-version.properties";

    public static final String VERSION = loadVersion();
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

    private static String loadVersion() {
        try (InputStream in = SdkVersion.class.getResourceAsStream(VERSION_RESOURCE)) {
            if (in == null) {
                return "unknown";
            }
            Properties properties = new Properties();
            properties.load(in);
            String version = properties.getProperty("version");
            return version == null || version.isEmpty() || version.startsWith("${") ? "unknown" : version;
        } catch (Exception e) {
            return "unknown";
        }
    }
}
