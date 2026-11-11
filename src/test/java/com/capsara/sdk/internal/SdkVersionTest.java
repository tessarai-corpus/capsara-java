package com.capsara.sdk.internal;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SdkVersionTest {

    @Test
    void version_isTheProjectVersionFromTheBuild() {
        String expected = System.getProperty("capsara.expectedSdkVersion");
        assertThat(expected).as("set by the build from the project version").isNotBlank();

        assertThat(SdkVersion.VERSION).isEqualTo(expected);
    }

    @Test
    void userAgent_reportsTheProjectVersion() {
        String expected = System.getProperty("capsara.expectedSdkVersion");

        assertThat(SdkVersion.buildUserAgent(null)).isEqualTo("Capsara-SDK-java/" + expected);
        assertThat(SdkVersion.buildUserAgent("MyApp/2.0")).isEqualTo("Capsara-SDK-java/" + expected + " MyApp/2.0");
    }
}
