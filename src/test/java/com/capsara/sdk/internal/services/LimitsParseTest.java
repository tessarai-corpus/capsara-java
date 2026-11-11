package com.capsara.sdk.internal.services;

import com.capsara.sdk.models.SystemLimits;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Per-field parsing of /api/limits: finite JSON numbers above zero, otherwise that field's fallback. */
class LimitsParseTest {

    private static final long FILE = 50L * 1024 * 1024;
    private static final long TOTAL = 1024L * 1024 * 1024;
    private static final long REQUEST = 2147483648L;
    private static final long FIELD_BYTES = 67108864L;

    private static void assertAllFallbacks(SystemLimits limits) {
        assertThat(limits.getMaxFileSize()).isEqualTo(FILE);
        assertThat(limits.getMaxFilesPerCapsa()).isEqualTo(500);
        assertThat(limits.getMaxTotalSize()).isEqualTo(TOTAL);
        assertThat(limits.getMaxRequestSize()).isEqualTo(REQUEST);
        assertThat(limits.getMaxRequestFieldBytes()).isEqualTo(FIELD_BYTES);
        assertThat(limits.getMaxExpirationDays()).isEqualTo(3650d);
        assertThat(limits.getMaxFilesPerRequest()).isEqualTo(500);
    }

    @Test
    void validValues_areUsed() {
        SystemLimits limits = LimitsService.parseLimits("{\"maxFileSize\":10,\"maxFilesPerCapsa\":3,"
                + "\"maxTotalSize\":30,\"maxRequestSize\":40,\"maxRequestFieldBytes\":50,\"maxExpirationDays\":7,"
                + "\"maxFilesPerRequest\":5000}");

        assertThat(limits.getMaxFileSize()).isEqualTo(10);
        assertThat(limits.getMaxFilesPerCapsa()).isEqualTo(3);
        assertThat(limits.getMaxTotalSize()).isEqualTo(30);
        assertThat(limits.getMaxRequestSize()).isEqualTo(40);
        assertThat(limits.getMaxRequestFieldBytes()).isEqualTo(50);
        assertThat(limits.getMaxExpirationDays()).isEqualTo(7d);
        assertThat(limits.getMaxFilesPerRequest()).isEqualTo(5000);
    }

    @Test
    void emptyObject_usesEveryFallback() {
        SystemLimits limits = LimitsService.parseLimits("{}");

        assertAllFallbacks(limits);
        assertThat(limits).isNotSameAs(SystemLimits.DEFAULT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"1000\"", "0", "-5", "null", "true", "[1]", "{\"a\":1}"})
    void invalidValue_usesThatFieldsFallback(String value) {
        SystemLimits limits = LimitsService.parseLimits("{\"maxFileSize\":" + value + ",\"maxFilesPerCapsa\":"
                + value + ",\"maxTotalSize\":" + value + ",\"maxRequestSize\":" + value
                + ",\"maxRequestFieldBytes\":" + value + ",\"maxExpirationDays\":" + value
                + ",\"maxFilesPerRequest\":" + value + "}");

        assertAllFallbacks(limits);
    }

    @Test
    void oneBadField_doesNotResetTheOthers() {
        SystemLimits limits = LimitsService.parseLimits(
                "{\"maxFileSize\":\"big\",\"maxTotalSize\":1e30,\"maxExpirationDays\":30,\"maxRequestSize\":99}");

        assertThat(limits.getMaxFileSize()).isEqualTo(FILE);
        assertThat(limits.getMaxTotalSize()).isEqualTo(Long.MAX_VALUE);
        assertThat(limits.getMaxExpirationDays()).isEqualTo(30d);
        assertThat(limits.getMaxRequestSize()).isEqualTo(99);
    }

    @Test
    void valuesBeyondTheJavaRange_areKeptAsTheLargestValue() {
        SystemLimits limits = LimitsService.parseLimits("{\"maxFileSize\":10000000000000000000,"
                + "\"maxFilesPerCapsa\":1e19,\"maxRequestSize\":1e300,\"maxExpirationDays\":1e300}");

        assertThat(limits.getMaxFileSize()).isEqualTo(Long.MAX_VALUE);
        assertThat(limits.getMaxFilesPerCapsa()).isEqualTo(Integer.MAX_VALUE);
        assertThat(limits.getMaxRequestSize()).isEqualTo(Long.MAX_VALUE);
        assertThat(limits.getMaxExpirationDays()).isEqualTo(1e300);
    }

    @Test
    void fractions_keepTheComparisonsTsMakes() {
        SystemLimits limits = LimitsService.parseLimits("{\"maxFileSize\":10.5,\"maxFilesPerCapsa\":2.5,"
                + "\"maxTotalSize\":0.5,\"maxRequestSize\":0.5,\"maxRequestFieldBytes\":7.9,"
                + "\"maxExpirationDays\":0.5}");

        // size > 10.5 iff size > 10; count >= 2.5 iff count >= 3; total > 0.5 iff total > 0
        assertThat(limits.getMaxFileSize()).isEqualTo(10);
        assertThat(limits.getMaxFilesPerCapsa()).isEqualTo(3);
        assertThat(limits.getMaxTotalSize()).isZero();
        // a request limit below 1 still applies (every capsa alone) instead of falling back
        assertThat(limits.getMaxRequestSize()).isEqualTo(1);
        assertThat(limits.getMaxRequestFieldBytes()).isEqualTo(7);
        assertThat(limits.getMaxExpirationDays()).isEqualTo(0.5);
        assertThat(limits.effectiveMaxExpirationDays()).isEqualTo(0.5);
    }

    @ParameterizedTest
    @ValueSource(strings = {"[]", "\"x\"", "42", "null", "", "<html>"})
    void nonObjectBody_isTheDefault(String body) {
        assertThat(LimitsService.parseLimits(body)).isSameAs(SystemLimits.DEFAULT);
    }
}
