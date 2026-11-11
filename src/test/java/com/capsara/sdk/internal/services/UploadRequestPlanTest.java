package com.capsara.sdk.internal.services;

import com.capsara.sdk.models.SystemLimits;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Upload requests are filled greedily under the request byte and JSON field byte limits. */
class UploadRequestPlanTest {

    private static final long FIELD_FALLBACK = 64L * 1024 * 1024;
    private static final long SIZE_FALLBACK = 2048L * 1024 * 1024;

    private static List<List<Integer>> plan(long[] json, long[] files, long maxRequestSize, long maxFieldBytes) {
        return UploadService.planRequests(json, files, maxRequestSize, maxFieldBytes);
    }

    @Test
    void jsonAndFileBytesCountTowardsTheRequestSize() {
        assertThat(plan(new long[]{100, 100}, new long[]{400, 400}, 1000, FIELD_FALLBACK))
                .containsExactly(List.of(0, 1));
        assertThat(plan(new long[]{100, 101}, new long[]{400, 400}, 1000, FIELD_FALLBACK))
                .containsExactly(List.of(0), List.of(1));
    }

    @Test
    void jsonFieldBytesAreLimitedPerRequest() {
        assertThat(plan(new long[]{400, 400, 400}, new long[3], SIZE_FALLBACK, 1000))
                .containsExactly(List.of(0, 1), List.of(2));
        assertThat(plan(new long[]{500, 500}, new long[2], SIZE_FALLBACK, 1000))
                .containsExactly(List.of(0, 1));
    }

    @Test
    void capsaOverALimitOnItsOwnGoesAlone() {
        assertThat(plan(new long[]{10, 1500, 10}, new long[3], SIZE_FALLBACK, 1000))
                .containsExactly(List.of(0), List.of(1), List.of(2));
        assertThat(plan(new long[]{10, 10}, new long[]{5000, 5}, 1000, FIELD_FALLBACK))
                .containsExactly(List.of(0), List.of(1));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(longs = {0, -1})
    void missingOrNonPositiveLimits_useTheFallbacks(Long advertised) {
        long fieldLimit = UploadService.effectiveLimit(advertised, FIELD_FALLBACK);

        assertThat(fieldLimit).isEqualTo(FIELD_FALLBACK);
        assertThat(UploadService.effectiveLimit(advertised, SIZE_FALLBACK)).isEqualTo(SIZE_FALLBACK);
        assertThat(plan(new long[]{400, 400, 400}, new long[3], SIZE_FALLBACK, fieldLimit))
                .containsExactly(List.of(0, 1, 2));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {0, -1})
    void missingOrNonPositiveFileLimit_fallsBackTo500(Integer advertised) {
        assertThat(UploadService.effectiveFileLimit(advertised)).isEqualTo(500);
    }

    @Test
    void advertisedFileLimit_isUsed() {
        assertThat(UploadService.effectiveFileLimit(5000)).isEqualTo(5000);
        assertThat(SystemLimits.DEFAULT.getMaxFilesPerRequest()).isEqualTo(500);
    }

    @Test
    void limitsResponse_readsMaxFilesPerRequest() throws Exception {
        SystemLimits limits = com.capsara.sdk.internal.json.JsonMapper.getInstance()
                .readValue("{\"maxFilesPerRequest\":5000}", SystemLimits.class);

        assertThat(limits.getMaxFilesPerRequest()).isEqualTo(5000);
    }

    @Test
    void advertisedPositiveLimit_isUsed() {
        assertThat(UploadService.effectiveLimit(1000L, FIELD_FALLBACK)).isEqualTo(1000L);
    }

    @Test
    void jsonBytesAreUtf8BytesNotCharacters() {
        String multibyte = "\u00e9".repeat(290);
        long bytes = UploadService.jsonBytes(Map.of("s", multibyte));

        assertThat(bytes).isEqualTo(2L * 290 + "{\"s\":\"\"}".length());
        assertThat(plan(new long[]{bytes, bytes}, new long[2], SIZE_FALLBACK, 1000))
                .containsExactly(List.of(0), List.of(1));
    }

    @Test
    void defaultLimits_carryTheFieldByteFallback() {
        assertThat(SystemLimits.DEFAULT.getMaxRequestFieldBytes()).isEqualTo(FIELD_FALLBACK);
        assertThat(SystemLimits.DEFAULT.getMaxRequestSize()).isEqualTo(SIZE_FALLBACK);
    }

    @Test
    void limitsResponse_readsMaxRequestFieldBytes() throws Exception {
        SystemLimits limits = com.capsara.sdk.internal.json.JsonMapper.getInstance()
                .readValue("{\"maxRequestFieldBytes\":1234}", SystemLimits.class);

        assertThat(limits.getMaxRequestFieldBytes()).isEqualTo(1234L);
    }
}
