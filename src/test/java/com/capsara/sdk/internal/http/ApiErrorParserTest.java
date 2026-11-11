package com.capsara.sdk.internal.http;

import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiErrorParserTest {

    private static HttpHeaders headers(String name, String value) {
        return HttpHeaders.of(Map.of(name, List.of(value)), (a, b) -> true);
    }

    @Test
    void standardBody_passesCodeMessageAndDetailsThroughVerbatim() {
        ApiError error = ApiErrorParser.parse(409,
                "{\"error\":{\"code\":\"KEYCHAIN_KEY_OUTDATED\",\"message\":\"Rebuild and retry\","
                        + "\"details\":{\"party\":\"party_x\"}},\"requestId\":\"req_1\"}");

        assertThat(error.getStatusCode()).isEqualTo(409);
        assertThat(error.getCode()).isEqualTo("KEYCHAIN_KEY_OUTDATED");
        assertThat(error.getMessage()).isEqualTo("Rebuild and retry");
        assertThat(error.getDetails()).isEqualTo(Map.of("party", "party_x"));
        assertThat(error.getRetryAfter()).isNull();
    }

    @Test
    void arrayDetails_areKeptAsAList() {
        ApiError error = ApiErrorParser.parse(400,
                "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"Invalid\","
                        + "\"details\":[{\"path\":\"limit\",\"message\":\"Too big\"}]}}");

        assertThat(error.getDetails()).isEqualTo(List.of(Map.of("path", "limit", "message", "Too big")));
    }

    @Test
    void stringDetails_areKeptAsAString() {
        ApiError error = ApiErrorParser.parse(400,
                "{\"error\":{\"code\":\"FIELD_PARSE_ERROR\",\"message\":\"Bad field\",\"details\":\"capsa_0\"}}");

        assertThat(error.getDetails()).isEqualTo("capsa_0");
    }

    @Test
    void expiredCapsa410_keepsStatusAndExpiryDetails() {
        ApiError error = ApiErrorParser.parse(410,
                "{\"error\":{\"code\":\"ENVELOPE_EXPIRED\",\"message\":\"Capsa has expired\","
                        + "\"details\":{\"status\":\"expired\",\"expiredAt\":\"2026-11-01T00:00:00Z\"}}}");

        assertThat(error.getCode()).isEqualTo("ENVELOPE_EXPIRED");
        assertThat(error.getDetails())
                .isEqualTo(Map.of("status", "expired", "expiredAt", "2026-11-01T00:00:00Z"));
    }

    @Test
    void bodyRetryAfter_isExposedInSeconds() {
        ApiError error = ApiErrorParser.parse(429,
                "{\"error\":{\"code\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"Slow down\",\"retryAfter\":30}}",
                headers("Retry-After", "99"));

        assertThat(error.getRetryAfter()).isEqualTo(30.0);
    }

    @Test
    void retryAfterHeaderInSeconds_isUsedWhenBodyHasNone() {
        ApiError error = ApiErrorParser.parse(503,
                "{\"error\":{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Try later\"}}",
                headers("Retry-After", "2"));

        assertThat(error.getCode()).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(error.getRetryAfter()).isEqualTo(2.0);
    }

    @Test
    void fractionalBodyRetryAfter_isExposedWithItsFraction() {
        ApiError error = ApiErrorParser.parse(429,
                "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":1.5}}", headers("Retry-After", "9"));

        assertThat(error.getRetryAfter()).isEqualTo(1.5);
    }

    @Test
    void wholeSecondsStringInBody_isExposed() {
        ApiError error = ApiErrorParser.parse(429,
                "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":\"7\"}}", headers("Retry-After", "9"));

        assertThat(error.getRetryAfter()).isEqualTo(7.0);
    }

    @Test
    void retryAfterHeaderAsHttpDate_isNotExposedButStillDelays() {
        String date = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(120)
                .format(DateTimeFormatter.RFC_1123_DATE_TIME);

        ApiError error = ApiErrorParser.parse(429, null, headers("Retry-After", date));

        assertThat(error.getRetryAfter()).isNull();
        assertThat(error.getRetryDelay()).isBetween(Duration.ofSeconds(110), Duration.ofSeconds(121));
    }

    @Test
    void fractionalRetryAfterHeader_isNotExposed() {
        ApiError error = ApiErrorParser.parse(503, null, headers("Retry-After", "1.5"));

        assertThat(error.getRetryAfter()).isNull();
    }

    @Test
    void fractionalBodyRetryAfter_isKeptExactlyForTheRetryDelay() {
        ApiError error = ApiErrorParser.parse(503,
                "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":1.25}}", headers("Retry-After", "9"));

        assertThat(error.getRetryDelay()).isEqualTo(Duration.ofMillis(1250));
    }

    @Test
    void negativeOrNonNumericBodyRetryAfter_fallsBackToTheHeader() {
        ApiError negative = ApiErrorParser.parse(503,
                "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":-3}}", headers("Retry-After", "2"));
        ApiError text = ApiErrorParser.parse(503,
                "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":\"5\"}}", headers("Retry-After", "2"));

        assertThat(negative.getRetryAfter()).isEqualTo(2.0);
        assertThat(negative.getRetryDelay()).isEqualTo(Duration.ofSeconds(2));
        assertThat(text.getRetryDelay()).isEqualTo(Duration.ofSeconds(2));
    }

    @Test
    void fractionalRetryAfterHeader_isUsedExactlyForTheRetryDelay() {
        assertThat(ApiErrorParser.parse(503, null, headers("Retry-After", "1.5")).getRetryDelay())
                .isEqualTo(Duration.ofMillis(1500));
    }

    @Test
    void pastRetryAfterDate_isAZeroRetryDelay() {
        String date = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(60)
                .format(DateTimeFormatter.RFC_1123_DATE_TIME);

        assertThat(ApiErrorParser.parse(429, null, headers("Retry-After", date)).getRetryDelay())
                .isEqualTo(Duration.ZERO);
    }

    @Test
    void unreadableRetryAfterHeader_hasNoRetryDelay() {
        assertThat(ApiErrorParser.parse(429, null, headers("Retry-After", "-1")).getRetryDelay()).isNull();
        assertThat(ApiErrorParser.parse(429, null, headers("Retry-After", "soon")).getRetryDelay()).isNull();
    }

    @Test
    void negativeRetryAfterHeader_isIgnored() {
        assertThat(ApiErrorParser.parse(503, null, headers("Retry-After", "-1")).getRetryAfter()).isNull();
    }

    @Test
    void unreadableRetryAfterHeader_isIgnored() {
        ApiError error = ApiErrorParser.parse(429, null, headers("Retry-After", "soon"));

        assertThat(error.getRetryAfter()).isNull();
    }

    @Test
    void nonJsonBody_fallsBackToStatusCodeAndReasonPhrase() {
        ApiError error = ApiErrorParser.parse(502, "<html>Bad Gateway</html>");

        assertThat(error.getCode()).isEqualTo("HTTP_502");
        assertThat(error.getMessage()).isEqualTo("Bad Gateway");
        assertThat(error.getDetails()).isNull();
        assertThat(error.getResponseBody()).isEqualTo("<html>Bad Gateway</html>");
    }

    @Test
    void jsonThatIsNotAnErrorObject_fallsBack() {
        assertThat(ApiErrorParser.parse(500, "[1,2,3]").getCode()).isEqualTo("HTTP_500");
        assertThat(ApiErrorParser.parse(500, "\"text\"").getCode()).isEqualTo("HTTP_500");
        assertThat(ApiErrorParser.parse(401, "{\"error\":\"Unauthorized\"}").getCode()).isEqualTo("HTTP_401");
        assertThat(ApiErrorParser.parse(404, "{}").getMessage()).isEqualTo("Not Found");
    }

    @Test
    void emptyOrNonTextCode_fallsBack() {
        ApiError error = ApiErrorParser.parse(418, "{\"error\":{\"code\":\"\",\"message\":7}}");

        assertThat(error.getCode()).isEqualTo("HTTP_418");
        assertThat(error.getMessage()).isEqualTo("HTTP 418");
    }

    @Test
    void reasonPhrases_coverCommonStatuses() {
        assertThat(ApiErrorParser.reasonPhrase(400)).isEqualTo("Bad Request");
        assertThat(ApiErrorParser.reasonPhrase(403)).isEqualTo("Forbidden");
        assertThat(ApiErrorParser.reasonPhrase(405)).isEqualTo("Method Not Allowed");
        assertThat(ApiErrorParser.reasonPhrase(408)).isEqualTo("Request Timeout");
        assertThat(ApiErrorParser.reasonPhrase(409)).isEqualTo("Conflict");
        assertThat(ApiErrorParser.reasonPhrase(410)).isEqualTo("Gone");
        assertThat(ApiErrorParser.reasonPhrase(413)).isEqualTo("Payload Too Large");
        assertThat(ApiErrorParser.reasonPhrase(415)).isEqualTo("Unsupported Media Type");
        assertThat(ApiErrorParser.reasonPhrase(422)).isEqualTo("Unprocessable Entity");
        assertThat(ApiErrorParser.reasonPhrase(429)).isEqualTo("Too Many Requests");
        assertThat(ApiErrorParser.reasonPhrase(501)).isEqualTo("Not Implemented");
        assertThat(ApiErrorParser.reasonPhrase(503)).isEqualTo("Service Unavailable");
        assertThat(ApiErrorParser.reasonPhrase(504)).isEqualTo("Gateway Timeout");
    }
}
