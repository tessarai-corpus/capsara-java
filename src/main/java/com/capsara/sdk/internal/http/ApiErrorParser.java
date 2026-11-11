package com.capsara.sdk.internal.http;

import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

/** Parses API error responses for every service; unreadable bodies map to HTTP_status. */
public final class ApiErrorParser {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();
    private static final Pattern DELTA_SECONDS = Pattern.compile("^\\d+(\\.\\d+)?$");
    private static final Pattern WHOLE_SECONDS = Pattern.compile("^\\d+$");

    private ApiErrorParser() {
    }

    /**
     * Parse an error response without headers.
     *
     * @param statusCode HTTP status code
     * @param body       raw response body, may be null
     * @return parsed error
     */
    public static ApiError parse(int statusCode, String body) {
        return parse(statusCode, body, null);
    }

    /**
     * Parse an error response.
     *
     * @param statusCode HTTP status code
     * @param body       raw response body, may be null
     * @param headers    response headers, used for Retry-After when the body has none
     * @return parsed error
     */
    public static ApiError parse(int statusCode, String body, HttpHeaders headers) {
        String code = "HTTP_" + statusCode;
        String message = reasonPhrase(statusCode);
        Object details = null;
        Double retryAfter = null;
        Duration retryDelay = null;

        String requestId = null;

        JsonNode root = readRoot(body);
        JsonNode error = root != null && root.get("error") != null && root.get("error").isObject()
                ? root.get("error") : null;
        if (error != null) {
            JsonNode codeNode = error.get("code");
            if (codeNode != null && codeNode.isTextual() && !codeNode.asText().isEmpty()) {
                code = codeNode.asText();
                JsonNode messageNode = error.get("message");
                if (messageNode != null && messageNode.isTextual() && !messageNode.asText().isEmpty()) {
                    message = messageNode.asText();
                }
                JsonNode detailsNode = error.get("details");
                if (detailsNode != null && !detailsNode.isNull()) {
                    details = OBJECT_MAPPER.convertValue(detailsNode, Object.class);
                }
            }
            JsonNode retryNode = error.get("retryAfter");
            if (retryNode != null && retryNode.isNumber()) {
                double seconds = retryNode.asDouble();
                if (Double.isFinite(seconds) && seconds >= 0) {
                    retryAfter = seconds;
                    retryDelay = Duration.ofMillis((long) (seconds * 1000));
                }
            } else if (retryNode != null && retryNode.isTextual()) {
                retryAfter = wholeSeconds(retryNode.asText());
            }
        }

        requestId = textOrNull(error != null ? error.get("requestId") : null);
        if (requestId == null && root != null) {
            requestId = textOrNull(root.get("requestId"));
        }

        if (retryAfter == null) {
            retryAfter = headers == null ? null : wholeSeconds(headers.firstValue("Retry-After").orElse(null));
        }
        if (retryDelay == null) {
            retryDelay = parseRetryAfterHeaderDelay(headers);
        }

        return new ApiError(statusCode, code, message, details, retryAfter, retryDelay, body, requestId);
    }

    /**
     * Exact delay from a Retry-After header: decimal seconds, or an HTTP-date (a past date is zero).
     *
     * @param headers response headers, may be null
     * @return the delay, or null when the header is absent or unreadable
     */
    static Duration parseRetryAfterHeaderDelay(HttpHeaders headers) {
        if (headers == null) {
            return null;
        }
        String value = headers.firstValue("Retry-After").orElse(null);
        if (value == null || value.isEmpty()) {
            return null;
        }
        String trimmed = value.trim();
        if (DELTA_SECONDS.matcher(trimmed).matches()) {
            return Duration.ofMillis((long) (Double.parseDouble(trimmed) * 1000));
        }
        try {
            ZonedDateTime date = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration delay = Duration.between(Instant.now(), date.toInstant());
            return delay.isNegative() ? Duration.ZERO : delay;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static JsonNode readRoot(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(body);
            return root != null && root.isObject() ? root : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String textOrNull(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    private static Double wholeSeconds(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return WHOLE_SECONDS.matcher(trimmed).matches() ? Double.valueOf(trimmed) : null;
    }

    /**
     * Standard reason phrase for a status code.
     *
     * @param statusCode HTTP status code
     * @return reason phrase, or "HTTP status" for codes without one here
     */
    public static String reasonPhrase(int statusCode) {
        switch (statusCode) {
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 403:
                return "Forbidden";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 408:
                return "Request Timeout";
            case 409:
                return "Conflict";
            case 410:
                return "Gone";
            case 413:
                return "Payload Too Large";
            case 415:
                return "Unsupported Media Type";
            case 422:
                return "Unprocessable Entity";
            case 429:
                return "Too Many Requests";
            case 500:
                return "Internal Server Error";
            case 501:
                return "Not Implemented";
            case 502:
                return "Bad Gateway";
            case 503:
                return "Service Unavailable";
            case 504:
                return "Gateway Timeout";
            default:
                return "HTTP " + statusCode;
        }
    }
}
