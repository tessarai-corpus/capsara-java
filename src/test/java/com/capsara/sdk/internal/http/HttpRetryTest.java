package com.capsara.sdk.internal.http;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.helpers.StubServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** One retry policy for every request: 429/503, dropped connections, and timeouts except on POST. */
class HttpRetryTest {

    private final RetryConfig fast = new RetryConfig(3, Duration.ofMillis(1), 2.0, Duration.ofMillis(20));

    private StubServer server;
    private HttpClient client;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    private HttpRequest get(Duration timeout) {
        return HttpRequest.newBuilder(URI.create(server.baseUrl() + "/r")).timeout(timeout).GET().build();
    }

    private HttpRequest post(Duration timeout) {
        return HttpRequest.newBuilder(URI.create(server.baseUrl() + "/r")).timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
    }

    private HttpResponse<String> send(HttpRequest request) {
        return HttpRetry.send(client, request, HttpResponse.BodyHandlers.ofString(), fast, null).join();
    }

    private HttpResponse<String> sendHonouringHints(HttpRequest request) {
        RetryConfig config = new RetryConfig(3, Duration.ofSeconds(5), 2.0, Duration.ofSeconds(5));
        return HttpRetry.send(client, request, HttpResponse.BodyHandlers.ofString(), config, null).join();
    }

    @Test
    void retries503ThenSucceeds() {
        server.on("/r", StubServer.json(503, "{}"), StubServer.json(200, "{\"ok\":true}"));

        assertThat(send(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(200);
        assertThat(server.requestsTo("/r")).hasSize(2);
    }

    @Test
    void retries429WithoutHint_andStopsAfterThreeRetries() {
        server.on("/r", StubServer.json(429, "{\"error\":{\"code\":\"RATE_LIMITED\",\"message\":\"x\"}}"));

        assertThat(send(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(429);
        assertThat(server.requestsTo("/r")).hasSize(4);
    }

    @Test
    void doesNotRetryOtherStatuses() {
        server.on("/r", StubServer.json(500, "{}"));

        assertThat(send(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(500);
        assertThat(server.requestsTo("/r")).hasSize(1);
    }

    @Test
    void doesNotRetry401() {
        server.on("/r", StubServer.json(401, "{}"));

        assertThat(send(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(401);
        assertThat(server.requestsTo("/r")).hasSize(1);
    }

    @Test
    void retriesDroppedConnectionOnPost() {
        server.on("/r", StubServer.dropConnection(), StubServer.json(201, "{}"));

        assertThat(send(post(Duration.ofSeconds(5))).statusCode()).isEqualTo(201);
        assertThat(server.requestsTo("/r")).hasSize(2);
    }

    @Test
    void doesNotRetryTimeoutOnPost() {
        server.on("/r", StubServer.delayed(StubServer.json(200, "{}"), 500));

        Throwable thrown = catchThrowable(() -> send(post(Duration.ofMillis(100))));

        assertThat(HttpRetry.unwrap(thrown)).isInstanceOf(HttpTimeoutException.class);
        assertThat(server.requestsTo("/r")).hasSize(1);
    }

    @Test
    void retriesTimeoutOnGet() {
        server.on("/r", StubServer.delayed(StubServer.json(200, "{}"), 500), StubServer.json(200, "{}"));

        assertThat(send(get(Duration.ofMillis(400))).statusCode()).isEqualTo(200);
        assertThat(server.requestsTo("/r").size()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void retriesWithBodyHintBeforeHeader() {
        server.on("/r", StubServer.json(503, "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":0}}",
                Map.of("Retry-After", "120")), StubServer.json(200, "{}"));

        long start = System.nanoTime();
        assertThat(send(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(200);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    void delay_capsServerHintAtMaxDelay() {
        RetryConfig config = new RetryConfig();

        assertThat(HttpRetry.delay(config, Duration.ofSeconds(120), 0)).isEqualTo(Duration.ofSeconds(30));
        assertThat(HttpRetry.delay(config, Duration.ofSeconds(5), 0)).isEqualTo(Duration.ofSeconds(5));
        assertThat(HttpRetry.delay(config, Duration.ofMillis(1500), 0)).isEqualTo(Duration.ofMillis(1500));
    }

    @Test
    void retriesWithFractionalBodyHintExactly() {
        server.on("/r", StubServer.json(503, "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":0.3}}",
                Map.of("Retry-After", "0")), StubServer.json(200, "{}"));

        long start = System.nanoTime();
        assertThat(sendHonouringHints(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(200);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(Duration.ofMillis(290));
    }

    @Test
    void negativeBodyHint_fallsBackToTheHeader() {
        server.on("/r", StubServer.json(503, "{\"error\":{\"code\":\"X\",\"message\":\"x\",\"retryAfter\":-5}}",
                Map.of("Retry-After", "0.3")), StubServer.json(200, "{}"));

        long start = System.nanoTime();
        assertThat(sendHonouringHints(get(Duration.ofSeconds(5))).statusCode()).isEqualTo(200);
        assertThat(Duration.ofNanos(System.nanoTime() - start))
                .isGreaterThanOrEqualTo(Duration.ofMillis(290))
                .isLessThan(Duration.ofMillis(950));
    }

    @Test
    void delay_capsServerHintAtThirtySecondsEvenWithALargerMaxDelay() {
        RetryConfig config = new RetryConfig(3, Duration.ofSeconds(1), 2.0, Duration.ofMinutes(5));

        assertThat(HttpRetry.delay(config, Duration.ofSeconds(120), 0)).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void tlsFailure_isNotRetried() {
        assertThat(HttpRetry.isRetryableFailure(new javax.net.ssl.SSLHandshakeException("bad cert"), "GET"))
                .isFalse();
        assertThat(HttpRetry.isRetryableFailure(new IOException("wrapped", new javax.net.ssl.SSLException("x")),
                "GET")).isFalse();
        assertThat(HttpRetry.isRetryableFailure(new java.net.ConnectException("refused"), "POST")).isTrue();
        assertThat(HttpRetry.isRetryableFailure(new java.util.concurrent.CancellationException(), "GET"))
                .isFalse();
    }

    @Test
    void backoff_isExponentialWithUpToThirtyPercentJitter() {
        RetryConfig config = new RetryConfig();

        for (int attempt = 0; attempt < 3; attempt++) {
            long base = 1000L << attempt;
            long delay = HttpRetry.delay(config, null, attempt).toMillis();
            assertThat(delay).isBetween(base, (long) (base * 1.3));
        }
        assertThat(HttpRetry.backoff(config, 10)).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void defaults_matchThePolicy() {
        RetryConfig config = RetryConfig.defaults();

        assertThat(config.getMaxRetries()).isEqualTo(3);
        assertThat(config.getInitialDelay()).isEqualTo(Duration.ofSeconds(1));
        assertThat(config.getMaxDelay()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void isRetryableFailure_classifiesFailures() {
        assertThat(HttpRetry.isRetryableFailure(new HttpTimeoutException("t"), "POST")).isFalse();
        assertThat(HttpRetry.isRetryableFailure(new HttpTimeoutException("t"), "GET")).isTrue();
        assertThat(HttpRetry.isRetryableFailure(new java.net.http.HttpConnectTimeoutException("t"), "GET"))
                .isTrue();
        assertThat(HttpRetry.isRetryableFailure(new IllegalStateException("x"), "GET")).isFalse();
    }

    @Test
    void isRetryableFailure_retriesTheNetworkDropAllowListOnEveryMethod() {
        Throwable[] drops = {
            new java.net.ConnectException("Connection refused"),
            new java.net.UnknownHostException("api.example"),
            new java.net.NoRouteToHostException("No route to host"),
            new java.net.SocketException("Connection reset"),
            new java.net.SocketException("Network is unreachable"),
            new IOException("Broken pipe"),
            new IOException("Connection reset by peer"),
            new IOException("An existing connection was forcibly closed by the remote host"),
            new java.io.EOFException("EOF reached while reading"),
            new IOException("HTTP/1.1 header parser received no bytes"),
            new IOException("wrapped", new java.net.ConnectException("refused")),
        };
        for (Throwable drop : drops) {
            assertThat(HttpRetry.isRetryableFailure(drop, "POST")).as(drop.toString()).isTrue();
            assertThat(HttpRetry.isRetryableFailure(drop, "GET")).as(drop.toString()).isTrue();
        }
    }

    @Test
    void isRetryableFailure_doesNotRetryOtherIoFailures() {
        assertThat(HttpRetry.isRetryableFailure(new IOException("too many concurrent streams"), "GET")).isFalse();
        assertThat(HttpRetry.isRetryableFailure(new java.net.ProtocolException("bad status line"), "GET"))
                .isFalse();
        assertThat(HttpRetry.isRetryableFailure(new java.nio.charset.MalformedInputException(1), "GET"))
                .isFalse();
        assertThat(HttpRetry.isRetryableFailure(new InterruptedException(), "GET")).isFalse();
    }
}
