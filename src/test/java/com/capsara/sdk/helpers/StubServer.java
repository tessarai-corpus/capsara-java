package com.capsara.sdk.helpers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A local HTTP server that answers each path from a queue of canned responses and
 * records every request it receives.
 */
public final class StubServer implements AutoCloseable {

    /** A canned response. A status of -1 drops the connection without answering. */
    public static final class Reply {
        final int status;
        final String body;
        final Map<String, String> headers;
        final long delayMillis;

        Reply(int status, String body, Map<String, String> headers) {
            this(status, body, headers, 0);
        }

        Reply(int status, String body, Map<String, String> headers, long delayMillis) {
            this.status = status;
            this.body = body;
            this.headers = headers;
            this.delayMillis = delayMillis;
        }
    }

    /** A request the server received. */
    public static final class Recorded {
        public final String method;
        public final String path;
        public final String body;
        public final Map<String, List<String>> headers;
        public final String query;

        Recorded(String method, String path, String body, Map<String, List<String>> headers, String query) {
            this.method = method;
            this.path = path;
            this.body = body;
            this.headers = headers;
            this.query = query;
        }

        public String header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
            return null;
        }
    }

    private final HttpServer server;
    private final Map<String, Deque<Reply>> replies = new HashMap<>();
    private final Map<String, Reply> lastReply = new HashMap<>();
    private final List<Recorded> requests = Collections.synchronizedList(new ArrayList<>());

    public StubServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public static Reply json(int status, String body) {
        return new Reply(status, body, Map.of("Content-Type", "application/json"));
    }

    public static Reply json(int status, String body, Map<String, String> headers) {
        Map<String, String> all = new HashMap<>(headers);
        all.put("Content-Type", "application/json");
        return new Reply(status, body, all);
    }

    public static Reply text(int status, String body) {
        return new Reply(status, body, Map.of("Content-Type", "text/plain"));
    }

    public static Reply redirect(String location) {
        return new Reply(302, "", Map.of("Location", location));
    }

    public static Reply dropConnection() {
        return new Reply(-1, "", Map.of());
    }

    public static Reply delayed(Reply reply, long delayMillis) {
        return new Reply(reply.status, reply.body, reply.headers, delayMillis);
    }

    /** Queue responses for a path; the last one repeats once the queue is drained. */
    public synchronized StubServer on(String path, Reply... queued) {
        Deque<Reply> deque = replies.computeIfAbsent(path, k -> new ArrayDeque<>());
        Collections.addAll(deque, queued);
        return this;
    }

    public List<Recorded> requests() {
        synchronized (requests) {
            return new ArrayList<>(requests);
        }
    }

    public List<Recorded> requestsTo(String path) {
        List<Recorded> result = new ArrayList<>();
        for (Recorded r : requests()) {
            if (r.path.equals(path)) {
                result.add(r);
            }
        }
        return result;
    }

    private synchronized Reply next(String path) {
        Deque<Reply> deque = replies.get(path);
        if (deque != null && !deque.isEmpty()) {
            Reply reply = deque.poll();
            lastReply.put(path, reply);
            return reply;
        }
        Reply last = lastReply.get(path);
        return last != null ? last : json(404, "{\"error\":{\"code\":\"NOT_STUBBED\",\"message\":\"" + path + "\"}}");
    }

    private void handle(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String path = exchange.getRequestURI().getPath();
        Map<String, List<String>> headers = new HashMap<>(exchange.getRequestHeaders());
        requests.add(new Recorded(exchange.getRequestMethod(), path, body, headers,
                exchange.getRequestURI().getRawQuery()));

        Reply reply = next(path);
        if (reply.delayMillis > 0) {
            try {
                Thread.sleep(reply.delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (reply.status < 0) {
            exchange.close();
            return;
        }
        byte[] bytes = reply.body.getBytes(StandardCharsets.UTF_8);
        reply.headers.forEach((k, v) -> exchange.getResponseHeaders().add(k, v));
        exchange.sendResponseHeaders(reply.status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
