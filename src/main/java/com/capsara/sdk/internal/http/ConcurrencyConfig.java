package com.capsara.sdk.internal.http;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Limits concurrent HTTP requests via semaphore and provides a dedicated response
 * processing executor to avoid ForkJoinPool starvation.
 */
public final class ConcurrencyConfig {

    private static final int DEFAULT_MAX_CONCURRENT_REQUESTS = 10;
    private static final int DEFAULT_RESPONSE_POOL_SIZE = Runtime.getRuntime().availableProcessors();

    private final Semaphore requestSemaphore;
    private final ExecutorService responseExecutor;
    private final int maxConcurrentRequests;

    public ConcurrencyConfig() {
        this(DEFAULT_MAX_CONCURRENT_REQUESTS);
    }

    public ConcurrencyConfig(int maxConcurrentRequests) {
        this(maxConcurrentRequests, DEFAULT_RESPONSE_POOL_SIZE);
    }

    /** Creates a concurrency config with custom request limit and response pool size. */
    public ConcurrencyConfig(int maxConcurrentRequests, int responsePoolSize) {
        if (maxConcurrentRequests < 1) {
            throw new IllegalArgumentException("maxConcurrentRequests must be at least 1");
        }
        if (responsePoolSize < 1) {
            throw new IllegalArgumentException("responsePoolSize must be at least 1");
        }

        this.maxConcurrentRequests = maxConcurrentRequests;
        this.requestSemaphore = new Semaphore(maxConcurrentRequests);
        this.responseExecutor = Executors.newFixedThreadPool(responsePoolSize, r -> {
            Thread t = new Thread(r, "capsara-response-processor");
            t.setDaemon(true);
            return t;
        });
    }

    public Semaphore getRequestSemaphore() {
        return requestSemaphore;
    }

    /** Use with thenApplyAsync() to avoid ForkJoinPool contention. */
    public ExecutorService getResponseExecutor() {
        return responseExecutor;
    }

    public int getMaxConcurrentRequests() {
        return maxConcurrentRequests;
    }

    /** Shuts down the response executor, waiting up to 5 seconds for completion. */
    public void shutdown() {
        responseExecutor.shutdown();
        try {
            if (!responseExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                responseExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            responseExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
