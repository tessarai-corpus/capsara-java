package com.capsara.sdk;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Deduplication of in-flight decrypted capsa fetches. */
class CapsaraClientInFlightTest {

    private final ConcurrentHashMap<String, CompletableFuture<String>> inFlight = new ConcurrentHashMap<>();

    @Test
    void synchronouslyCompletedFetch_isReturnedAndLeavesNoEntry() {
        CompletableFuture<String> result = CapsaraClient.shareInFlight(inFlight, "c",
                () -> CompletableFuture.completedFuture("done"));

        assertThat(result.join()).isEqualTo("done");
        assertThat(inFlight).isEmpty();
    }

    @Test
    void synchronouslyFailedFetch_failsAndLeavesNoEntry() {
        CompletableFuture<String> result = CapsaraClient.shareInFlight(inFlight, "c",
                () -> CompletableFuture.failedFuture(new IllegalStateException("boom")));

        assertThatThrownBy(result::join).isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(IllegalStateException.class);
        assertThat(inFlight).isEmpty();
    }

    @Test
    void throwingStart_rethrowsAndLeavesNoEntry() {
        assertThatThrownBy(() -> CapsaraClient.<String>shareInFlight(inFlight, "c", () -> {
            throw new IllegalArgumentException("bad");
        })).isInstanceOf(IllegalArgumentException.class);
        assertThat(inFlight).isEmpty();
    }

    @Test
    void concurrentCallers_shareOneFetch_thenANewCallStartsAgain() {
        AtomicInteger starts = new AtomicInteger();
        CompletableFuture<String> pending = new CompletableFuture<>();

        CompletableFuture<String> first = CapsaraClient.shareInFlight(inFlight, "c", () -> {
            starts.incrementAndGet();
            return pending;
        });
        CompletableFuture<String> second = CapsaraClient.shareInFlight(inFlight, "c", () -> {
            starts.incrementAndGet();
            return CompletableFuture.completedFuture("other");
        });

        assertThat(second).isSameAs(first);
        pending.complete("v");
        assertThat(first.join()).isEqualTo("v");
        assertThat(inFlight).isEmpty();

        CompletableFuture<String> third = CapsaraClient.shareInFlight(inFlight, "c",
                () -> {
                    starts.incrementAndGet();
                    return CompletableFuture.completedFuture("again");
                });
        assertThat(third.join()).isEqualTo("again");
        assertThat(starts).hasValue(2);
    }
}
