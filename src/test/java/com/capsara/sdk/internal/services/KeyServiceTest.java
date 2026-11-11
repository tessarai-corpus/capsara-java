package com.capsara.sdk.internal.services;

import com.capsara.sdk.RetryConfig;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.StubServer;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.PartyKey;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Party-key lookups stay within the server's cap of 500 ids per request. */
class KeyServiceTest {

    private static final String KEYS = "/api/party/keys";

    private StubServer server;
    private ConcurrencyConfig concurrency;
    private KeyService keys;

    @BeforeEach
    void start() throws Exception {
        server = new StubServer();
        concurrency = new ConcurrencyConfig();
        keys = new KeyService(HttpClientFactory.createDefault(), server.baseUrl(), () -> "t", null,
                new RetryConfig(1, Duration.ofMillis(1), 1.0, Duration.ofMillis(5)), null, concurrency);
    }

    @AfterEach
    void stop() {
        server.close();
        concurrency.shutdown();
    }

    private static String[] ids(int count) {
        String[] ids = new String[count];
        for (int i = 0; i < count; i++) {
            ids[i] = "party_" + i;
        }
        return ids;
    }

    private List<JsonNode> requestedIds() throws Exception {
        List<JsonNode> bodies = new java.util.ArrayList<>();
        for (StubServer.Recorded request : server.requestsTo(KEYS)) {
            bodies.add(JsonMapper.getInstance().readTree(request.body).get("ids"));
        }
        return bodies;
    }

    @Test
    void fiveHundredIds_goInOneRequest() throws Exception {
        server.on(KEYS, StubServer.json(200, "{\"parties\":[{\"id\":\"party_0\",\"publicKey\":\"k\"}]}"));

        PartyKey[] result = keys.fetchPartyKeysAsync(ids(500)).join();

        assertThat(result).hasSize(1);
        assertThat(requestedIds()).singleElement().satisfies(body -> assertThat(body.size()).isEqualTo(500));
    }

    @Test
    void moreThanFiveHundredIds_areSplitAndTheResultsConcatenated() throws Exception {
        server.on(KEYS,
                StubServer.json(200, "{\"parties\":[{\"id\":\"party_0\",\"publicKey\":\"k0\"}]}"),
                StubServer.json(200, "{\"parties\":[{\"id\":\"party_500\",\"publicKey\":\"k500\"}]}"));

        PartyKey[] result = keys.fetchPartyKeysAsync(ids(501)).join();

        assertThat(result).extracting(PartyKey::getId).containsExactly("party_0", "party_500");
        List<JsonNode> bodies = requestedIds();
        assertThat(bodies).hasSize(2);
        assertThat(bodies.get(0).size()).isEqualTo(500);
        assertThat(bodies.get(1).size()).isEqualTo(1);
        assertThat(bodies.get(1).get(0).asText()).isEqualTo("party_500");
    }

    @Test
    void duplicateIds_areSentOnce() throws Exception {
        server.on(KEYS, StubServer.json(200, "{\"parties\":[]}"));
        String[] withDuplicates = new String[600];
        String[] unique = ids(300);
        System.arraycopy(unique, 0, withDuplicates, 0, 300);
        System.arraycopy(unique, 0, withDuplicates, 300, 300);

        keys.fetchPartyKeysAsync(withDuplicates).join();

        assertThat(requestedIds()).singleElement().satisfies(body -> assertThat(body.size()).isEqualTo(300));
    }

    @Test
    void failureOfALaterRequest_failsTheLookup() {
        server.on(KEYS,
                StubServer.json(200, "{\"parties\":[]}"),
                StubServer.json(400, "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"Too many ids\"}}"));

        Throwable thrown = catchThrowable(() -> keys.fetchPartyKeysAsync(ids(501)).join());

        assertThat(thrown).isInstanceOf(CompletionException.class);
        assertThat(((CapsaraException) thrown.getCause()).getCode()).isEqualTo("VALIDATION_ERROR");
    }
}
