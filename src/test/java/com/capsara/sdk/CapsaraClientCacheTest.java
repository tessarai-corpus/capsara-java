package com.capsara.sdk;

import com.capsara.sdk.builder.BuiltCapsa;
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.DecryptedCapsa;
import com.capsara.sdk.models.DecryptedFileResult;
import com.capsara.sdk.models.EncryptedFile;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.KeychainEntry;
import com.capsara.sdk.models.PartyKey;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The client's master key cache is independent of the caller's DecryptedCapsa. */
class CapsaraClientCacheTest {

    private static final String CREATOR_ID = "party_creator_cache";
    private static final String RECIPIENT_ID = "party_recipient_cache";
    private static final String FILE_CONTENT = "cached file content";

    private HttpServer server;
    private CapsaraClient client;
    private String capsaId;
    private String fileId;

    @BeforeEach
    void setUp() throws Exception {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        BuiltCapsa built;
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeys.getPrivateKey(), null)) {
            builder.setExpiresAt(OffsetDateTime.now().plusDays(30));
            builder.addRecipient(RECIPIENT_ID).addTextFile("note.txt", FILE_CONTENT);
            built = builder.build(new PartyKey[]{
                    TestHelpers.createMockPartyKey(CREATOR_ID, creatorKeys),
                    TestHelpers.createMockPartyKey(RECIPIENT_ID, SharedKeyFixture.getSecondaryKeyPair())
            });
        }

        capsaId = built.getCapsa().getPackageId();
        fileId = built.getCapsa().getFiles()[0].getFileId();
        String capsaJson = JsonMapper.getInstance().writeValueAsString(toCapsa(built, creatorKeys.getPublicKey()));
        byte[] blob = built.getFiles()[0].getData();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/api/capsas/" + capsaId, exchange -> {
            if (exchange.getRequestURI().getPath().endsWith("/download")) {
                respond(exchange, JsonMapper.getInstance().writeValueAsBytes(
                        Map.of("fileId", fileId, "downloadUrl", baseUrl + "/blob/" + fileId)));
            } else {
                respond(exchange, capsaJson.getBytes(StandardCharsets.UTF_8));
            }
        });
        server.createContext("/blob/", exchange -> respond(exchange, blob));
        server.start();

        CapsaraClientOptions options = new CapsaraClientOptions();
        options.setAccessToken("token");
        client = new CapsaraClient(baseUrl, options);
        client.setPrivateKey(creatorKeys.getPrivateKey());
    }

    @AfterEach
    void tearDown() {
        client.close();
        server.stop(0);
    }

    private static void respond(HttpExchange exchange, byte[] body) throws IOException {
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static Capsa toCapsa(BuiltCapsa built, String creatorPublicKey) {
        long totalSize = 0;
        for (EncryptedFile f : built.getCapsa().getFiles()) {
            totalSize += f.getSize();
        }
        Capsa capsa = new Capsa();
        capsa.setId(built.getCapsa().getPackageId());
        capsa.setCreator(CREATOR_ID);
        capsa.setStatus("active");
        capsa.setSignature(built.getCapsa().getSignature());
        CapsaKeychain keychain = built.getCapsa().getKeychain();
        keychain.setKeys(Arrays.stream(keychain.getKeys())
                .filter(entry -> CREATOR_ID.equals(entry.getParty()))
                .toArray(KeychainEntry[]::new));
        capsa.setKeychain(keychain);
        capsa.setCreatorPublicKey(creatorPublicKey);
        capsa.setFiles(built.getCapsa().getFiles());
        capsa.setAccessControl(built.getCapsa().getAccessControl());
        capsa.setTotalSize(totalSize);
        return capsa;
    }

    @Test
    void downloadFile_afterDecryptedCapsaClosed_stillDecrypts() {
        try (DecryptedCapsa decrypted = client.getDecryptedCapsaAsync(capsaId).join()) {
            assertThat(decrypted.getMasterKey()).isNotEmpty();
        }

        DecryptedFileResult file = client.downloadFileAsync(capsaId, fileId).join();

        assertThat(new String(file.getData(), StandardCharsets.UTF_8)).isEqualTo(FILE_CONTENT);
        assertThat(file.getFilename()).isEqualTo("note.txt");
    }

    @Test
    void clearingCache_doesNotZeroCallersMasterKey() {
        try (DecryptedCapsa decrypted = client.getDecryptedCapsaAsync(capsaId).join()) {
            byte[] expected = decrypted.getMasterKey().clone();

            client.clearCache();

            assertThat(decrypted.getMasterKey()).isEqualTo(expected).isNotEqualTo(new byte[expected.length]);
        }
    }
}
