package com.capsara.sdk.models;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs the shared safe file name vectors against DecryptedFileResult. */
class SafeFilenameTest {

    static List<JsonNode> loadVectors() throws IOException {
        try (InputStream in = SafeFilenameTest.class.getResourceAsStream("/safe-filename-vectors.json")) {
            assertThat(in).as("safe-filename-vectors.json on the test classpath").isNotNull();
            JsonNode root = new ObjectMapper().readTree(in);
            List<JsonNode> vectors = new ArrayList<>();
            root.get("vectors").forEach(vectors::add);
            return vectors;
        }
    }

    static Stream<Arguments> vectors() throws IOException {
        return loadVectors().stream().map(v -> Arguments.of(
                v.get("name").asText(), v.get("input").asText(), v.get("expected").asText()));
    }

    @Test
    void loadsTheSharedVectors() throws IOException {
        assertThat(loadVectors()).hasSizeGreaterThanOrEqualTo(25);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void sanitizeFilenameMatchesVector(String name, String input, String expected) {
        String result = DecryptedFileResult.sanitizeFilename(input);
        assertThat(result).isEqualTo(expected);
        assertThat(result.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(255);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void safeFilenameMatchesVector(String name, String input, String expected) {
        DecryptedFileResult result = new DecryptedFileResult();
        result.setFilename(input);
        assertThat(result.getFilename()).isEqualTo(input);
        assertThat(result.getSafeFilename()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void safeFilenameStaysInsideTheTargetDirectory(String name, String input, String expected) {
        Path dir = Paths.get(System.getProperty("java.io.tmpdir"), "capsara-downloads").toAbsolutePath().normalize();
        Path target = dir.resolve(DecryptedFileResult.sanitizeFilename(input)).normalize();
        assertThat(target.getParent()).isEqualTo(dir);
    }

    @Test
    void nullNameBecomesFile() {
        assertThat(DecryptedFileResult.sanitizeFilename(null)).isEqualTo("file");
        assertThat(new DecryptedFileResult().getSafeFilename()).isEqualTo("file");
    }
}
