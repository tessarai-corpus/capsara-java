package com.capsara.sdk.builder;

import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.models.FileInput;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Runs the shared file name vectors against the builder's file name check. */
class FilenameCheckTest {

    private static CapsaBuilder newBuilder() {
        return new CapsaBuilder("party_creator", SharedKeyFixture.getPrimaryKeyPair().getPrivateKey(), null);
    }

    static Stream<Arguments> vectors() throws IOException {
        try (InputStream in = FilenameCheckTest.class.getResourceAsStream("/safe-filename-vectors.json")) {
            assertThat(in).isNotNull();
            JsonNode root = new ObjectMapper().readTree(in);
            List<Arguments> args = new ArrayList<>();
            root.get("vectors").forEach(v -> args.add(Arguments.of(
                    v.get("name").asText(), v.get("input").asText(), v.get("rejectOnSend").asBoolean())));
            return args.stream();
        }
    }

    private static void assertValidationError(Throwable thrown) {
        assertThat(thrown).isInstanceOf(CapsaraException.class);
        assertThat(((CapsaraException) thrown).getCode()).isEqualTo("VALIDATION_ERROR");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void addFileMatchesVector(String name, String input, boolean rejectOnSend) {
        try (CapsaBuilder builder = newBuilder()) {
            Throwable thrown = catchThrowable(() -> builder.addFile("x".getBytes(StandardCharsets.UTF_8), input));
            if (rejectOnSend) {
                assertValidationError(thrown);
                assertThat(builder.getFileCount()).isZero();
            } else {
                assertThat(thrown).isNull();
            }
        }
    }

    @Test
    void messageDoesNotEchoTheName() {
        try (CapsaBuilder builder = newBuilder()) {
            Throwable thrown = catchThrowable(() -> builder.addTextFile("../../.ssh/authorized_keys", "x"));
            assertValidationError(thrown);
            assertThat(thrown.getMessage()).contains("path separator").doesNotContain("authorized_keys");
        }
    }

    @Test
    void nullNameIsRejected() {
        try (CapsaBuilder builder = newBuilder()) {
            assertValidationError(catchThrowable(() -> builder.addFile("x".getBytes(StandardCharsets.UTF_8), null)));
        }
    }

    @Test
    void everyAddFileEntryPointIsChecked(@TempDir Path dir) throws IOException {
        Path file = Files.write(dir.resolve("real.txt"), "x".getBytes(StandardCharsets.UTF_8));
        byte[] data = "x".getBytes(StandardCharsets.UTF_8);
        try (CapsaBuilder builder = newBuilder()) {
            assertValidationError(catchThrowable(() -> builder.addFile(FileInput.fromData(data, "../x.txt"))));
            assertValidationError(catchThrowable(() -> builder.addFile(data, "a/b.txt", "text/plain")));
            assertValidationError(catchThrowable(() -> builder.addFile(
                    new ByteArrayInputStream(data), "a\\b.txt", null)));
            assertValidationError(catchThrowable(() -> builder.addFile(file.toString(), "../x.txt", null)));
            assertValidationError(catchThrowable(() -> builder.addFiles(FileInput.fromData(data, ".."))));
            assertValidationError(catchThrowable(() -> builder.addTextFile("a/b.txt", "x")));
            assertValidationError(catchThrowable(() -> builder.addJsonFile("a\\b.json", Collections.emptyMap())));
            assertThat(builder.getFileCount()).isZero();
        }
    }

    @Test
    void pathEntryPointsUseTheFileNamePart(@TempDir Path dir) throws IOException {
        Path file = Files.write(dir.resolve("real.txt"), "x".getBytes(StandardCharsets.UTF_8));
        try (CapsaBuilder builder = newBuilder()) {
            assertThatCode(() -> {
                builder.addFile(file.toString());
                builder.addFiles(file.toString());
                builder.addFiles(Collections.singletonList(file.toString()));
            }).doesNotThrowAnyException();
            assertThat(builder.getFileCount()).isEqualTo(3);
        }
    }
}
