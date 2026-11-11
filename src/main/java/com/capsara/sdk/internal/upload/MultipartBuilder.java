package com.capsara.sdk.internal.upload;

import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.json.JsonMapper;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Multipart form-data builder for capsa uploads (supports 1-500 capsas).
 */
public final class MultipartBuilder {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final String boundary;
    private final List<MultipartPart> parts = new ArrayList<>();
    private boolean metadataSet;

    /**
     * Create a new multipart builder with a random boundary.
     */
    public MultipartBuilder() {
        byte[] randomBytes = SecureMemory.generateRandomBytes(16);
        StringBuilder sb = new StringBuilder("----CapsaBoundary");
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        this.boundary = sb.toString();
    }

    /**
     * Add capsa batch metadata (must be first).
     *
     * @param capsaCount number of capsas in request
     * @param creator    creator party ID
     * @return this builder
     */
    public MultipartBuilder addMetadata(int capsaCount, String creator) {
        if (metadataSet) {
            throw new IllegalStateException("Metadata already set");
        }

        try {
            MetadataRequest metadata = new MetadataRequest();
            metadata.capsaCount = capsaCount;
            metadata.creator = creator;

            MultipartPart part = new MultipartPart();
            part.name = "metadata";
            part.content = OBJECT_MAPPER.writeValueAsString(metadata);
            part.contentType = "application/json";
            parts.add(part);

            metadataSet = true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize metadata", e);
        }

        return this;
    }

    /**
     * Add capsa metadata part with index.
     *
     * @param capsa      capsa upload data
     * @param capsaIndex capsa index in request
     * @return this builder
     */
    public MultipartBuilder addCapsaMetadata(Object capsa, int capsaIndex) {
        if (!metadataSet) {
            throw new IllegalStateException("Must call addMetadata() first");
        }

        try {
            MultipartPart part = new MultipartPart();
            part.name = "capsa_" + capsaIndex;
            part.content = OBJECT_MAPPER.writeValueAsString(capsa);
            part.contentType = "application/json";
            parts.add(part);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize capsa metadata", e);
        }

        return this;
    }

    /**
     * Add file binary part with file ID.
     *
     * @param fileData encrypted file data
     * @param fileId   file ID from metadata (should include .enc extension)
     * @return this builder
     */
    public MultipartBuilder addFileBinary(byte[] fileData, String fileId) {
        if (!metadataSet) {
            throw new IllegalStateException("Must call addMetadata() first");
        }

        MultipartPart part = new MultipartPart();
        part.name = "file";
        part.binaryContent = fileData;
        part.contentType = "application/octet-stream";
        part.filename = fileId;
        parts.add(part);

        return this;
    }

    /**
     * Build the complete multipart body.
     *
     * @return multipart body as byte array
     */
    public byte[] build() {
        if (!metadataSet) {
            throw new IllegalStateException("Must call addMetadata() first");
        }

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (MultipartPart part : parts) {
                // Add boundary
                writeString(baos, "--" + boundary + "\r\n");

                // Add Content-Disposition header
                String disposition = "Content-Disposition: form-data; name=\"" + part.name + "\"";
                if (part.filename != null && !part.filename.isEmpty()) {
                    disposition += "; filename=\"" + part.filename + "\"";
                }
                writeString(baos, disposition + "\r\n");

                // Add Content-Type header
                if (part.contentType != null && !part.contentType.isEmpty()) {
                    writeString(baos, "Content-Type: " + part.contentType + "\r\n");
                }

                // Add blank line
                writeString(baos, "\r\n");

                // Add content
                if (part.binaryContent != null) {
                    baos.write(part.binaryContent);
                } else if (part.content != null) {
                    byte[] contentBytes = part.content.getBytes(StandardCharsets.UTF_8);
                    baos.write(contentBytes);
                }

                // Add trailing line break
                writeString(baos, "\r\n");
            }

            // Add final boundary
            writeString(baos, "--" + boundary + "--\r\n");

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to build multipart body", e);
        }
    }

    /**
     * Get the Content-Type header value.
     */
    public String getContentType() {
        return "multipart/form-data; boundary=" + boundary;
    }

    /**
     * Get the boundary string.
     */
    public String getBoundary() {
        return boundary;
    }

    private static void writeString(ByteArrayOutputStream baos, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        baos.write(bytes);
    }

    @SuppressWarnings("unused") // Fields used by Jackson serialization
    private static final class MetadataRequest {
        public int capsaCount;
        public String creator;
    }

    private static final class MultipartPart {
        String name;
        String content;
        byte[] binaryContent;
        String contentType;
        String filename;
    }
}
