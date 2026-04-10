package com.capsara.sdk.models;

import java.io.InputStream;
import java.nio.file.Paths;
import java.time.OffsetDateTime;

/** Input descriptor for a file to encrypt and send, supporting path, byte array, or stream sources. */
public final class FileInput {

    private String path;
    private byte[] data;
    private InputStream stream;
    private String filename = "";
    private String mimetype;
    private Boolean compress;
    private OffsetDateTime expiresAt;
    private String transform;

    /** Mutually exclusive with data and stream. */
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    /** Mutually exclusive with path and stream. */
    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    /** Mutually exclusive with path and data. */
    public InputStream getStream() {
        return stream;
    }

    public void setStream(InputStream stream) {
        this.stream = stream;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    /** Auto-detected if not specified. */
    public String getMimetype() {
        return mimetype;
    }

    public void setMimetype(String mimetype) {
        this.mimetype = mimetype;
    }

    public Boolean getCompress() {
        return compress;
    }

    public void setCompress(Boolean compress) {
        this.compress = compress;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public static FileInput fromPath(String path) {
        return fromPath(path, null, null);
    }

    /** Creates a FileInput from a file path with optional filename and MIME type overrides. */
    public static FileInput fromPath(String path, String filename, String mimetype) {
        FileInput input = new FileInput();
        input.setPath(path);
        input.setFilename(filename != null ? filename : Paths.get(path).getFileName().toString());
        input.setMimetype(mimetype);
        return input;
    }

    public static FileInput fromData(byte[] data, String filename) {
        return fromData(data, filename, null);
    }

    /** Creates a FileInput from a byte array with a required filename and optional MIME type. */
    public static FileInput fromData(byte[] data, String filename, String mimetype) {
        FileInput input = new FileInput();
        input.setData(data);
        input.setFilename(filename);
        input.setMimetype(mimetype);
        return input;
    }

    public static FileInput fromStream(InputStream stream, String filename) {
        return fromStream(stream, filename, null);
    }

    /** Creates a FileInput from an InputStream with a required filename and optional MIME type. */
    public static FileInput fromStream(InputStream stream, String filename, String mimetype) {
        FileInput input = new FileInput();
        input.setStream(stream);
        input.setFilename(filename);
        input.setMimetype(mimetype);
        return input;
    }

    public FileInput withMimetype(String mimetype) {
        this.mimetype = mimetype;
        return this;
    }

    public FileInput withCompression(boolean compress) {
        this.compress = compress;
        return this;
    }

    public FileInput withExpiration(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    /** One-way transform reference (URL or @partyId/id). */
    public String getTransform() {
        return transform;
    }

    public void setTransform(String transform) {
        this.transform = transform;
    }

    public FileInput withTransform(String transform) {
        this.transform = transform;
        return this;
    }
}
