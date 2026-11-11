package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Matches API response. */
public final class EncryptedFile {

    @JsonProperty("fileId")
    private String fileId = "";

    @JsonProperty("encryptedFilename")
    private String encryptedFilename = "";

    @JsonProperty("filenameIV")
    private String filenameIV = "";

    @JsonProperty("filenameAuthTag")
    private String filenameAuthTag = "";

    @JsonProperty("iv")
    private String iv = "";

    @JsonProperty("authTag")
    private String authTag = "";

    @JsonProperty("mimetype")
    private String mimetype = "";

    @JsonProperty("size")
    private long size;

    @JsonProperty("hash")
    private String hash = "";

    @JsonProperty("hashAlgorithm")
    private String hashAlgorithm = "SHA-256";

    @JsonProperty("expiresAt")
    private String expiresAt;

    @JsonProperty("compressed")
    private Boolean compressed;

    @JsonProperty("compressionAlgorithm")
    private String compressionAlgorithm;

    @JsonProperty("originalSize")
    private Long originalSize;

    @JsonProperty("transform")
    private String transform;

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getEncryptedFilename() {
        return encryptedFilename;
    }

    public void setEncryptedFilename(String encryptedFilename) {
        this.encryptedFilename = encryptedFilename;
    }

    public String getFilenameIV() {
        return filenameIV;
    }

    public void setFilenameIV(String filenameIV) {
        this.filenameIV = filenameIV;
    }

    public String getFilenameAuthTag() {
        return filenameAuthTag;
    }

    public void setFilenameAuthTag(String filenameAuthTag) {
        this.filenameAuthTag = filenameAuthTag;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getAuthTag() {
        return authTag;
    }

    public void setAuthTag(String authTag) {
        this.authTag = authTag;
    }

    public String getMimetype() {
        return mimetype;
    }

    public void setMimetype(String mimetype) {
        this.mimetype = mimetype;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(String expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Boolean getCompressed() {
        return compressed;
    }

    public void setCompressed(Boolean compressed) {
        this.compressed = compressed;
    }

    public String getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public void setCompressionAlgorithm(String compressionAlgorithm) {
        this.compressionAlgorithm = compressionAlgorithm;
    }

    public Long getOriginalSize() {
        return originalSize;
    }

    public void setOriginalSize(Long originalSize) {
        this.originalSize = originalSize;
    }

    /** One-way transform reference (URL or @partyId/id). */
    public String getTransform() {
        return transform;
    }

    public void setTransform(String transform) {
        this.transform = transform;
    }
}
