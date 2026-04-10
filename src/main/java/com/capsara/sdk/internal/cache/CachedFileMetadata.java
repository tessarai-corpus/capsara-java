package com.capsara.sdk.internal.cache;

/** Cached file metadata for decryption. */
public final class CachedFileMetadata {

    private String fileId = "";
    private String iv = "";
    private String authTag = "";
    private boolean compressed;
    private String encryptedFilename = "";
    private String filenameIV = "";
    private String filenameAuthTag = "";

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
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

    public boolean isCompressed() {
        return compressed;
    }

    public void setCompressed(boolean compressed) {
        this.compressed = compressed;
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
}
