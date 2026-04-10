package com.capsara.sdk.internal.crypto;

/**
 * File data for signature canonical string.
 */
public final class FileHashData {

    private final String fileId;
    private final String hash;
    private final long size;
    private final String iv;
    private final String filenameIV;

    /**
     * Create file hash data for signature.
     *
     * @param fileId     file identifier
     * @param hash       file content hash
     * @param size       file size in bytes
     * @param iv         content IV
     * @param filenameIV filename IV
     */
    public FileHashData(String fileId, String hash, long size, String iv, String filenameIV) {
        this.fileId = fileId;
        this.hash = hash;
        this.size = size;
        this.iv = iv;
        this.filenameIV = filenameIV;
    }

    public String getFileId() {
        return fileId;
    }

    public String getHash() {
        return hash;
    }

    public long getSize() {
        return size;
    }

    public String getIv() {
        return iv;
    }

    public String getFilenameIV() {
        return filenameIV;
    }
}
