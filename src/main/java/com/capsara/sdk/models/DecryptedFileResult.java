package com.capsara.sdk.models;

/** Result of decrypting a file, containing the plaintext data and filename. */
public final class DecryptedFileResult {

    private byte[] data;
    private String filename;

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }
}
