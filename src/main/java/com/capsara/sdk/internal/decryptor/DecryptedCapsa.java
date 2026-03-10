package com.capsara.sdk.internal.decryptor;

import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaAccessControl;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.CapsaMetadata;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.CapsaStatus;
import com.capsara.sdk.models.EncryptedFile;

import java.util.Map;

/**
 * Decrypted capsa with plaintext subject, body, and structured data.
 * <p>
 * File contents remain encrypted until explicitly downloaded via
 * {@link com.capsara.sdk.CapsaraClient#downloadFileAsync}.
 * <p>
 * Implements AutoCloseable to securely clear the master key from memory.
 * Call {@link #close()} or use try-with-resources when done.
 */
public final class DecryptedCapsa implements AutoCloseable {

    private byte[] masterKey;
    private boolean disposed;

    private String id = "";
    private String creator = "";
    private String createdAt = "";
    private String updatedAt = "";
    private CapsaStatus status;
    private String subject;
    private String body;
    private Map<String, Object> structured;
    private EncryptedFile[] files = new EncryptedFile[0];
    private CapsaAccessControl accessControl;
    private CapsaKeychain keychain;
    private CapsaSignature signature;
    private CapsaMetadata metadata;
    private long totalSize;
    private Capsa encryptedCapsa;

    /** Capsa identifier. */
    public String getId() {
        return id;
    }

    void setId(String id) {
        this.id = id;
    }

    /** Creator party ID. */
    public String getCreator() {
        return creator;
    }

    void setCreator(String creator) {
        this.creator = creator;
    }

    /** Creation timestamp (ISO 8601). */
    public String getCreatedAt() {
        return createdAt;
    }

    void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    /** Last update timestamp (ISO 8601). */
    public String getUpdatedAt() {
        return updatedAt;
    }

    void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /** Lifecycle status. */
    public CapsaStatus getStatus() {
        return status;
    }

    void setStatus(CapsaStatus status) {
        this.status = status;
    }

    /** Decrypted subject. */
    public String getSubject() {
        return subject;
    }

    void setSubject(String subject) {
        this.subject = subject;
    }

    /** Decrypted body/message. */
    public String getBody() {
        return body;
    }

    void setBody(String body) {
        this.body = body;
    }

    /** Decrypted structured data. */
    public Map<String, Object> getStructured() {
        return structured;
    }

    void setStructured(Map<String, Object> structured) {
        this.structured = structured;
    }

    /** Encrypted file metadata. Files are decrypted on download. */
    public EncryptedFile[] getFiles() {
        return files;
    }

    void setFiles(EncryptedFile[] files) {
        this.files = files;
    }

    /** Access control settings including expiration. */
    public CapsaAccessControl getAccessControl() {
        return accessControl;
    }

    void setAccessControl(CapsaAccessControl accessControl) {
        this.accessControl = accessControl;
    }

    /** Keychain entries. */
    public CapsaKeychain getKeychain() {
        return keychain;
    }

    void setKeychain(CapsaKeychain keychain) {
        this.keychain = keychain;
    }

    /** Creator signature. */
    public CapsaSignature getSignature() {
        return signature;
    }

    void setSignature(CapsaSignature signature) {
        this.signature = signature;
    }

    /** Unencrypted metadata (visible to server). */
    public CapsaMetadata getMetadata() {
        return metadata;
    }

    void setMetadata(CapsaMetadata metadata) {
        this.metadata = metadata;
    }

    /** Total size of all encrypted files in bytes. */
    public long getTotalSize() {
        return totalSize;
    }

    void setTotalSize(long totalSize) {
        this.totalSize = totalSize;
    }

    /** Number of files in this capsa. */
    public int getFileCount() {
        return files != null ? files.length : 0;
    }

    /** Original encrypted capsa for reference. */
    public Capsa getEncryptedCapsa() {
        return encryptedCapsa;
    }

    void setEncryptedCapsa(Capsa encryptedCapsa) {
        this.encryptedCapsa = encryptedCapsa;
    }

    /**
     * Get the decrypted master key for file decryption.
     * <p>
     * SECURITY: This key is only valid for THIS capsa. Compromise does not
     * affect other capsas or the party's private key.
     * <p>
     * Call {@link #clearMasterKey()} or {@link #close()} when done.
     *
     * @return decrypted AES-256 master key
     * @throws IllegalStateException if disposed or key not available
     */
    public byte[] getMasterKey() {
        if (disposed) {
            throw new IllegalStateException("DecryptedCapsa has been disposed");
        }
        if (masterKey == null) {
            throw new IllegalStateException("Master key not available");
        }
        return masterKey;
    }

    void setMasterKey(byte[] key) {
        this.masterKey = key;
    }

    /**
     * Clear the master key from memory.
     */
    public void clearMasterKey() {
        if (masterKey != null) {
            SecureMemory.clear(masterKey);
            masterKey = null;
        }
    }

    /**
     * Dispose and clear master key.
     */
    @Override
    public void close() {
        if (!disposed) {
            clearMasterKey();
            disposed = true;
        }
    }
}
