package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/** Matches API GET /capsas/:id response. */
public final class Capsa {

    @JsonProperty("id")
    private String id = "";

    @JsonProperty("createdAt")
    private String createdAt = "";

    @JsonProperty("updatedAt")
    private String updatedAt = "";

    @JsonProperty("status")
    private String status;

    @JsonProperty("creator")
    private String creator = "";

    @JsonProperty("creatorPublicKey")
    private String creatorPublicKey;

    @JsonProperty("signature")
    private CapsaSignature signature = new CapsaSignature();

    @JsonProperty("keychain")
    private CapsaKeychain keychain = new CapsaKeychain();

    @JsonProperty("files")
    private EncryptedFile[] files = new EncryptedFile[0];

    @JsonProperty("encryptedStructured")
    private String encryptedStructured;

    @JsonProperty("structuredIV")
    private String structuredIV;

    @JsonProperty("structuredAuthTag")
    private String structuredAuthTag;

    @JsonProperty("encryptedSubject")
    private String encryptedSubject;

    @JsonProperty("subjectIV")
    private String subjectIV;

    @JsonProperty("subjectAuthTag")
    private String subjectAuthTag;

    @JsonProperty("encryptedBody")
    private String encryptedBody;

    @JsonProperty("bodyIV")
    private String bodyIV;

    @JsonProperty("bodyAuthTag")
    private String bodyAuthTag;

    @JsonProperty("accessControl")
    private CapsaAccessControl accessControl = new CapsaAccessControl();

    @JsonProperty("metadata")
    private CapsaMetadata metadata;

    private Long totalSize;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /** Status string as the server sent it, or null when missing. */
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    /** PEM public key the server verified the creator's signature with at upload. */
    public String getCreatorPublicKey() {
        return creatorPublicKey;
    }

    public void setCreatorPublicKey(String creatorPublicKey) {
        this.creatorPublicKey = creatorPublicKey;
    }

    public CapsaSignature getSignature() {
        return signature;
    }

    public void setSignature(CapsaSignature signature) {
        this.signature = signature;
    }

    public CapsaKeychain getKeychain() {
        return keychain;
    }

    public void setKeychain(CapsaKeychain keychain) {
        this.keychain = keychain;
    }

    public EncryptedFile[] getFiles() {
        return files;
    }

    public void setFiles(EncryptedFile[] files) {
        this.files = files;
    }

    public String getEncryptedStructured() {
        return encryptedStructured;
    }

    public void setEncryptedStructured(String encryptedStructured) {
        this.encryptedStructured = encryptedStructured;
    }

    public String getStructuredIV() {
        return structuredIV;
    }

    public void setStructuredIV(String structuredIV) {
        this.structuredIV = structuredIV;
    }

    public String getStructuredAuthTag() {
        return structuredAuthTag;
    }

    public void setStructuredAuthTag(String structuredAuthTag) {
        this.structuredAuthTag = structuredAuthTag;
    }

    public String getEncryptedSubject() {
        return encryptedSubject;
    }

    public void setEncryptedSubject(String encryptedSubject) {
        this.encryptedSubject = encryptedSubject;
    }

    public String getSubjectIV() {
        return subjectIV;
    }

    public void setSubjectIV(String subjectIV) {
        this.subjectIV = subjectIV;
    }

    public String getSubjectAuthTag() {
        return subjectAuthTag;
    }

    public void setSubjectAuthTag(String subjectAuthTag) {
        this.subjectAuthTag = subjectAuthTag;
    }

    public String getEncryptedBody() {
        return encryptedBody;
    }

    public void setEncryptedBody(String encryptedBody) {
        this.encryptedBody = encryptedBody;
    }

    public String getBodyIV() {
        return bodyIV;
    }

    public void setBodyIV(String bodyIV) {
        this.bodyIV = bodyIV;
    }

    public String getBodyAuthTag() {
        return bodyAuthTag;
    }

    public void setBodyAuthTag(String bodyAuthTag) {
        this.bodyAuthTag = bodyAuthTag;
    }

    public CapsaAccessControl getAccessControl() {
        return accessControl;
    }

    public void setAccessControl(CapsaAccessControl accessControl) {
        this.accessControl = accessControl;
    }

    public CapsaMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(CapsaMetadata metadata) {
        this.metadata = metadata;
    }

    /** Total encrypted file bytes, or null when the response omits it or it is not a whole number. */
    @JsonProperty("totalSize")
    public Long getTotalSize() {
        return totalSize;
    }

    @JsonIgnore
    public void setTotalSize(Long totalSize) {
        this.totalSize = totalSize;
    }

    @JsonProperty("totalSize")
    private void readTotalSize(JsonNode node) {
        boolean whole = node != null && node.isNumber() && node.canConvertToLong()
                && (node.isIntegralNumber() || node.asDouble() == Math.rint(node.asDouble()));
        this.totalSize = whole ? node.asLong() : null;
    }
}
