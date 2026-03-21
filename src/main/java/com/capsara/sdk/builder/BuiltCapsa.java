package com.capsara.sdk.builder;

import com.capsara.sdk.models.CapsaAccessControl;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.CapsaMetadata;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.EncryptedFile;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of building a capsa, ready for upload.
 */
public final class BuiltCapsa {

    private CapsaUploadData capsa;
    private EncryptedFileData[] files;

    public CapsaUploadData getCapsa() {
        return capsa;
    }

    public void setCapsa(CapsaUploadData capsa) {
        this.capsa = capsa;
    }

    public EncryptedFileData[] getFiles() {
        return files;
    }

    public void setFiles(EncryptedFileData[] files) {
        this.files = files;
    }

    /**
     * Capsa data for upload.
     */
    public static final class CapsaUploadData {
        @JsonProperty("packageId")
        private String packageId;

        @JsonProperty("keychain")
        private CapsaKeychain keychain;

        @JsonProperty("signature")
        private CapsaSignature signature;

        @JsonProperty("accessControl")
        private CapsaAccessControl accessControl;

        @JsonProperty("deliveryPriority")
        private String deliveryPriority = "normal";

        @JsonProperty("files")
        private EncryptedFile[] files;

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

        @JsonProperty("encryptedStructured")
        private String encryptedStructured;

        @JsonProperty("structuredIV")
        private String structuredIV;

        @JsonProperty("structuredAuthTag")
        private String structuredAuthTag;

        @JsonProperty("metadata")
        private CapsaMetadata metadata;

        // Getters and setters
        public String getPackageId() {
            return packageId;
        }

        public void setPackageId(String packageId) {
            this.packageId = packageId;
        }

        public CapsaKeychain getKeychain() {
            return keychain;
        }

        public void setKeychain(CapsaKeychain keychain) {
            this.keychain = keychain;
        }

        public CapsaSignature getSignature() {
            return signature;
        }

        public void setSignature(CapsaSignature signature) {
            this.signature = signature;
        }

        public CapsaAccessControl getAccessControl() {
            return accessControl;
        }

        public void setAccessControl(CapsaAccessControl accessControl) {
            this.accessControl = accessControl;
        }

        public String getDeliveryPriority() {
            return deliveryPriority;
        }

        public void setDeliveryPriority(String deliveryPriority) {
            this.deliveryPriority = deliveryPriority;
        }

        public EncryptedFile[] getFiles() {
            return files;
        }

        public void setFiles(EncryptedFile[] files) {
            this.files = files;
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

        public CapsaMetadata getMetadata() {
            return metadata;
        }

        public void setMetadata(CapsaMetadata metadata) {
            this.metadata = metadata;
        }
    }

    /**
     * Encrypted file data with content.
     */
    public static final class EncryptedFileData {
        private EncryptedFile metadata;
        private byte[] data;

        public EncryptedFile getMetadata() {
            return metadata;
        }

        public void setMetadata(EncryptedFile metadata) {
            this.metadata = metadata;
        }

        public byte[] getData() {
            return data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }
    }
}
