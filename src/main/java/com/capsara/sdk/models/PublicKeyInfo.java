package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Server-registered public key details including fingerprint and active status. */
public final class PublicKeyInfo {

    @JsonProperty("publicKey")
    private String publicKey = "";

    @JsonProperty("keyFingerprint")
    private String keyFingerprint = "";

    @JsonProperty("createdAt")
    private String createdAt = "";

    @JsonProperty("isActive")
    private boolean isActive;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getKeyFingerprint() {
        return keyFingerprint;
    }

    public void setKeyFingerprint(String keyFingerprint) {
        this.keyFingerprint = keyFingerprint;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }
}
