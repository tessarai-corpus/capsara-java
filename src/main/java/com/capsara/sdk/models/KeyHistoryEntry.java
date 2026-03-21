package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Historical record of a party's public key, including rotation and revocation dates. */
public final class KeyHistoryEntry {

    @JsonProperty("publicKey")
    private String publicKey = "";

    @JsonProperty("keyFingerprint")
    private String keyFingerprint = "";

    @JsonProperty("createdAt")
    private String createdAt = "";

    @JsonProperty("revokedAt")
    private String revokedAt;

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

    public String getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(String revokedAt) {
        this.revokedAt = revokedAt;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }
}
