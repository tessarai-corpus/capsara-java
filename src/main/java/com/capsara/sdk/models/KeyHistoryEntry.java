package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** A public key this party rotated away from, as recorded in its key history. */
public final class KeyHistoryEntry {

    @JsonProperty("keyFingerprint")
    private String keyFingerprint = "";

    @JsonProperty("rotatedAt")
    private String rotatedAt = "";

    @JsonProperty("rotatedBy")
    private String rotatedBy;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("envelopesAffected")
    private Integer envelopesAffected;

    /** SHA-256 fingerprint of the retired public key. */
    public String getKeyFingerprint() {
        return keyFingerprint;
    }

    public void setKeyFingerprint(String keyFingerprint) {
        this.keyFingerprint = keyFingerprint;
    }

    /** When the key was replaced (ISO 8601). */
    public String getRotatedAt() {
        return rotatedAt;
    }

    public void setRotatedAt(String rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    /** Who performed the rotation. */
    public String getRotatedBy() {
        return rotatedBy;
    }

    public void setRotatedBy(String rotatedBy) {
        this.rotatedBy = rotatedBy;
    }

    /** Reason given for the rotation, if any. */
    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    /** Number of capsas encrypted to this key at rotation time, or null when the server omits it. */
    public Integer getEnvelopesAffected() {
        return envelopesAffected;
    }

    public void setEnvelopesAffected(Integer envelopesAffected) {
        this.envelopesAffected = envelopesAffected;
    }
}
