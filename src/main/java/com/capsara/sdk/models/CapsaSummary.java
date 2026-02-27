package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Lightweight capsa summary for list responses. */
public final class CapsaSummary {

    @JsonProperty("id")
    private String id = "";

    @JsonProperty("createdAt")
    private String createdAt = "";

    @JsonProperty("creator")
    private String creator = "";

    @JsonProperty("status")
    private String status = "";

    @JsonProperty("expiresAt")
    private String expiresAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(String expiresAt) {
        this.expiresAt = expiresAt;
    }
}
