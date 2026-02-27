package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Access control settings for a capsa, such as expiration. */
public final class CapsaAccessControl {

    @JsonProperty("expiresAt")
    private String expiresAt;

    public String getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(String expiresAt) {
        this.expiresAt = expiresAt;
    }
}
