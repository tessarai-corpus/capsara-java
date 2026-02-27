package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Resolved public key for a recipient party, used during encryption. */
public final class PartyKey {

    @JsonProperty("id")
    private String id = "";

    @JsonProperty("email")
    private String email = "";

    @JsonProperty("publicKey")
    private String publicKey = "";

    @JsonProperty("fingerprint")
    private String fingerprint = "";

    @JsonProperty("isDelegate")
    private String[] isDelegate;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /** Party IDs this delegate acts for, or null if not a delegate. */
    public String[] getIsDelegate() {
        return isDelegate;
    }

    public void setIsDelegate(String[] isDelegate) {
        this.isDelegate = isDelegate;
    }
}
