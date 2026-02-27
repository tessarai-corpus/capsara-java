package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Authenticated party profile including identity, kind, and public key. */
public final class PartyInfo {

    @JsonProperty("id")
    private String id = "";

    @JsonProperty("email")
    private String email = "";

    @JsonProperty("name")
    private String name = "";

    @JsonProperty("kind")
    private String kind = "";

    @JsonProperty("publicKey")
    private String publicKey;

    @JsonProperty("publicKeyFingerprint")
    private String publicKeyFingerprint;

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPublicKeyFingerprint() {
        return publicKeyFingerprint;
    }

    public void setPublicKeyFingerprint(String publicKeyFingerprint) {
        this.publicKeyFingerprint = publicKeyFingerprint;
    }
}
