package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Single entry in a capsa keychain, holding an encrypted master key for one party. */
public final class KeychainEntry {

    @JsonProperty("party")
    private String party = "";

    @JsonProperty("encryptedKey")
    private String encryptedKey = "";

    @JsonProperty("iv")
    private String iv = "";

    @JsonProperty("fingerprint")
    private String fingerprint = "";

    @JsonProperty("permissions")
    private String[] permissions = new String[0];

    @JsonProperty("actingFor")
    private String[] actingFor;

    @JsonProperty("revoked")
    private Boolean revoked;

    public String getParty() {
        return party;
    }

    public void setParty(String party) {
        this.party = party;
    }

    public String getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(String encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String[] getPermissions() {
        return permissions;
    }

    public void setPermissions(String[] permissions) {
        this.permissions = permissions;
    }

    public String[] getActingFor() {
        return actingFor;
    }

    public void setActingFor(String[] actingFor) {
        this.actingFor = actingFor;
    }

    public Boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }
}
