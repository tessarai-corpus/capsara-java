package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Party ID and password credentials for authentication. */
public final class AuthCredentials {

    @JsonProperty("partyId")
    private String partyId;

    @JsonProperty("password")
    private String password;

    public AuthCredentials() {
    }

    public AuthCredentials(String partyId, String password) {
        this.partyId = partyId;
        this.password = password;
    }

    public String getPartyId() {
        return partyId;
    }

    public void setPartyId(String partyId) {
        this.partyId = partyId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
