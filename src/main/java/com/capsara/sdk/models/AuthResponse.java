package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Response from a successful authentication containing tokens and party info. */
public final class AuthResponse {

    @JsonProperty("party")
    private PartyInfo party = new PartyInfo();

    @JsonProperty("accessToken")
    private String accessToken = "";

    @JsonProperty("refreshToken")
    private String refreshToken = "";

    @JsonProperty("expiresIn")
    private int expiresIn;

    public PartyInfo getParty() {
        return party;
    }

    public void setParty(PartyInfo party) {
        this.party = party;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }
}
