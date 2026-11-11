package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Configuration for a capsa recipient, specifying party ID, permissions, and delegation. */
public final class RecipientConfig {

    @JsonProperty("partyId")
    private String partyId = "";

    @JsonProperty("permissions")
    private String[] permissions = new String[]{"read"};

    @JsonProperty("actingFor")
    private String[] actingFor;

    public RecipientConfig() {
    }

    public RecipientConfig(String partyId, String... permissions) {
        this.partyId = partyId;
        this.permissions = permissions.length > 0 ? permissions : new String[]{"read"};
    }

    public String getPartyId() {
        return partyId;
    }

    public void setPartyId(String partyId) {
        this.partyId = partyId;
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
}
