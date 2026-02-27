package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** Audit trail entry for a capsa. */
public final class AuditEntry {

    @JsonProperty("id")
    private String id = "";

    @JsonProperty("packageId")
    private String packageId = "";

    @JsonProperty("action")
    private String action = "";

    @JsonProperty("party")
    private String party = "";

    @JsonProperty("timestamp")
    private String timestamp = "";

    @JsonProperty("details")
    private Map<String, Object> details;

    @JsonProperty("ipAddress")
    private String ipAddress;

    @JsonProperty("userAgent")
    private String userAgent;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPackageId() {
        return packageId;
    }

    public void setPackageId(String packageId) {
        this.packageId = packageId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getParty() {
        return party;
    }

    public void setParty(String party) {
        this.party = party;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public void setDetails(Map<String, Object> details) {
        this.details = details;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
}
