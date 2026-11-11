package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/** Only {@link AuditActions#LOG} and {@link AuditActions#PROCESSED} are allowed via API. */
public final class CreateAuditEntryRequest {

    @JsonProperty("action")
    private String action = AuditActions.LOG;

    @JsonProperty("details")
    private Map<String, Object> details;

    public CreateAuditEntryRequest() {
    }

    public CreateAuditEntryRequest(String action, Map<String, Object> details) {
        this.action = action;
        this.details = details;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    /** Required for LOG action. */
    public void setDetails(Map<String, Object> details) {
        this.details = details;
    }
}
