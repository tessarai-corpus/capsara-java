package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Paginated response containing audit trail entries. */
public final class GetAuditEntriesResponse {

    @JsonProperty("auditEntries")
    private AuditEntry[] auditEntries = new AuditEntry[0];

    @JsonProperty("pagination")
    private OffsetPagination pagination = new OffsetPagination();

    public AuditEntry[] getAuditEntries() {
        return auditEntries;
    }

    public void setAuditEntries(AuditEntry[] auditEntries) {
        this.auditEntries = auditEntries;
    }

    public OffsetPagination getPagination() {
        return pagination;
    }

    public void setPagination(OffsetPagination pagination) {
        this.pagination = pagination;
    }
}
