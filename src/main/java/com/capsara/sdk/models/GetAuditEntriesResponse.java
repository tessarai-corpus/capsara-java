package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Paginated response containing audit trail entries. */
public final class GetAuditEntriesResponse {

    @JsonProperty("auditEntries")
    private AuditEntry[] auditEntries = new AuditEntry[0];

    @JsonProperty("pagination")
    private CursorPagination pagination = new CursorPagination();

    public AuditEntry[] getAuditEntries() {
        return auditEntries;
    }

    public void setAuditEntries(AuditEntry[] auditEntries) {
        this.auditEntries = auditEntries;
    }

    public CursorPagination getPagination() {
        return pagination;
    }

    public void setPagination(CursorPagination pagination) {
        this.pagination = pagination;
    }
}
