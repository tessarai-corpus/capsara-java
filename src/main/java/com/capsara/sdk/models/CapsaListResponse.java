package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Paginated response containing a list of capsa summaries. */
public final class CapsaListResponse {

    @JsonProperty("capsas")
    private CapsaSummary[] capsas = new CapsaSummary[0];

    @JsonProperty("pagination")
    private CursorPagination pagination = new CursorPagination();

    public CapsaSummary[] getCapsas() {
        return capsas;
    }

    public void setCapsas(CapsaSummary[] capsas) {
        this.capsas = capsas;
    }

    public CursorPagination getPagination() {
        return pagination;
    }

    public void setPagination(CursorPagination pagination) {
        this.pagination = pagination;
    }
}
