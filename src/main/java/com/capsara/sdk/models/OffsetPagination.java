package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Offset-based pagination metadata with page number and total counts. */
public final class OffsetPagination {

    @JsonProperty("page")
    private int page = 1;

    @JsonProperty("limit")
    private int limit = 20;

    @JsonProperty("total")
    private int total;

    @JsonProperty("totalPages")
    private int totalPages;

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public int getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(int totalPages) {
        this.totalPages = totalPages;
    }
}
