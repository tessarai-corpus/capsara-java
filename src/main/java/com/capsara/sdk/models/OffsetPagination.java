package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Page-based pagination metadata for audit trail responses; a field the server omits is null. */
public final class OffsetPagination {

    @JsonProperty("page")
    private Integer page;

    @JsonProperty("limit")
    private Integer limit;

    @JsonProperty("total")
    private Integer total;

    @JsonProperty("totalPages")
    private Integer totalPages;

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getLimit() {
        return limit;
    }

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public Integer getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(Integer totalPages) {
        this.totalPages = totalPages;
    }
}
