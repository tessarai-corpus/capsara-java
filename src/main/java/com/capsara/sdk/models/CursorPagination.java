package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Cursor-based pagination metadata for list responses. */
public final class CursorPagination {

    @JsonProperty("limit")
    private int limit = 20;

    @JsonProperty("hasMore")
    private boolean hasMore;

    @JsonProperty("nextCursor")
    private String nextCursor;

    @JsonProperty("prevCursor")
    private String prevCursor;

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    public boolean isHasMore() {
        return hasMore;
    }

    public void setHasMore(boolean hasMore) {
        this.hasMore = hasMore;
    }

    public String getNextCursor() {
        return nextCursor;
    }

    public void setNextCursor(String nextCursor) {
        this.nextCursor = nextCursor;
    }

    public String getPrevCursor() {
        return prevCursor;
    }

    public void setPrevCursor(String prevCursor) {
        this.prevCursor = prevCursor;
    }
}
