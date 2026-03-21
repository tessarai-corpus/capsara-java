package com.capsara.sdk.models;

/** Query filters for retrieving audit trail entries. */
public final class GetAuditEntriesFilters {

    private String action;
    private String party;
    private Integer page;
    private Integer limit;

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
}
