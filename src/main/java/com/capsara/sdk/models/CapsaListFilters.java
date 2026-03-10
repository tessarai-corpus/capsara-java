package com.capsara.sdk.models;

/** Query filters for listing capsas. */
public final class CapsaListFilters {

    private CapsaStatus status;
    private String createdBy;
    private String startDate;
    private String endDate;
    private String expiringBefore;
    private Boolean hasLegalHold;
    private Integer limit;
    private String after;
    private String before;

    public CapsaStatus getStatus() {
        return status;
    }

    public void setStatus(CapsaStatus status) {
        this.status = status;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getStartDate() {
        return startDate;
    }

    public void setStartDate(String startDate) {
        this.startDate = startDate;
    }

    public String getEndDate() {
        return endDate;
    }

    public void setEndDate(String endDate) {
        this.endDate = endDate;
    }

    public String getExpiringBefore() {
        return expiringBefore;
    }

    public void setExpiringBefore(String expiringBefore) {
        this.expiringBefore = expiringBefore;
    }

    public Boolean getHasLegalHold() {
        return hasLegalHold;
    }

    public void setHasLegalHold(Boolean hasLegalHold) {
        this.hasLegalHold = hasLegalHold;
    }

    public Integer getLimit() {
        return limit;
    }

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    public String getAfter() {
        return after;
    }

    public void setAfter(String after) {
        this.after = after;
    }

    public String getBefore() {
        return before;
    }

    public void setBefore(String before) {
        this.before = before;
    }
}
