package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Unencrypted metadata visible to server for routing and display. */
public final class CapsaMetadata {

    @JsonProperty("label")
    private String label;

    @JsonProperty("tags")
    private String[] tags;

    @JsonProperty("notes")
    private String notes;

    @JsonProperty("relatedPackages")
    private String[] relatedPackages;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String[] getTags() {
        return tags;
    }

    public void setTags(String[] tags) {
        this.tags = tags;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String[] getRelatedPackages() {
        return relatedPackages;
    }

    public void setRelatedPackages(String[] relatedPackages) {
        this.relatedPackages = relatedPackages;
    }
}
