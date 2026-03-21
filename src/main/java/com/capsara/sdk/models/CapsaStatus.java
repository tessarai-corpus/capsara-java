package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonValue;

/** Lifecycle status of a capsa (active, soft-deleted, expired, or legal hold). */
public enum CapsaStatus {
    ACTIVE("active"),
    SOFT_DELETED("soft_deleted"),
    EXPIRED("expired"),
    LEGAL_HOLD("legal_hold");

    private final String value;

    CapsaStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public String toApiString() {
        return value;
    }

    /** Parses a status string (case-insensitive) into a CapsaStatus enum value. */
    public static CapsaStatus fromString(String value) {
        if (value == null) {
            return null;
        }
        for (CapsaStatus status : values()) {
            if (status.value.equalsIgnoreCase(value)) {
                return status;
            }
        }
        return null;
    }
}
