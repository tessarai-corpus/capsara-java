package com.capsara.sdk.models;

/** Audit actions the API reports; only {@link #LOG} and {@link #PROCESSED} can be created via the API. */
public final class AuditActions {

    private AuditActions() {
    }

    /** Capsa was created. */
    public static final String CREATED = "created";

    /** Capsa metadata was accessed. */
    public static final String ACCESSED = "accessed";

    /** File was downloaded from capsa. */
    public static final String FILE_DOWNLOADED = "file_downloaded";

    /** Capsa was processed by recipient. User-creatable via API. */
    public static final String PROCESSED = "processed";

    /** Capsa expired. */
    public static final String EXPIRED = "expired";

    /** Capsa was soft-deleted by its creator. */
    public static final String SOFT_DELETED = "soft_deleted";

    /** Capsa was permanently deleted. */
    public static final String HARD_DELETED = "hard_deleted";

    /** A webhook for the capsa was delivered. */
    public static final String WEBHOOK_DELIVERED = "webhook.delivered";

    /** A webhook for the capsa failed to deliver. */
    public static final String WEBHOOK_FAILED = "webhook.failed";

    /** Custom log entry. User-creatable via API. Requires details. */
    public static final String LOG = "log";
}
