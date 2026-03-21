package com.capsara.sdk.models;

/** Only {@link #LOG} and {@link #PROCESSED} can be created via the API. */
public final class AuditActions {

    private AuditActions() {
        // Constants class
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

    /** Capsa was deleted. */
    public static final String DELETED = "deleted";

    /** Custom log entry. User-creatable via API. Requires details. */
    public static final String LOG = "log";
}
