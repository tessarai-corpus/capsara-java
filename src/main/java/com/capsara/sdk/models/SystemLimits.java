package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Server-enforced size and count limits for files and capsas. */
public final class SystemLimits {

    public static final SystemLimits DEFAULT = new SystemLimits(
            100L * 1024 * 1024,   // 100MB max file size
            100,                   // 100 files per capsa
            500L * 1024 * 1024    // 500MB total size
    );

    @JsonProperty("maxFileSize")
    private long maxFileSize;

    @JsonProperty("maxFilesPerCapsa")
    private int maxFilesPerCapsa;

    @JsonProperty("maxTotalSize")
    private long maxTotalSize;

    public SystemLimits() {
    }

    /** Constructs system limits with the given file size, file count, and total size constraints. */
    public SystemLimits(long maxFileSize, int maxFilesPerCapsa, long maxTotalSize) {
        this.maxFileSize = maxFileSize;
        this.maxFilesPerCapsa = maxFilesPerCapsa;
        this.maxTotalSize = maxTotalSize;
    }

    public long getMaxFileSize() {
        return maxFileSize;
    }

    public void setMaxFileSize(long maxFileSize) {
        this.maxFileSize = maxFileSize;
    }

    public int getMaxFilesPerCapsa() {
        return maxFilesPerCapsa;
    }

    public void setMaxFilesPerCapsa(int maxFilesPerCapsa) {
        this.maxFilesPerCapsa = maxFilesPerCapsa;
    }

    public long getMaxTotalSize() {
        return maxTotalSize;
    }

    public void setMaxTotalSize(long maxTotalSize) {
        this.maxTotalSize = maxTotalSize;
    }
}
