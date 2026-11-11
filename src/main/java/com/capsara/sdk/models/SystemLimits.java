package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Server-enforced size and count limits for files and capsas. */
public final class SystemLimits {

    /**
     * Fallback limits, used when /api/limits cannot be reached.
     * Matches the server defaults, so the builder refuses the same capsas the server
     * would when the limits endpoint is unreachable.
     */
    public static final SystemLimits DEFAULT = defaults();

    private static SystemLimits defaults() {
        SystemLimits limits = new SystemLimits(
                50L * 1024 * 1024,          // 50MB max file size
                500,                         // 500 files per capsa
                1024L * 1024 * 1024,        // 1GB per capsa
                2048L * 1024 * 1024,        // 2GB per request
                64L * 1024 * 1024
        );
        limits.maxFilesPerRequest = 500;   // 500 files per request
        return limits;
    }

    @JsonProperty("maxFileSize")
    private long maxFileSize;

    @JsonProperty("maxFilesPerCapsa")
    private int maxFilesPerCapsa;

    @JsonProperty("maxTotalSize")
    private long maxTotalSize;

    /** Maximum bytes in one upload request, which may batch several capsas. */
    @JsonProperty("maxRequestSize")
    private Long maxRequestSize;

    /** Longest allowed capsa or file lifetime in days, counted from the time of build. */
    @JsonProperty("maxExpirationDays")
    private Double maxExpirationDays;

    /** Maximum bytes of capsa JSON fields in one upload request. */
    @JsonProperty("maxRequestFieldBytes")
    private Long maxRequestFieldBytes;

    /** Maximum number of files in one upload request, across all of its capsas. */
    @JsonProperty("maxFilesPerRequest")
    private Integer maxFilesPerRequest;

    public SystemLimits() {
    }

    /** Constructs system limits with the given file size, file count, and total size constraints. */
    public SystemLimits(long maxFileSize, int maxFilesPerCapsa, long maxTotalSize) {
        this.maxFileSize = maxFileSize;
        this.maxFilesPerCapsa = maxFilesPerCapsa;
        this.maxTotalSize = maxTotalSize;
    }

    /**
     * Constructs system limits including both per-request limits.
     *
     * @param maxFileSize          maximum bytes per file
     * @param maxFilesPerCapsa     maximum files per capsa
     * @param maxTotalSize         maximum encrypted bytes per capsa
     * @param maxRequestSize       maximum bytes per upload request, may be null
     * @param maxRequestFieldBytes maximum capsa JSON field bytes per upload request, may be null
     */
    public SystemLimits(long maxFileSize, int maxFilesPerCapsa, long maxTotalSize, Long maxRequestSize,
            Long maxRequestFieldBytes) {
        this(maxFileSize, maxFilesPerCapsa, maxTotalSize, maxRequestSize);
        this.maxRequestFieldBytes = maxRequestFieldBytes;
    }

    /** Constructs system limits including the per-request byte limit. */
    public SystemLimits(long maxFileSize, int maxFilesPerCapsa, long maxTotalSize, Long maxRequestSize) {
        this.maxFileSize = maxFileSize;
        this.maxFilesPerCapsa = maxFilesPerCapsa;
        this.maxTotalSize = maxTotalSize;
        this.maxRequestSize = maxRequestSize;
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

    /** @return maximum bytes per upload request, or null if the API did not advertise one */
    public Long getMaxRequestSize() {
        return maxRequestSize;
    }

    public void setMaxRequestSize(Long maxRequestSize) {
        this.maxRequestSize = maxRequestSize;
    }

    /** Longest allowed capsa or file lifetime in days, or null when not advertised. */
    public Double getMaxExpirationDays() {
        return maxExpirationDays;
    }

    public void setMaxExpirationDays(Double maxExpirationDays) {
        this.maxExpirationDays = maxExpirationDays;
    }

    /**
     * Expiration limit the builder applies.
     *
     * @return maxExpirationDays when it is a positive finite number, otherwise 3650
     */
    public double effectiveMaxExpirationDays() {
        Double days = maxExpirationDays;
        return days != null && Double.isFinite(days) && days > 0 ? days : 3650d;
    }

    /** Maximum bytes of capsa JSON fields in one upload request, or null when not advertised. */
    public Long getMaxRequestFieldBytes() {
        return maxRequestFieldBytes;
    }

    public void setMaxRequestFieldBytes(Long maxRequestFieldBytes) {
        this.maxRequestFieldBytes = maxRequestFieldBytes;
    }

    /** Maximum number of files in one upload request, or null when not advertised. */
    public Integer getMaxFilesPerRequest() {
        return maxFilesPerRequest;
    }

    public void setMaxFilesPerRequest(Integer maxFilesPerRequest) {
        this.maxFilesPerRequest = maxFilesPerRequest;
    }
}
