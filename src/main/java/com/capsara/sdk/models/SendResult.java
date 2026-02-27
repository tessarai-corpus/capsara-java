package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Result of a batch send operation, summarizing created capsas and any errors. */
public final class SendResult {

    @JsonProperty("batchId")
    private String batchId;

    @JsonProperty("successful")
    private int successful;

    @JsonProperty("failed")
    private int failed;

    @JsonProperty("partialSuccess")
    private Boolean partialSuccess;

    @JsonProperty("created")
    private List<CreatedCapsa> created;

    @JsonProperty("errors")
    private List<SendError> errors;

    public String getBatchId() {
        return batchId;
    }

    public void setBatchId(String batchId) {
        this.batchId = batchId;
    }

    public int getSuccessful() {
        return successful;
    }

    public void setSuccessful(int successful) {
        this.successful = successful;
    }

    public int getFailed() {
        return failed;
    }

    public void setFailed(int failed) {
        this.failed = failed;
    }

    public Boolean getPartialSuccess() {
        return partialSuccess;
    }

    public void setPartialSuccess(Boolean partialSuccess) {
        this.partialSuccess = partialSuccess;
    }

    public List<CreatedCapsa> getCreated() {
        return created;
    }

    public void setCreated(List<CreatedCapsa> created) {
        this.created = created;
    }

    public List<SendError> getErrors() {
        return errors;
    }

    public void setErrors(List<SendError> errors) {
        this.errors = errors;
    }

    /** Successfully created capsa with its assigned package ID and batch index. */
    public static final class CreatedCapsa {
        @JsonProperty("packageId")
        private String packageId;

        @JsonProperty("index")
        private int index;

        public String getPackageId() {
            return packageId;
        }

        public void setPackageId(String packageId) {
            this.packageId = packageId;
        }

        public int getIndex() {
            return index;
        }

        public void setIndex(int index) {
            this.index = index;
        }
    }

    /** Error detail for a failed capsa in a batch send operation. */
    public static final class SendError {
        @JsonProperty("index")
        private int index;

        @JsonProperty("packageId")
        private String packageId;

        @JsonProperty("error")
        private String error;

        public int getIndex() {
            return index;
        }

        public void setIndex(int index) {
            this.index = index;
        }

        public String getPackageId() {
            return packageId;
        }

        public void setPackageId(String packageId) {
            this.packageId = packageId;
        }

        public String getError() {
            return error;
        }

        public void setError(String error) {
            this.error = error;
        }
    }
}
