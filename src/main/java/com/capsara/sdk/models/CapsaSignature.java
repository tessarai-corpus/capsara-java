package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** RSA-SHA256 digital signature proving capsa creator authenticity. */
public final class CapsaSignature {

    @JsonProperty("algorithm")
    private String algorithm = "RS256";

    @JsonProperty("protected")
    private String protectedHeader = "";

    @JsonProperty("payload")
    private String payload = "";

    @JsonProperty("signature")
    private String signature = "";

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getProtectedHeader() {
        return protectedHeader;
    }

    public void setProtectedHeader(String protectedHeader) {
        this.protectedHeader = protectedHeader;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
