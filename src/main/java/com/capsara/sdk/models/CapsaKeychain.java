package com.capsara.sdk.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Keychain containing encrypted master key copies for authorized parties. */
public final class CapsaKeychain {

    @JsonProperty("algorithm")
    private String algorithm = "AES-256-GCM";

    @JsonProperty("keys")
    private KeychainEntry[] keys = new KeychainEntry[0];

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public KeychainEntry[] getKeys() {
        return keys;
    }

    public void setKeys(KeychainEntry[] keys) {
        this.keys = keys;
    }
}
