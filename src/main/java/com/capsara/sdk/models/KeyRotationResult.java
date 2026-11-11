package com.capsara.sdk.models;

/** Result of a key rotation operation, containing the new key pair and server-registered info. */
public final class KeyRotationResult {

    private GeneratedKeyPairResult keyPair;
    private PublicKeyInfo serverInfo;

    public GeneratedKeyPairResult getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(GeneratedKeyPairResult keyPair) {
        this.keyPair = keyPair;
    }

    public PublicKeyInfo getServerInfo() {
        return serverInfo;
    }

    public void setServerInfo(PublicKeyInfo serverInfo) {
        this.serverInfo = serverInfo;
    }
}
