package com.capsara.sdk.models;

/** Result of RSA-4096 key pair generation, containing PEM keys and fingerprint. */
public final class GeneratedKeyPairResult {

    private final String publicKey;
    private final String privateKey;
    private final String fingerprint;
    private final int keySize;

    /** Constructs a key pair result with the given PEM keys, fingerprint, and key size. */
    public GeneratedKeyPairResult(String publicKey, String privateKey, String fingerprint, int keySize) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.fingerprint = fingerprint;
        this.keySize = keySize;
    }

    /** PEM-encoded public key (SPKI format). */
    public String getPublicKey() {
        return publicKey;
    }

    /** PEM-encoded private key (PKCS#8 format). */
    public String getPrivateKey() {
        return privateKey;
    }

    /** SHA-256 fingerprint of the public key (hex, 64 characters). */
    public String getFingerprint() {
        return fingerprint;
    }

    public int getKeySize() {
        return keySize;
    }
}
