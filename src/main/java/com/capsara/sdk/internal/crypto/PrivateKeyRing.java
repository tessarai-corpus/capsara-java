package com.capsara.sdk.internal.crypto;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Current and previous private keys, selected by keychain entry fingerprint. */
public final class PrivateKeyRing {

    private static final String CURRENT = "current";
    private static final String PREVIOUS = "previous";

    private final String currentKey;
    private final List<String> previousKeys;

    /**
     * Creates a key ring.
     *
     * @param currentKey   current private key (PKCS#8 PEM)
     * @param previousKeys earlier private keys (PKCS#8 PEM), may be null
     */
    public PrivateKeyRing(String currentKey, List<String> previousKeys) {
        if (currentKey == null || currentKey.isEmpty()) {
            throw CapsaraException.invalidPrivateKey(CURRENT);
        }
        this.currentKey = currentKey;
        this.previousKeys = previousKeys == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(previousKeys));
    }

    public String getCurrentKey() {
        return currentKey;
    }

    public List<String> getPreviousKeys() {
        return previousKeys;
    }

    /**
     * Private key matching a keychain entry fingerprint.
     *
     * @param capsaId     capsa being decrypted
     * @param fingerprint fingerprint on the caller's keychain entry, may be null
     * @return the matching private key PEM
     * @throws CapsaraCapsaException PRIVATE_KEY_NOT_AVAILABLE when the entry has no fingerprint or no key matches
     */
    public String selectFor(String capsaId, String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw CapsaraCapsaException.privateKeyNotAvailable(capsaId, null);
        }

        if (fingerprint.equals(usableFingerprint(currentKey, CURRENT, capsaId))) {
            return currentKey;
        }
        for (String key : previousKeys) {
            if (fingerprint.equals(usableFingerprint(key, PREVIOUS, capsaId))) {
                return key;
            }
        }

        throw CapsaraCapsaException.privateKeyNotAvailable(capsaId, fingerprint);
    }

    /**
     * Reject a private key the SDK cannot use.
     *
     * @param privateKeyPem private key (PKCS#8 PEM)
     * @param previous      true for a previous key, false for the current key
     * @throws CapsaraException INVALID_PRIVATE_KEY when the key is empty, unparseable or cannot be fingerprinted
     */
    public static void requireUsable(String privateKeyPem, boolean previous) {
        usableFingerprint(privateKeyPem, previous ? PREVIOUS : CURRENT, null);
    }

    private static String usableFingerprint(String privateKeyPem, String which, String capsaId) {
        String fingerprint = privateKeyPem == null || privateKeyPem.isEmpty() ? null : fingerprintOf(privateKeyPem);
        if (fingerprint == null) {
            throw CapsaraException.invalidPrivateKey(which, capsaId);
        }
        return fingerprint;
    }

    /**
     * Fingerprint of the public half of a private key.
     *
     * @param privateKeyPem private key (PKCS#8 PEM)
     * @return the fingerprint, or null if the key cannot be read
     */
    static String fingerprintOf(String privateKeyPem) {
        try {
            String publicPem = derivePublicKeyPem(privateKeyPem);
            return publicPem == null ? null : KeyGenerator.calculateFingerprint(publicPem);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String derivePublicKeyPem(String privateKeyPem) {
        RSAPrivateKey privateKey = PemHelper.importPrivateKey(privateKeyPem);
        if (!(privateKey instanceof RSAPrivateCrtKey)) {
            return null;
        }
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) privateKey;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            return PemHelper.exportPublicKeyPem(publicKey);
        } catch (Exception e) {
            return null;
        }
    }
}
