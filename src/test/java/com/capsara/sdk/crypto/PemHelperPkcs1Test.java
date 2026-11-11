package com.capsara.sdk.crypto;

import com.capsara.sdk.CapsaraClient;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.PemHelper;
import com.capsara.sdk.internal.crypto.PrivateKeyRing;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Private keys are accepted as PKCS#8 or PKCS#1 PEM; public keys stay SPKI only. */
class PemHelperPkcs1Test {

    private static final GeneratedKeyPairResult KEYS = SharedKeyFixture.getPrimaryKeyPair();

    private static String pkcs1Pem(String pkcs8Pem, String lineEnding) {
        String base64 = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        int offset = 1 + lengthBytes(der, 1) + 3 + 15 + 1;
        int contentLength = readLength(der, offset);
        offset += lengthBytes(der, offset);
        byte[] pkcs1 = Arrays.copyOfRange(der, offset, offset + contentLength);
        String body = Base64.getMimeEncoder(64, lineEnding.getBytes()).encodeToString(pkcs1);
        return "-----BEGIN RSA PRIVATE KEY-----" + lineEnding + body + lineEnding + "-----END RSA PRIVATE KEY-----";
    }

    private static int lengthBytes(byte[] der, int at) {
        int first = der[at] & 0xff;
        return first < 0x80 ? 1 : 1 + (first & 0x7f);
    }

    private static int readLength(byte[] der, int at) {
        int first = der[at] & 0xff;
        if (first < 0x80) {
            return first;
        }
        int value = 0;
        for (int i = 1; i <= (first & 0x7f); i++) {
            value = (value << 8) | (der[at + i] & 0xff);
        }
        return value;
    }

    @Test
    void pkcs1PrivateKey_importsAsTheSameKey() {
        String pkcs1 = pkcs1Pem(KEYS.getPrivateKey(), "\n");

        assertThat(PemHelper.importPrivateKey(pkcs1).getEncoded())
                .isEqualTo(PemHelper.importPrivateKey(KEYS.getPrivateKey()).getEncoded());
        assertThat(KeyGenerator.calculateFingerprintFromPrivateKey(pkcs1)).isEqualTo(KEYS.getFingerprint());
    }

    @Test
    void pkcs1PrivateKeyWithCrlf_isAcceptedByTheClientAndDecrypts() {
        String pkcs1 = pkcs1Pem(KEYS.getPrivateKey(), "\r\n");
        byte[] masterKey = new byte[32];
        String encrypted = RsaProvider.encryptMasterKey(masterKey, KEYS.getPublicKey());

        try (CapsaraClient client = new CapsaraClient("http://127.0.0.1:1")) {
            client.setPrivateKey(pkcs1);
            client.addPreviousPrivateKey(pkcs1);
        }
        PrivateKeyRing.requireUsable(pkcs1, false);
        assertThat(RsaProvider.decryptMasterKey(encrypted, pkcs1)).isEqualTo(masterKey);
    }

    @Test
    void corruptPkcs1PrivateKey_isInvalidPrivateKey() {
        String corrupt = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";

        assertThatThrownBy(() -> PrivateKeyRing.requireUsable(corrupt, false))
                .isInstanceOf(CapsaraException.class)
                .extracting(e -> ((CapsaraException) e).getCode())
                .isEqualTo("INVALID_PRIVATE_KEY");
    }

    @Test
    void encryptedPkcs1PrivateKey_isInvalidPrivateKey() {
        String encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                + "DEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nAAAA\n-----END RSA PRIVATE KEY-----";

        assertThatThrownBy(() -> PrivateKeyRing.requireUsable(encrypted, true))
                .isInstanceOf(CapsaraException.class)
                .extracting(e -> ((CapsaraException) e).getCode())
                .isEqualTo("INVALID_PRIVATE_KEY");
    }

    @Test
    void pkcs1PublicKey_isStillRejectedByTheFingerprintHelper() {
        String pkcs1Public = "-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----";

        assertThatThrownBy(() -> KeyGenerator.calculateFingerprint(pkcs1Public))
                .isInstanceOf(RuntimeException.class);
    }
}
