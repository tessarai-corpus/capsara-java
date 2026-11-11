package com.capsara.sdk.golden;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden tests for key pair generation, fingerprint matching, and public key format.
 */
class AccountGoldenTest {

    private static GeneratedKeyPairResult keyPair;

    @BeforeAll
    static void setUp() {
        keyPair = SharedKeyFixture.getPrimaryKeyPair();
    }

    // Key Pair Generation Tests

    @Test
    void generateKeyPair_producesValidKeyComponents() {
        assertThat(keyPair.getPublicKey()).isNotNull().isNotEmpty();
        assertThat(keyPair.getPrivateKey()).isNotNull().isNotEmpty();
        assertThat(keyPair.getFingerprint()).isNotNull().isNotEmpty();
        assertThat(keyPair.getKeySize()).isEqualTo(4096);
    }

    @Test
    void generateKeyPair_publicKeyIsSpkiPemFormat() {
        assertThat(keyPair.getPublicKey()).startsWith("-----BEGIN PUBLIC KEY-----");
        assertThat(keyPair.getPublicKey()).endsWith("-----END PUBLIC KEY-----");
    }

    @Test
    void generateKeyPair_privateKeyIsPkcs8PemFormat() {
        assertThat(keyPair.getPrivateKey()).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(keyPair.getPrivateKey()).endsWith("-----END PRIVATE KEY-----");
    }

    // Fingerprint Tests

    @Test
    void fingerprint_isSixtyFourCharHexString() {
        assertThat(keyPair.getFingerprint()).hasSize(64);
        assertThat(keyPair.getFingerprint()).matches("[0-9a-f]{64}");
    }

    @Test
    void calculateFingerprint_matchesGeneratedFingerprint() {
        String recalculated = KeyGenerator.calculateFingerprint(keyPair.getPublicKey());

        assertThat(recalculated).isEqualTo(keyPair.getFingerprint());
    }
}
