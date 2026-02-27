package com.capsara.sdk.crypto;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaProviderTest {

    private static GeneratedKeyPairResult keyPair;

    @BeforeAll
    static void setUp() {
        keyPair = SharedKeyFixture.getPrimaryKeyPair();
    }

    @Test
    void encryptMasterKey_shouldProduceBase64EncodedOutput() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        assertThat(encrypted).isNotEmpty();
        // RSA-4096 produces 512 bytes = ~684 base64 chars
        assertThat(encrypted.length()).isGreaterThan(500);
    }

    @Test
    void decryptMasterKey_shouldRecoverOriginalKey() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());
        byte[] decrypted = RsaProvider.decryptMasterKey(encrypted, keyPair.getPrivateKey());

        assertThat(decrypted).isEqualTo(masterKey);
    }

    @Test
    void decryptMasterKey_shouldFailWithWrongPrivateKey() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        GeneratedKeyPairResult otherKeyPair = SharedKeyFixture.getSecondaryKeyPair();

        String encrypted = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        assertThatThrownBy(() ->
                RsaProvider.decryptMasterKey(encrypted, otherKeyPair.getPrivateKey())
        ).isInstanceOf(RuntimeException.class);
    }

    @Test
    void encryptMasterKey_shouldRejectNon32ByteKey() {
        byte[] invalidKey = new byte[16];

        assertThatThrownBy(() ->
                RsaProvider.encryptMasterKey(invalidKey, keyPair.getPublicKey())
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void encryptMasterKey_shouldRejectNullKey() {
        assertThatThrownBy(() ->
                RsaProvider.encryptMasterKey(null, keyPair.getPublicKey())
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encryptMasterKey_shouldRejectNullPublicKey() {
        byte[] masterKey = SecureMemory.generateMasterKey();

        assertThatThrownBy(() ->
                RsaProvider.encryptMasterKey(masterKey, (String) null)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decryptMasterKey_shouldRejectNullEncryptedKey() {
        assertThatThrownBy(() ->
                RsaProvider.decryptMasterKey(null, keyPair.getPrivateKey())
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decryptMasterKey_shouldRejectNullPrivateKey() {
        assertThatThrownBy(() ->
                RsaProvider.decryptMasterKey("encrypted", (String) null)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encrypt_shouldWorkWithArbitraryData() {
        byte[] data = "test data".getBytes();

        byte[] encrypted = RsaProvider.encrypt(data, keyPair.getPublicKey());
        byte[] decrypted = RsaProvider.decrypt(encrypted, keyPair.getPrivateKey());

        assertThat(decrypted).isEqualTo(data);
    }

    @Test
    void roundTrip_shouldWorkWithMultipleKeys() {
        byte[] masterKey = SecureMemory.generateMasterKey();
        GeneratedKeyPairResult keyPair1 = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult keyPair2 = SharedKeyFixture.getSecondaryKeyPair();

        String encrypted1 = RsaProvider.encryptMasterKey(masterKey, keyPair1.getPublicKey());
        String encrypted2 = RsaProvider.encryptMasterKey(masterKey, keyPair2.getPublicKey());

        byte[] decrypted1 = RsaProvider.decryptMasterKey(encrypted1, keyPair1.getPrivateKey());
        byte[] decrypted2 = RsaProvider.decryptMasterKey(encrypted2, keyPair2.getPrivateKey());

        assertThat(decrypted1).isEqualTo(masterKey);
        assertThat(decrypted2).isEqualTo(masterKey);
        assertThat(encrypted1).isNotEqualTo(encrypted2); // Different ciphertext due to OAEP padding
    }
}
