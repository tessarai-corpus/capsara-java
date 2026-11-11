package com.capsara.sdk.crypto;

import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.HashProvider;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.PemHelper;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyGeneratorTest {

    @Test
    void generateKeyPair_shouldReturn4096BitKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getKeySize()).isEqualTo(4096);
    }

    @Test
    void generateKeyPair_shouldReturnPemEncodedPublicKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getPublicKey()).startsWith("-----BEGIN PUBLIC KEY-----");
        assertThat(result.getPublicKey()).endsWith("-----END PUBLIC KEY-----");
    }

    @Test
    void generateKeyPair_shouldReturnPemEncodedPrivateKey() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getPrivateKey()).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(result.getPrivateKey()).endsWith("-----END PRIVATE KEY-----");
    }

    @Test
    void generateKeyPair_shouldReturn64CharFingerprint() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(result.getFingerprint()).hasSize(64);
        assertThat(result.getFingerprint()).matches("[a-f0-9]+");
    }

    @Test
    void generateKeyPair_shouldGenerateDifferentKeysEachTime() {
        GeneratedKeyPairResult result1 = KeyGenerator.generateKeyPair();
        GeneratedKeyPairResult result2 = KeyGenerator.generateKeyPair();

        assertThat(result1.getPublicKey()).isNotEqualTo(result2.getPublicKey());
        assertThat(result1.getFingerprint()).isNotEqualTo(result2.getFingerprint());
    }

    @Test
    void generateKeyPair_isRsa4096WithExponent65537() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();
        java.security.interfaces.RSAPublicKey key = PemHelper.importPublicKey(result.getPublicKey());

        assertThat(key.getModulus().bitLength()).isEqualTo(4096);
        assertThat(key.getPublicExponent()).isEqualTo(java.math.BigInteger.valueOf(65537));
    }

    @Test
    void keyGenerator_offersNoOtherKeySize() {
        assertThat(java.util.Arrays.stream(KeyGenerator.class.getMethods())
                .filter(m -> m.getName().startsWith("generateKeyPair"))
                .mapToInt(m -> m.getParameterCount()))
                .containsOnly(0);
    }

    @Test
    void generateKeyPairAsync_shouldWorkCorrectly() throws ExecutionException, InterruptedException {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPairAsync().get();

        assertThat(result.getKeySize()).isEqualTo(4096);
        assertThat(result.getPublicKey()).isNotEmpty();
        assertThat(result.getPrivateKey()).isNotEmpty();
        assertThat(result.getFingerprint()).hasSize(64);
    }

    @Test
    void calculateFingerprint_shouldMatchGeneratedFingerprint() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        String recalculatedFingerprint = KeyGenerator.calculateFingerprint(result.getPublicKey());

        assertThat(recalculatedFingerprint).isEqualTo(result.getFingerprint());
    }

    @Test
    void calculateFingerprint_isSha256OfTheDerSubjectPublicKeyInfo() {
        String pem = SharedKeyFixture.getPrimaryKeyPair().getPublicKey();
        byte[] der = PemHelper.importPublicKey(pem).getEncoded();

        assertThat(KeyGenerator.calculateFingerprint(pem)).isEqualTo(HashProvider.computeHash(der));
    }

    @Test
    void calculateFingerprint_ignoresPemLayout() {
        String lf = SharedKeyFixture.getPrimaryKeyPair().getPublicKey();
        String crlf = lf.replace("\n", "\r\n");
        String body = lf.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        String unwrapped = "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----";
        String expected = KeyGenerator.calculateFingerprint(lf);

        assertThat(KeyGenerator.calculateFingerprint(lf + "\n")).isEqualTo(expected);
        assertThat(KeyGenerator.calculateFingerprint(crlf)).isEqualTo(expected);
        assertThat(KeyGenerator.calculateFingerprint(crlf + "\r\n")).isEqualTo(expected);
        assertThat(KeyGenerator.calculateFingerprint(unwrapped)).isEqualTo(expected);
        assertThat(expected).matches("[0-9a-f]{64}");
    }

    @Test
    void calculateFingerprint_rejectsPkcs1PublicKey() {
        String pkcs1 = "-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEA\n-----END RSA PUBLIC KEY-----";

        assertThatThrownBy(() -> KeyGenerator.calculateFingerprint(pkcs1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void generatedPublicKey_isSpki() {
        assertThat(SharedKeyFixture.getPrimaryKeyPair().getPublicKey()).startsWith("-----BEGIN PUBLIC KEY-----");
    }

    @Test
    void calculateFingerprint_rejectsNonPem() {
        assertThatThrownBy(() -> KeyGenerator.calculateFingerprint("not a key"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validateKeySize_shouldReturnTrueForSufficientSize() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        assertThat(KeyGenerator.validateKeySize(result.getPublicKey())).isTrue();
    }

    @Test
    void validateKeySize_shouldReturnFalseForSmallKey() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String smallKey = PemHelper.exportPublicKeyPem(generator.generateKeyPair().getPublic());

        assertThat(KeyGenerator.validateKeySize(smallKey, 4096)).isFalse();
        assertThat(KeyGenerator.validateKeySize(smallKey)).isFalse();
    }

    @Test
    void validateKeySize_shouldReturnFalseForNullInput() {
        assertThat(KeyGenerator.validateKeySize(null)).isFalse();
    }

    @Test
    void getKeySize_shouldReturnCorrectSize() {
        GeneratedKeyPairResult result = KeyGenerator.generateKeyPair();

        int keySize = KeyGenerator.getKeySize(result.getPublicKey());

        assertThat(keySize).isEqualTo(4096);
    }

    @Test
    void getKeySize_shouldReturnNegativeOneForInvalidKey() {
        assertThat(KeyGenerator.getKeySize("invalid")).isEqualTo(-1);
        assertThat(KeyGenerator.getKeySize(null)).isEqualTo(-1);
    }
}
