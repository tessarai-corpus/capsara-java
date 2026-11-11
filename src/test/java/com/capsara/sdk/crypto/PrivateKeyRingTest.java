package com.capsara.sdk.crypto;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.internal.crypto.PrivateKeyRing;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrivateKeyRingTest {

    private static final String CAPSA_ID = "capsa_ring_test";

    private final GeneratedKeyPairResult current = SharedKeyFixture.getPrimaryKeyPair();
    private final GeneratedKeyPairResult previous = SharedKeyFixture.getSecondaryKeyPair();
    private final GeneratedKeyPairResult unrelated = SharedKeyFixture.getTertiaryKeyPair();

    @Test
    void selectsCurrentKeyByFingerprint() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));

        assertThat(ring.selectFor(CAPSA_ID, current.getFingerprint())).isEqualTo(current.getPrivateKey());
    }

    @Test
    void selectsPreviousKeyByFingerprint() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));

        assertThat(ring.selectFor(CAPSA_ID, previous.getFingerprint())).isEqualTo(previous.getPrivateKey());
    }

    @Test
    void fingerprintComparisonIsExact() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));
        String upper = previous.getFingerprint().toUpperCase(Locale.ROOT);

        assertThatThrownBy(() -> ring.selectFor(CAPSA_ID, upper))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
    }

    @Test
    void keyStoredWithCrlfLineEndings_stillMatches() {
        String crlf = previous.getPrivateKey().replace("\n", "\r\n");
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(crlf));

        assertThat(ring.selectFor(CAPSA_ID, previous.getFingerprint())).isEqualTo(crlf);
    }

    @Test
    void noMatchingKey_throwsPrivateKeyNotAvailableWithFingerprint() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));

        assertThatThrownBy(() -> ring.selectFor(CAPSA_ID, unrelated.getFingerprint()))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> {
                    CapsaraCapsaException ex = (CapsaraCapsaException) e;
                    assertThat(ex.getCode()).isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
                    assertThat(ex.getDetails()).isEqualTo(details(unrelated.getFingerprint()));
                });
    }

    @Test
    void unreadablePreviousKey_isNotSkipped_throwsInvalidPrivateKey() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(),
                List.of("not a key", previous.getPrivateKey()));

        assertThatThrownBy(() -> ring.selectFor(CAPSA_ID, previous.getFingerprint()))
                .isExactlyInstanceOf(CapsaraException.class)
                .satisfies(e -> assertInvalidPrivateKeyFor((CapsaraException) e, "previous"));
    }

    @Test
    void unreadableCurrentKey_throwsInvalidPrivateKey() {
        PrivateKeyRing ring = new PrivateKeyRing("not a key", List.of(previous.getPrivateKey()));

        assertThatThrownBy(() -> ring.selectFor(CAPSA_ID, previous.getFingerprint()))
                .satisfies(e -> assertInvalidPrivateKeyFor((CapsaraException) e, "current"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @org.junit.jupiter.params.provider.ValueSource(strings = {
        "garbage",
        "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----"
    })
    void requireUsable_rejectsUnusableKeys(String pem) {
        assertThatThrownBy(() -> PrivateKeyRing.requireUsable(pem, false))
                .satisfies(e -> assertInvalidPrivateKey((CapsaraException) e, "current"));
        assertThatThrownBy(() -> PrivateKeyRing.requireUsable(pem, true))
                .satisfies(e -> assertInvalidPrivateKey((CapsaraException) e, "previous"));
    }

    @Test
    void requireUsable_rejectsAPublicKeyPem() {
        assertThatThrownBy(() -> PrivateKeyRing.requireUsable(current.getPublicKey(), false))
                .satisfies(e -> assertInvalidPrivateKey((CapsaraException) e, "current"));
    }

    @Test
    void requireUsable_acceptsARealKey() {
        PrivateKeyRing.requireUsable(current.getPrivateKey(), false);
        PrivateKeyRing.requireUsable(previous.getPrivateKey(), true);
    }

    private static void assertInvalidPrivateKeyFor(CapsaraException ex, String which) {
        assertThat(ex).isExactlyInstanceOf(CapsaraException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_PRIVATE_KEY");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(java.util.Map.of("capsaId", CAPSA_ID));
        assertThat(ex.getMessage()).contains(which).doesNotContain("BEGIN");
    }

    private static void assertInvalidPrivateKey(CapsaraException ex, String which) {
        assertThat(ex).isExactlyInstanceOf(CapsaraException.class);
        assertThat(ex.getCode()).isEqualTo("INVALID_PRIVATE_KEY");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isNull();
        assertThat(ex.getMessage()).contains(which).doesNotContain("BEGIN").doesNotContain("garbage");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void missingFingerprint_throwsPrivateKeyNotAvailableWithNullFingerprint(String fingerprint) {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));

        assertThatThrownBy(() -> ring.selectFor(CAPSA_ID, fingerprint))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> {
                    CapsaraCapsaException ex = (CapsaraCapsaException) e;
                    assertThat(ex.getCode()).isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
                    assertThat(ex.getStatusCode()).isZero();
                    assertThat(ex.getDetails()).isEqualTo(details(null));
                });
    }

    @Test
    void requiresCurrentKey() {
        assertThatThrownBy(() -> new PrivateKeyRing(null, null))
                .satisfies(e -> assertInvalidPrivateKey((CapsaraException) e, "current"));
        assertThatThrownBy(() -> new PrivateKeyRing("", null))
                .satisfies(e -> assertInvalidPrivateKey((CapsaraException) e, "current"));
    }

    @Test
    void exposesItsKeys() {
        PrivateKeyRing ring = new PrivateKeyRing(current.getPrivateKey(), List.of(previous.getPrivateKey()));

        assertThat(ring.getCurrentKey()).isEqualTo(current.getPrivateKey());
        assertThat(ring.getPreviousKeys()).containsExactly(previous.getPrivateKey());
    }

    private static Map<String, Object> details(String fingerprint) {
        Map<String, Object> details = new HashMap<>();
        details.put("capsaId", CAPSA_ID);
        details.put("fingerprint", fingerprint);
        return details;
    }
}
