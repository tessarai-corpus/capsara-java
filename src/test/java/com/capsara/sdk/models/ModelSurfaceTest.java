package com.capsara.sdk.models;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** Models expose only what the API supports. */
class ModelSurfaceTest {

    @Test
    void capsaStatus_hasNoLegalHold() {
        assertThat(CapsaStatus.values()).extracting(CapsaStatus::getValue)
                .containsExactly("active", "soft_deleted", "expired");
        assertThat(CapsaStatus.fromString("legal_hold")).isNull();
    }

    @Test
    void listFilters_haveNoLegalHoldFilter() {
        assertThat(Arrays.stream(CapsaListFilters.class.getMethods()).map(Method::getName))
                .noneMatch(name -> name.toLowerCase().contains("legalhold"));
    }

    @Test
    void keyHistoryEntry_exposesTheApiFields() {
        assertThat(Arrays.stream(KeyHistoryEntry.class.getMethods()).map(Method::getName))
                .contains("getKeyFingerprint", "getRotatedAt", "getRotatedBy", "getReason", "getEnvelopesAffected")
                .doesNotContain("getPublicKey", "getRevokedAt", "isActive");
    }

    @Test
    void partyKey_exposesOnlyTheApiFields() {
        assertThat(Arrays.stream(PartyKey.class.getMethods()).map(Method::getName))
                .contains("getId", "getPublicKey", "getFingerprint", "getIsDelegate")
                .doesNotContain("getEmail", "setEmail");
    }

    @Test
    void partyKey_ignoresAnEmailTheServerMightSend() throws Exception {
        PartyKey key = com.capsara.sdk.internal.json.JsonMapper.getInstance().readValue(
                "{\"id\":\"party_1\",\"email\":\"a@b.c\",\"publicKey\":\"PEM\",\"fingerprint\":\"fp\"}", PartyKey.class);
        assertThat(key.getId()).isEqualTo("party_1");
        assertThat(key.getFingerprint()).isEqualTo("fp");
    }
}
