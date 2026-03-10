package com.capsara.sdk.crypto;

import com.capsara.sdk.internal.crypto.Base64Url;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Base64UrlTest {

    @Test
    void encode_shouldEncodeWithoutPadding() {
        byte[] data = "hello".getBytes();
        String encoded = Base64Url.encode(data);
        assertThat(encoded).isEqualTo("aGVsbG8");
        assertThat(encoded).doesNotContain("=");
    }

    @Test
    void encode_shouldUseUrlSafeCharacters() {
        byte[] data = {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD};
        String encoded = Base64Url.encode(data);
        assertThat(encoded).doesNotContain("+");
        assertThat(encoded).doesNotContain("/");
    }

    @Test
    void decode_shouldDecodeUrlSafeBase64() {
        String encoded = "aGVsbG8";
        byte[] decoded = Base64Url.decode(encoded);
        assertThat(new String(decoded)).isEqualTo("hello");
    }

    @Test
    void encodeString_shouldEncodeUtf8String() {
        String encoded = Base64Url.encodeString("test");
        assertThat(encoded).isEqualTo("dGVzdA");
    }

    @Test
    void decodeToString_shouldDecodeToUtf8String() {
        String decoded = Base64Url.decodeToString("dGVzdA");
        assertThat(decoded).isEqualTo("test");
    }

    @Test
    void roundTrip_shouldPreserveData() {
        byte[] original = {0, 1, 2, 127, (byte) 128, (byte) 255};
        String encoded = Base64Url.encode(original);
        byte[] decoded = Base64Url.decode(encoded);
        assertThat(decoded).isEqualTo(original);
    }
}
