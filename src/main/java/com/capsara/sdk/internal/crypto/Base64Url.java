package com.capsara.sdk.internal.crypto;

import java.util.Base64;

/**
 * Base64url encoding/decoding per RFC 4648.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
        // Utility class
    }

    /**
     * Encode bytes to base64url string (no padding).
     *
     * @param data bytes to encode
     * @return base64url encoded string
     */
    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * Decode base64url string to bytes.
     *
     * @param encoded base64url encoded string
     * @return decoded bytes
     */
    public static byte[] decode(String encoded) {
        return DECODER.decode(encoded);
    }

    /**
     * Encode a string (UTF-8) to base64url.
     *
     * @param text text to encode
     * @return base64url encoded string
     */
    public static String encodeString(String text) {
        return encode(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Decode base64url to a string (UTF-8).
     *
     * @param encoded base64url encoded string
     * @return decoded string
     */
    public static String decodeToString(String encoded) {
        return new String(decode(encoded), java.nio.charset.StandardCharsets.UTF_8);
    }
}
