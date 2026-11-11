package com.capsara.sdk.internal.utils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Safe file names for received files.
 *
 * <p>A received file's name is decrypted from what the sender supplied, so it is untrusted: it can hold
 * path separators, control characters or names that Windows reserves. {@link #sanitize(String)} turns any
 * name into a single path segment that is safe to join to a directory of the caller's choosing.</p>
 */
public final class SafeFilename {

    /** Maximum UTF-8 bytes of a safe file name. */
    public static final int MAX_FILENAME_BYTES = 255;

    /** Longest extension, in UTF-8 bytes including the dot, kept when a name is cut. */
    private static final int MAX_EXTENSION_BYTES = 32;

    private static final String FALLBACK_FILENAME = "file";

    private static final String WINDOWS_INVALID = "<>:\"|?*";

    private static final Set<String> RESERVED_NAMES = new HashSet<>(Arrays.asList(
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"));

    private SafeFilename() {
    }

    /**
     * Whether a code point is a control character (U+0000 to U+001F, or U+007F).
     * @param codePoint the code point
     * @return true for a control character
     */
    public static boolean isControl(int codePoint) {
        return codePoint <= 0x1F || codePoint == 0x7F;
    }

    /**
     * Turn an untrusted file name into a safe single path segment.
     *
     * <p>Rules, applied in order:</p>
     * <ol>
     *   <li>Keep only the part after the last "/" or "\".</li>
     *   <li>Remove control characters (U+0000 to U+001F and U+007F).</li>
     *   <li>Replace the characters Windows does not allow (&lt; &gt; : " | ? *) with "_".</li>
     *   <li>Trim leading and trailing spaces, and trailing dots.</li>
     *   <li>Cap the name at 255 UTF-8 bytes, keeping an extension of up to 32 bytes and never splitting a
     *       character.</li>
     *   <li>Use "file" for an empty result, and prefix "_" to ".", "..", and Windows reserved device names
     *       (CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9, in any case, with or without an extension).</li>
     * </ol>
     *
     * <p>The result is never empty, holds no path separator, and is at most 255 UTF-8 bytes. It is a name
     * only: join it to a directory you chose.</p>
     * @param name the untrusted file name (null is treated as empty)
     * @return a safe file name
     */
    public static String sanitize(String name) {
        String source = name == null ? "" : name;
        int lastSeparator = Math.max(source.lastIndexOf('/'), source.lastIndexOf('\\'));
        String segment = source.substring(lastSeparator + 1);

        StringBuilder cleaned = new StringBuilder(segment.length());
        segment.codePoints().forEach(cp -> {
            if (isControl(cp)) {
                return;
            }
            if (cp < 0x80 && WINDOWS_INVALID.indexOf(cp) >= 0) {
                cleaned.append('_');
            } else {
                cleaned.appendCodePoint(cp);
            }
        });

        String result = trimEndSpacesAndDots(trimStartSpaces(cleaned.toString()));
        result = capLength(result, MAX_FILENAME_BYTES);

        if (result.isEmpty()) {
            return FALLBACK_FILENAME;
        }
        if (".".equals(result) || "..".equals(result) || isReserved(result)) {
            return "_" + capLength(result, MAX_FILENAME_BYTES - 1);
        }
        return result;
    }

    private static String trimStartSpaces(String value) {
        int start = 0;
        while (start < value.length() && value.charAt(start) == ' ') {
            start++;
        }
        return value.substring(start);
    }

    private static String trimEndSpacesAndDots(String value) {
        int end = value.length();
        while (end > 0 && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '.')) {
            end--;
        }
        return value.substring(0, end);
    }

    private static boolean isReserved(String name) {
        int dot = name.indexOf('.');
        String stem = dot == -1 ? name : name.substring(0, dot);
        int end = stem.length();
        while (end > 0 && stem.charAt(end - 1) == ' ') {
            end--;
        }
        return RESERVED_NAMES.contains(stem.substring(0, end).toUpperCase(Locale.ROOT));
    }

    private static int utf8Length(int codePoint) {
        if (codePoint < 0x80) {
            return 1;
        }
        if (codePoint < 0x800) {
            return 2;
        }
        if (codePoint < 0x10000) {
            return 3;
        }
        return 4;
    }

    private static int utf8ByteLength(String value) {
        return value.codePoints().map(SafeFilename::utf8Length).sum();
    }

    private static String truncateUtf8(String value, int maxBytes) {
        int used = 0;
        int index = 0;
        while (index < value.length()) {
            int cp = value.codePointAt(index);
            int size = utf8Length(cp);
            if (used + size > maxBytes) {
                break;
            }
            used += size;
            index += Character.charCount(cp);
        }
        return value.substring(0, index);
    }

    private static String capLength(String name, int maxBytes) {
        if (utf8ByteLength(name) <= maxBytes) {
            return name;
        }
        String stem = name;
        String extension = "";
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            String candidate = name.substring(dot);
            if (utf8ByteLength(candidate) <= MAX_EXTENSION_BYTES) {
                extension = candidate;
                stem = name.substring(0, dot);
            }
        }
        stem = trimEndSpacesAndDots(truncateUtf8(stem, maxBytes - utf8ByteLength(extension)));
        return stem + extension;
    }
}
