package com.capsara.sdk.models;

import com.capsara.sdk.internal.utils.SafeFilename;

/** Result of decrypting a file, containing the plaintext data and filename. */
public final class DecryptedFileResult {

    private byte[] data;
    private String filename;

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * The file name exactly as the sender supplied it. It is untrusted and can hold path separators or other
     * unsafe characters; do not use it as a path. Use {@link #getSafeFilename()} to write the file.
     * @return the decrypted original file name
     */
    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    /**
     * The file name made safe to write to disk: a single path segment with no separators, control
     * characters, Windows-invalid characters or reserved device names, at most 255 UTF-8 bytes. Join it to a
     * directory you chose. See {@link #sanitizeFilename(String)} for the rules.
     * @return the safe file name
     */
    public String getSafeFilename() {
        return sanitizeFilename(filename);
    }

    /**
     * Turn an untrusted file name into a safe single path segment.
     *
     * <p>Rules, applied in order: keep only the part after the last "/" or "\"; remove control characters
     * (U+0000 to U+001F and U+007F); replace &lt; &gt; : " | ? * with "_"; trim leading and trailing spaces
     * and trailing dots; cap at 255 UTF-8 bytes, keeping an extension of up to 32 bytes and never splitting
     * a character; use "file" for an empty result, and prefix "_" to ".", "..", and Windows reserved device
     * names (CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9, in any case, with or without an
     * extension).</p>
     * @param name the untrusted file name (null is treated as empty)
     * @return a safe file name, never empty and at most 255 UTF-8 bytes
     */
    public static String sanitizeFilename(String name) {
        return SafeFilename.sanitize(name);
    }
}
