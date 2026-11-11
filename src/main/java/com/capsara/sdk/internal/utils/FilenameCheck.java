package com.capsara.sdk.internal.utils;

/** File name check for files added to a capsa. */
public final class FilenameCheck {

    private FilenameCheck() {
    }

    /**
     * Describe why a file name cannot be sent, or return null if it can.
     *
     * <p>A sent name must be a plain file name: no "/" or "\", no control characters, not empty or only
     * spaces, and not "." or "..". The message does not repeat the name.</p>
     * @param name the file name a sender supplied (null is treated as empty)
     * @return a message describing the problem, or null if the name can be sent
     */
    public static String sendProblem(String name) {
        String value = name == null ? "" : name;
        if (value.indexOf('/') >= 0 || value.indexOf('\\') >= 0) {
            return "File name must not contain a path separator (\"/\" or \"\\\"). Pass the file name only.";
        }
        if (value.codePoints().anyMatch(SafeFilename::isControl)) {
            return "File name must not contain control characters.";
        }
        if (value.replace(" ", "").isEmpty()) {
            return "File name must not be empty or only spaces.";
        }
        if (".".equals(value) || "..".equals(value)) {
            return "File name must not be \".\" or \"..\".";
        }
        return null;
    }
}
