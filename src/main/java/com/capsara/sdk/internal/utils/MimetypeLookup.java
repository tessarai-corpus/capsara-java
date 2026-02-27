package com.capsara.sdk.internal.utils;

import java.util.HashMap;
import java.util.Map;

/** MIME type lookup by file extension. */
public final class MimetypeLookup {

    private static final String DEFAULT_MIMETYPE = "application/octet-stream";

    private static final Map<String, String> EXTENSION_MAP = new HashMap<>();

    static {
        // Documents
        EXTENSION_MAP.put("pdf", "application/pdf");
        EXTENSION_MAP.put("doc", "application/msword");
        EXTENSION_MAP.put("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        EXTENSION_MAP.put("xls", "application/vnd.ms-excel");
        EXTENSION_MAP.put("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        EXTENSION_MAP.put("ppt", "application/vnd.ms-powerpoint");
        EXTENSION_MAP.put("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation");

        // Text
        EXTENSION_MAP.put("txt", "text/plain");
        EXTENSION_MAP.put("csv", "text/csv");
        EXTENSION_MAP.put("html", "text/html");
        EXTENSION_MAP.put("htm", "text/html");
        EXTENSION_MAP.put("css", "text/css");
        EXTENSION_MAP.put("js", "text/javascript");
        EXTENSION_MAP.put("json", "application/json");
        EXTENSION_MAP.put("xml", "application/xml");
        EXTENSION_MAP.put("md", "text/markdown");
        EXTENSION_MAP.put("yaml", "text/yaml");
        EXTENSION_MAP.put("yml", "text/yaml");

        // Images
        EXTENSION_MAP.put("jpg", "image/jpeg");
        EXTENSION_MAP.put("jpeg", "image/jpeg");
        EXTENSION_MAP.put("png", "image/png");
        EXTENSION_MAP.put("gif", "image/gif");
        EXTENSION_MAP.put("bmp", "image/bmp");
        EXTENSION_MAP.put("svg", "image/svg+xml");
        EXTENSION_MAP.put("webp", "image/webp");
        EXTENSION_MAP.put("ico", "image/x-icon");
        EXTENSION_MAP.put("tiff", "image/tiff");
        EXTENSION_MAP.put("tif", "image/tiff");

        // Audio
        EXTENSION_MAP.put("mp3", "audio/mpeg");
        EXTENSION_MAP.put("wav", "audio/wav");
        EXTENSION_MAP.put("ogg", "audio/ogg");
        EXTENSION_MAP.put("m4a", "audio/mp4");
        EXTENSION_MAP.put("flac", "audio/flac");

        // Video
        EXTENSION_MAP.put("mp4", "video/mp4");
        EXTENSION_MAP.put("webm", "video/webm");
        EXTENSION_MAP.put("avi", "video/x-msvideo");
        EXTENSION_MAP.put("mov", "video/quicktime");
        EXTENSION_MAP.put("mkv", "video/x-matroska");

        // Archives
        EXTENSION_MAP.put("zip", "application/zip");
        EXTENSION_MAP.put("rar", "application/vnd.rar");
        EXTENSION_MAP.put("7z", "application/x-7z-compressed");
        EXTENSION_MAP.put("tar", "application/x-tar");
        EXTENSION_MAP.put("gz", "application/gzip");
        EXTENSION_MAP.put("bz2", "application/x-bzip2");

        // Other
        EXTENSION_MAP.put("eml", "message/rfc822");
        EXTENSION_MAP.put("rtf", "application/rtf");
    }

    private MimetypeLookup() {
    }

    /** @return MIME type or null if extension is unknown. */
    public static String lookup(String filename) {
        if (filename == null || filename.isEmpty()) {
            return null;
        }

        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1 || dotIndex == filename.length() - 1) {
            return null;
        }

        String extension = filename.substring(dotIndex + 1).toLowerCase();
        return EXTENSION_MAP.get(extension);
    }

    /** @return MIME type or "application/octet-stream" if unknown. */
    public static String lookupOrDefault(String filename) {
        String mimeType = lookup(filename);
        return mimeType != null ? mimeType : DEFAULT_MIMETYPE;
    }

    /** Returns whether the given MIME type represents text-based content. */
    public static boolean isTextBased(String mimeType) {
        if (mimeType == null) {
            return false;
        }
        return mimeType.startsWith("text/") ||
                mimeType.equals("application/json") ||
                mimeType.equals("application/xml") ||
                mimeType.equals("application/javascript");
    }
}
