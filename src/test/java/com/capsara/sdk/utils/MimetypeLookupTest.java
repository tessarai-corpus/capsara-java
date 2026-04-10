package com.capsara.sdk.utils;

import com.capsara.sdk.internal.utils.MimetypeLookup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for MimetypeLookup file extension to MIME type mapping.
 */
class MimetypeLookupTest {

    // Document Types
    @ParameterizedTest
    @CsvSource({
            "document.pdf, application/pdf",
            "report.PDF, application/pdf",
            "/path/to/file.pdf, application/pdf"
    })
    void lookup_pdfFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    @ParameterizedTest
    @CsvSource({
            "document.doc, application/msword",
            "document.docx, application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "spreadsheet.xls, application/vnd.ms-excel",
            "spreadsheet.xlsx, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "presentation.ppt, application/vnd.ms-powerpoint",
            "presentation.pptx, application/vnd.openxmlformats-officedocument.presentationml.presentation"
    })
    void lookup_microsoftOfficeFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Image Types
    @ParameterizedTest
    @CsvSource({
            "photo.jpg, image/jpeg",
            "photo.jpeg, image/jpeg",
            "image.png, image/png",
            "animation.gif, image/gif",
            "bitmap.bmp, image/bmp",
            "scan.tif, image/tiff",
            "scan.tiff, image/tiff",
            "modern.webp, image/webp",
            "vector.svg, image/svg+xml"
    })
    void lookup_imageFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Audio Types
    @ParameterizedTest
    @CsvSource({
            "song.mp3, audio/mpeg",
            "audio.wav, audio/wav",
            "music.m4a, audio/mp4",
            "track.ogg, audio/ogg",
            "lossless.flac, audio/flac"
    })
    void lookup_audioFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Video Types
    @ParameterizedTest
    @CsvSource({
            "video.mp4, video/mp4",
            "movie.mov, video/quicktime",
            "clip.avi, video/x-msvideo",
            "container.mkv, video/x-matroska",
            "web.webm, video/webm"
    })
    void lookup_videoFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Text and Data Types
    @ParameterizedTest
    @CsvSource({
            "readme.txt, text/plain",
            "data.csv, text/csv",
            "config.json, application/json",
            "data.xml, application/xml",
            "page.html, text/html",
            "page.htm, text/html"
    })
    void lookup_textDataFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Archive Types
    @ParameterizedTest
    @CsvSource({
            "archive.zip, application/zip",
            "compressed.gz, application/gzip",
            "archive.tar, application/x-tar",
            "archive.7z, application/x-7z-compressed",
            "archive.rar, application/vnd.rar"
    })
    void lookup_archiveFiles_returnsCorrectMimeType(String path, String expectedMime) {
        assertThat(MimetypeLookup.lookup(path)).isEqualTo(expectedMime);
    }

    // Email Types
    @Test
    void lookup_emlFile_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("message.eml")).isEqualTo("message/rfc822");
    }

    // Edge Cases
    @Test
    void lookup_nullPath_returnsNull() {
        assertThat(MimetypeLookup.lookup(null)).isNull();
    }

    @Test
    void lookup_emptyString_returnsNull() {
        assertThat(MimetypeLookup.lookup("")).isNull();
    }

    @Test
    void lookup_unknownExtension_returnsNull() {
        assertThat(MimetypeLookup.lookup("file.unknown123")).isNull();
    }

    @Test
    void lookup_noExtension_returnsNull() {
        assertThat(MimetypeLookup.lookup("filename")).isNull();
    }

    @Test
    void lookup_endsWithDot_returnsNull() {
        assertThat(MimetypeLookup.lookup("filename.")).isNull();
    }

    @Test
    void lookup_caseInsensitive_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("file.pdf")).isEqualTo("application/pdf");
        assertThat(MimetypeLookup.lookup("FILE.PDF")).isEqualTo("application/pdf");
        assertThat(MimetypeLookup.lookup("File.PdF")).isEqualTo("application/pdf");
    }

    @Test
    void lookup_pathWithSpaces_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("/path/to/my file with spaces.pdf"))
                .isEqualTo("application/pdf");
    }

    @Test
    void lookup_pathWithMultipleDots_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("file.name.with.dots.pdf"))
                .isEqualTo("application/pdf");
    }

    @Test
    void lookup_windowsPath_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("C:\\Users\\test\\Documents\\file.pdf"))
                .isEqualTo("application/pdf");
    }

    @Test
    void lookup_unixPath_returnsCorrectMimeType() {
        assertThat(MimetypeLookup.lookup("/home/user/documents/file.pdf"))
                .isEqualTo("application/pdf");
    }

    // lookupOrDefault tests
    @Test
    void lookupOrDefault_knownExtension_returnsMimeType() {
        assertThat(MimetypeLookup.lookupOrDefault("file.pdf")).isEqualTo("application/pdf");
    }

    @Test
    void lookupOrDefault_unknownExtension_returnsDefault() {
        assertThat(MimetypeLookup.lookupOrDefault("file.unknown"))
                .isEqualTo("application/octet-stream");
    }

    @Test
    void lookupOrDefault_nullPath_returnsDefault() {
        assertThat(MimetypeLookup.lookupOrDefault(null))
                .isEqualTo("application/octet-stream");
    }

    @Test
    void lookupOrDefault_noExtension_returnsDefault() {
        assertThat(MimetypeLookup.lookupOrDefault("filename"))
                .isEqualTo("application/octet-stream");
    }

    // isTextBased tests
    @Test
    void isTextBased_textMimeTypes_returnsTrue() {
        assertThat(MimetypeLookup.isTextBased("text/plain")).isTrue();
        assertThat(MimetypeLookup.isTextBased("text/html")).isTrue();
        assertThat(MimetypeLookup.isTextBased("text/css")).isTrue();
        assertThat(MimetypeLookup.isTextBased("text/csv")).isTrue();
    }

    @Test
    void isTextBased_jsonAndXml_returnsTrue() {
        assertThat(MimetypeLookup.isTextBased("application/json")).isTrue();
        assertThat(MimetypeLookup.isTextBased("application/xml")).isTrue();
        assertThat(MimetypeLookup.isTextBased("application/javascript")).isTrue();
    }

    @Test
    void isTextBased_binaryMimeTypes_returnsFalse() {
        assertThat(MimetypeLookup.isTextBased("application/pdf")).isFalse();
        assertThat(MimetypeLookup.isTextBased("image/png")).isFalse();
        assertThat(MimetypeLookup.isTextBased("audio/mpeg")).isFalse();
        assertThat(MimetypeLookup.isTextBased("video/mp4")).isFalse();
    }

    @Test
    void isTextBased_nullMimeType_returnsFalse() {
        assertThat(MimetypeLookup.isTextBased(null)).isFalse();
    }
}
