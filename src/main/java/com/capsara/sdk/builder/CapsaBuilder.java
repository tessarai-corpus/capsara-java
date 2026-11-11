package com.capsara.sdk.builder;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.CompressionProvider;
import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.HashProvider;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.internal.utils.FilenameCheck;
import com.capsara.sdk.internal.utils.IdGenerator;
import com.capsara.sdk.internal.utils.MimetypeLookup;
import com.capsara.sdk.models.CapsaAccessControl;
import com.capsara.sdk.models.CapsaKeychain;
import com.capsara.sdk.models.CapsaMetadata;
import com.capsara.sdk.models.CapsaSignature;
import com.capsara.sdk.models.EncryptedFile;
import com.capsara.sdk.models.FileInput;
import com.capsara.sdk.models.KeychainEntry;
import com.capsara.sdk.models.PartyKey;
import com.capsara.sdk.models.RecipientConfig;
import com.capsara.sdk.models.SystemLimits;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.math.BigDecimal;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** Fluent builder for creating encrypted capsas. Implements AutoCloseable to securely clear the master key. */
public final class CapsaBuilder implements AutoCloseable {

    /** Server-aligned validation constants. */
    public static final int MAX_KEYCHAIN_KEYS = 100;
    public static final int MAX_ENCRYPTED_SUBJECT = 65_536;
    public static final int MAX_ENCRYPTED_BODY = 1_048_576;
    public static final int MAX_ENCRYPTED_STRUCTURED = 1_048_576;
    public static final int MAX_METADATA_LABEL = 512;
    public static final int MAX_METADATA_TAGS = 100;
    public static final int MAX_TAG_LENGTH = 100;
    public static final int MAX_METADATA_NOTES = 10_240;
    public static final int MAX_RELATED_PACKAGES = 50;
    public static final int MAX_PARTY_ID_LENGTH = 100;
    public static final int MAX_ENCRYPTED_FILENAME = 2_048;
    public static final int MAX_SIGNATURE_PAYLOAD = 65_536;
    public static final int MAX_JSON_FIELD_BYTES = 1_048_576;

    private static final String NO_RECIPIENT_MESSAGE =
            "Capsa has no recipient. Call addRecipient() with the party this capsa is sent to.";

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final byte[] masterKey;
    private final String creatorId;
    private final String creatorPrivateKey;
    private final SystemLimits limits;
    private Clock clock = Clock.systemUTC();
    private final List<RecipientConfig> recipients = new ArrayList<>();
    private final List<FileInput> files = new ArrayList<>();
    private final Map<String, Object> structured = new LinkedHashMap<>();
    private final CapsaMetadata metadata = new CapsaMetadata();

    private String subject;
    private String body;
    private OffsetDateTime expiresAt;
    private boolean disposed;

    /**
     * Create a new capsa builder.
     *
     * @param creatorId         creator party ID
     * @param creatorPrivateKey creator's RSA private key (PEM format)
     * @param limits            system limits for validation (null for defaults)
     */
    public CapsaBuilder(String creatorId, String creatorPrivateKey, SystemLimits limits) {
        if (creatorId == null || creatorId.isEmpty()) {
            throw new IllegalArgumentException("Creator ID cannot be null or empty");
        }
        if (creatorPrivateKey == null || creatorPrivateKey.isEmpty()) {
            throw new IllegalArgumentException("Creator private key cannot be null or empty");
        }

        this.creatorId = creatorId;
        this.creatorPrivateKey = creatorPrivateKey;
        this.limits = limits != null ? limits : SystemLimits.DEFAULT;
        this.masterKey = SecureMemory.generateMasterKey();
    }

    /** Subject text (encrypted, only visible to recipients). */
    public String getSubject() {
        return subject;
    }

    /** Subject text (encrypted, only visible to recipients). */
    public void setSubject(String subject) {
        this.subject = subject;
    }

    /** Body/message text (encrypted, only visible to recipients). */
    public String getBody() {
        return body;
    }

    /** Body/message text (encrypted, only visible to recipients). */
    public void setBody(String body) {
        this.body = body;
    }

    /** Structured data map (encrypted, only visible to recipients). */
    public Map<String, Object> getStructured() {
        return structured;
    }

    /** Unencrypted metadata (visible to server for routing/display). */
    public CapsaMetadata getMetadata() {
        return metadata;
    }

    /** Expiration date/time. */
    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    /**
     * Set expiration (rounded to minute granularity).
     * @param expiresAt expiration date/time, or null to clear
     */
    public void setExpiresAt(OffsetDateTime expiresAt) {
        if (expiresAt == null) {
            this.expiresAt = null;
            return;
        }
        // Round to minute granularity
        this.expiresAt = expiresAt.withSecond(0).withNano(0);
    }

    /**
     * Set the capsa's recipient (its principal).
     * <p>
     * A capsa goes to exactly one recipient. The recipient's registered delegates
     * are added automatically at send time, each acting for this recipient, so
     * several parties can still access the capsa through their own keys. To send
     * to several recipients, use one builder per recipient and send them together
     * in one batch with sendCapsasAsync().
     * <p>
     * The recipient may be the creator itself (a self-send); the creator's own
     * delegates are then added, acting for the creator.
     *
     * @param partyId recipient party ID
     * @return this builder for chaining
     * @throws CapsaraException VALIDATION_ERROR if the ID is empty or too long, or a recipient was already added
     */
    public CapsaBuilder addRecipient(String partyId) {
        if (partyId == null || partyId.isEmpty()) {
            throw CapsaraException.validationError("Party ID cannot be empty.", null);
        }
        if (partyId.length() > MAX_PARTY_ID_LENGTH) {
            throw CapsaraException.validationError(
                    String.format("Party ID (%d chars) exceeds server limit of %d chars.",
                            partyId.length(), MAX_PARTY_ID_LENGTH), null);
        }
        if (!recipients.isEmpty()) {
            throw CapsaraException.validationError(
                    String.format("Capsa already has a recipient (\"%s\"). A capsa goes to exactly one "
                            + "recipient; that recipient's delegates are added automatically. To send to "
                            + "several recipients, create one builder per recipient and send them together "
                            + "in one batch.",
                            recipients.get(0).getPartyId()), null);
        }
        recipients.add(new RecipientConfig(partyId, "read"));
        return this;
    }

    /**
     * Add a file.
     * @param input file input configuration
     * @return this builder for chaining
     * @throws CapsaraException VALIDATION_ERROR if the file name contains "/", "\" or control characters, is
     *     empty or only spaces, or is "." or ".."; if limits are exceeded; or if the file has no readable source
     */
    public CapsaBuilder addFile(FileInput input) {
        String filenameProblem = FilenameCheck.sendProblem(input.getFilename());
        if (filenameProblem != null) {
            throw CapsaraException.validationError(filenameProblem, null);
        }

        if (files.size() >= limits.getMaxFilesPerCapsa()) {
            throw CapsaraException.validationError(
                    String.format("Cannot add file: capsa already has %d files (max: %d)",
                            files.size(), limits.getMaxFilesPerCapsa()), null);
        }

        long fileSize = getFileSize(input);
        if (fileSize > limits.getMaxFileSize()) {
            throw CapsaraException.validationError(
                    String.format("File \"%s\" exceeds maximum size of %dMB",
                            input.getFilename(), limits.getMaxFileSize() / 1024 / 1024), null);
        }

        files.add(input);
        return this;
    }

    /**
     * Add a file from path.
     * @param path file path on disk
     * @return this builder for chaining
     */
    public CapsaBuilder addFile(String path) {
        return addFile(FileInput.fromPath(path));
    }

    /**
     * Add a file from path with overrides.
     * @param path     file path on disk
     * @param filename filename override (null uses basename)
     * @param mimetype MIME type (null for auto-detect)
     * @return this builder for chaining
     */
    public CapsaBuilder addFile(String path, String filename, String mimetype) {
        return addFile(FileInput.fromPath(path, filename, mimetype));
    }

    /**
     * Add a file from byte array.
     * @param data     file content
     * @param filename filename
     * @return this builder for chaining
     */
    public CapsaBuilder addFile(byte[] data, String filename) {
        return addFile(FileInput.fromData(data, filename));
    }

    /**
     * Add a file from byte array.
     * @param data     file content
     * @param filename filename
     * @param mimetype MIME type (null for auto-detect)
     * @return this builder for chaining
     */
    public CapsaBuilder addFile(byte[] data, String filename, String mimetype) {
        return addFile(FileInput.fromData(data, filename, mimetype));
    }

    /**
     * Add a file from stream.
     * @param stream   input stream (consumed fully)
     * @param filename filename
     * @param mimetype MIME type (null for auto-detect)
     * @return this builder for chaining
     */
    public CapsaBuilder addFile(InputStream stream, String filename, String mimetype) {
        return addFile(FileInput.fromStream(stream, filename, mimetype));
    }

    /**
     * Add multiple files from paths.
     * @param paths file paths on disk
     * @return this builder for chaining
     */
    public CapsaBuilder addFiles(String... paths) {
        for (String path : paths) {
            addFile(FileInput.fromPath(path));
        }
        return this;
    }

    /**
     * Add multiple files from paths.
     * @param paths file paths on disk
     * @return this builder for chaining
     */
    public CapsaBuilder addFiles(Iterable<String> paths) {
        for (String path : paths) {
            addFile(FileInput.fromPath(path));
        }
        return this;
    }

    /**
     * Add multiple files.
     * @param files file inputs
     * @return this builder for chaining
     */
    public CapsaBuilder addFiles(FileInput... files) {
        for (FileInput file : files) {
            addFile(file);
        }
        return this;
    }

    /**
     * Add a text file from string content (UTF-8).
     * @param filename filename (e.g., "notes.txt")
     * @param content  text content
     * @return this builder for chaining
     */
    public CapsaBuilder addTextFile(String filename, String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return addFile(FileInput.fromData(bytes, filename, "text/plain"));
    }

    /**
     * Add a JSON file from an object.
     * @param filename filename (e.g., "data.json")
     * @param data     object to serialize
     * @return this builder for chaining
     */
    public CapsaBuilder addJsonFile(String filename, Object data) {
        try {
            String json = OBJECT_MAPPER.writeValueAsString(data);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            return addFile(FileInput.fromData(bytes, filename, "application/json"));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize object to JSON", e);
        }
    }

    /**
     * Set a structured data field (encrypted).
     * @param key   field key
     * @param value field value (must be JSON-serializable)
     * @return this builder for chaining
     */
    public CapsaBuilder withStructured(String key, Object value) {
        structured.put(key, value);
        return this;
    }

    /**
     * Set structured data fields from an object.
     * @param data object with properties to add
     * @return this builder for chaining
     */
    public CapsaBuilder withStructured(Object data) {
        try {
            String json = OBJECT_MAPPER.writeValueAsString(data);
            JsonNode node = OBJECT_MAPPER.readTree(json);
            if (node.isObject()) {
                ObjectNode objNode = (ObjectNode) node;
                objNode.fields().forEachRemaining(entry -> {
                    structured.put(entry.getKey(), convertJsonNode(entry.getValue()));
                });
            }
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to convert object to structured data", e);
        }
        return this;
    }

    /**
     * Set structured data from a map.
     * @param data map of structured data
     * @return this builder for chaining
     */
    public CapsaBuilder withStructured(Map<String, Object> data) {
        structured.putAll(data);
        return this;
    }

    /**
     * Set the subject (encrypted).
     * @param subject subject text
     * @return this builder for chaining
     */
    public CapsaBuilder withSubject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * Set the body (encrypted).
     * @param body body/message text
     * @return this builder for chaining
     */
    public CapsaBuilder withBody(String body) {
        this.body = body;
        return this;
    }

    /**
     * Set expiration (rounded to minute granularity).
     * @param expiresAt expiration date/time
     * @return this builder for chaining
     */
    public CapsaBuilder withExpiration(OffsetDateTime expiresAt) {
        setExpiresAt(expiresAt);
        return this;
    }

    /**
     * Get recipient party IDs for key fetching.
     * @return array of recipient party IDs
     */
    public String[] getRecipientIds() {
        return recipients.stream()
                .map(RecipientConfig::getPartyId)
                .toArray(String[]::new);
    }

    /**
     * Get file count.
     * @return number of files added to this builder
     */
    public int getFileCount() {
        return files.size();
    }

    /**
     * Build the capsa asynchronously.
     * @param partyKeys public keys for all recipients (from API)
     * @return CompletableFuture with built capsa ready for upload
     */
    public CompletableFuture<BuiltCapsa> buildAsync(PartyKey[] partyKeys) {
        return CompletableFuture.supplyAsync(() -> build(partyKeys));
    }

    /**
     * Build the capsa synchronously.
     * <p>
     * Encrypts all files and metadata, creates keychain entries,
     * and signs with the creator's private key.
     *
     * @param partyKeys public keys for the creator, the recipient and its delegates (from API);
     *                  other parties in the list are ignored
     * @return built capsa ready for upload
     * @throws CapsaraException BUILD_FAILED with {@code details.reason} when the capsa cannot be built
     */
    public BuiltCapsa build(PartyKey[] partyKeys) {
        throwIfDisposed();

        if (recipients.isEmpty()) {
            throw refuse("NO_RECIPIENT", NO_RECIPIENT_MESSAGE);
        }
        final RecipientConfig principal = recipients.get(0);
        final String principalId = principal.getPartyId();

        // No-content guard: server requires files OR a message (subject/body)
        boolean hasContent = !files.isEmpty()
                || (subject != null && !subject.isEmpty())
                || (body != null && !body.isEmpty());
        if (!hasContent) {
            throw refuse("NO_CONTENT",
                    "Capsa must contain either files or a message (subject/body). Server will reject empty capsas.");
        }

        if (expiresAt == null) {
            throw refuse("EXPIRATION_REQUIRED",
                    "Expiration is required. Call withExpiration() with the date this capsa should "
                    + "expire, based on how long the record needs to be retained.");
        }

        final Instant now = clock.instant();
        final double maxDays = limits.effectiveMaxExpirationDays();
        final Instant latest = latestExpiration(now, maxDays);
        final String days = formatDays(maxDays);
        if (!expiresAt.toInstant().isAfter(now)) {
            throw refuse("EXPIRATION_IN_PAST", String.format(
                    "Expiration %s is in the past. Set an expiration after the current time.",
                    formatMillis(expiresAt)));
        }
        if (expiresAt.toInstant().isAfter(latest)) {
            throw refuse("EXPIRATION_TOO_FAR", String.format(
                    "Expiration %s is more than %s days in the future. "
                            + "The latest allowed expiration is %s days from now.",
                    formatMillis(expiresAt), days, days));
        }

        if (!hasPublicKey(partyKeys, principalId)) {
            throw CapsaraCapsaException.recipientKeyNotFound(principalId);
        }

        final String packageId = "capsa_" + IdGenerator.generate(22);
        List<BuiltCapsa.EncryptedFileData> encryptedFiles = new ArrayList<>();
        long totalSize = 0;

        for (FileInput file : files) {
            byte[] fileData = readFileData(file);
            if (fileData.length == 0) {
                throw refuse("EMPTY_FILE", String.format("File \"%s\" is empty", file.getFilename()));
            }
            long originalSize = fileData.length;

            // Compress if needed (>= 150 bytes - gzip header breakeven point)
            boolean compressed = false;
            String compressionAlgorithm = null;
            if (file.getCompress() != Boolean.FALSE && CompressionProvider.shouldCompress(originalSize)) {
                CompressionProvider.CompressionResult compressionResult =
                        CompressionProvider.compressIfBeneficial(fileData);
                if (compressionResult.wasCompressed()) {
                    fileData = compressionResult.getData();
                    compressed = true;
                    compressionAlgorithm = compressionResult.getCompressionAlgorithm();
                }
            }

            byte[] contentIV = SecureMemory.generateIv();
            AesGcmProvider.EncryptionResult contentResult = AesGcmProvider.encrypt(fileData, masterKey, contentIV);

            final String hash = HashProvider.computeHash(contentResult.getCiphertext());

            byte[] filenameIV = SecureMemory.generateIv();
            byte[] filenameBytes = file.getFilename().getBytes(StandardCharsets.UTF_8);
            AesGcmProvider.EncryptionResult filenameResult =
                    AesGcmProvider.encrypt(filenameBytes, masterKey, filenameIV);

            String mimetype = file.getMimetype();
            if (mimetype == null || mimetype.isEmpty()) {
                mimetype = MimetypeLookup.lookupOrDefault(file.getFilename());
            }

            String encryptedFilename = Base64Url.encode(filenameResult.getCiphertext());
            if (encryptedFilename.length() > MAX_ENCRYPTED_FILENAME) {
                throw refuse("FILENAME_TOO_LONG",
                        String.format("Encrypted filename for \"%s...\" (%d chars) exceeds "
                                + "server limit of %d chars. Use a shorter filename.",
                                file.getFilename().substring(
                                        0, Math.min(30, file.getFilename().length())),
                                encryptedFilename.length(), MAX_ENCRYPTED_FILENAME));
            }

            EncryptedFile fileMetadata = new EncryptedFile();
            fileMetadata.setFileId("file_" + IdGenerator.generate(16) + ".enc");
            fileMetadata.setEncryptedFilename(encryptedFilename);
            fileMetadata.setFilenameIV(Base64Url.encode(filenameIV));
            fileMetadata.setFilenameAuthTag(Base64Url.encode(filenameResult.getAuthTag()));
            fileMetadata.setIv(Base64Url.encode(contentIV));
            fileMetadata.setAuthTag(Base64Url.encode(contentResult.getAuthTag()));
            fileMetadata.setMimetype(mimetype);
            fileMetadata.setSize(contentResult.getCiphertext().length);
            fileMetadata.setHash(hash);
            fileMetadata.setHashAlgorithm("SHA-256");

            if (compressed) {
                fileMetadata.setCompressed(true);
                fileMetadata.setCompressionAlgorithm(compressionAlgorithm);
                fileMetadata.setOriginalSize(originalSize);
            }

            if (file.getExpiresAt() != null) {
                OffsetDateTime fileExpiresAt = file.getExpiresAt().withSecond(0).withNano(0);
                if (!fileExpiresAt.toInstant().isAfter(now)) {
                    throw refuse("FILE_EXPIRATION_IN_PAST", String.format(
                            "Expiration for \"%s\" (%s) is in the past. Set an expiration after the current time.",
                            file.getFilename(), formatMillis(fileExpiresAt)));
                }
                if (fileExpiresAt.toInstant().isAfter(latest)) {
                    throw refuse("FILE_EXPIRATION_TOO_FAR", String.format(
                            "Expiration for \"%s\" (%s) is more than %s days in the future. "
                                    + "The latest allowed expiration is %s days from now.",
                            file.getFilename(), formatMillis(fileExpiresAt), days, days));
                }
                if (fileExpiresAt.isAfter(expiresAt)) {
                    throw refuse("FILE_OUTLIVES_CAPSA", String.format(
                            "Expiration for \"%s\" (%s) is after the capsa expires (%s). "
                            + "A file cannot outlive the capsa that carries it.",
                            file.getFilename(), formatIso8601(fileExpiresAt), formatIso8601(expiresAt)));
                }
                fileMetadata.setExpiresAt(formatIso8601(fileExpiresAt));
            }

            if (file.getTransform() != null && !file.getTransform().isEmpty()) {
                fileMetadata.setTransform(file.getTransform());
            }

            BuiltCapsa.EncryptedFileData encryptedFileData = new BuiltCapsa.EncryptedFileData();
            encryptedFileData.setMetadata(fileMetadata);
            encryptedFileData.setData(contentResult.getCiphertext());
            encryptedFiles.add(encryptedFileData);

            totalSize += contentResult.getCiphertext().length;
        }

        if (totalSize > limits.getMaxTotalSize()) {
            throw refuse("TOTAL_SIZE_EXCEEDED",
                    String.format("Total capsa size %d bytes exceeds maximum of %dMB",
                            totalSize, limits.getMaxTotalSize() / 1024 / 1024));
        }

        String encryptedSubject = null;
        String subjectIV = null;
        String subjectAuthTag = null;
        String encryptedBody = null;
        String bodyIV = null;
        String bodyAuthTag = null;
        String encryptedStructured = null;
        String structuredIV = null;
        String structuredAuthTag = null;

        if (subject != null && !subject.isEmpty()) {
            byte[] iv = SecureMemory.generateIv();
            AesGcmProvider.EncryptionResult result = AesGcmProvider.encrypt(
                    subject.getBytes(StandardCharsets.UTF_8), masterKey, iv);
            encryptedSubject = Base64Url.encode(result.getCiphertext());
            subjectIV = Base64Url.encode(iv);
            subjectAuthTag = Base64Url.encode(result.getAuthTag());

            if (encryptedSubject.length() > MAX_ENCRYPTED_SUBJECT) {
                throw refuse("SUBJECT_TOO_LARGE",
                        String.format("Encrypted subject (%d chars) exceeds server "
                                + "limit of %d chars. Reduce subject length.",
                                encryptedSubject.length(), MAX_ENCRYPTED_SUBJECT));
            }
        }

        if (body != null && !body.isEmpty()) {
            byte[] iv = SecureMemory.generateIv();
            AesGcmProvider.EncryptionResult result = AesGcmProvider.encrypt(
                    body.getBytes(StandardCharsets.UTF_8), masterKey, iv);
            encryptedBody = Base64Url.encode(result.getCiphertext());
            bodyIV = Base64Url.encode(iv);
            bodyAuthTag = Base64Url.encode(result.getAuthTag());

            if (encryptedBody.length() > MAX_ENCRYPTED_BODY) {
                throw refuse("BODY_TOO_LARGE",
                        String.format("Encrypted body (%d chars) exceeds server limit of %d chars. Reduce body length.",
                                encryptedBody.length(), MAX_ENCRYPTED_BODY));
            }
        }

        if (!structured.isEmpty()) {
            try {
                String json = OBJECT_MAPPER.writeValueAsString(structured);
                byte[] iv = SecureMemory.generateIv();
                AesGcmProvider.EncryptionResult result = AesGcmProvider.encrypt(
                        json.getBytes(StandardCharsets.UTF_8), masterKey, iv);
                encryptedStructured = Base64Url.encode(result.getCiphertext());
                structuredIV = Base64Url.encode(iv);
                structuredAuthTag = Base64Url.encode(result.getAuthTag());

                if (encryptedStructured.length() > MAX_ENCRYPTED_STRUCTURED) {
                    throw refuse("STRUCTURED_TOO_LARGE",
                            String.format("Encrypted structured data (%d chars) exceeds "
                                    + "server limit of %d chars. "
                                    + "Reduce structured data size.",
                                    encryptedStructured.length(),
                                    MAX_ENCRYPTED_STRUCTURED));
                }
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to serialize structured data", e);
            }
        }

        List<KeychainEntry> keychainEntries = new ArrayList<>();

        for (PartyKey partyKey : partyKeys) {
            boolean isCreator = partyKey.getId().equals(creatorId);
            boolean isPrincipal = partyKey.getId().equals(principalId);
            // A delegate is included only when it acts for this capsa's recipient, and
            // then only on that recipient's behalf.
            boolean actsForPrincipal = !isPrincipal && containsParty(partyKey.getIsDelegate(), principalId);

            String[] permissions;
            String[] actingFor = null;

            if (actsForPrincipal) {
                permissions = new String[]{"delegate"};
                actingFor = new String[]{principalId};
            } else if (isCreator) {
                permissions = new String[0];
            } else if (isPrincipal) {
                permissions = principal.getPermissions();
            } else {
                continue;
            }

            boolean isDelegatedRecipient = permissions.length == 0 && !isCreator;
            byte[] keyIV = SecureMemory.generateIv();

            KeychainEntry entry = new KeychainEntry();
            entry.setParty(partyKey.getId());
            entry.setEncryptedKey(isDelegatedRecipient
                    ? ""
                    : RsaProvider.encryptMasterKey(masterKey, partyKey.getPublicKey()));
            entry.setIv(Base64Url.encode(keyIV));
            entry.setFingerprint(partyKey.getFingerprint() != null && !partyKey.getFingerprint().isEmpty()
                    ? partyKey.getFingerprint()
                    : null);
            entry.setPermissions(permissions);
            entry.setActingFor(actingFor);
            entry.setRevoked(false);

            keychainEntries.add(entry);
        }

        if (keychainEntries.size() > MAX_KEYCHAIN_KEYS) {
            throw refuse("TOO_MANY_KEYCHAIN_ENTRIES",
                    String.format("Keychain has %d entries (creator, recipient and delegates), "
                            + "exceeding the server limit of %d.",
                            keychainEntries.size(), MAX_KEYCHAIN_KEYS));
        }

        FileHashData[] fileHashDataArray = encryptedFiles.stream()
                .map(f -> new FileHashData(
                        f.getMetadata().getFileId(),
                        f.getMetadata().getHash(),
                        f.getMetadata().getSize(),
                        f.getMetadata().getIv(),
                        f.getMetadata().getFilenameIV()))
                .toArray(FileHashData[]::new);

        String canonicalString = SignatureProvider.buildCanonicalString(
                packageId,
                totalSize,
                "AES-256-GCM",
                creatorId,
                KeyGenerator.calculateFingerprintFromPrivateKey(creatorPrivateKey),
                fileHashDataArray,
                structuredIV,
                subjectIV,
                bodyIV);

        final CapsaSignature signature = SignatureProvider.createJws(canonicalString, creatorPrivateKey);

        if (signature.getPayload().length() > MAX_SIGNATURE_PAYLOAD) {
            throw refuse("SIGNATURE_TOO_LARGE",
                    String.format("Signature payload (%d chars) exceeds server limit of %d chars.",
                            signature.getPayload().length(), MAX_SIGNATURE_PAYLOAD));
        }

        BuiltCapsa.CapsaUploadData capsaData = new BuiltCapsa.CapsaUploadData();
        capsaData.setPackageId(packageId);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(keychainEntries.toArray(new KeychainEntry[0]));
        capsaData.setKeychain(keychain);

        capsaData.setSignature(signature);

        CapsaAccessControl accessControl = new CapsaAccessControl();
        if (expiresAt != null) {
            accessControl.setExpiresAt(formatIso8601(expiresAt));
        }
        capsaData.setAccessControl(accessControl);

        capsaData.setDeliveryPriority("normal");
        capsaData.setFiles(encryptedFiles.stream()
                .map(BuiltCapsa.EncryptedFileData::getMetadata)
                .toArray(EncryptedFile[]::new));

        if (encryptedSubject != null) {
            capsaData.setEncryptedSubject(encryptedSubject);
            capsaData.setSubjectIV(subjectIV);
            capsaData.setSubjectAuthTag(subjectAuthTag);
        }

        if (encryptedBody != null) {
            capsaData.setEncryptedBody(encryptedBody);
            capsaData.setBodyIV(bodyIV);
            capsaData.setBodyAuthTag(bodyAuthTag);
        }

        if (encryptedStructured != null) {
            capsaData.setEncryptedStructured(encryptedStructured);
            capsaData.setStructuredIV(structuredIV);
            capsaData.setStructuredAuthTag(structuredAuthTag);
        }

        if (hasMetadata()) {
            if (metadata.getLabel() != null && metadata.getLabel().length() > MAX_METADATA_LABEL) {
                throw refuse("METADATA_LABEL_TOO_LONG",
                        String.format("Metadata label (%d chars) exceeds server limit of %d chars.",
                                metadata.getLabel().length(), MAX_METADATA_LABEL));
            }
            if (metadata.getTags() != null && metadata.getTags().length > MAX_METADATA_TAGS) {
                throw refuse("TOO_MANY_TAGS",
                        String.format("Metadata tags count (%d) exceeds server limit of %d.",
                                metadata.getTags().length, MAX_METADATA_TAGS));
            }
            if (metadata.getTags() != null) {
                for (String tag : metadata.getTags()) {
                    if (tag.length() > MAX_TAG_LENGTH) {
                        throw refuse("TAG_TOO_LONG",
                                String.format("Metadata tag \"%s...\" (%d chars) exceeds server limit of %d chars.",
                                        tag.substring(0, Math.min(20, tag.length())), tag.length(), MAX_TAG_LENGTH));
                    }
                }
            }
            if (metadata.getNotes() != null && metadata.getNotes().length() > MAX_METADATA_NOTES) {
                throw refuse("METADATA_NOTES_TOO_LONG",
                        String.format("Metadata notes (%d chars) exceeds server limit of %d chars.",
                                metadata.getNotes().length(), MAX_METADATA_NOTES));
            }
            if (metadata.getRelatedPackages() != null && metadata.getRelatedPackages().length > MAX_RELATED_PACKAGES) {
                throw refuse("TOO_MANY_RELATED_PACKAGES",
                        String.format("Related packages count (%d) exceeds server limit of %d.",
                                metadata.getRelatedPackages().length, MAX_RELATED_PACKAGES));
            }
            capsaData.setMetadata(metadata);
        }

        // Defense-in-depth: detect duplicate IVs across all fields.
        // Server performs the same check and will reject duplicates.
        List<String> ivList = new ArrayList<>();
        if (subjectIV != null) {
            ivList.add(subjectIV);
        }
        if (bodyIV != null) {
            ivList.add(bodyIV);
        }
        if (structuredIV != null) {
            ivList.add(structuredIV);
        }
        for (KeychainEntry entry : keychainEntries) {
            if (entry.getIv() != null) {
                ivList.add(entry.getIv());
            }
        }
        for (BuiltCapsa.EncryptedFileData f : encryptedFiles) {
            ivList.add(f.getMetadata().getIv());
            ivList.add(f.getMetadata().getFilenameIV());
        }
        java.util.Set<String> allIVs = new java.util.HashSet<>();
        for (String iv : ivList) {
            if (!allIVs.add(iv)) {
                throw refuse("DUPLICATE_IV",
                        "Duplicate IV detected across capsa fields. "
                        + "This indicates a CSPRNG failure. "
                        + "Do not send this capsa.");
            }
        }

        long capsaJsonBytes;
        try {
            capsaJsonBytes = OBJECT_MAPPER.writeValueAsString(capsaData).getBytes(StandardCharsets.UTF_8).length;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize capsa metadata", e);
        }
        if (capsaJsonBytes > MAX_JSON_FIELD_BYTES) {
            throw refuse("CAPSA_JSON_TOO_LARGE",
                    String.format("Capsa metadata (%d bytes) exceeds the server limit of %d bytes per JSON field. "
                            + "Reduce the subject, body, structured data or metadata.",
                            capsaJsonBytes, MAX_JSON_FIELD_BYTES));
        }

        BuiltCapsa result = new BuiltCapsa();
        result.setCapsa(capsaData);
        result.setFiles(encryptedFiles.toArray(new BuiltCapsa.EncryptedFileData[0]));

        return result;
    }

    private boolean hasMetadata() {
        return (metadata.getLabel() != null && !metadata.getLabel().isEmpty()) ||
                (metadata.getTags() != null && metadata.getTags().length > 0) ||
                (metadata.getNotes() != null && !metadata.getNotes().isEmpty()) ||
                (metadata.getRelatedPackages() != null && metadata.getRelatedPackages().length > 0);
    }

    private static boolean hasPublicKey(PartyKey[] partyKeys, String partyId) {
        if (partyKeys == null) {
            return false;
        }
        for (PartyKey partyKey : partyKeys) {
            if (partyKey != null && partyId.equals(partyKey.getId()) && hasPublicKey(partyKey)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasPublicKey(PartyKey partyKey) {
        return partyKey.getPublicKey() != null && !partyKey.getPublicKey().isEmpty();
    }

    private static boolean containsParty(String[] partyIds, String partyId) {
        if (partyIds == null) {
            return false;
        }
        for (String id : partyIds) {
            if (partyId.equals(id)) {
                return true;
            }
        }
        return false;
    }

    private long getFileSize(FileInput file) {
        if (file == null) {
            throw CapsaraException.validationError("File input must have data, path, or stream", null);
        }
        if (file.getData() != null) {
            return file.getData().length;
        }
        if (file.getPath() != null && !file.getPath().isEmpty()) {
            try {
                return Files.size(Paths.get(file.getPath()));
            } catch (IOException | RuntimeException e) {
                throw CapsaraException.validationError("Cannot read file: " + file.getPath(), null);
            }
        }
        if (file.getStream() != null) {
            try {
                byte[] data = readStream(file.getStream());
                file.setData(data);
                file.setStream(null);
                return data.length;
            } catch (IOException e) {
                throw CapsaraException.validationError("Cannot read file stream: " + file.getFilename(), null);
            }
        }
        throw CapsaraException.validationError("File input must have data, path, or stream", null);
    }

    private byte[] readFileData(FileInput file) {
        if (file.getData() != null) {
            return file.getData();
        }
        if (file.getPath() != null && !file.getPath().isEmpty()) {
            try {
                return Files.readAllBytes(Paths.get(file.getPath()));
            } catch (IOException | RuntimeException e) {
                throw refuse("FILE_READ_FAILED", "Failed to read file: " + file.getPath());
            }
        }
        if (file.getStream() != null) {
            try {
                return readStream(file.getStream());
            } catch (IOException e) {
                throw refuse("FILE_READ_FAILED", "Failed to read stream for " + file.getFilename());
            }
        }
        throw refuse("FILE_SOURCE_MISSING", "File input must have data, path, or stream");
    }

    private byte[] readStream(InputStream stream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int len;
        while ((len = stream.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        return baos.toByteArray();
    }

    private Object convertJsonNode(JsonNode node) {
        if (node.isTextual()) {
            return node.asText();
        } else if (node.isNumber()) {
            if (node.isInt() || node.isLong()) {
                return node.asLong();
            }
            return node.asDouble();
        } else if (node.isBoolean()) {
            return node.asBoolean();
        } else if (node.isNull()) {
            return null;
        } else if (node.isArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonNode element : node) {
                list.add(convertJsonNode(element));
            }
            return list.toArray();
        } else if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.fields().forEachRemaining(entry -> {
                map.put(entry.getKey(), convertJsonNode(entry.getValue()));
            });
            return map;
        }
        return node.toString();
    }

    private String formatIso8601(OffsetDateTime dateTime) {
        return dateTime.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }

    /**
     * Replace the clock used for expiration checks.
     *
     * @param clock clock to read the current time from
     */
    void setClock(Clock clock) {
        this.clock = clock;
    }

    private static Instant latestExpiration(Instant now, double maxDays) {
        try {
            return now.plusMillis((long) (maxDays * 86_400_000d));
        } catch (ArithmeticException | DateTimeException e) {
            return Instant.MAX;
        }
    }

    /** Date.prototype.toISOString form: four-digit years, otherwise a sign and six digits. */
    static String formatMillis(OffsetDateTime dateTime) {
        OffsetDateTime utc = dateTime.withOffsetSameInstant(ZoneOffset.UTC);
        int year = utc.getYear();
        String yearText = year >= 0 && year <= 9999
                ? String.format("%04d", year)
                : (year < 0 ? "-" : "+") + String.format("%06d", Math.abs((long) year));
        return yearText + DateTimeFormatter.ofPattern("-MM-dd'T'HH:mm:ss.SSS'Z'").format(utc);
    }

    /** Number.prototype.toString form for a finite double. */
    static String formatDays(double days) {
        if (days == 0) {
            return "0";
        }
        if (days < 0) {
            return "-" + formatDays(-days);
        }
        BigDecimal value = new BigDecimal(Double.toString(days)).stripTrailingZeros();
        String digits = value.unscaledValue().toString();
        int k = digits.length();
        int n = k - value.scale();
        if (k <= n && n <= 21) {
            return digits + "0".repeat(n - k);
        }
        if (0 < n && n <= 21) {
            return digits.substring(0, n) + "." + digits.substring(n);
        }
        if (-6 < n && n <= 0) {
            return "0." + "0".repeat(-n) + digits;
        }
        String mantissa = k == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        int exponent = n - 1;
        return mantissa + "e" + (exponent < 0 ? "-" : "+") + Math.abs(exponent);
    }

    private static CapsaraException refuse(String reason, String message) {
        return CapsaraException.buildFailed(message, reason);
    }

    private void throwIfDisposed() {
        if (disposed) {
            throw new IllegalStateException("CapsaBuilder has been disposed");
        }
    }

    /** Securely clear the master key from memory. */
    @Override
    public void close() {
        if (disposed) {
            return;
        }
        disposed = true;
        SecureMemory.clear(masterKey);
    }
}
