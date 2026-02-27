package com.capsara.sdk.builder;

import com.capsara.sdk.internal.crypto.AesGcmProvider;
import com.capsara.sdk.internal.crypto.Base64Url;
import com.capsara.sdk.internal.crypto.CompressionProvider;
import com.capsara.sdk.internal.crypto.FileHashData;
import com.capsara.sdk.internal.crypto.HashProvider;
import com.capsara.sdk.internal.crypto.RsaProvider;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.crypto.SignatureProvider;
import com.capsara.sdk.internal.json.JsonMapper;
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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
    public static final int MAX_ACTING_FOR = 10;

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.getInstance();

    private final byte[] masterKey;
    private final String creatorId;
    private final String creatorPrivateKey;
    private final SystemLimits limits;
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
     * Add a recipient.
     * @param partyId recipient party ID
     * @return this builder for chaining
     */
    public CapsaBuilder addRecipient(String partyId) {
        if (partyId == null || partyId.isEmpty()) {
            throw new IllegalArgumentException("Party ID cannot be empty.");
        }
        if (partyId.length() > MAX_PARTY_ID_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("Party ID (%d chars) exceeds server limit of %d chars.",
                            partyId.length(), MAX_PARTY_ID_LENGTH));
        }
        // +1 for the creator who also gets a keychain entry
        if (recipients.size() + 1 >= MAX_KEYCHAIN_KEYS) {
            throw new IllegalStateException(
                    String.format("Cannot add recipient: keychain would exceed %d entries "
                            + "(including creator). Server will reject this capsa.",
                            MAX_KEYCHAIN_KEYS));
        }
        recipients.add(new RecipientConfig(partyId, "read"));
        return this;
    }

    /**
     * Add multiple recipients.
     * @param partyIds recipient party IDs
     * @return this builder for chaining
     */
    public CapsaBuilder addRecipients(String... partyIds) {
        for (String partyId : partyIds) {
            if (partyId == null || partyId.isEmpty()) {
                throw new IllegalArgumentException("Party ID cannot be empty.");
            }
            if (partyId.length() > MAX_PARTY_ID_LENGTH) {
                throw new IllegalArgumentException(
                        String.format("Party ID (%d chars) exceeds server limit of %d chars.",
                                partyId.length(), MAX_PARTY_ID_LENGTH));
            }
        }
        // +1 for the creator who also gets a keychain entry
        if (recipients.size() + partyIds.length + 1 > MAX_KEYCHAIN_KEYS) {
            throw new IllegalStateException(
                    String.format("Cannot add %d recipients: keychain would have %d entries "
                            + "(max %d). Server will reject this capsa.",
                            partyIds.length, recipients.size() + partyIds.length + 1,
                            MAX_KEYCHAIN_KEYS));
        }
        for (String partyId : partyIds) {
            recipients.add(new RecipientConfig(partyId, "read"));
        }
        return this;
    }

    /**
     * Add multiple recipients.
     * @param partyIds recipient party IDs
     * @return this builder for chaining
     */
    public CapsaBuilder addRecipients(Iterable<String> partyIds) {
        for (String partyId : partyIds) {
            addRecipient(partyId);
        }
        return this;
    }

    /**
     * Add a file.
     * @param input file input configuration
     * @return this builder for chaining
     * @throws IllegalStateException if file count or size limits exceeded
     */
    public CapsaBuilder addFile(FileInput input) {
        if (files.size() >= limits.getMaxFilesPerCapsa()) {
            throw new IllegalStateException(
                    String.format("Cannot add file: capsa already has %d files (max: %d)",
                            files.size(), limits.getMaxFilesPerCapsa()));
        }

        long fileSize = getFileSize(input);
        if (fileSize > limits.getMaxFileSize()) {
            throw new IllegalStateException(
                    String.format("File \"%s\" exceeds maximum size of %dMB",
                            input.getFilename(), limits.getMaxFileSize() / 1024 / 1024));
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
     * @param partyKeys public keys for all recipients (from API)
     * @return built capsa ready for upload
     * @throws IllegalStateException if builder is disposed or size limits exceeded
     */
    public BuiltCapsa build(PartyKey[] partyKeys) {
        throwIfDisposed();

        // No-content guard: server requires files OR a message (subject/body)
        boolean hasContent = !files.isEmpty()
                || (subject != null && !subject.isEmpty())
                || (body != null && !body.isEmpty());
        if (!hasContent) {
            throw new IllegalStateException(
                    "Capsa must contain either files or a message (subject/body). Server will reject empty capsas.");
        }

        final String packageId = "capsa_" + IdGenerator.generate(22);
        List<BuiltCapsa.EncryptedFileData> encryptedFiles = new ArrayList<>();
        long totalSize = 0;

        for (FileInput file : files) {
            byte[] fileData = readFileData(file);
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
                throw new IllegalStateException(
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
                fileMetadata.setExpiresAt(formatIso8601(file.getExpiresAt()));
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
            throw new IllegalStateException(
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
                throw new IllegalStateException(
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
                throw new IllegalStateException(
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
                    throw new IllegalStateException(
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
        String[] recipientIds = getRecipientIds();

        for (PartyKey partyKey : partyKeys) {
            RecipientConfig recipient = findRecipient(partyKey.getId());
            boolean isCreator = partyKey.getId().equals(creatorId);

            String[] permissions;
            String[] actingFor = null;

            if (partyKey.getIsDelegate() != null && partyKey.getIsDelegate().length > 0) {
                // Filter to only include recipients of THIS capsa
                List<String> relevantActingFor = new ArrayList<>();
                for (String delegateFor : partyKey.getIsDelegate()) {
                    if (containsRecipient(recipientIds, delegateFor)) {
                        relevantActingFor.add(delegateFor);
                    }
                }

                if (relevantActingFor.isEmpty()) {
                    continue;
                }

                if (relevantActingFor.size() > MAX_ACTING_FOR) {
                    throw new IllegalStateException(
                            String.format("Delegate \"%s\" acting for %d parties exceeds server limit of %d.",
                                    partyKey.getId(), relevantActingFor.size(), MAX_ACTING_FOR));
                }

                permissions = new String[]{"delegate"};
                actingFor = relevantActingFor.toArray(new String[0]);
            } else if (isCreator) {
                permissions = new String[0];
            } else if (recipient != null) {
                permissions = recipient.getPermissions();
                actingFor = recipient.getActingFor();
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
            entry.setFingerprint(partyKey.getFingerprint());
            entry.setPermissions(permissions);
            entry.setActingFor(actingFor);
            entry.setRevoked(false);

            keychainEntries.add(entry);
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
                fileHashDataArray,
                structuredIV,
                subjectIV,
                bodyIV);

        final CapsaSignature signature = SignatureProvider.createJws(canonicalString, creatorPrivateKey);

        if (signature.getPayload().length() > MAX_SIGNATURE_PAYLOAD) {
            throw new IllegalStateException(
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
                throw new IllegalStateException(
                        String.format("Metadata label (%d chars) exceeds server limit of %d chars.",
                                metadata.getLabel().length(), MAX_METADATA_LABEL));
            }
            if (metadata.getTags() != null && metadata.getTags().length > MAX_METADATA_TAGS) {
                throw new IllegalStateException(
                        String.format("Metadata tags count (%d) exceeds server limit of %d.",
                                metadata.getTags().length, MAX_METADATA_TAGS));
            }
            if (metadata.getTags() != null) {
                for (String tag : metadata.getTags()) {
                    if (tag.length() > MAX_TAG_LENGTH) {
                        throw new IllegalStateException(
                                String.format("Metadata tag \"%s...\" (%d chars) exceeds server limit of %d chars.",
                                        tag.substring(0, Math.min(20, tag.length())), tag.length(), MAX_TAG_LENGTH));
                    }
                }
            }
            if (metadata.getNotes() != null && metadata.getNotes().length() > MAX_METADATA_NOTES) {
                throw new IllegalStateException(
                        String.format("Metadata notes (%d chars) exceeds server limit of %d chars.",
                                metadata.getNotes().length(), MAX_METADATA_NOTES));
            }
            if (metadata.getRelatedPackages() != null && metadata.getRelatedPackages().length > MAX_RELATED_PACKAGES) {
                throw new IllegalStateException(
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
                throw new IllegalStateException(
                        "Duplicate IV detected across capsa fields. "
                        + "This indicates a CSPRNG failure. "
                        + "Do not send this capsa.");
            }
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

    private RecipientConfig findRecipient(String partyId) {
        for (RecipientConfig r : recipients) {
            if (r.getPartyId().equals(partyId)) {
                return r;
            }
        }
        return null;
    }

    private boolean containsRecipient(String[] recipientIds, String partyId) {
        for (String id : recipientIds) {
            if (id.equals(partyId)) {
                return true;
            }
        }
        return false;
    }

    private long getFileSize(FileInput file) {
        if (file.getData() != null) {
            return file.getData().length;
        }
        if (file.getPath() != null && !file.getPath().isEmpty()) {
            try {
                return Files.size(Paths.get(file.getPath()));
            } catch (IOException e) {
                throw new RuntimeException("Failed to get file size: " + file.getPath(), e);
            }
        }
        if (file.getStream() != null) {
            try {
                // Read stream to get size - this consumes the stream
                byte[] data = readStream(file.getStream());
                file.setData(data);
                file.setStream(null);
                return data.length;
            } catch (IOException e) {
                throw new RuntimeException("Failed to read stream for size calculation", e);
            }
        }
        throw new IllegalArgumentException("File input must have data, path, or stream");
    }

    private byte[] readFileData(FileInput file) {
        if (file.getData() != null) {
            return file.getData();
        }
        if (file.getPath() != null && !file.getPath().isEmpty()) {
            try {
                return Files.readAllBytes(Paths.get(file.getPath()));
            } catch (IOException e) {
                throw new RuntimeException("Failed to read file: " + file.getPath(), e);
            }
        }
        if (file.getStream() != null) {
            try {
                return readStream(file.getStream());
            } catch (IOException e) {
                throw new RuntimeException("Failed to read stream", e);
            }
        }
        throw new IllegalArgumentException("File input must have data, path, or stream");
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
