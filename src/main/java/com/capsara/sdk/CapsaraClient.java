package com.capsara.sdk;

import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.internal.cache.CachedFileMetadata;
import com.capsara.sdk.internal.cache.CapsaCache;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.PrivateKeyRing;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.services.AccountService;
import com.capsara.sdk.internal.services.AuditService;
import com.capsara.sdk.internal.services.AuthService;
import com.capsara.sdk.internal.services.CapsaService;
import com.capsara.sdk.internal.services.DownloadService;
import com.capsara.sdk.internal.services.KeyService;
import com.capsara.sdk.internal.services.LimitsService;
import com.capsara.sdk.internal.services.TokenRefreshingHttpClient;
import com.capsara.sdk.internal.services.UploadService;
import com.capsara.sdk.internal.SdkVersion;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.AuthResponse;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.DecryptedCapsa;
import com.capsara.sdk.models.DecryptedFileResult;
import com.capsara.sdk.models.EncryptedFile;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import com.capsara.sdk.models.GetAuditEntriesResponse;
import com.capsara.sdk.models.KeyHistoryEntry;
import com.capsara.sdk.models.KeyRotationResult;
import com.capsara.sdk.models.PublicKeyInfo;
import com.capsara.sdk.models.SendResult;
import com.capsara.sdk.models.SystemLimits;

import java.net.http.HttpClient;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Primary interface for zero-knowledge encrypted file sharing. */
public final class CapsaraClient implements AutoCloseable {

    private final String baseUrl;
    private final CapsaraClientOptions options;
    private final HttpClient apiHttpClient;
    private final HttpClient blobHttpClient;
    private final ConcurrencyConfig concurrencyConfig;
    private final AuthService authService;
    private final KeyService keyService;
    private final CapsaService capsaService;
    private final DownloadService downloadService;
    private final UploadService uploadService;
    private final AuditService auditService;
    private final AccountService accountService;
    private final LimitsService limitsService;
    private final CapsaCache capsaCache;

    private final ConcurrentHashMap<String, CompletableFuture<DecryptedCapsa>> inFlightCapsaFetches =
            new ConcurrentHashMap<>();

    private volatile String creatorId;
    private volatile String creatorPrivateKey;
    private final CopyOnWriteArrayList<String> previousPrivateKeys = new CopyOnWriteArrayList<>();
    private volatile boolean disposed;

    public String getBaseUrl() {
        return baseUrl;
    }

    public CapsaraClient(String baseUrl) {
        this(baseUrl, null);
    }

    /**
     * @param baseUrl API base URL
     * @param options client configuration options (nullable)
     */
    public CapsaraClient(String baseUrl, CapsaraClientOptions options) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("baseUrl cannot be null or empty");
        }

        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.options = options != null ? options : new CapsaraClientOptions();
        if (this.options.getPreviousPrivateKeys() != null) {
            for (String key : this.options.getPreviousPrivateKeys()) {
                PrivateKeyRing.requireUsable(key, true);
            }
        }

        HttpTimeoutConfig timeout = this.options.getTimeout();
        RetryConfig retry = this.options.getRetry();
        String userAgent = buildUserAgent(this.options.getUserAgent());
        this.authService = new AuthService(baseUrl, timeout, retry, userAgent);

        this.apiHttpClient = new TokenRefreshingHttpClient(HttpClientFactory.createForApi(timeout), authService);
        this.blobHttpClient = HttpClientFactory.createForBlob(timeout);
        this.concurrencyConfig = new ConcurrencyConfig();
        this.keyService = new KeyService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);
        this.capsaService = new CapsaService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);
        this.downloadService = new DownloadService(apiHttpClient, blobHttpClient, baseUrl, authService::getToken,
                timeout, retry, userAgent, concurrencyConfig);
        this.uploadService = new UploadService(apiHttpClient, baseUrl, authService::getToken, keyService,
                this.options.getMaxBatchSize(), retry, timeout, userAgent, concurrencyConfig);
        this.auditService = new AuditService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);
        this.accountService = new AccountService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);
        this.limitsService = new LimitsService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);

        this.uploadService.setLimitsSupplier(() -> limitsService.getLimitsAsync().join());

        this.capsaCache = this.options.getCacheTTL() != null
                ? new CapsaCache(this.options.getCacheTTL())
                : new CapsaCache();

        if (this.options.getAccessToken() != null && !this.options.getAccessToken().isEmpty()) {
            authService.setToken(this.options.getAccessToken());
        }

        if (this.options.getPreviousPrivateKeys() != null) {
            previousPrivateKeys.addAllAbsent(this.options.getPreviousPrivateKeys());
        }
    }

    private String buildUserAgent(String customUserAgent) {
        return SdkVersion.buildUserAgent(customUserAgent);
    }


    /**
     * @param credentials authentication credentials
     * @return auth response
     */
    public CompletableFuture<AuthResponse> loginAsync(AuthCredentials credentials) {
        return authService.loginAsync(credentials).thenApply(response -> {
            this.creatorId = response.getParty().getId();
            return response;
        });
    }

    /**
     * Clear local tokens and cached keys, then revoke the session server-side.
     *
     * @return true once the server confirms; fails with the server's error or a network error otherwise
     */
    public CompletableFuture<Boolean> logoutAsync() {
        clearCache();
        return authService.logoutAsync();
    }

    /** @return true if access token is set */
    public boolean isAuthenticated() {
        return authService.isAuthenticated();
    }

    /**
     * Set the current private key.
     *
     * @param privateKey RSA private key (PEM)
     * @throws com.capsara.sdk.exceptions.CapsaraException INVALID_PRIVATE_KEY if the key is empty or unusable;
     *         the current key is then unchanged
     */
    public void setPrivateKey(String privateKey) {
        PrivateKeyRing.requireUsable(privateKey, false);
        this.creatorPrivateKey = privateKey;
    }

    /**
     * Add a private key this party rotated away from, for capsas encrypted to it.
     *
     * @param privateKey earlier RSA private key (PEM)
     * @throws com.capsara.sdk.exceptions.CapsaraException INVALID_PRIVATE_KEY if the key is empty or unusable;
     *         it is then not added
     */
    public void addPreviousPrivateKey(String privateKey) {
        PrivateKeyRing.requireUsable(privateKey, true);
        previousPrivateKeys.addIfAbsent(privateKey);
    }


    /** @return new CapsaBuilder configured with current identity and server limits */
    public CompletableFuture<CapsaBuilder> createCapsaBuilderAsync() {
        if (creatorId == null) {
            return CompletableFuture.failedFuture(CapsaraException.notLoggedIn());
        }
        if (creatorPrivateKey == null) {
            return CompletableFuture.failedFuture(CapsaraException.missingPrivateKey());
        }

        return getLimitsAsync()
                .thenApply(limits -> new CapsaBuilder(creatorId, creatorPrivateKey, limits));
    }

    /**
     * @param builders array of CapsaBuilder instances
     * @return send result with success/failure counts
     */
    public CompletableFuture<SendResult> sendCapsasAsync(CapsaBuilder[] builders) {
        if (creatorId == null) {
            return CompletableFuture.failedFuture(CapsaraException.notLoggedIn());
        }

        return uploadService.sendCapsasAsync(builders, creatorId);
    }

    /** Get capsa without decryption. */
    public CompletableFuture<Capsa> getCapsaAsync(String capsaId) {
        return capsaService.getCapsaAsync(capsaId);
    }

    /**
     * Fetch, verify and decrypt a capsa; concurrent requests for one capsaId are deduplicated.
     *
     * @param capsaId capsa ID
     * @return decrypted capsa
     */
    public CompletableFuture<DecryptedCapsa> getDecryptedCapsaAsync(String capsaId) {
        if (creatorPrivateKey == null) {
            return CompletableFuture.failedFuture(CapsaraException.missingPrivateKey());
        }

        return shareInFlight(inFlightCapsaFetches, capsaId, () -> fetchAndDecryptCapsa(capsaId));
    }

    /**
     * Join the in-flight future for key, or start one; the entry is removed before the shared future completes,
     * so a fetch that completes synchronously never updates the map from inside its own registration.
     */
    static <T> CompletableFuture<T> shareInFlight(ConcurrentHashMap<String, CompletableFuture<T>> inFlight,
                                                  String key, Supplier<CompletableFuture<T>> start) {
        CompletableFuture<T> shared = new CompletableFuture<>();
        CompletableFuture<T> existing = inFlight.putIfAbsent(key, shared);
        if (existing != null) {
            return existing;
        }
        CompletableFuture<T> fetch;
        try {
            fetch = start.get();
        } catch (RuntimeException e) {
            inFlight.remove(key, shared);
            shared.completeExceptionally(e);
            throw e;
        }
        fetch.whenComplete((result, error) -> {
            inFlight.remove(key, shared);
            if (error != null) {
                shared.completeExceptionally(error);
            } else {
                shared.complete(result);
            }
        });
        return shared;
    }

    private CompletableFuture<DecryptedCapsa> fetchAndDecryptCapsa(String capsaId) {
        PrivateKeyRing keys = new PrivateKeyRing(creatorPrivateKey, previousPrivateKeys);
        String partyId = creatorId;
        return capsaService.getCapsaAsync(capsaId)
                .thenApply(capsa -> {
                    DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keys, partyId);
                    cacheDecryptedCapsa(capsaId, decrypted);
                    return decrypted;
                });
    }

    private void cacheDecryptedCapsa(String capsaId, DecryptedCapsa decrypted) {
        byte[] masterKey = decrypted.getMasterKey();
        CachedFileMetadata[] cachedFiles = new CachedFileMetadata[decrypted.getFiles().length];

        for (int i = 0; i < decrypted.getFiles().length; i++) {
            EncryptedFile f = decrypted.getFiles()[i];
            CachedFileMetadata cached = new CachedFileMetadata();
            cached.setFileId(f.getFileId());
            cached.setIv(f.getIv());
            cached.setAuthTag(f.getAuthTag());
            cached.setCompressed(f.getCompressed() != null && f.getCompressed());
            cached.setEncryptedFilename(f.getEncryptedFilename());
            cached.setFilenameIV(f.getFilenameIV());
            cached.setFilenameAuthTag(f.getFilenameAuthTag());
            cachedFiles[i] = cached;
        }

        capsaCache.set(capsaId, masterKey, cachedFiles);
    }

    /** @param filters query filters */
    public CompletableFuture<CapsaListResponse> listCapsasAsync(CapsaListFilters filters) {
        return capsaService.listCapsasAsync(filters);
    }

    /** Soft delete a capsa. */
    public CompletableFuture<Void> deleteCapsaAsync(String capsaId) {
        capsaCache.clear(capsaId);
        return capsaService.deleteCapsaAsync(capsaId);
    }

    /** Download and decrypt a single file from a capsa. */
    public CompletableFuture<DecryptedFileResult> downloadFileAsync(String capsaId, String fileId) {
        if (!capsaCache.contains(capsaId, fileId)) {
            return getDecryptedCapsaAsync(capsaId)
                    .thenCompose(decrypted -> downloadFileWithCache(capsaId, fileId));
        }

        return downloadFileWithCache(capsaId, fileId);
    }

    private CompletableFuture<DecryptedFileResult> downloadFileWithCache(String capsaId, String fileId) {
        CachedFileMetadata cachedFile = capsaCache.getFileMetadata(capsaId, fileId);
        byte[] masterKey = cachedFile != null ? capsaCache.getMasterKey(capsaId) : null;

        if (masterKey == null || cachedFile == null) {
            if (masterKey != null) {
                SecureMemory.clear(masterKey);
            }
            return CompletableFuture.failedFuture(CapsaraCapsaException.fileNotFound(capsaId, fileId));
        }

        return decryptDownload(downloadService.downloadEncryptedFileAsync(capsaId, fileId), capsaId, masterKey,
                cachedFile);
    }

    /**
     * Decrypt a downloaded file with a master key copy, zeroing the copy whether or not the download succeeds.
     *
     * @param download  the encrypted file download
     * @param capsaId   capsa the file belongs to
     * @param masterKey a copy of the capsa's master key, owned by this call
     * @param file      cached file metadata
     * @return the decrypted file; a decrypt or decompress failure is DOWNLOAD_FAILED
     */
    static CompletableFuture<DecryptedFileResult> decryptDownload(CompletableFuture<byte[]> download,
            String capsaId, byte[] masterKey, CachedFileMetadata file) {
        return download
                .thenApply(encryptedData -> {
                    try {
                        DecryptedFileResult result = new DecryptedFileResult();
                        result.setData(CapsaDecryptor.decryptFile(encryptedData, masterKey, file.getIv(),
                                file.getAuthTag(), file.isCompressed()));
                        result.setFilename(CapsaDecryptor.decryptFilename(file.getEncryptedFilename(), masterKey,
                                file.getFilenameIV(), file.getFilenameAuthTag()));
                        return result;
                    } catch (RuntimeException e) {
                        throw CapsaraCapsaException.downloadFailed(capsaId, file.getFileId(), e);
                    }
                })
                .whenComplete((result, error) -> SecureMemory.clear(masterKey));
    }


    /**
     * @param capsaId capsa ID
     * @param filters query filters
     */
    public CompletableFuture<GetAuditEntriesResponse> getAuditEntriesAsync(String capsaId,
            GetAuditEntriesFilters filters) {
        return auditService.getAuditEntriesAsync(capsaId, filters);
    }

    /**
     * @param capsaId capsa ID
     * @param entry   audit entry to create
     * @return true if successful
     */
    public CompletableFuture<Boolean> createAuditEntryAsync(String capsaId, CreateAuditEntryRequest entry) {
        return auditService.createAuditEntryAsync(capsaId, entry);
    }


    /** @return current public key info, or null if not set */
    public CompletableFuture<PublicKeyInfo> getCurrentPublicKeyAsync() {
        return accountService.getCurrentPublicKeyAsync();
    }

    /**
     * Add new public key (auto-rotates: moves current to history).
     *
     * @param publicKey   PEM-encoded public key
     * @param fingerprint SHA-256 fingerprint
     * @param reason      optional rotation reason
     */
    public CompletableFuture<PublicKeyInfo> addPublicKeyAsync(String publicKey, String fingerprint, String reason) {
        return accountService.addPublicKeyAsync(publicKey, fingerprint, reason);
    }

    /** @return keys this party rotated away from, newest first (the current key is not included) */
    public CompletableFuture<KeyHistoryEntry[]> getKeyHistoryAsync() {
        return accountService.getKeyHistoryAsync();
    }

    /**
     * Generate a new key pair, register it, and switch to it, keeping the old key as a previous key.
     *
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync() {
        return rotateKeyAsync(null);
    }

    /**
     * Rotate keys, handing the new key pair to the caller to store before it is registered.
     *
     * @param onKeyPairGenerated receives the new key pair before the request; if it throws, nothing is sent
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync(Consumer<GeneratedKeyPairResult> onKeyPairGenerated) {
        return rotateKeyAsync(onKeyPairGenerated, null);
    }

    /**
     * Rotate keys with a reason recorded in key history.
     *
     * @param onKeyPairGenerated receives the new key pair before the request, may be null
     * @param reason             rotation reason, may be null
     * @return new key pair and updated server info
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync(Consumer<GeneratedKeyPairResult> onKeyPairGenerated,
            String reason) {
        return accountService.rotateKeyAsync(onKeyPairGenerated, reason).thenApply(result -> {
            String oldPrivateKey = creatorPrivateKey;
            creatorPrivateKey = result.getKeyPair().getPrivateKey();
            if (oldPrivateKey != null && !oldPrivateKey.equals(creatorPrivateKey)) {
                previousPrivateKeys.addIfAbsent(oldPrivateKey);
            }
            capsaCache.clearAll();
            return result;
        });
    }


    public CompletableFuture<SystemLimits> getLimitsAsync() {
        return limitsService.getLimitsAsync();
    }

    public static GeneratedKeyPairResult generateKeyPair() {
        return KeyGenerator.generateKeyPair();
    }

    public static CompletableFuture<GeneratedKeyPairResult> generateKeyPairAsync() {
        return KeyGenerator.generateKeyPairAsync();
    }

    /** Securely clear all cached master keys. */
    public void clearCache() {
        capsaCache.clearAll();
        limitsService.clearCache();
    }

    /** Log out (blocking, errors ignored), clear tokens and keys, and release resources. */
    @Override
    public void close() {
        if (disposed) {
            return;
        }
        disposed = true;
        capsaCache.clearAll();
        inFlightCapsaFetches.clear();
        creatorId = null;
        creatorPrivateKey = null;
        previousPrivateKeys.clear();
        try {
            authService.logoutAsync().join();
        } catch (RuntimeException ignored) {
        }
        authService.clearTokens();
        capsaCache.close();
        concurrencyConfig.shutdown();
    }
}
