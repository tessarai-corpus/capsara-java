package com.capsara.sdk;

import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.internal.cache.CachedFileMetadata;
import com.capsara.sdk.internal.cache.CapsaCache;
import com.capsara.sdk.internal.crypto.KeyGenerator;
import com.capsara.sdk.internal.crypto.SecureMemory;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.internal.decryptor.DecryptedCapsa;
import com.capsara.sdk.internal.http.ConcurrencyConfig;
import com.capsara.sdk.internal.http.HttpClientFactory;
import com.capsara.sdk.internal.http.HttpTimeoutConfig;
import com.capsara.sdk.internal.http.RetryConfig;
import com.capsara.sdk.internal.services.AccountService;
import com.capsara.sdk.internal.services.AuditService;
import com.capsara.sdk.internal.services.AuthService;
import com.capsara.sdk.internal.services.CapsaService;
import com.capsara.sdk.internal.services.DownloadService;
import com.capsara.sdk.internal.services.KeyService;
import com.capsara.sdk.internal.services.LimitsService;
import com.capsara.sdk.internal.services.UploadService;
import com.capsara.sdk.internal.SdkVersion;
import com.capsara.sdk.models.AuthCredentials;
import com.capsara.sdk.models.AuthResponse;
import com.capsara.sdk.models.Capsa;
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CreateAuditEntryRequest;
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

        HttpTimeoutConfig timeout = this.options.getTimeout();
        this.apiHttpClient = HttpClientFactory.createForApi(timeout);
        this.blobHttpClient = HttpClientFactory.createForBlob(timeout);
        this.concurrencyConfig = new ConcurrencyConfig();

        RetryConfig retry = this.options.getRetry();
        String userAgent = buildUserAgent(this.options.getUserAgent());
        this.authService = new AuthService(baseUrl, timeout, retry, userAgent);
        this.keyService = new KeyService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, concurrencyConfig);
        this.capsaService = new CapsaService(apiHttpClient, baseUrl, authService::getToken, timeout, retry,
                userAgent, keyService, concurrencyConfig);
        this.downloadService = new DownloadService(apiHttpClient, blobHttpClient, baseUrl, authService::getToken,
                timeout, retry, userAgent, concurrencyConfig);
        this.uploadService = new UploadService(apiHttpClient, baseUrl, authService::getToken, keyService,
                this.options.getMaxBatchSize(), retry, timeout, userAgent, concurrencyConfig);
        this.auditService = new AuditService(apiHttpClient, baseUrl, authService::getToken, timeout, userAgent,
                concurrencyConfig);
        this.accountService = new AccountService(apiHttpClient, baseUrl, authService::getToken, timeout, userAgent,
                concurrencyConfig);
        this.limitsService = new LimitsService(apiHttpClient, baseUrl, authService::getToken, timeout, userAgent,
                concurrencyConfig);

        this.capsaCache = this.options.getCacheTTL() != null
                ? new CapsaCache(this.options.getCacheTTL())
                : new CapsaCache();

        if (this.options.getAccessToken() != null && !this.options.getAccessToken().isEmpty()) {
            authService.setToken(this.options.getAccessToken());
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

    /** @return true if logout succeeded */
    public CompletableFuture<Boolean> logoutAsync() {
        clearCache();
        return authService.logoutAsync();
    }

    /** @return true if access token is set */
    public boolean isAuthenticated() {
        return authService.isAuthenticated();
    }

    /**
     * @param privateKey RSA private key (PEM)
     */
    public void setPrivateKey(String privateKey) {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("privateKey cannot be null or empty");
        }
        this.creatorPrivateKey = privateKey;
    }


    /** @return new CapsaBuilder configured with current identity and server limits */
    public CompletableFuture<CapsaBuilder> createCapsaBuilderAsync() {
        if (creatorId == null || creatorPrivateKey == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Creator identity not set. "
                            + "Call loginAsync() and setPrivateKey() first."));
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
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Creator identity not set. "
                            + "Call loginAsync() and setPrivateKey() first."));
        }

        return uploadService.sendCapsasAsync(builders, creatorId);
    }

    /** Get capsa without decryption. */
    public CompletableFuture<Capsa> getCapsaAsync(String capsaId) {
        return capsaService.getCapsaAsync(capsaId);
    }

    public CompletableFuture<DecryptedCapsa> getDecryptedCapsaAsync(String capsaId) {
        return getDecryptedCapsaAsync(capsaId, true);
    }

    /**
     * Concurrent requests for the same capsaId are deduplicated.
     *
     * @param verifySignature whether to verify the creator's signature
     */
    public CompletableFuture<DecryptedCapsa> getDecryptedCapsaAsync(String capsaId, boolean verifySignature) {
        if (creatorPrivateKey == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Private key required. Call setPrivateKey() first."));
        }

        return inFlightCapsaFetches.computeIfAbsent(capsaId, id ->
                fetchAndDecryptCapsa(id, verifySignature)
                        .whenComplete((result, error) -> inFlightCapsaFetches.remove(id))
        );
    }

    private CompletableFuture<DecryptedCapsa> fetchAndDecryptCapsa(String capsaId, boolean verifySignature) {
        return capsaService.getCapsaAsync(capsaId)
                .thenCompose(capsa -> {
                    if (verifySignature) {
                        return capsaService.getCreatorPublicKeyAsync(capsa.getCreator())
                                .thenApply(creatorPublicKey -> {
                                    DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                                            capsa,
                                            creatorPrivateKey,
                                            null,
                                            creatorPublicKey,
                                            true);
                                    cacheDecryptedCapsa(capsaId, decrypted);
                                    return decrypted;
                                });
                    } else {
                        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                                capsa,
                                creatorPrivateKey,
                                null,
                                null,
                                false);
                        cacheDecryptedCapsa(capsaId, decrypted);
                        return CompletableFuture.completedFuture(decrypted);
                    }
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
        byte[] masterKey = capsaCache.getMasterKey(capsaId);
        CachedFileMetadata cachedFile = capsaCache.getFileMetadata(capsaId, fileId);

        if (masterKey == null || cachedFile == null) {
            return getDecryptedCapsaAsync(capsaId, true)
                    .thenCompose(decrypted -> downloadFileWithCache(capsaId, fileId));
        }

        return downloadFileWithCache(capsaId, fileId);
    }

    private CompletableFuture<DecryptedFileResult> downloadFileWithCache(String capsaId, String fileId) {
        byte[] masterKey = capsaCache.getMasterKey(capsaId);
        CachedFileMetadata cachedFile = capsaCache.getFileMetadata(capsaId, fileId);

        if (masterKey == null || cachedFile == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("File " + fileId + " not found in capsa " + capsaId));
        }

        return downloadService.downloadEncryptedFileAsync(capsaId, fileId)
                .thenApply(encryptedData -> {
                    try {
                        byte[] decryptedData = CapsaDecryptor.decryptFile(
                                encryptedData,
                                masterKey,
                                cachedFile.getIv(),
                                cachedFile.getAuthTag(),
                                cachedFile.isCompressed());

                        String filename = CapsaDecryptor.decryptFilename(
                                cachedFile.getEncryptedFilename(),
                                masterKey,
                                cachedFile.getFilenameIV(),
                                cachedFile.getFilenameAuthTag());

                        DecryptedFileResult result = new DecryptedFileResult();
                        result.setData(decryptedData);
                        result.setFilename(filename);
                        return result;
                    } finally {
                        // Securely clear the master key copy from cache
                        SecureMemory.clear(masterKey);
                    }
                });
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

    /** @return all historical keys including current */
    public CompletableFuture<KeyHistoryEntry[]> getKeyHistoryAsync() {
        return accountService.getKeyHistoryAsync();
    }

    /**
     * Generate new key pair and update on server.
     * IMPORTANT: Application must store the returned private key securely.
     */
    public CompletableFuture<KeyRotationResult> rotateKeyAsync() {
        return accountService.rotateKeyAsync();
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

    /** Release resources and securely clear cached keys. */
    @Override
    public void close() {
        if (!disposed) {
            capsaCache.close();
            concurrencyConfig.shutdown();
            creatorPrivateKey = null;
            creatorId = null;
            disposed = true;
        }
    }
}
