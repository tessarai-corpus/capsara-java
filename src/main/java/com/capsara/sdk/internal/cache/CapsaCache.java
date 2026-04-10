package com.capsara.sdk.internal.cache;

import com.capsara.sdk.internal.crypto.SecureMemory;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory cache for decrypted capsa master keys and file metadata.
 * Master keys stored in memory only; securely zeroed on eviction, close, or TTL expiry.
 */
public final class CapsaCache implements AutoCloseable {

    public static final int DEFAULT_MAX_SIZE = 100;
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    private final Map<String, CapsaCacheEntry> cache = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    private final Duration ttl;
    private final int maxSize;
    private volatile boolean disposed;

    public CapsaCache() {
        this(DEFAULT_TTL, DEFAULT_MAX_SIZE);
    }

    public CapsaCache(Duration ttl) {
        this(ttl, DEFAULT_MAX_SIZE);
    }

    public CapsaCache(Duration ttl, int maxSize) {
        this.ttl = ttl != null ? ttl : DEFAULT_TTL;
        this.maxSize = maxSize > 0 ? maxSize : DEFAULT_MAX_SIZE;
    }

    /**
     * Store a decrypted capsa in the cache.
     *
     * @param capsaId   capsa ID
     * @param masterKey master key bytes (will be copied)
     * @param files     file metadata array
     */
    public void set(String capsaId, byte[] masterKey, CachedFileMetadata[] files) {
        throwIfDisposed();

        synchronized (lock) {
            CapsaCacheEntry existing = cache.get(capsaId);
            if (existing != null) {
                existing.dispose();
                cache.remove(capsaId);
            }

            while (cache.size() >= maxSize) {
                evictOldest();
            }

            Map<String, CachedFileMetadata> fileMap = new HashMap<>();
            if (files != null) {
                for (CachedFileMetadata file : files) {
                    fileMap.put(file.getFileId(), file);
                }
            }

            byte[] keyCopy = new byte[masterKey.length];
            System.arraycopy(masterKey, 0, keyCopy, 0, masterKey.length);

            CapsaCacheEntry entry = new CapsaCacheEntry(keyCopy);
            entry.setFiles(fileMap);
            entry.setCachedAt(Instant.now());

            cache.put(capsaId, entry);
        }
    }

    /**
     * Get the master key for a cached capsa.
     *
     * @param capsaId capsa ID
     * @return copy of master key bytes or null if not cached/expired
     */
    public byte[] getMasterKey(String capsaId) {
        throwIfDisposed();

        synchronized (lock) {
            CapsaCacheEntry entry = cache.get(capsaId);
            if (entry == null) {
                return null;
            }

            if (isExpired(entry)) {
                entry.dispose();
                cache.remove(capsaId);
                return null;
            }

            return entry.getMasterKey();
        }
    }

    /**
     * Get file metadata for a specific file.
     *
     * @param capsaId capsa ID
     * @param fileId  file ID
     * @return file metadata or null if not cached/expired
     */
    public CachedFileMetadata getFileMetadata(String capsaId, String fileId) {
        throwIfDisposed();

        synchronized (lock) {
            CapsaCacheEntry entry = cache.get(capsaId);
            if (entry == null) {
                return null;
            }

            if (isExpired(entry)) {
                entry.dispose();
                cache.remove(capsaId);
                return null;
            }

            return entry.getFiles().get(fileId);
        }
    }

    /**
     * Clear a specific capsa from the cache, securely wiping the master key.
     *
     * @param capsaId capsa ID to clear
     */
    public void clear(String capsaId) {
        synchronized (lock) {
            CapsaCacheEntry entry = cache.get(capsaId);
            if (entry != null) {
                entry.dispose();
                cache.remove(capsaId);
            }
        }
    }

    /**
     * Clear all entries from the cache, securely wiping all master keys.
     */
    public void clearAll() {
        synchronized (lock) {
            for (CapsaCacheEntry entry : cache.values()) {
                entry.dispose();
            }
            cache.clear();
        }
    }

    /** Returns the number of entries currently in the cache. */
    public int size() {
        synchronized (lock) {
            return cache.size();
        }
    }

    /** Removes all expired entries from the cache. */
    public void prune() {
        synchronized (lock) {
            cache.entrySet().removeIf(e -> {
                if (isExpired(e.getValue())) {
                    e.getValue().dispose();
                    return true;
                }
                return false;
            });
        }
    }

    private void evictOldest() {
        String oldestKey = null;
        Instant oldestTime = Instant.MAX;

        for (Map.Entry<String, CapsaCacheEntry> e : cache.entrySet()) {
            if (e.getValue().getCachedAt().isBefore(oldestTime)) {
                oldestTime = e.getValue().getCachedAt();
                oldestKey = e.getKey();
            }
        }

        if (oldestKey != null) {
            CapsaCacheEntry entry = cache.get(oldestKey);
            if (entry != null) {
                entry.dispose();
                cache.remove(oldestKey);
            }
        }
    }

    private boolean isExpired(CapsaCacheEntry entry) {
        return Instant.now().isAfter(entry.getCachedAt().plus(ttl));
    }

    private void throwIfDisposed() {
        if (disposed) {
            throw new IllegalStateException("CapsaCache has been disposed");
        }
    }

    @Override
    public void close() {
        if (!disposed) {
            disposed = true;
            clearAll();
        }
    }

    private static final class CapsaCacheEntry {
        private byte[] masterKey;
        private Map<String, CachedFileMetadata> files = new HashMap<>();
        private Instant cachedAt;
        private boolean disposed;

        CapsaCacheEntry(byte[] masterKey) {
            this.masterKey = masterKey;
        }

        byte[] getMasterKey() {
            if (disposed) {
                throw new IllegalStateException("CapsaCacheEntry has been disposed");
            }
            byte[] copy = new byte[masterKey.length];
            System.arraycopy(masterKey, 0, copy, 0, masterKey.length);
            return copy;
        }

        Map<String, CachedFileMetadata> getFiles() {
            return files;
        }

        void setFiles(Map<String, CachedFileMetadata> files) {
            this.files = files;
        }

        Instant getCachedAt() {
            return cachedAt;
        }

        void setCachedAt(Instant cachedAt) {
            this.cachedAt = cachedAt;
        }

        void dispose() {
            if (!disposed) {
                disposed = true;
                SecureMemory.clear(masterKey);
                masterKey = new byte[0];
            }
        }
    }
}
