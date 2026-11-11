# Capsara SDK - Java

A **capsa** is a zero-knowledge encrypted envelope for securely exchanging files and data between multiple parties. Each capsa is sealed with its own encryption key and can only be opened by the parties explicitly authorized to access it. Capsara never sees your content, your keys, or your metadata.

## Features

- **AES-256-GCM** encryption with unique keys per capsa
- **RSA-4096-OAEP** key encryption for multi-party access
- **Compression** with gzip before encryption
- **Digital signatures** using RSA-SHA256 for sender authenticity
- **Encrypted subject, body, and structured data**
- **Batch sending** with automatic chunking

## Requirements

- Java 11 or later

## Installation

### Maven

```xml
<dependency>
  <groupId>com.capsara</groupId>
  <artifactId>capsara-sdk</artifactId>
  <version>2.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.capsara:capsara-sdk:2.0.0'
```

## Initialize the Client

```java
import com.capsara.sdk.CapsaraClient;

CapsaraClient client = new CapsaraClient("https://capsara-env-api-url.com");
```

## Authentication

Authentication requires two steps: login with your credentials, then set your private key for cryptographic operations.

### Login

```java
import com.capsara.sdk.models.AuthCredentials;

client.loginAsync(new AuthCredentials("party_YourPartyId0000000000", "...")).join();
```

### Set Private Key

After logging in, set your private key for signing and decryption. Generate and register your keypair using `CapsaraClient.generateKeyPair()` and `addPublicKeyAsync()`, then store the private key securely.

```java
// Your code to load the private key from secure storage (key vault, HSM, etc.)
String privateKey = loadPrivateKeyFromSecureStorage();

client.setPrivateKey(privateKey);
```

## Sending Capsas

Use the `CapsaBuilder` to create capsas with recipients and files. Always use `sendCapsasAsync()` even for a single capsa since it handles encryption and batching efficiently.

Every client call returns a `CompletableFuture`. `join()` wraps a failure in a `CompletionException`, so catch that and read the `CapsaraException` from its cause (see [Error Handling](#error-handling)).

```java
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.exceptions.CapsaraException;
import com.capsara.sdk.models.FileInput;
import com.capsara.sdk.models.SendResult;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CompletionException;

try {
    // Create a builder for each capsa you want to send
    CapsaBuilder builder = client.createCapsaBuilderAsync().join();

    // Add the recipient (one per capsa; their delegates are added automatically)
    builder.addRecipient("party_recipient1");

    // Add files from path or bytes
    builder.addFile(FileInput.fromPath("./documents/policy.pdf"));
    builder.addFile(FileInput.fromData(
        "Policy data here".getBytes(StandardCharsets.UTF_8),
        "policy-data.txt"
    ));

    // Add optional metadata
    builder.withSubject("Policy Documents - Q1 2025");
    builder.withBody("Please review the attached policy documents.");
    builder.withStructured(Map.of(
        "policyNumber", "POL-12345",
        "effectiveDate", "2025-01-01"
    ));

    // Set expiration
    builder.withExpiration(OffsetDateTime.now(ZoneOffset.UTC).plusDays(90));

    // Send
    SendResult result = client.sendCapsasAsync(new CapsaBuilder[]{builder}).join();
    System.out.printf("Sent %d capsa(s)%n", result.getSuccessful());

    if (result.getFailed() > 0) {
        for (SendResult.SendError error : result.getErrors()) {
            System.err.printf("Capsa %d failed: %s %s%n", error.getIndex(), error.getCode(), error.getMessage());
        }
    }
} catch (CompletionException e) {
    if (!(e.getCause() instanceof CapsaraException)) {
        throw e;
    }
    CapsaraException error = (CapsaraException) e.getCause();
    // getCode() is the server's error code, e.g. ENVELOPE_NOT_FOUND or RATE_LIMIT_EXCEEDED
    System.err.println("Failed to send: " + error.getCode() + " " + error.getMessage());
}
```

A **capsa** maps one-to-one with a *matter*, which is a unique combination of sender, recipient, client, and action. You can send multiple capsas in one call:

```java
CapsaBuilder matter1 = client.createCapsaBuilderAsync().join();
matter1
    .addRecipient("party_org_b")
    .withSubject("Client 1 - New Home Policy")
    .addFile(FileInput.fromPath("./policy.pdf"));

CapsaBuilder matter2 = client.createCapsaBuilderAsync().join();
matter2
    .addRecipient("party_org_b")
    .withSubject("Client 1 - Auto Endorsement")
    .withBody("Endorsement effective 3/1. No documents required.");

client.sendCapsasAsync(new CapsaBuilder[]{matter1, matter2}).join();
```

Each capsa goes to exactly one recipient, its principal. Multi-party access comes through that recipient's delegates, which the SDK adds automatically, each with its own encrypted key and acting for the recipient. A second `addRecipient()` on the same builder throws, and a builder with no recipient is rejected before anything is sent. To send to yourself, pass your own party ID; your delegates are then included. To reach several recipients, create one builder per recipient and send them together in one batch:

```java
import java.util.ArrayList;
import java.util.List;

List<CapsaBuilder> builders = new ArrayList<>();
for (String recipient : List.of("party_recipient1", "party_recipient2")) {
    CapsaBuilder builder = client.createCapsaBuilderAsync().join();
    builder.addRecipient(recipient)
        .withSubject("Policy Documents - Q1 2025")
        .addFile(FileInput.fromPath("./documents/policy.pdf"))
        .withExpiration(OffsetDateTime.now(ZoneOffset.UTC).plusDays(90));
    builders.add(builder);
}

SendResult result = client.sendCapsasAsync(builders.toArray(new CapsaBuilder[0])).join();
if (result.getErrors() != null) {
    for (SendResult.SendError error : result.getErrors()) {
        // getCode() is the reason the capsa was rejected, e.g. DELEGATE_PRINCIPAL_MISMATCH
        System.err.printf("Capsa %d failed: %s (%s)%n", error.getIndex(), error.getMessage(), error.getCode());
    }
}
```

The SDK automatically splits large batches to stay within server limits. Call `getLimitsAsync()` to read the current limits.

## Receiving Capsas

### List Capsas

```java
import com.capsara.sdk.models.CapsaListFilters;
import com.capsara.sdk.models.CapsaListResponse;
import com.capsara.sdk.models.CapsaStatus;
import com.capsara.sdk.models.CapsaSummary;

CapsaListFilters filters = new CapsaListFilters();
filters.setStatus(CapsaStatus.ACTIVE);
filters.setLimit(50);

CapsaListResponse response = client.listCapsasAsync(filters).join();

System.out.printf("Found %d capsas%n", response.getCapsas().length);

for (CapsaSummary capsa : response.getCapsas()) {
    System.out.printf("- %s (%s)%n", capsa.getId(), capsa.getStatus());
    System.out.printf("  Created: %s%n", capsa.getCreatedAt());
    System.out.printf("  From: %s%n", capsa.getCreator());
}

// Pagination
if (response.getPagination().isHasMore()) {
    CapsaListFilters next = new CapsaListFilters();
    next.setAfter(response.getPagination().getNextCursor());
    CapsaListResponse nextPage = client.listCapsasAsync(next).join();
}
```

### Get Capsa and Download Files

A file's `getFilename()` comes from the sender and is untrusted, so write each file under a directory you choose using `getSafeFilename()`, which is always a single, safe path segment (see `DecryptedFileResult.sanitizeFilename` for the rules). The decrypted capsa holds its master key until it is closed, so open it in a try-with-resources block:

```java
import com.capsara.sdk.models.DecryptedCapsa;
import com.capsara.sdk.models.DecryptedFileResult;
import com.capsara.sdk.models.EncryptedFile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

static void downloadAll(CapsaraClient client) throws IOException {
    Path downloadDir = Path.of("downloads");

    try (DecryptedCapsa capsa = client.getDecryptedCapsaAsync("capsa_abc-123").join()) {
        System.out.println("Subject: " + capsa.getSubject());
        System.out.println("Body: " + capsa.getBody());
        System.out.println("Structured data: " + capsa.getStructured());

        // Download each file
        for (EncryptedFile file : capsa.getFiles()) {
            DecryptedFileResult result = client.downloadFileAsync(
                capsa.getId(), file.getFileId()
            ).join();
            Files.write(downloadDir.resolve(result.getSafeFilename()), result.getData());
        }
    }
}
```

## Delegation

Capsara supports delegation for scenarios where a system acts on behalf of a party. For example, an agency management system (AMS) might process capsas on behalf of the agencies it serves. When a capsa is sent to a delegated recipient, the delegate receives its own RSA-encrypted copy of the master key. If the recipient also has a public key registered in the system, they receive their own encrypted copy as well. Otherwise, only the delegate can decrypt on their behalf.

If you're a delegate, the flow is identical to receiving. To see which party a capsa belongs to, find your own entry in the capsa's keychain: its `getActingFor()` lists the party IDs you act for on that capsa. This lets you route the data to the correct recipient in your system.

```java
import com.capsara.sdk.models.AuthResponse;
import com.capsara.sdk.models.KeychainEntry;

// Authenticate as the delegate (e.g., an AMS)
CapsaraClient client = new CapsaraClient("https://capsara-env-api-url.com");
AuthResponse auth = client.loginAsync(new AuthCredentials("party_AmsPartyId00000000000", "...")).join();
client.setPrivateKey(loadPrivateKeyFromSecureStorage());
String myPartyId = auth.getParty().getId();

// List capsas (includes capsas for all parties you represent)
CapsaListResponse response = client.listCapsasAsync(null).join();

for (CapsaSummary summary : response.getCapsas()) {
    try (DecryptedCapsa capsa = client.getDecryptedCapsaAsync(summary.getId()).join()) {
        // Check who this capsa is for
        String agencyId = null;
        for (KeychainEntry entry : capsa.getKeychain().getKeys()) {
            if (myPartyId.equals(entry.getParty()) && entry.getActingFor() != null
                    && entry.getActingFor().length > 0) {
                agencyId = entry.getActingFor()[0];
            }
        }
        if (agencyId != null) {
            System.out.printf("Capsa %s is for agency %s%n", summary.getId(), agencyId);
            routeToAgency(agencyId, capsa);
        }

        // Download and process files
        for (EncryptedFile file : capsa.getFiles()) {
            DecryptedFileResult result = client.downloadFileAsync(
                summary.getId(), file.getFileId()
            ).join();
            processFile(agencyId, result.getSafeFilename(), result.getData());
        }
    }
}
```

## Error Handling

Every SDK error is a `CapsaraException` (an unchecked exception in `com.capsara.sdk.exceptions`). The subclasses `CapsaraAuthException`, `CapsaraCapsaException`, `CapsaraAuditException` and `CapsaraAccountException` tell you which area failed. A failed future surfaces it as the cause of the `CompletionException` thrown by `join()`, so unwrap it:

```java
import com.capsara.sdk.exceptions.CapsaraAuthException;
import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.exceptions.CapsaraException;
import java.util.concurrent.CompletionException;

try (DecryptedCapsa capsa = client.getDecryptedCapsaAsync("capsa_abc-123").join()) {
    System.out.println("Subject: " + capsa.getSubject());
} catch (CompletionException e) {
    Throwable cause = e.getCause();
    if (cause instanceof CapsaraAuthException) {
        System.err.println("Auth error: " + cause.getMessage() + " (" + ((CapsaraException) cause).getCode() + ")");
    } else if (cause instanceof CapsaraCapsaException) {
        System.err.println("Capsa error: " + cause.getMessage() + " (" + ((CapsaraException) cause).getCode() + ")");
    } else if (cause instanceof CapsaraException) {
        System.err.println("Error: " + cause.getMessage() + " (" + ((CapsaraException) cause).getCode() + ")");
    } else {
        throw e;
    }
}
```

Every `CapsaraException` exposes:

- `getCode()`: the API error code exactly as the server sent it (e.g. `ENVELOPE_NOT_FOUND`, `RATE_LIMIT_EXCEEDED`), or an SDK code for client-side failures. A response without a usable error body gets `HTTP_<status>`.
- `getStatusCode()`: the HTTP status (0 for client-side failures).
- `getDetails()`: the server's details as sent, when provided.
- `getRetryAfter()`: seconds to wait on 429/503, when provided.
- `getRequestId()`: the server request ID, when provided.

Expired and deleted capsas fail with `CapsaraCapsaException` status 410 and code `ENVELOPE_EXPIRED` or `ENVELOPE_DELETED`. Signature problems fail before decryption with `SIGNATURE_KEY_MISSING`, `SIGNATURE_KEY_MISMATCH` or `SIGNATURE_VERIFICATION_FAILED`. A capsa encrypted to a key you have not configured fails with `PRIVATE_KEY_NOT_AVAILABLE`.

## Encryption

Every capsa is protected by its own AES-256-GCM key (the "master key"), generated in the SDK at send time. Files, filenames, and the subject, body and structured data are each encrypted with the master key under a fresh random IV, so any change to the ciphertext is detected on decryption. Files are gzip-compressed before encryption by default. The master key is then encrypted for the sender, the recipient and each of the recipient's delegates with their RSA-4096 public key using OAEP with SHA-256, so only the holder of a matching private key can recover it. The sender signs the capsa with RS256 (RSA-SHA256 in JWS format) over a canonical string that binds the capsa ID, its total size, the key-encryption algorithm, the sender's party ID, the fingerprint of the sender's public key, the SHA-256 hash of each encrypted file, every file and filename IV, and the IVs of the subject, body and structured data. The server checks this signature at upload. On receive, the SDK checks the sender's public key against the sender's keychain fingerprint, rebuilds the canonical string from the capsa it received, and verifies the signature before decrypting anything, so a signature cannot be moved to another capsa or key. Key fingerprints are lowercase hex SHA-256 hashes of the DER-encoded SubjectPublicKeyInfo, so PEM formatting does not change them. All encryption, decryption, signing, and verification happen locally in the SDK. Capsara's servers only ever store ciphertext and cannot read your files, your metadata, or your keys.

## Private Key Security

Your private key is the sole point of access to every capsa encrypted for you. Capsara uses zero-knowledge encryption: your private key never leaves your environment, is never transmitted to Capsara's servers, and is never stored by Capsara. There is no recovery mechanism, no master backdoor, and no support override. If your private key is lost, every capsa encrypted for your party becomes permanently inaccessible. No one (not Capsara, not the sender, not an administrator) can recover your data without your private key.

You are fully responsible for your private key's lifecycle: generation, secure storage, and backup. Store it in a cloud key vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), a hardware security module, or at minimum an encrypted secrets manager. Never store it in source code, configuration files, or logs. Back it up to a secondary secure location so that a single infrastructure failure does not result in permanent data loss.

The SDK provides a `rotateKeyAsync(onKeyPairGenerated)` method that generates a new RSA-4096 key pair, passes it to your callback so you can store the private key before anything is sent, and then registers the new public key with Capsara. If the callback throws, nothing is registered. After a successful rotation the client uses the new private key and keeps the old one as a previous key. New capsas sent to you will be encrypted with your new key. However, capsas are immutable once created and their keychain and encrypted contents never change. Existing capsas remain accessible only with the private key that was active when they were created. Keep prior private keys available for as long as you need access to capsas encrypted under them, and give them to the client with `addPreviousPrivateKey(privateKey)` (or `CapsaraClientOptions.setPreviousPrivateKeys`). The SDK picks the key whose fingerprint matches your keychain entry; if none matches it throws `PRIVATE_KEY_NOT_AVAILABLE`.

## API Reference

| Method | Description |
|--------|-------------|
| `CapsaraClient.generateKeyPair()` | Generate an RSA-4096 key pair (static; `generateKeyPairAsync()` runs it off the calling thread) |
| `loginAsync(credentials)` | Authenticate with party ID and password |
| `logoutAsync()` | Clear tokens and cached data, then revoke the session (fails if the server does not confirm) |
| `isAuthenticated()` | Check whether the client has an access token |
| `setPrivateKey(privateKey)` | Set the private key for signing and decryption |
| `addPreviousPrivateKey(privateKey)` | Keep a rotated-out private key for older capsas |
| `createCapsaBuilderAsync()` | Create a `CapsaBuilder` pre-loaded with server limits |
| `sendCapsasAsync(builders)` | Encrypt and send one or more capsas |
| `getDecryptedCapsaAsync(capsaId)` | Fetch, verify and decrypt a capsa |
| `getCapsaAsync(capsaId)` | Fetch a capsa without decryption |
| `listCapsasAsync(filters)` | List capsas; `filters` may be `null` |
| `deleteCapsaAsync(capsaId)` | Soft-delete a capsa |
| `downloadFileAsync(capsaId, fileId)` | Download and decrypt a file |
| `getAuditEntriesAsync(capsaId, filters)` | Get audit trail entries; `filters` may be `null` |
| `createAuditEntryAsync(capsaId, entry)` | Add an audit entry (`log` or `processed`) |
| `getCurrentPublicKeyAsync()` | Get your current registered public key |
| `addPublicKeyAsync(key, fp, reason)` | Register a new public key |
| `rotateKeyAsync(onKeyPairGenerated)` | Generate a key pair, hand it to the callback to store, register it, then switch to it |
| `getKeyHistoryAsync()` | Get fingerprints of previous public keys |
| `getLimitsAsync()` | Get server-enforced limits |
| `clearCache()` | Clear cached master keys |
| `close()` | Release resources (`AutoCloseable`) |

## Support

Email support@tessarai.com.

## License

Capsara SDK License. See [LICENSE](./LICENSE) for details.

Copyright (c) 2024-2026 Tessarai, LLC and Laird Rixford. All rights reserved.
