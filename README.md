# Capsara SDK - Java

A **capsa** is a zero-knowledge encrypted envelope for securely exchanging files and data between multiple parties. Each capsa is sealed with its own encryption key and can only be opened by the parties explicitly authorized to access it. Capsara never sees your content, your keys, or your metadata.

## Features

- **AES-256-GCM** encryption with unique keys per capsa
- **RSA-4096-OAEP** key encryption for multi-party access
- **Compression** with gzip before encryption
- **Digital signatures** using RSA-SHA256 for sender authenticity
- **Encrypted subject, body, and structured data**
- **Batch sending** with automatic chunking

## Installation

### Maven

```xml
<dependency>
  <groupId>com.capsara</groupId>
  <artifactId>capsara-sdk</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.capsara:capsara-sdk:1.0.0'
```

## Initialize the Client

```java
import com.capsara.sdk.CapsaraClient;

CapsaraClient client = new CapsaraClient("https://your-api-url.com");
```

## Authentication

Authentication requires two steps: login with your credentials, then set your private key for cryptographic operations.

### Login

```java
import com.capsara.sdk.models.AuthCredentials;

client.loginAsync(new AuthCredentials("you@example.com", "...")).join();
```

### Set Private Key

After logging in, set your private key for signing and decryption. Generate and register your keypair using `generateKeyPair()` and `addPublicKeyAsync()`, then store the private key securely.

```java
// Your code to load the private key from secure storage (key vault, HSM, etc.)
String privateKey = loadPrivateKeyFromSecureStorage();

client.setPrivateKey(privateKey);
```

## Sending Capsas

Use the `CapsaBuilder` to create capsas with recipients and files. Always use `sendCapsasAsync()` even for a single capsa since it handles encryption and batching efficiently.

```java
import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.models.*;

try {
    // Create a builder for each capsa you want to send
    CapsaBuilder builder = client.createCapsaBuilderAsync().join();

    // Add recipients (can add multiple)
    builder.addRecipient("party_recipient1");
    builder.addRecipient("party_recipient2");

    // Add files from path or buffer
    builder.addFile(FileInput.fromPath("./documents/policy.pdf"));
    builder.addFile(FileInput.fromBuffer(
        "Policy data here".getBytes(),
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
    builder.withExpiration(Instant.now().plus(90, ChronoUnit.DAYS));

    // Send
    SendResult result = client.sendCapsasAsync(new CapsaBuilder[]{builder}).join();
    System.out.printf("Sent %d capsa(s)%n", result.getSuccessful());

    if (result.getFailed() > 0) {
        System.err.printf("%d capsas failed to send%n", result.getFailed());
    }
} catch (CapsaraException e) {
    System.err.println("Failed to send: " + e.getMessage());
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

The SDK automatically splits large batches to stay within server limits.

## Receiving Capsas

### List Capsas

```java
CapsaListResponse response = client.listCapsasAsync(
    new CapsaListFilters().status("active").limit(50)
).join();

System.out.printf("Found %d capsas%n", response.getCapsas().size());

for (CapsaSummary capsa : response.getCapsas()) {
    System.out.printf("- %s: %d files%n", capsa.getId(), capsa.getFileCount());
    System.out.printf("  Created: %s%n", capsa.getCreatedAt());
    System.out.printf("  From: %s%n", capsa.getCreatorId());
}

// Pagination
if (response.getPagination().isHasMore()) {
    CapsaListResponse nextPage = client.listCapsasAsync(
        new CapsaListFilters().after(response.getPagination().getNextCursor())
    ).join();
}
```

### Get Capsa and Download Files

```java
import java.nio.file.Files;
import java.nio.file.Path;

DecryptedCapsa capsa = client.getDecryptedCapsaAsync("capsa_abc-123").join();

System.out.println("Subject: " + capsa.getSubject());
System.out.println("Body: " + capsa.getBody());
System.out.println("Structured data: " + capsa.getStructured());

// Download each file
for (FileInfo file : capsa.getFiles()) {
    DecryptedFileResult result = client.downloadFileAsync(
        capsa.getPackageId(), file.getId()
    ).join();
    Files.write(Path.of("./downloads/" + result.getFilename()), result.getData());
}
```

## Delegation

Capsara supports delegation for scenarios where a system acts on behalf of a party. For example, an agency management system (AMS) might process capsas on behalf of the agencies it serves. When a capsa is sent to a delegated recipient, the delegate receives its own RSA-encrypted copy of the master key. If the recipient also has a public key registered in the system, they receive their own encrypted copy as well. Otherwise, only the delegate can decrypt on their behalf.

If you're a delegate, the flow is identical to receiving. List your capsas and check the `actingFor` field on each one to see which party it belongs to. This lets you route the data to the correct recipient in your system.

```java
// Authenticate as the delegate (e.g., an AMS)
CapsaraClient client = new CapsaraClient("https://your-api-url.com");
client.loginAsync(new AuthCredentials("ams@example.com", "...")).join();
client.setPrivateKey(loadPrivateKeyFromSecureStorage());

// List capsas (includes capsas for all parties you represent)
CapsaListResponse response = client.listCapsasAsync(null).join();

for (CapsaSummary summary : response.getCapsas()) {
    DecryptedCapsa capsa = client.getDecryptedCapsaAsync(summary.getId()).join();

    // Check who this capsa is for
    if (capsa.getActingFor() != null) {
        System.out.printf("Capsa %s is for agency %s%n",
            summary.getId(), capsa.getActingFor());
        routeToAgency(capsa.getActingFor(), capsa);
    }

    // Download and process files
    for (FileInfo file : capsa.getFiles()) {
        DecryptedFileResult result = client.downloadFileAsync(
            summary.getId(), file.getId()
        ).join();
        processFile(capsa.getActingFor(), result.getFilename(), result.getData());
    }
}
```

## Encryption

Every capsa is protected by a unique AES-256-GCM symmetric key (the "master key") generated at send time. Files and metadata (subject, body, and structured data) are each encrypted with this master key using a fresh random IV, producing authenticated ciphertext that guarantees both confidentiality and tamper detection. The master key itself is then encrypted once per authorized party and any authorized delegates using their RSA-4096 public key with OAEP-SHA256 padding, so only the holder of the corresponding private key can recover it. Each file is independently hashed with SHA-256 before encryption, and these hashes along with all IVs are bound into a canonical string that the sender signs using RS256 (RSA-SHA256 in JWS format). Recipients and the server validate this signature against the sender's public key before trusting any content, ensuring both authenticity and integrity of the entire capsa. Key fingerprints are SHA-256 hashes of the public key PEM, providing a compact identifier for key verification. Files are gzip-compressed before encryption by default to reduce storage and transfer costs. All encryption, decryption, signing, and verification happen locally in the SDK. Capsara's servers only ever store ciphertext and cannot read your files, your metadata, or your keys.

## Private Key Security

Your private key is the sole point of access to every capsa encrypted for you. Capsara uses zero-knowledge encryption: your private key never leaves your environment, is never transmitted to Capsara's servers, and is never stored by Capsara. There is no recovery mechanism, no master backdoor, and no support override. If your private key is lost, every capsa encrypted for your party becomes permanently inaccessible. No one (not Capsara, not the sender, not an administrator) can recover your data without your private key.

You are fully responsible for your private key's lifecycle: generation, secure storage, and backup. Store it in a cloud key vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), a hardware security module, or at minimum an encrypted secrets manager. Never store it in source code, configuration files, or logs. Back it up to a secondary secure location so that a single infrastructure failure does not result in permanent data loss.

The SDK provides a `rotateKeyAsync()` method that generates a new RSA-4096 key pair and registers the new public key with Capsara. New capsas sent to you will be encrypted with your new key. However, capsas are immutable once created and their keychain and encrypted contents never change. Existing capsas remain accessible only with the private key that was active when they were created. Keep prior private keys available for as long as you need access to capsas encrypted under them.

## API Reference

| Method | Description |
|--------|-------------|
| `CapsaraClient.generateKeyPair()` | Generate an RSA-4096 key pair (static) |
| `loginAsync(credentials)` | Authenticate with email and password |
| `logoutAsync()` | Log out and clear cached data |
| `setPrivateKey(privateKey)` | Set the private key for signing and decryption |
| `createCapsaBuilderAsync()` | Create a `CapsaBuilder` pre-loaded with server limits |
| `sendCapsasAsync(builders)` | Encrypt and send one or more capsas |
| `getDecryptedCapsaAsync(capsaId)` | Fetch and decrypt a capsa |
| `getCapsaAsync(capsaId)` | Fetch a capsa without decryption |
| `listCapsasAsync(filters)` | List capsas with optional filters |
| `deleteCapsaAsync(capsaId)` | Soft-delete a capsa |
| `downloadFileAsync(capsaId, fileId)` | Download and decrypt a file |
| `getAuditEntriesAsync(capsaId)` | Get audit trail entries |
| `addPublicKeyAsync(key, fp, reason)` | Register a new public key |
| `rotateKeyAsync()` | Generate and register a new key pair |
| `getKeyHistoryAsync()` | Get previous public keys |
| `getLimitsAsync()` | Get server-enforced limits |
| `close()` | Release resources (`AutoCloseable`) |

## License

Capsara SDK License. See [LICENSE](./LICENSE) for details.
