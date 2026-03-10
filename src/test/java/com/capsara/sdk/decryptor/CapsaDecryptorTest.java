package com.capsara.sdk.decryptor;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.internal.decryptor.DecryptedCapsa;
import com.capsara.sdk.models.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for CapsaDecryptor decryption utilities.
 */
class CapsaDecryptorTest {

    // decryptFile Tests

    @Test
    void decryptFile_withValidData_decryptsSuccessfully() {
        byte[] originalData = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(originalData, masterKey, iv);

        byte[] decrypted = CapsaDecryptor.decryptFile(
                encrypted.getCiphertext(),
                masterKey,
                Base64Url.encode(iv),
                Base64Url.encode(encrypted.getAuthTag()),
                false);

        assertThat(decrypted).isEqualTo(originalData);
    }

    @Test
    void decryptFile_withCompressedData_decompressesSuccessfully() {
        byte[] originalData = "Hello, World! This is some compressible text.".getBytes(StandardCharsets.UTF_8);
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();

        byte[] compressed = CompressionProvider.compress(originalData);
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(compressed, masterKey, iv);

        byte[] decrypted = CapsaDecryptor.decryptFile(
                encrypted.getCiphertext(),
                masterKey,
                Base64Url.encode(iv),
                Base64Url.encode(encrypted.getAuthTag()),
                true);

        assertThat(decrypted).isEqualTo(originalData);
    }

    @Test
    void decryptFile_withNullAuthTag_throwsSecurityError() {
        byte[] encryptedData = new byte[32];
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        String iv = Base64Url.encode(TestHelpers.generateTestIV());

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFile(encryptedData, masterKey, iv, null, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR")
                .hasMessageContaining("authTag is required");
    }

    @Test
    void decryptFile_withEmptyAuthTag_throwsSecurityError() {
        byte[] encryptedData = new byte[32];
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        String iv = Base64Url.encode(TestHelpers.generateTestIV());

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFile(encryptedData, masterKey, iv, "", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR");
    }

    @Test
    void decryptFile_withLargeFile_decryptsSuccessfully() {
        byte[] originalData = TestHelpers.randomBytes(1024 * 100); // 100KB
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(originalData, masterKey, iv);

        byte[] decrypted = CapsaDecryptor.decryptFile(
                encrypted.getCiphertext(),
                masterKey,
                Base64Url.encode(iv),
                Base64Url.encode(encrypted.getAuthTag()),
                false);

        assertThat(decrypted).isEqualTo(originalData);
    }

    // decryptFilename Tests

    @Test
    void decryptFilename_withValidData_decryptsSuccessfully() {
        String originalFilename = "document.pdf";
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                originalFilename.getBytes(StandardCharsets.UTF_8), masterKey, iv);

        String decrypted = CapsaDecryptor.decryptFilename(
                Base64Url.encode(encrypted.getCiphertext()),
                masterKey,
                Base64Url.encode(iv),
                Base64Url.encode(encrypted.getAuthTag()));

        assertThat(decrypted).isEqualTo(originalFilename);
    }

    @Test
    void decryptFilename_withUnicodeFilename_decryptsSuccessfully() {
        String originalFilename = "文档-档案.pdf";
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();

        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                originalFilename.getBytes(StandardCharsets.UTF_8), masterKey, iv);

        String decrypted = CapsaDecryptor.decryptFilename(
                Base64Url.encode(encrypted.getCiphertext()),
                masterKey,
                Base64Url.encode(iv),
                Base64Url.encode(encrypted.getAuthTag()));

        assertThat(decrypted).isEqualTo(originalFilename);
    }

    @Test
    void decryptFilename_withNullAuthTag_throwsSecurityError() {
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        String iv = Base64Url.encode(TestHelpers.generateTestIV());
        String encryptedFilename = Base64Url.encode(new byte[32]);

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFilename(encryptedFilename, masterKey, iv, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR");
    }

    @Test
    void decryptFilename_withEmptyAuthTag_throwsSecurityError() {
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        String iv = Base64Url.encode(TestHelpers.generateTestIV());
        String encryptedFilename = Base64Url.encode(new byte[32]);

        assertThatThrownBy(() ->
                CapsaDecryptor.decryptFilename(encryptedFilename, masterKey, iv, ""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SECURITY ERROR");
    }

    // decrypt Capsa Tests

    @Test
    void decrypt_withValidCapsa_decryptsSubjectAndBody() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        // Encrypt subject
        String subject = "Test Subject";
        byte[] subjectIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedSubject = AesGcmProvider.encrypt(
                subject.getBytes(StandardCharsets.UTF_8), masterKey, subjectIv);

        // Encrypt body
        String body = "Test Body Content";
        byte[] bodyIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedBody = AesGcmProvider.encrypt(
                body.getBytes(StandardCharsets.UTF_8), masterKey, bodyIv);

        // Encrypt master key for party
        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        // Create signature
        FileHashData[] files = new FileHashData[0];
        String canonicalString = SignatureProvider.buildCanonicalString(
                capsaId, 0, "AES-256-GCM", files,
                null,
                Base64Url.encode(subjectIv),
                Base64Url.encode(bodyIv));
        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        // Build capsa
        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(partyId);
        capsa.setStatus("active");
        capsa.setEncryptedSubject(Base64Url.encode(encryptedSubject.getCiphertext()));
        capsa.setSubjectIV(Base64Url.encode(subjectIv));
        capsa.setSubjectAuthTag(Base64Url.encode(encryptedSubject.getAuthTag()));
        capsa.setEncryptedBody(Base64Url.encode(encryptedBody.getCiphertext()));
        capsa.setBodyIV(Base64Url.encode(bodyIv));
        capsa.setBodyAuthTag(Base64Url.encode(encryptedBody.getAuthTag()));
        capsa.setSignature(signature);

        // Build keychain
        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);
        entry.setFingerprint(keyPair.getFingerprint());
        entry.setPermissions(new String[]{"read"});

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        // Decrypt
        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), partyId, keyPair.getPublicKey(), true);

        assertThat(decrypted.getSubject()).isEqualTo(subject);
        assertThat(decrypted.getBody()).isEqualTo(body);
        assertThat(decrypted.getId()).isEqualTo(capsaId);
        assertThat(decrypted.getMasterKey()).isNotNull();
        assertThat(decrypted.getMasterKey()).hasSize(32);
    }

    @Test
    void decrypt_withoutSignatureVerification_succeeds() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        // Encrypt master key for party
        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        // Build minimal capsa (no signature)
        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(partyId);
        capsa.setStatus("active");

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);
        entry.setFingerprint(keyPair.getFingerprint());

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        // Decrypt without signature verification
        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), partyId, null, false);

        assertThat(decrypted.getId()).isEqualTo(capsaId);
        assertThat(decrypted.getMasterKey()).isNotNull();
    }

    @Test
    void decrypt_withSignatureVerificationButNoPublicKey_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(partyId);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId, null, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("creatorPublicKeyPem is required");
    }

    @Test
    void decrypt_withPartyNotInKeychain_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String differentPartyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(partyId);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), differentPartyId, null, false))
                .isInstanceOf(CapsaraCapsaException.class)
                .hasMessageContaining(differentPartyId);
    }

    @Test
    void decrypt_withDelegateActingForParty_succeeds() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String delegatePartyId = TestHelpers.generatePartyId();
        String recipientPartyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(TestHelpers.generatePartyId());

        // Delegate has the encrypted key and is acting for the recipient
        KeychainEntry delegateEntry = new KeychainEntry();
        delegateEntry.setParty(delegatePartyId);
        delegateEntry.setEncryptedKey(encryptedMasterKey);
        delegateEntry.setActingFor(new String[]{recipientPartyId});

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{delegateEntry});
        capsa.setKeychain(keychain);

        // Try to decrypt as recipient - should find delegate entry
        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), recipientPartyId, null, false);

        assertThat(decrypted.getId()).isEqualTo(capsaId);
    }

    @Test
    void decrypt_withDelegatedRecipientNoKey_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(TestHelpers.generatePartyId());

        // Entry exists but has no encrypted key
        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(""); // Empty key

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId, null, false))
                .isInstanceOf(CapsaraCapsaException.class)
                .hasMessageContaining(partyId);
    }

    @Test
    void decrypt_withEmptyKeychain_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(TestHelpers.generatePartyId());

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[0]);
        capsa.setKeychain(keychain);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), null, null, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No keychain entries");
    }

    @Test
    void decrypt_withInvalidSignature_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        // Create signature with different canonical string
        CapsaSignature invalidSignature = SignatureProvider.createJws("wrong_canonical_string", keyPair.getPrivateKey());

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(partyId);
        capsa.setSignature(invalidSignature);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        assertThatThrownBy(() ->
                CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId, keyPair.getPublicKey(), true))
                .isInstanceOf(CapsaraCapsaException.class);
    }

    @Test
    void decrypt_withNullPartyId_usesFirstKeychainEntry() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(partyId);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        // Pass null for partyId - should auto-select first entry
        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), null, null, false);

        assertThat(decrypted.getId()).isEqualTo(capsaId);
    }

    @Test
    void decrypt_withStructuredData_decryptsSuccessfully() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        // Encrypt structured data
        String structuredJson = "{\"key\":\"value\",\"number\":42}";
        byte[] structuredIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedStructured = AesGcmProvider.encrypt(
                structuredJson.getBytes(StandardCharsets.UTF_8), masterKey, structuredIv);

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        // Create signature
        FileHashData[] files = new FileHashData[0];
        String canonicalString = SignatureProvider.buildCanonicalString(
                capsaId, 0, "AES-256-GCM", files,
                Base64Url.encode(structuredIv),
                null, null);
        CapsaSignature signature = SignatureProvider.createJws(canonicalString, keyPair.getPrivateKey());

        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(partyId);
        capsa.setEncryptedStructured(Base64Url.encode(encryptedStructured.getCiphertext()));
        capsa.setStructuredIV(Base64Url.encode(structuredIv));
        capsa.setStructuredAuthTag(Base64Url.encode(encryptedStructured.getAuthTag()));
        capsa.setSignature(signature);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), partyId, keyPair.getPublicKey(), true);

        assertThat(decrypted.getStructured()).isNotNull();
        assertThat(decrypted.getStructured().get("key")).isEqualTo("value");
        assertThat(decrypted.getStructured().get("number")).isEqualTo(42);
    }

    // Master Key Validation Tests

    @Test
    void decrypt_masterKeyIs32Bytes() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        assertThat(masterKey).hasSize(32);

        String encryptedMasterKey = RsaProvider.encryptMasterKey(masterKey, keyPair.getPublicKey());

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(partyId);

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(encryptedMasterKey);

        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setKeys(new KeychainEntry[]{entry});
        capsa.setKeychain(keychain);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(
                capsa, keyPair.getPrivateKey(), partyId, null, false);

        assertThat(decrypted.getMasterKey()).hasSize(32);
    }
}
