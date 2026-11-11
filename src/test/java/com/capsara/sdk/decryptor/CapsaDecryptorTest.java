package com.capsara.sdk.decryptor;

import com.capsara.sdk.exceptions.CapsaraCapsaException;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.helpers.TestHelpers;
import com.capsara.sdk.internal.crypto.*;
import com.capsara.sdk.internal.decryptor.CapsaDecryptor;
import com.capsara.sdk.models.*;
import com.capsara.sdk.models.DecryptedCapsa;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        String subject = "Test Subject";
        byte[] subjectIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedSubject = AesGcmProvider.encrypt(
                subject.getBytes(StandardCharsets.UTF_8), masterKey, subjectIv);

        String body = "Test Body Content";
        byte[] bodyIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedBody = AesGcmProvider.encrypt(
                body.getBytes(StandardCharsets.UTF_8), masterKey, bodyIv);

        Capsa capsa = capsaWithEntry(capsaId, partyId, entry(partyId, masterKey, keyPair));
        capsa.setEncryptedSubject(Base64Url.encode(encryptedSubject.getCiphertext()));
        capsa.setSubjectIV(Base64Url.encode(subjectIv));
        capsa.setSubjectAuthTag(Base64Url.encode(encryptedSubject.getAuthTag()));
        capsa.setEncryptedBody(Base64Url.encode(encryptedBody.getCiphertext()));
        capsa.setBodyIV(Base64Url.encode(bodyIv));
        capsa.setBodyAuthTag(Base64Url.encode(encryptedBody.getAuthTag()));
        TestHelpers.signAsCreator(capsa, keyPair);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId);

        assertThat(decrypted.getSubject()).isEqualTo(subject);
        assertThat(decrypted.getBody()).isEqualTo(body);
        assertThat(decrypted.getId()).isEqualTo(capsaId);
        assertThat(decrypted.getMasterKey()).hasSize(32);
    }

    // Signature verification: always on

    @Test
    void decrypt_withoutCreatorPublicKey_throwsSignatureKeyMissing() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair));
        TestHelpers.signAsCreator(capsa, keyPair);
        capsa.setCreatorPublicKey(null);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_KEY_MISSING");
    }

    @Test
    void decrypt_creatorKeyNotTheOneItsEntryNames_throwsSignatureKeyMismatch() {
        // The creator reads its own capsa, so its own entry is in the response
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult otherKeys = SharedKeyFixture.getSecondaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(creatorId, TestHelpers.generateTestMasterKey(), creatorKeys));
        // Signed with, and carrying, a key other than the one the entry records
        TestHelpers.signAsCreator(capsa, otherKeys);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, creatorKeys.getPrivateKey(), creatorId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_KEY_MISMATCH");
    }

    @Test
    void decrypt_recipientWithoutCreatorEntry_skipsFingerprintCheckAndVerifies() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(capsa, creatorKeys);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId);

        assertThat(decrypted.getMasterKey()).hasSize(32);
    }

    @Test
    void decrypt_signedByKeyOtherThanCreatorPublicKey_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        GeneratedKeyPairResult forgerKeys = SharedKeyFixture.getTertiaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(capsa, forgerKeys);
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    @Test
    void decrypt_validSignatureForAnotherCapsa_throwsSignatureVerificationFailed() {
        // A genuine creator signature lifted from one capsa must not vouch for another
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        String recipientId = TestHelpers.generatePartyId();
        Capsa original = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(original, creatorKeys);

        Capsa other = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        other.setSignature(original.getSignature());
        other.setCreatorPublicKey(creatorKeys.getPublicKey());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(other, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    @Test
    void decrypt_withInvalidSignature_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair));
        capsa.setSignature(SignatureProvider.createJws("wrong_canonical_string", keyPair.getPrivateKey()));
        capsa.setCreatorPublicKey(keyPair.getPublicKey());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    @Test
    void decrypt_withMissingSignature_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair));
        capsa.setCreatorPublicKey(keyPair.getPublicKey());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    // Signed creator

    private static String canonical(Capsa capsa, String creatorId, String fingerprint) {
        return SignatureProvider.buildCanonicalString(capsa.getId(), capsa.getTotalSize(),
                capsa.getKeychain().getAlgorithm(), creatorId, fingerprint, new FileHashData[0],
                capsa.getStructuredIV(), capsa.getSubjectIV(), capsa.getBodyIV());
    }

    private static void assertSignatureFails(Capsa capsa, GeneratedKeyPairResult keys, String partyId) {
        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keys.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    @Test
    void decrypt_signatureBindsCreatorAndKeyFingerprint() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(capsa, creatorKeys);

        String payload = new String(Base64Url.decode(capsa.getSignature().getPayload()), StandardCharsets.UTF_8);

        assertThat(payload).isEqualTo(capsa.getId() + "|1.0.0|0|AES-256-GCM|" + creatorId + "|"
                + creatorKeys.getFingerprint());
        assertThat(CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId).getMasterKey())
                .hasSize(32);
    }

    @Test
    void decrypt_tamperedCreator_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(capsa, SharedKeyFixture.getPrimaryKeyPair());
        capsa.setCreator(TestHelpers.generatePartyId());

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_signedFingerprintOfAnotherKey_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), creatorId,
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        String otherFingerprint = SharedKeyFixture.getTertiaryKeyPair().getFingerprint();
        capsa.setSignature(SignatureProvider.createJws(canonical(capsa, creatorId, otherFingerprint),
                creatorKeys.getPrivateKey()));
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_oldFormatSignatureWithoutCreator_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        String oldFormat = capsa.getId() + "|1.0.0|" + capsa.getTotalSize() + "|AES-256-GCM";
        capsa.setSignature(SignatureProvider.createJws(oldFormat, creatorKeys.getPrivateKey()));
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    private static Capsa capsaWithOptionalIvs(String recipientId, GeneratedKeyPairResult recipientKeys,
                                              String subjectIv, String bodyIv) {
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        capsa.setSubjectIV(subjectIv);
        capsa.setBodyIV(bodyIv);
        return capsa;
    }

    @Test
    void decrypt_labelledOptionalIvs_verify() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = signed(capsaWithOptionalIvs(recipientId, recipientKeys, "subjectIv01", "bodyIv0002"), creatorKeys);

        String payload = new String(Base64Url.decode(capsa.getSignature().getPayload()), StandardCharsets.UTF_8);

        assertThat(payload).endsWith("|subject:subjectIv01|body:bodyIv0002");
        assertThat(CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId).getMasterKey())
                .hasSize(32);
    }

    @Test
    void decrypt_swappedSubjectAndBodyIvs_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = signed(capsaWithOptionalIvs(recipientId, recipientKeys, "subjectIv01", "bodyIv0002"),
                SharedKeyFixture.getPrimaryKeyPair());
        capsa.setSubjectIV("bodyIv0002");
        capsa.setBodyIV("subjectIv01");

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_subjectIvMovedToBody_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = signed(capsaWithOptionalIvs(recipientId, recipientKeys, "subjectIv01", null),
                SharedKeyFixture.getPrimaryKeyPair());
        capsa.setSubjectIV(null);
        capsa.setBodyIV("subjectIv01");

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_unlabelledOptionalIvSignature_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithOptionalIvs(recipientId, recipientKeys, "subjectIv01", "bodyIv0002");
        String unlabelled = canonical(capsa, capsa.getCreator(), creatorKeys.getFingerprint())
                .replace("|subject:", "|").replace("|body:", "|");
        capsa.setSignature(SignatureProvider.createJws(unlabelled, creatorKeys.getPrivateKey()));
        capsa.setCreatorPublicKey(creatorKeys.getPublicKey());

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_unparseableCreatorPublicKey_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        TestHelpers.signAsCreator(capsa, SharedKeyFixture.getPrimaryKeyPair());
        capsa.setCreatorPublicKey("-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----");

        assertSignatureFails(capsa, recipientKeys, recipientId);
    }

    @Test
    void decrypt_unparseableCreatorPublicKeyWithCreatorEntry_throwsSignatureVerificationFailedWithCapsaId() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, creatorId,
                entry(creatorId, TestHelpers.generateTestMasterKey(), creatorKeys)), creatorKeys);
        capsa.setCreatorPublicKey("-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----");

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, creatorKeys.getPrivateKey(), creatorId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertSignatureVerificationFailed((CapsaraCapsaException) e, capsaId));
    }

    @Test
    void decrypt_signatureNotBase64Url_throwsSignatureVerificationFailedWithCapsaId() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys)),
                SharedKeyFixture.getPrimaryKeyPair());
        capsa.getSignature().setSignature("***not base64***");

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertSignatureVerificationFailed((CapsaraCapsaException) e, capsaId));
    }

    @Test
    void decrypt_signatureWrongLength_throwsSignatureVerificationFailedWithCapsaId() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys)),
                SharedKeyFixture.getPrimaryKeyPair());
        capsa.getSignature().setSignature(Base64Url.encode(new byte[256]));

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertSignatureVerificationFailed((CapsaraCapsaException) e, capsaId));
    }

    @Test
    void decrypt_missingTotalSize_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys)),
                SharedKeyFixture.getPrimaryKeyPair());
        capsa.setTotalSize(null);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertSignatureVerificationFailed((CapsaraCapsaException) e, capsaId));
    }

    @Test
    void decrypt_fileWithoutHash_throwsSignatureVerificationFailed() {
        GeneratedKeyPairResult recipientKeys = SharedKeyFixture.getSecondaryKeyPair();
        String recipientId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = capsaWithEntry(capsaId, TestHelpers.generatePartyId(),
                entry(recipientId, TestHelpers.generateTestMasterKey(), recipientKeys));
        EncryptedFile file = new EncryptedFile();
        file.setFileId("file_1");
        file.setHash("h");
        file.setIv("iv");
        file.setFilenameIV("fiv");
        capsa.setFiles(new EncryptedFile[]{file});
        signed(capsa, SharedKeyFixture.getPrimaryKeyPair());
        file.setHash(null);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, recipientKeys.getPrivateKey(), recipientId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertSignatureVerificationFailed((CapsaraCapsaException) e, capsaId));
    }

    @Test
    void decrypt_creatorEntryFingerprintDiffersOnlyInCase_throwsSignatureKeyMismatch() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        KeychainEntry creatorEntry = entry(creatorId, TestHelpers.generateTestMasterKey(), creatorKeys);
        creatorEntry.setFingerprint(creatorKeys.getFingerprint().toUpperCase(java.util.Locale.ROOT));
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), creatorId, creatorEntry), creatorKeys);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, creatorKeys.getPrivateKey(), creatorId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_KEY_MISMATCH");
    }

    @Test
    void decrypt_creatorEntryActingForAnotherParty_isStillTheCreatorEntry() {
        GeneratedKeyPairResult creatorKeys = SharedKeyFixture.getPrimaryKeyPair();
        String creatorId = TestHelpers.generatePartyId();
        KeychainEntry creatorEntry = entry(creatorId, TestHelpers.generateTestMasterKey(), creatorKeys);
        creatorEntry.setActingFor(new String[]{TestHelpers.generatePartyId()});
        creatorEntry.setFingerprint(SharedKeyFixture.getSecondaryKeyPair().getFingerprint());
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), creatorId, creatorEntry), creatorKeys);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, creatorKeys.getPrivateKey(), creatorId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_KEY_MISMATCH");
    }

    private static void assertSignatureVerificationFailed(CapsaraCapsaException ex, String capsaId) {
        assertThat(ex.getCode()).isEqualTo("SIGNATURE_VERIFICATION_FAILED");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(Map.of("capsaId", capsaId));
    }

    // Keychain entry selection

    @Test
    void decrypt_withPartyNotInKeychain_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String differentPartyId = TestHelpers.generatePartyId();
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair)), keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), differentPartyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .hasMessageContaining(differentPartyId)
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "NOT_IN_KEYCHAIN", capsa.getId()));
    }

    @Test
    void decrypt_withDelegateActingForParty_succeeds() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String delegatePartyId = TestHelpers.generatePartyId();
        String recipientPartyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();

        KeychainEntry delegateEntry = entry(delegatePartyId, TestHelpers.generateTestMasterKey(), keyPair);
        delegateEntry.setActingFor(new String[]{recipientPartyId});
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(), delegateEntry),
                SharedKeyFixture.getSecondaryKeyPair());

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), recipientPartyId);

        assertThat(decrypted.getId()).isEqualTo(capsaId);
    }

    @Test
    void decrypt_withDelegatedRecipientNoKey_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();

        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey("");
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(), entry),
                SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .hasMessageContaining(partyId)
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "NO_ENCRYPTED_KEY", capsa.getId()));
    }

    @Test
    void decrypt_entryWithNullEncryptedKey_throwsNoEncryptedKey() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(null);
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(), entry),
                SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), null))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "NO_ENCRYPTED_KEY", capsa.getId()));
    }

    @Test
    void decrypt_withEmptyKeychainAndPartyId_throwsNotInKeychain() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        Capsa capsa = signed(capsaWithEntries(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId()),
                SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), "party_me"))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "NOT_IN_KEYCHAIN", capsa.getId()));
    }

    @Test
    void decrypt_shortEncryptedKey_failsLengthCheckBeforeKeySelection() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(Base64Url.encode(new byte[256]));
        entry.setFingerprint(null);
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(), entry),
                SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .hasMessageContaining("256 bytes")
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "INVALID_ENCRYPTED_KEY", capsa.getId()));
    }

    @Test
    void decrypt_arrayStructuredData_isReturnedAsParsed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] structuredIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                "[1,2]".getBytes(StandardCharsets.UTF_8), masterKey, structuredIv);
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId, entry(partyId, masterKey, keyPair));
        capsa.setEncryptedStructured(Base64Url.encode(encrypted.getCiphertext()));
        capsa.setStructuredIV(Base64Url.encode(structuredIv));
        capsa.setStructuredAuthTag(Base64Url.encode(encrypted.getAuthTag()));
        signed(capsa, keyPair);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId);

        assertThat(decrypted.getStructuredValue()).isEqualTo(List.of(1, 2));
        assertThat(decrypted.getStructured()).isNull();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource(value = {"soft_deleted,SOFT_DELETED", "expired,EXPIRED",
        "active,ACTIVE", "archived,", ","}, nullValues = "")
    void decrypt_statusIsTheRawServerString(String status, CapsaStatus typed) {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair));
        capsa.setStatus(status);
        signed(capsa, keyPair);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId);

        assertThat(decrypted.getStatus()).isEqualTo(status);
        assertThat(decrypted.getStatusValue()).isEqualTo(typed);
    }

    @Test
    void capsaAndSummary_withoutStatus_decodeAsNull() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = com.capsara.sdk.internal.json.JsonMapper.getInstance();

        assertThat(mapper.readValue("{\"id\":\"c\"}", Capsa.class).getStatus()).isNull();
        assertThat(mapper.readValue("{\"id\":\"c\"}", CapsaSummary.class).getStatus()).isNull();
        assertThat(mapper.readValue("{\"status\":\"Archived\"}", CapsaSummary.class).getStatus())
                .isEqualTo("Archived");
    }

    @Test
    void decrypt_totalSizeDecodedFromWholeFloat_verifies() throws Exception {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = withTotalSize(signedForParty(partyId, keyPair), "0.0");

        assertThat(capsa.getTotalSize()).isZero();
        assertThat(CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId).getId()).isEqualTo(capsa.getId());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"0.5", "\"0\"", "null", "-"})
    void decrypt_totalSizeNotAWholeNumber_decodesAndFailsVerification(String totalSize) throws Exception {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = withTotalSize(signedForParty(partyId, keyPair), totalSize);

        assertThat(capsa.getTotalSize()).isNull();
        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .extracting(e -> ((CapsaraCapsaException) e).getCode())
                .isEqualTo("SIGNATURE_VERIFICATION_FAILED");
    }

    @Test
    void decrypt_encryptedKeyNotForThisKey_isKeyDecryptionFailed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        KeychainEntry entry = entry(partyId, TestHelpers.generateTestMasterKey(), keyPair);
        entry.setEncryptedKey(Base64Url.encode(TestHelpers.randomBytes(512)));
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), partyId, entry), keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "KEY_DECRYPTION_FAILED", capsa.getId()));
    }

    @Test
    void decrypt_masterKeyNot32Bytes_isKeyDecryptionFailed() throws Exception {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, PemHelper.importPublicKey(keyPair.getPublicKey()),
                new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT));
        KeychainEntry shortKey = entry(partyId, TestHelpers.generateTestMasterKey(), keyPair);
        shortKey.setEncryptedKey(Base64Url.encode(cipher.doFinal(new byte[16])));
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), partyId, shortKey), keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "KEY_DECRYPTION_FAILED", capsa.getId()));
    }

    @Test
    void decrypt_tamperedSubject_isContentDecryptionFailed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                "hello".getBytes(StandardCharsets.UTF_8), masterKey, iv);
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId, entry(partyId, masterKey, keyPair));
        capsa.setEncryptedSubject(Base64Url.encode(encrypted.getCiphertext()));
        capsa.setSubjectIV(Base64Url.encode(iv));
        capsa.setSubjectAuthTag(Base64Url.encode(new byte[16]));
        signed(capsa, keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "CONTENT_DECRYPTION_FAILED",
                        capsa.getId()));
    }

    @Test
    void decrypt_structuredNotJson_isContentDecryptionFailed() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        byte[] iv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encrypted = AesGcmProvider.encrypt(
                "{not json".getBytes(StandardCharsets.UTF_8), masterKey, iv);
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId, entry(partyId, masterKey, keyPair));
        capsa.setEncryptedStructured(Base64Url.encode(encrypted.getCiphertext()));
        capsa.setStructuredIV(Base64Url.encode(iv));
        capsa.setStructuredAuthTag(Base64Url.encode(encrypted.getAuthTag()));
        signed(capsa, keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .satisfies(e -> assertCapsaCode((CapsaraCapsaException) e, "CONTENT_DECRYPTION_FAILED",
                        capsa.getId()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @org.junit.jupiter.params.provider.ValueSource(strings = {"not a key"})
    void decrypt_unusableCurrentKey_isInvalidPrivateKeyWithCapsaId(String privateKey) {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = signedForParty(partyId, keyPair);

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, privateKey, partyId))
                .isExactlyInstanceOf(com.capsara.sdk.exceptions.CapsaraException.class)
                .satisfies(e -> {
                    com.capsara.sdk.exceptions.CapsaraException error = (com.capsara.sdk.exceptions.CapsaraException) e;
                    assertThat(error.getCode()).isEqualTo("INVALID_PRIVATE_KEY");
                    assertThat(error.getStatusCode()).isZero();
                    assertThat(error.getDetails()).isEqualTo(Map.of("capsaId", capsa.getId()));
                });
    }

    private static Capsa signedForParty(String partyId, GeneratedKeyPairResult keyPair) {
        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId,
                entry(partyId, TestHelpers.generateTestMasterKey(), keyPair));
        return signed(capsa, keyPair);
    }

    private static Capsa withTotalSize(Capsa capsa, String totalSizeJson) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = com.capsara.sdk.internal.json.JsonMapper.getInstance();
        com.fasterxml.jackson.databind.node.ObjectNode node = mapper.valueToTree(capsa);
        node.remove("totalSize");
        if (!"-".equals(totalSizeJson)) {
            node.set("totalSize", mapper.readTree(totalSizeJson));
        }
        return mapper.treeToValue(node, Capsa.class);
    }

    private static void assertCapsaCode(CapsaraCapsaException ex, String code, String capsaId) {
        assertThat(ex.getCode()).isEqualTo(code);
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(Map.of("capsaId", capsaId));
    }

    @Test
    void decrypt_withEmptyKeychain_throwsException() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();

        Capsa capsa = new Capsa();
        capsa.setId(TestHelpers.generateCapsaId());
        capsa.setCreator(TestHelpers.generatePartyId());
        capsa.setTotalSize(0L);
        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(new KeychainEntry[0]);
        capsa.setKeychain(keychain);
        signed(capsa, SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), null))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> {
                    CapsaraCapsaException error = (CapsaraCapsaException) e;
                    assertThat(error.getCode()).isEqualTo("NOT_IN_KEYCHAIN");
                    assertThat(error.getStatusCode()).isZero();
                    assertThat(error.getDetails()).isEqualTo(java.util.Map.of("capsaId", capsa.getId()));
                });
    }

    @ParameterizedTest
    @NullAndEmptySource
    void decrypt_withoutPartyId_singleEntry_usesIt(String partyId) {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String ownerId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, ownerId,
                entry(ownerId, TestHelpers.generateTestMasterKey(), keyPair)), keyPair);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId);

        assertThat(decrypted.getId()).isEqualTo(capsaId);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void decrypt_withoutPartyId_severalEntries_throwsPrivateKeyNotAvailable(String partyId) {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String capsaId = TestHelpers.generateCapsaId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();
        Capsa capsa = signed(capsaWithEntries(capsaId, TestHelpers.generatePartyId(),
                entry(TestHelpers.generatePartyId(), masterKey, keyPair),
                entry(TestHelpers.generatePartyId(), masterKey, keyPair)), SharedKeyFixture.getSecondaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertPrivateKeyNotAvailable((CapsaraCapsaException) e, capsaId, null));
    }

    @Test
    void decrypt_partyHasOwnEntryAndIsActedFor_usesOwnEntry() {
        GeneratedKeyPairResult ownKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult delegateKeys = SharedKeyFixture.getSecondaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        KeychainEntry delegateEntry = entry(TestHelpers.generatePartyId(), masterKey, delegateKeys);
        delegateEntry.setActingFor(new String[]{partyId});
        Capsa capsa = signed(capsaWithEntries(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                delegateEntry, entry(partyId, masterKey, ownKeys)), SharedKeyFixture.getTertiaryKeyPair());

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, ownKeys.getPrivateKey(), partyId);

        assertThat(decrypted.getMasterKey()).isEqualTo(masterKey);
    }

    @Test
    void decrypt_withStructuredData_decryptsSuccessfully() {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        byte[] masterKey = TestHelpers.generateTestMasterKey();

        String structuredJson = "{\"key\":\"value\",\"number\":42}";
        byte[] structuredIv = TestHelpers.generateTestIV();
        AesGcmProvider.EncryptionResult encryptedStructured = AesGcmProvider.encrypt(
                structuredJson.getBytes(StandardCharsets.UTF_8), masterKey, structuredIv);

        Capsa capsa = capsaWithEntry(TestHelpers.generateCapsaId(), partyId, entry(partyId, masterKey, keyPair));
        capsa.setEncryptedStructured(Base64Url.encode(encryptedStructured.getCiphertext()));
        capsa.setStructuredIV(Base64Url.encode(structuredIv));
        capsa.setStructuredAuthTag(Base64Url.encode(encryptedStructured.getAuthTag()));
        signed(capsa, keyPair);

        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, keyPair.getPrivateKey(), partyId);

        assertThat(decrypted.getStructured()).isNotNull();
        assertThat(decrypted.getStructured().get("key")).isEqualTo("value");
        assertThat(decrypted.getStructured().get("number")).isEqualTo(42);
    }

    // Private key selection by fingerprint

    @Test
    void decrypt_capsaEncryptedToPreviousKey_usesPreviousKey() {
        GeneratedKeyPairResult oldKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult newKeys = SharedKeyFixture.getSecondaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        Capsa capsa = signed(capsaWithEntry(TestHelpers.generateCapsaId(), TestHelpers.generatePartyId(),
                entry(partyId, TestHelpers.generateTestMasterKey(), oldKeys)), SharedKeyFixture.getTertiaryKeyPair());

        PrivateKeyRing ring = new PrivateKeyRing(newKeys.getPrivateKey(), List.of(oldKeys.getPrivateKey()));
        DecryptedCapsa decrypted = CapsaDecryptor.decrypt(capsa, ring, partyId);

        assertThat(decrypted.getMasterKey()).hasSize(32);
    }

    @Test
    void decrypt_noConfiguredKeyMatches_throwsPrivateKeyNotAvailable() {
        GeneratedKeyPairResult oldKeys = SharedKeyFixture.getPrimaryKeyPair();
        GeneratedKeyPairResult newKeys = SharedKeyFixture.getSecondaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(),
                entry(partyId, TestHelpers.generateTestMasterKey(), oldKeys)), SharedKeyFixture.getTertiaryKeyPair());

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, newKeys.getPrivateKey(), partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertPrivateKeyNotAvailable((CapsaraCapsaException) e, capsaId,
                        oldKeys.getFingerprint()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void decrypt_entryWithoutFingerprint_throwsPrivateKeyNotAvailable(String fingerprint) {
        GeneratedKeyPairResult keyPair = SharedKeyFixture.getPrimaryKeyPair();
        String partyId = TestHelpers.generatePartyId();
        String capsaId = TestHelpers.generateCapsaId();
        KeychainEntry entry = entry(partyId, TestHelpers.generateTestMasterKey(), keyPair);
        entry.setFingerprint(fingerprint);
        Capsa capsa = signed(capsaWithEntry(capsaId, TestHelpers.generatePartyId(), entry),
                SharedKeyFixture.getSecondaryKeyPair());

        PrivateKeyRing ring = new PrivateKeyRing(keyPair.getPrivateKey(),
                List.of(SharedKeyFixture.getTertiaryKeyPair().getPrivateKey()));

        assertThatThrownBy(() -> CapsaDecryptor.decrypt(capsa, ring, partyId))
                .isInstanceOf(CapsaraCapsaException.class)
                .satisfies(e -> assertPrivateKeyNotAvailable((CapsaraCapsaException) e, capsaId, null));
    }

    // Helpers

    private static void assertPrivateKeyNotAvailable(CapsaraCapsaException ex, String capsaId, String fingerprint) {
        Map<String, Object> expected = new HashMap<>();
        expected.put("capsaId", capsaId);
        expected.put("fingerprint", fingerprint);
        assertThat(ex.getCode()).isEqualTo("PRIVATE_KEY_NOT_AVAILABLE");
        assertThat(ex.getStatusCode()).isZero();
        assertThat(ex.getDetails()).isEqualTo(expected);
    }

    private static KeychainEntry entry(String partyId, byte[] masterKey, GeneratedKeyPairResult keys) {
        KeychainEntry entry = new KeychainEntry();
        entry.setParty(partyId);
        entry.setEncryptedKey(RsaProvider.encryptMasterKey(masterKey, keys.getPublicKey()));
        entry.setFingerprint(keys.getFingerprint());
        entry.setPermissions(new String[]{"read"});
        return entry;
    }

    private static Capsa capsaWithEntry(String capsaId, String creatorId, KeychainEntry entry) {
        return capsaWithEntries(capsaId, creatorId, entry);
    }

    private static Capsa capsaWithEntries(String capsaId, String creatorId, KeychainEntry... entries) {
        Capsa capsa = new Capsa();
        capsa.setId(capsaId);
        capsa.setCreator(creatorId);
        capsa.setStatus("active");
        capsa.setTotalSize(0L);
        CapsaKeychain keychain = new CapsaKeychain();
        keychain.setAlgorithm("AES-256-GCM");
        keychain.setKeys(entries);
        capsa.setKeychain(keychain);
        return capsa;
    }

    private static Capsa signed(Capsa capsa, GeneratedKeyPairResult creatorKeys) {
        return TestHelpers.signAsCreator(capsa, creatorKeys);
    }
}
