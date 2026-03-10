package com.capsara.sdk.golden;

import com.capsara.sdk.builder.CapsaBuilder;
import com.capsara.sdk.helpers.SharedKeyFixture;
import com.capsara.sdk.models.GeneratedKeyPairResult;
import com.capsara.sdk.models.SendResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden tests for send/upload behavior.
 * Tests validation, batch splitting, and edge cases testable without HTTP mocks.
 */
class SendGoldenTest {

    private static GeneratedKeyPairResult creatorKeyPair;
    private static final String CREATOR_ID = "party_creator_send";
    private static final String RECIPIENT_ID = "party_recipient_send";

    @BeforeAll
    static void setUp() {
        creatorKeyPair = SharedKeyFixture.getPrimaryKeyPair();
    }

    // SendResult Model Tests

    @Test
    void sendResult_defaultsToZeroCounts() {
        SendResult result = new SendResult();

        assertThat(result.getSuccessful()).isEqualTo(0);
        assertThat(result.getFailed()).isEqualTo(0);
        assertThat(result.getPartialSuccess()).isNull();
    }

    @Test
    void sendResult_settersAndGettersWork() {
        SendResult result = new SendResult();
        result.setBatchId("batch_123");
        result.setSuccessful(5);
        result.setFailed(2);
        result.setPartialSuccess(true);

        assertThat(result.getBatchId()).isEqualTo("batch_123");
        assertThat(result.getSuccessful()).isEqualTo(5);
        assertThat(result.getFailed()).isEqualTo(2);
        assertThat(result.getPartialSuccess()).isTrue();
    }

    @Test
    void sendResult_createdListCanBeSet() {
        SendResult result = new SendResult();
        List<SendResult.CreatedCapsa> created = new ArrayList<>();
        SendResult.CreatedCapsa capsa = new SendResult.CreatedCapsa();
        capsa.setPackageId("capsa_abc123");
        capsa.setIndex(0);
        created.add(capsa);

        result.setCreated(created);

        assertThat(result.getCreated()).hasSize(1);
        assertThat(result.getCreated().get(0).getPackageId()).isEqualTo("capsa_abc123");
        assertThat(result.getCreated().get(0).getIndex()).isEqualTo(0);
    }

    @Test
    void sendResult_errorsListCanBeSet() {
        SendResult result = new SendResult();
        List<SendResult.SendError> errors = new ArrayList<>();
        SendResult.SendError error = new SendResult.SendError();
        error.setIndex(2);
        error.setPackageId("capsa_failed");
        error.setError("Validation failed");
        errors.add(error);

        result.setErrors(errors);

        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0).getIndex()).isEqualTo(2);
        assertThat(result.getErrors().get(0).getError()).isEqualTo("Validation failed");
    }

    @Test
    void sendResult_nullErrorsIsAllowed() {
        SendResult result = new SendResult();
        result.setErrors(null);

        assertThat(result.getErrors()).isNull();
    }

    // Builder Batch-Related Validation Tests

    @Test
    void builder_getFileCountReturnsZeroWhenEmpty() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            assertThat(builder.getFileCount()).isEqualTo(0);
        }
    }

    @Test
    void builder_getFileCountIncrementsWithAddedFiles() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addTextFile("f1.txt", "content1");
            builder.addTextFile("f2.txt", "content2");
            builder.addTextFile("f3.txt", "content3");

            assertThat(builder.getFileCount()).isEqualTo(3);
        }
    }

    @Test
    void builder_getRecipientIdsReturnsAddedRecipients() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipient(RECIPIENT_ID);
            builder.addRecipient("party_extra");

            String[] ids = builder.getRecipientIds();
            assertThat(ids).hasSize(2);
            assertThat(ids).contains(RECIPIENT_ID, "party_extra");
        }
    }

    @Test
    void builder_getRecipientIdsReturnsEmptyWhenNoneAdded() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            String[] ids = builder.getRecipientIds();
            assertThat(ids).isEmpty();
        }
    }

    @Test
    void builder_addRecipients_varargs_addsAllRecipients() {
        try (CapsaBuilder builder = new CapsaBuilder(CREATOR_ID, creatorKeyPair.getPrivateKey(), null)) {
            builder.addRecipients("party_a", "party_b", "party_c");

            String[] ids = builder.getRecipientIds();
            assertThat(ids).hasSize(3);
            assertThat(ids).containsExactly("party_a", "party_b", "party_c");
        }
    }
}
