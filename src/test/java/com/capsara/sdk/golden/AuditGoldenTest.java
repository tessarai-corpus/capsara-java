package com.capsara.sdk.golden;

import com.capsara.sdk.models.AuditActions;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden tests for audit request construction, validation, and action types.
 */
class AuditGoldenTest {

    // Action Type Constants Tests

    @Test
    void auditActions_hasExpectedConstants() {
        assertThat(AuditActions.CREATED).isEqualTo("created");
        assertThat(AuditActions.ACCESSED).isEqualTo("accessed");
        assertThat(AuditActions.FILE_DOWNLOADED).isEqualTo("file_downloaded");
        assertThat(AuditActions.PROCESSED).isEqualTo("processed");
        assertThat(AuditActions.EXPIRED).isEqualTo("expired");
        assertThat(AuditActions.DELETED).isEqualTo("deleted");
        assertThat(AuditActions.LOG).isEqualTo("log");
    }

    // CreateAuditEntryRequest Tests

    @Test
    void createAuditEntryRequest_defaultActionIsLog() {
        CreateAuditEntryRequest request = new CreateAuditEntryRequest();

        assertThat(request.getAction()).isEqualTo("log");
        assertThat(request.getDetails()).isNull();
    }

    @Test
    void createAuditEntryRequest_constructorSetsActionAndDetails() {
        Map<String, Object> details = new HashMap<>();
        details.put("message", "Processed claim #12345");
        details.put("status", "approved");

        CreateAuditEntryRequest request = new CreateAuditEntryRequest(AuditActions.PROCESSED, details);

        assertThat(request.getAction()).isEqualTo("processed");
        assertThat(request.getDetails()).containsEntry("message", "Processed claim #12345");
        assertThat(request.getDetails()).containsEntry("status", "approved");
    }

    // GetAuditEntriesFilters Tests

    @Test
    void getAuditEntriesFilters_allFieldsDefaultToNull() {
        GetAuditEntriesFilters filters = new GetAuditEntriesFilters();

        assertThat(filters.getAction()).isNull();
        assertThat(filters.getParty()).isNull();
        assertThat(filters.getPage()).isNull();
        assertThat(filters.getLimit()).isNull();
    }
}
