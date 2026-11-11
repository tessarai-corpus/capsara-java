package com.capsara.sdk.golden;

import com.capsara.sdk.internal.json.JsonMapper;
import com.capsara.sdk.models.AuditActions;
import com.capsara.sdk.models.CreateAuditEntryRequest;
import com.capsara.sdk.models.GetAuditEntriesFilters;
import com.capsara.sdk.models.GetAuditEntriesResponse;
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
        assertThat(AuditActions.SOFT_DELETED).isEqualTo("soft_deleted");
        assertThat(AuditActions.HARD_DELETED).isEqualTo("hard_deleted");
        assertThat(AuditActions.WEBHOOK_DELIVERED).isEqualTo("webhook.delivered");
        assertThat(AuditActions.WEBHOOK_FAILED).isEqualTo("webhook.failed");
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

    // GetAuditEntriesResponse Tests

    @Test
    void getAuditEntriesResponse_parsesPagePagination() throws Exception {
        String json = "{"
                + "\"auditEntries\":["
                + "{\"timestamp\":\"2025-01-02T00:00:00.000Z\",\"party\":\"party_2\",\"action\":\"accessed\"},"
                + "{\"timestamp\":\"2025-01-01T00:00:00.000Z\",\"party\":\"party_1\",\"action\":\"created\"}"
                + "],"
                + "\"pagination\":{\"page\":2,\"limit\":2,\"total\":5,\"totalPages\":3}"
                + "}";

        GetAuditEntriesResponse response =
                JsonMapper.getInstance().readValue(json, GetAuditEntriesResponse.class);

        assertThat(response.getAuditEntries()).hasSize(2);
        assertThat(response.getAuditEntries()[0].getParty()).isEqualTo("party_2");
        assertThat(response.getPagination().getPage()).isEqualTo(2);
        assertThat(response.getPagination().getLimit()).isEqualTo(2);
        assertThat(response.getPagination().getTotal()).isEqualTo(5);
        assertThat(response.getPagination().getTotalPages()).isEqualTo(3);
    }

    @Test
    void getAuditEntriesResponse_parsesEmptyTrail() throws Exception {
        String json = "{\"auditEntries\":[],"
                + "\"pagination\":{\"page\":1,\"limit\":100,\"total\":0,\"totalPages\":0}}";

        GetAuditEntriesResponse response =
                JsonMapper.getInstance().readValue(json, GetAuditEntriesResponse.class);

        assertThat(response.getAuditEntries()).isEmpty();
        assertThat(response.getPagination().getPage()).isEqualTo(1);
        assertThat(response.getPagination().getLimit()).isEqualTo(100);
        assertThat(response.getPagination().getTotal()).isZero();
        assertThat(response.getPagination().getTotalPages()).isZero();
    }

    @Test
    void getAuditEntriesResponse_missingOrNullPaginationFields_areNull() throws Exception {
        String json = "{\"auditEntries\":[],\"pagination\":{\"page\":null,\"total\":3}}";

        GetAuditEntriesResponse response =
                JsonMapper.getInstance().readValue(json, GetAuditEntriesResponse.class);

        assertThat(response.getPagination().getPage()).isNull();
        assertThat(response.getPagination().getLimit()).isNull();
        assertThat(response.getPagination().getTotal()).isEqualTo(3);
        assertThat(response.getPagination().getTotalPages()).isNull();
    }
}
