package com.capsara.sdk.internal.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * Centralized Jackson ObjectMapper configuration.
 * Mirrors .NET SDK's JsonSerializerOptions with:
 * - Ignore unknown properties on deserialization
 * - Skip null values on serialization
 */
public final class JsonMapper {

    private static final ObjectMapper INSTANCE = createMapper();

    private JsonMapper() {
        // Utility class
    }

    /**
     * Get the shared ObjectMapper instance.
     * Thread-safe for both serialization and deserialization.
     */
    public static ObjectMapper getInstance() {
        return INSTANCE;
    }

    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Ignore unknown fields during deserialization (like .NET's JsonIgnoreCondition)
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // Skip null values during serialization (like .NET's WhenWritingNull)
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        // Support Java 8 date/time types
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        return mapper;
    }
}
