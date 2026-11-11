package com.capsara.sdk.utils;

import com.capsara.sdk.internal.utils.IdGenerator;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for IdGenerator cryptographically secure ID generation.
 */
class IdGeneratorTest {

    private static final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

    @Test
    void generate_defaultLength_returns22Characters() {
        String id = IdGenerator.generate();
        assertThat(id).hasSize(22);
    }

    @Test
    void generate_specifiedLength_returnsCorrectLength() {
        assertThat(IdGenerator.generate(1)).hasSize(1);
        assertThat(IdGenerator.generate(10)).hasSize(10);
        assertThat(IdGenerator.generate(21)).hasSize(21);
        assertThat(IdGenerator.generate(50)).hasSize(50);
        assertThat(IdGenerator.generate(100)).hasSize(100);
    }

    @Test
    void generate_usesOnlyValidAlphabetCharacters() {
        String id = IdGenerator.generate(100);

        for (char c : id.toCharArray()) {
            assertThat(ALPHABET).contains(String.valueOf(c));
        }
    }

    @Test
    void generate_producesUniqueIds() {
        int count = 1000;
        Set<String> ids = new HashSet<>();

        for (int i = 0; i < count; i++) {
            ids.add(IdGenerator.generate());
        }

        assertThat(ids).hasSize(count);
    }

    @Test
    void generate_producesGoodDistribution() {
        // Generate many IDs and check character distribution
        int sampleSize = 10000;
        int[] charCounts = new int[ALPHABET.length()];

        for (int i = 0; i < sampleSize; i++) {
            String id = IdGenerator.generate();
            for (char c : id.toCharArray()) {
                int index = ALPHABET.indexOf(c);
                if (index >= 0) {
                    charCounts[index]++;
                }
            }
        }

        // Check that all characters appear
        for (int count : charCounts) {
            assertThat(count).isGreaterThan(0);
        }

        // Check distribution is roughly uniform (within 50% of expected)
        int totalChars = sampleSize * 22;
        double expectedPerChar = totalChars / (double) ALPHABET.length();

        for (int count : charCounts) {
            assertThat(count).isBetween((int)(expectedPerChar * 0.5), (int)(expectedPerChar * 1.5));
        }
    }

    @Test
    void generate_isUrlSafe() {
        String id = IdGenerator.generate(100);

        // Should not contain URL-unsafe characters
        assertThat(id).doesNotContain("+");
        assertThat(id).doesNotContain("/");
        assertThat(id).doesNotContain("=");
        assertThat(id).doesNotContain(" ");
        assertThat(id).doesNotContain("\n");
    }

    @Test
    void generate_multipleCallsProduceDifferentResults() {
        String id1 = IdGenerator.generate();
        String id2 = IdGenerator.generate();
        String id3 = IdGenerator.generate();

        assertThat(id1).isNotEqualTo(id2);
        assertThat(id2).isNotEqualTo(id3);
        assertThat(id1).isNotEqualTo(id3);
    }

    @Test
    void generate_shortIds() {
        String id = IdGenerator.generate(5);
        assertThat(id).hasSize(5);
        for (char c : id.toCharArray()) {
            assertThat(ALPHABET).contains(String.valueOf(c));
        }
    }

    @Test
    void generate_veryLongIds() {
        String id = IdGenerator.generate(1000);
        assertThat(id).hasSize(1000);
        for (char c : id.toCharArray()) {
            assertThat(ALPHABET).contains(String.valueOf(c));
        }
    }
}
