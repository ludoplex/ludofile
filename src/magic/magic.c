/*
 * LudoFile - Magic Pattern Matching Engine Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "magic.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
 * Hash table size for named tests
 */
#define NAMED_TESTS_SIZE 256

/*
 * Initial capacity for dynamic arrays
 */
#define INITIAL_CAPACITY 64

/*
 * Simple string hash function
 */
static size_t hash_string(const char *str) {
    size_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + (size_t)c;
    }
    return hash;
}

/*
 * String unescape - handles escape sequences in magic patterns
 */
uint8_t* magic_unescape(const char *str, size_t len, size_t *out_len) {
    if (!str || !out_len) return NULL;
    
    uint8_t *result = malloc(len + 1);
    if (!result) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\\' && i + 1 < len) {
            i++;
            switch (str[i]) {
                case 'n': result[j++] = '\n'; break;
                case 'r': result[j++] = '\r'; break;
                case 't': result[j++] = '\t'; break;
                case 'b': result[j++] = '\b'; break;
                case 'v': result[j++] = '\v'; break;
                case 'f': result[j++] = '\f'; break;
                case '0': case '1': case '2': case '3':
                case '4': case '5': case '6': case '7': {
                    /* Octal escape */
                    int val = str[i] - '0';
                    if (i + 1 < len && str[i+1] >= '0' && str[i+1] <= '7') {
                        val = val * 8 + (str[++i] - '0');
                        if (i + 1 < len && str[i+1] >= '0' && str[i+1] <= '7') {
                            val = val * 8 + (str[++i] - '0');
                        }
                    }
                    result[j++] = (uint8_t)val;
                    break;
                }
                case 'x': {
                    /* Hex escape */
                    if (i + 1 < len && isxdigit((unsigned char)str[i+1])) {
                        int val = 0;
                        i++;
                        if (str[i] >= '0' && str[i] <= '9') {
                            val = str[i] - '0';
                        } else if (str[i] >= 'a' && str[i] <= 'f') {
                            val = str[i] - 'a' + 10;
                        } else {
                            val = str[i] - 'A' + 10;
                        }
                        if (i + 1 < len && isxdigit((unsigned char)str[i+1])) {
                            i++;
                            val *= 16;
                            if (str[i] >= '0' && str[i] <= '9') {
                                val += str[i] - '0';
                            } else if (str[i] >= 'a' && str[i] <= 'f') {
                                val += str[i] - 'a' + 10;
                            } else {
                                val += str[i] - 'A' + 10;
                            }
                        }
                        result[j++] = (uint8_t)val;
                    } else {
                        result[j++] = 'x';
                    }
                    break;
                }
                default:
                    result[j++] = (uint8_t)str[i];
                    break;
            }
        } else {
            result[j++] = (uint8_t)str[i];
        }
    }
    
    result[j] = '\0';
    *out_len = j;
    return result;
}

/*
 * Parse numeric value from text
 */
int64_t magic_parse_numeric(const char *text) {
    if (!text) return 0;
    
    while (isspace((unsigned char)*text)) text++;
    
    int sign = 1;
    if (*text == '-') {
        sign = -1;
        text++;
    } else if (*text == '+') {
        text++;
    }
    
    /* Remove trailing 'L' */
    size_t len = strlen(text);
    char *copy = NULL;
    if (len > 0 && (text[len-1] == 'L' || text[len-1] == 'l')) {
        copy = strdup(text);
        copy[len-1] = '\0';
        text = copy;
    }
    
    int64_t value;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        /* Hex */
        value = (int64_t)strtoll(text + 2, NULL, 16);
    } else if (text[0] == '0' && len > 1) {
        /* Octal */
        value = (int64_t)strtoll(text, NULL, 8);
    } else {
        /* Decimal */
        value = (int64_t)strtoll(text, NULL, 10);
    }
    
    free(copy);
    return sign * value;
}

/*
 * Create new magic matcher
 */
MagicMatcher* magic_matcher_new(void) {
    MagicMatcher *matcher = calloc(1, sizeof(MagicMatcher));
    if (!matcher) return NULL;
    
    matcher->named_tests = calloc(NAMED_TESTS_SIZE, sizeof(NamedTest*));
    if (!matcher->named_tests) {
        free(matcher);
        return NULL;
    }
    matcher->named_tests_size = NAMED_TESTS_SIZE;
    
    matcher->tests = malloc(INITIAL_CAPACITY * sizeof(MagicTest*));
    if (!matcher->tests) {
        free(matcher->named_tests);
        free(matcher);
        return NULL;
    }
    matcher->tests_capacity = INITIAL_CAPACITY;
    
    return matcher;
}

/*
 * Free a magic test and its children
 */
static void magic_test_free(MagicTest *test) {
    if (!test) return;
    
    for (size_t i = 0; i < test->num_children; i++) {
        magic_test_free(test->children[i]);
    }
    
    free(test->children);
    free(test->mime);
    free(test->message);
    
    if (test->extensions) {
        for (size_t i = 0; i < test->num_extensions; i++) {
            free(test->extensions[i]);
        }
        free(test->extensions);
    }
    
    /* Free type-specific data */
    MagicTestExt *ext = (MagicTestExt*)test;
    switch (ext->data_type_category) {
        case DATA_TYPE_STRING:
            free(ext->data.string.pattern);
            break;
        case DATA_TYPE_REGEX:
            free(ext->data.regex.pattern);
            /* Free compiled regex if present */
            break;
        case DATA_TYPE_SEARCH:
            free(ext->data.search.pattern);
            break;
        case DATA_TYPE_USE:
            free(ext->data.use.test_name);
            break;
        default:
            break;
    }
    
    free(test);
}

/*
 * Free magic matcher
 */
void magic_matcher_free(MagicMatcher *matcher) {
    if (!matcher) return;
    
    /* Free tests */
    for (size_t i = 0; i < matcher->num_tests; i++) {
        magic_test_free(matcher->tests[i]);
    }
    free(matcher->tests);
    
    /* Free named tests */
    for (size_t i = 0; i < matcher->named_tests_size; i++) {
        NamedTest *nt = matcher->named_tests[i];
        while (nt) {
            NamedTest *next = nt->next;
            free(nt->name);
            /* Test is freed above */
            free(nt);
            nt = next;
        }
    }
    free(matcher->named_tests);
    
    /* Free indices */
    free(matcher->text_tests);
    free(matcher->binary_tests);
    
    for (size_t i = 0; i < matcher->num_mimetypes; i++) {
        free(matcher->mimetypes[i]);
    }
    free(matcher->mimetypes);
    
    for (size_t i = 0; i < matcher->num_extensions; i++) {
        free(matcher->extensions[i]);
    }
    free(matcher->extensions);
    
    free(matcher);
}

/*
 * Add a test to the matcher
 */
LudofileResult magic_matcher_add_test(MagicMatcher *matcher, MagicTest *test) {
    if (!matcher || !test) return LUDOFILE_ERROR_INVALID;
    
    if (matcher->num_tests >= matcher->tests_capacity) {
        size_t new_cap = matcher->tests_capacity * 2;
        MagicTest **new_tests = realloc(matcher->tests, new_cap * sizeof(MagicTest*));
        if (!new_tests) return LUDOFILE_ERROR_MEMORY;
        matcher->tests = new_tests;
        matcher->tests_capacity = new_cap;
    }
    
    matcher->tests[matcher->num_tests++] = test;
    return LUDOFILE_OK;
}

/*
 * Add a named test to the matcher
 */
LudofileResult magic_matcher_add_named_test(MagicMatcher *matcher,
                                             const char *name, MagicTest *test) {
    if (!matcher || !name || !test) return LUDOFILE_ERROR_INVALID;
    
    size_t idx = hash_string(name) % matcher->named_tests_size;
    
    NamedTest *nt = malloc(sizeof(NamedTest));
    if (!nt) return LUDOFILE_ERROR_MEMORY;
    
    nt->name = strdup(name);
    if (!nt->name) {
        free(nt);
        return LUDOFILE_ERROR_MEMORY;
    }
    
    nt->test = test;
    nt->next = matcher->named_tests[idx];
    matcher->named_tests[idx] = nt;
    
    return LUDOFILE_OK;
}

/*
 * Get a named test from the matcher
 */
MagicTest* magic_matcher_get_named_test(MagicMatcher *matcher, const char *name) {
    if (!matcher || !name) return NULL;
    
    size_t idx = hash_string(name) % matcher->named_tests_size;
    
    NamedTest *nt = matcher->named_tests[idx];
    while (nt) {
        if (strcmp(nt->name, name) == 0) {
            return nt->test;
        }
        nt = nt->next;
    }
    
    return NULL;
}

/*
 * Create a new match context
 */
MatchContext* match_context_new(const uint8_t *data, size_t len) {
    MatchContext *ctx = malloc(sizeof(MatchContext));
    if (!ctx) return NULL;
    
    ctx->data = data;
    ctx->data_len = len;
    ctx->path = NULL;
    ctx->only_match_mime = false;
    ctx->is_executable = false;
    
    return ctx;
}

/*
 * Create match context from file
 */
MatchContext* match_context_from_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    uint8_t *data = malloc((size_t)len);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    
    if (fread(data, 1, (size_t)len, fp) != (size_t)len) {
        free(data);
        fclose(fp);
        return NULL;
    }
    
    fclose(fp);
    
    MatchContext *ctx = match_context_new(data, (size_t)len);
    if (!ctx) {
        free(data);
        return NULL;
    }
    
    ctx->path = path;
    
    /* Check if executable (simplified check) */
    #ifdef _WIN32
    ctx->is_executable = false;
    #else
    /* Would normally check file permissions */
    ctx->is_executable = false;
    #endif
    
    return ctx;
}

/*
 * Free match context
 */
void match_context_free(MatchContext *context) {
    if (context) {
        /* Note: data may be owned by caller or allocated here */
        if (context->path) {
            /* Data was allocated by match_context_from_file */
            free((void*)context->data);
        }
        free(context);
    }
}

/*
 * Perform numeric comparison test
 */
static MatchResult* test_numeric(MagicTestExt *test, const uint8_t *data,
                                  size_t data_len, size_t offset, MatchResult *parent) {
    NumericDataSpec *spec = &test->data.numeric.spec;
    NumericTestValue *expected = &test->data.numeric.expected;
    
    if (offset + (size_t)spec->num_bytes > data_len) {
        return NULL;
    }
    
    int64_t value = 0;
    const uint8_t *ptr = data + offset;
    
    if (spec->endianness == ENDIAN_LITTLE) {
        for (int i = 0; i < spec->num_bytes; i++) {
            value |= ((int64_t)ptr[i]) << (i * 8);
        }
    } else if (spec->endianness == ENDIAN_BIG) {
        for (int i = 0; i < spec->num_bytes; i++) {
            value |= ((int64_t)ptr[i]) << ((spec->num_bytes - 1 - i) * 8);
        }
    } else if (spec->endianness == ENDIAN_PDP) {
        /* Middle-endian (PDP-11 style) */
        if (spec->num_bytes == 4) {
            value = ((int64_t)(ptr[1]) << 24) |
                    ((int64_t)(ptr[0]) << 16) |
                    ((int64_t)(ptr[3]) << 8) |
                    (int64_t)(ptr[2]);
        }
    } else {
        /* Native endianness */
        memcpy(&value, ptr, (size_t)spec->num_bytes);
    }
    
    /* Sign extension if needed */
    if (!spec->is_unsigned && (value & (1LL << (spec->num_bytes * 8 - 1)))) {
        value |= ~((1LL << (spec->num_bytes * 8)) - 1);
    }
    
    /* Apply preprocessing */
    if (spec->preprocess) {
        value = spec->preprocess(value);
    }
    
    /* Perform comparison */
    bool matched = false;
    if (expected->is_wildcard) {
        matched = true;
    } else {
        switch (expected->op) {
            case OP_EQUALS:
                matched = (value == expected->value);
                break;
            case OP_NOT_EQUAL:
                matched = (value != expected->value);
                break;
            case OP_LESS_THAN:
                matched = (value < expected->value);
                break;
            case OP_GREATER_THAN:
                matched = (value > expected->value);
                break;
            case OP_ALL_BITS_SET:
                matched = ((value & expected->value) == expected->value);
                break;
            case OP_ALL_BITS_CLEAR:
                matched = ((value & expected->value) == 0);
                break;
        }
    }
    
    if (matched) {
        return match_result_new(&test->base, offset, (size_t)spec->num_bytes, 
                                (void*)(intptr_t)value, parent);
    }
    
    return NULL;
}

/*
 * Perform string test
 */
static MatchResult* test_string(MagicTestExt *test, const uint8_t *data,
                                 size_t data_len, size_t offset, MatchResult *parent) {
    StringTestSpec *spec = &test->data.string;
    
    if (offset >= data_len) return NULL;
    
    if (spec->is_wildcard) {
        /* Match any null-terminated string */
        size_t len = 0;
        while (offset + len < data_len && data[offset + len] != 0) {
            len++;
        }
        return match_result_new(&test->base, offset, len, NULL, parent);
    }
    
    const uint8_t *ptr = data + offset;
    size_t remaining = data_len - offset;
    
    if (remaining < spec->pattern_len) return NULL;
    
    bool matched = true;
    
    if (spec->case_insensitive_lower || spec->case_insensitive_upper) {
        for (size_t i = 0; i < spec->pattern_len && matched; i++) {
            char c1 = (char)ptr[i];
            char c2 = (char)spec->pattern[i];
            
            if (spec->case_insensitive_lower && c2 >= 'a' && c2 <= 'z') {
                matched = (tolower((unsigned char)c1) == c2);
            } else if (spec->case_insensitive_upper && c2 >= 'A' && c2 <= 'Z') {
                matched = (toupper((unsigned char)c1) == c2);
            } else {
                matched = (c1 == c2);
            }
        }
    } else {
        matched = (memcmp(ptr, spec->pattern, spec->pattern_len) == 0);
    }
    
    if (spec->is_negated) {
        matched = !matched;
    }
    
    if (matched) {
        return match_result_new(&test->base, offset, spec->pattern_len, NULL, parent);
    }
    
    return NULL;
}

/*
 * Test function dispatcher
 */
static MatchResult* run_test(MagicTest *test, const uint8_t *data, size_t data_len,
                              size_t offset, MatchResult *parent) {
    MagicTestExt *ext = (MagicTestExt*)test;
    
    switch (ext->data_type_category) {
        case DATA_TYPE_NUMERIC:
            return test_numeric(ext, data, data_len, offset, parent);
        case DATA_TYPE_STRING:
            return test_string(ext, data, data_len, offset, parent);
        case DATA_TYPE_DEFAULT:
            /* Default test matches if no sibling matched */
            if (parent && !parent->matched) {
                return match_result_new(test, offset, 0, NULL, parent);
            }
            return NULL;
        case DATA_TYPE_CLEAR:
            /* Clear test always matches and resets sibling match state */
            return match_result_new(test, offset, 0, NULL, parent);
        default:
            /* TODO: Implement other test types */
            return NULL;
    }
}

/*
 * Recursively match a test and its children
 */
static void match_test(MagicTest *test, MatchContext *ctx, Match *match,
                       MatchResult *parent_result) {
    /* Calculate absolute offset */
    int64_t abs_offset = offset_to_absolute(&test->offset, ctx->data, 
                                             ctx->data_len, parent_result);
    if (abs_offset < 0 || (size_t)abs_offset >= ctx->data_len) {
        return;
    }
    
    /* Run the test */
    MatchResult *result = run_test(test, ctx->data, ctx->data_len, 
                                    (size_t)abs_offset, parent_result);
    
    if (result) {
        /* Add to results */
        if (match->num_results >= match->results_capacity) {
            size_t new_cap = match->results_capacity == 0 ? 
                             16 : match->results_capacity * 2;
            MatchResult **new_results = realloc(match->results, 
                                                new_cap * sizeof(MatchResult*));
            if (new_results) {
                match->results = new_results;
                match->results_capacity = new_cap;
            }
        }
        
        if (match->num_results < match->results_capacity) {
            match->results[match->num_results++] = result;
        }
        
        /* Match children */
        for (size_t i = 0; i < test->num_children; i++) {
            match_test(test->children[i], ctx, match, result);
        }
    }
}

/*
 * Match against context
 */
Match* magic_matcher_match_context(MagicMatcher *matcher, MatchContext *context) {
    if (!matcher || !context) return NULL;
    
    Match *match = calloc(1, sizeof(Match));
    if (!match) return NULL;
    
    match->matcher = matcher;
    match->context = context;
    
    /* Try all tests */
    for (size_t i = 0; i < matcher->num_tests; i++) {
        match_test(matcher->tests[i], context, match, NULL);
    }
    
    return match;
}

/*
 * Match against raw data
 */
Match* magic_matcher_match(MagicMatcher *matcher, const uint8_t *data, size_t len) {
    MatchContext *ctx = match_context_new(data, len);
    if (!ctx) return NULL;
    
    Match *result = magic_matcher_match_context(matcher, ctx);
    
    /* Note: Don't free context as it's referenced by match */
    
    return result;
}

/*
 * Match against file
 */
Match* magic_matcher_match_file(MagicMatcher *matcher, const char *path) {
    MatchContext *ctx = match_context_from_file(path);
    if (!ctx) return NULL;
    
    return magic_matcher_match_context(matcher, ctx);
}

/*
 * Get message from match
 */
const char* match_get_message(Match *match) {
    if (!match || match->num_results == 0) return NULL;
    
    /* Build message from results */
    /* TODO: Proper message construction */
    if (match->results[0]->test->message) {
        return match->results[0]->test->message;
    }
    
    return NULL;
}

/*
 * Get MIME types from match
 */
const char** match_get_mimetypes(Match *match, size_t *count) {
    if (!match || !count) return NULL;
    
    *count = 0;
    
    /* Count MIME types */
    for (size_t i = 0; i < match->num_results; i++) {
        if (match->results[i]->test->mime) {
            (*count)++;
        }
    }
    
    if (*count == 0) return NULL;
    
    const char **mimes = malloc(*count * sizeof(char*));
    if (!mimes) {
        *count = 0;
        return NULL;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < match->num_results && j < *count; i++) {
        if (match->results[i]->test->mime) {
            mimes[j++] = match->results[i]->test->mime;
        }
    }
    
    return mimes;
}

/*
 * Free match
 */
void match_free(Match *match) {
    if (!match) return;
    
    for (size_t i = 0; i < match->num_results; i++) {
        match_result_free(match->results[i]);
    }
    free(match->results);
    
    /* Context is owned by match if it was created internally */
    match_context_free(match->context);
    
    free(match);
}
