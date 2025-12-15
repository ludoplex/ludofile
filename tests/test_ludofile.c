/*
 * LudoFile - Test Suite
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/core/types.h"
#include "../src/magic/magic.h"
#include "../src/parsers/parser.h"
#include "../src/parsers/pdf.h"
#include "../src/parsers/zip.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros */
#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s...", #name); \
    tests_run++; \
    test_##name(); \
    tests_passed++; \
    printf(" PASSED\n"); \
} while(0)

#define ASSERT(expr) do { \
    if (!(expr)) { \
        printf(" FAILED\n"); \
        printf("    Assertion failed: %s\n", #expr); \
        printf("    At %s:%d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(a) ASSERT((a) == NULL)
#define ASSERT_NOT_NULL(a) ASSERT((a) != NULL)
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/* ============= Core Types Tests ============= */

TEST(byte_buffer_new) {
    ByteBuffer *buf = byte_buffer_new(32);
    ASSERT_NOT_NULL(buf);
    ASSERT_NOT_NULL(buf->data);
    ASSERT_EQ(buf->length, 0);
    ASSERT_EQ(buf->capacity, 32);
    byte_buffer_free(buf);
}

TEST(byte_buffer_append) {
    ByteBuffer *buf = byte_buffer_new(8);
    ASSERT_NOT_NULL(buf);
    
    uint8_t data[] = {1, 2, 3, 4, 5};
    LudofileResult res = byte_buffer_append(buf, data, 5);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(buf->length, 5);
    ASSERT_EQ(buf->data[0], 1);
    ASSERT_EQ(buf->data[4], 5);
    
    /* Test growth */
    res = byte_buffer_append(buf, data, 5);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(buf->length, 10);
    
    byte_buffer_free(buf);
}

TEST(string_buffer_new) {
    StringBuffer *buf = string_buffer_new(32);
    ASSERT_NOT_NULL(buf);
    ASSERT_NOT_NULL(buf->data);
    ASSERT_EQ(buf->length, 0);
    ASSERT_EQ(buf->data[0], '\0');
    string_buffer_free(buf);
}

TEST(string_buffer_append) {
    StringBuffer *buf = string_buffer_new(8);
    ASSERT_NOT_NULL(buf);
    
    LudofileResult res = string_buffer_append(buf, "Hello");
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(buf->length, 5);
    ASSERT_STR_EQ(buf->data, "Hello");
    
    res = string_buffer_append(buf, " World");
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(buf->length, 11);
    ASSERT_STR_EQ(buf->data, "Hello World");
    
    string_buffer_free(buf);
}

TEST(file_stream_memory) {
    uint8_t data[] = {0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37};
    FileStream *stream = file_stream_from_memory(data, sizeof(data));
    ASSERT_NOT_NULL(stream);
    ASSERT_EQ(stream->length, sizeof(data));
    ASSERT_EQ(stream->offset, 0);
    ASSERT_EQ(stream->is_memory, true);
    
    uint8_t buf[4];
    size_t read = file_stream_read(stream, buf, 4);
    ASSERT_EQ(read, 4);
    ASSERT_EQ(buf[0], 0x50);
    ASSERT_EQ(stream->offset, 4);
    
    file_stream_close(stream);
}

TEST(parse_match_new) {
    ParseMatch *match = parse_match_new("TestType", 10, 100, NULL);
    ASSERT_NOT_NULL(match);
    ASSERT_STR_EQ(match->name, "TestType");
    ASSERT_EQ(match->relative_offset, 10);
    ASSERT_EQ(match->length, 100);
    ASSERT_EQ(match->offset, 10);
    ASSERT_NULL(match->parent);
    
    parse_match_free(match);
}

TEST(parse_match_hierarchy) {
    ParseMatch *parent = parse_match_new("Parent", 0, 1000, NULL);
    ASSERT_NOT_NULL(parent);
    
    ParseMatch *child = parse_match_new("Child", 50, 100, parent);
    ASSERT_NOT_NULL(child);
    ASSERT_EQ(child->offset, 50);  /* Global offset = parent offset + relative */
    
    LudofileResult res = parse_match_add_child(parent, child);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(parent->num_children, 1);
    ASSERT_EQ(parent->children[0], child);
    
    parse_match_free(parent);  /* Should also free child */
}

/* ============= Magic Tests ============= */

TEST(magic_matcher_new) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    ASSERT_NOT_NULL(matcher->tests);
    ASSERT_NOT_NULL(matcher->named_tests);
    ASSERT_EQ(matcher->num_tests, 0);
    magic_matcher_free(matcher);
}

TEST(magic_unescape) {
    size_t len;
    
    /* Test simple string */
    uint8_t *result = magic_unescape("hello", 5, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 5);
    ASSERT_EQ(memcmp(result, "hello", 5), 0);
    free(result);
    
    /* Test escape sequences */
    result = magic_unescape("\\n\\t\\r", 6, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 3);
    ASSERT_EQ(result[0], '\n');
    ASSERT_EQ(result[1], '\t');
    ASSERT_EQ(result[2], '\r');
    free(result);
    
    /* Test hex escape */
    result = magic_unescape("\\x50\\x4b", 8, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 2);
    ASSERT_EQ(result[0], 0x50);
    ASSERT_EQ(result[1], 0x4b);
    free(result);
}

TEST(magic_parse_numeric) {
    ASSERT_EQ(magic_parse_numeric("123"), 123);
    ASSERT_EQ(magic_parse_numeric("-42"), -42);
    ASSERT_EQ(magic_parse_numeric("0x10"), 16);
    ASSERT_EQ(magic_parse_numeric("0777"), 511);  /* Octal */
}

/* ============= Parser Tests ============= */

TEST(parser_registry) {
    ParserRegistry *reg = parser_registry_new();
    ASSERT_NOT_NULL(reg);
    ASSERT_EQ(reg->count, 0);
    
    /* Test registration - use placeholder function */
    LudofileResult res = parser_registry_register(reg, "application/test",
                                                   NULL, "Test", "Test parser");
    /* Should fail with NULL parser */
    ASSERT_EQ(res, LUDOFILE_ERROR_INVALID);
    
    parser_registry_free(reg);
}

TEST(parser_registry_default) {
    ParserRegistry *reg = parser_registry_default();
    ASSERT_NOT_NULL(reg);
    
    /* Should have PDF and ZIP parsers registered */
    ParserEntry *pdf = parser_registry_lookup(reg, "application/pdf");
    ASSERT_NOT_NULL(pdf);
    ASSERT_STR_EQ(pdf->mime_type, "application/pdf");
    
    ParserEntry *zip = parser_registry_lookup(reg, "application/zip");
    ASSERT_NOT_NULL(zip);
    ASSERT_STR_EQ(zip->mime_type, "application/zip");
}

/* ============= PDF Parser Tests ============= */

TEST(pdf_find_header) {
    uint8_t data[] = "%PDF-1.7\n%test";
    size_t offset;
    const uint8_t *header = pdf_find_header(data, sizeof(data), &offset);
    ASSERT_NOT_NULL(header);
    ASSERT_EQ(offset, 0);
    ASSERT_EQ(memcmp(header, "%PDF-1.7", 8), 0);
}

TEST(pdf_find_header_offset) {
    uint8_t data[] = "garbage%PDF-1.4test";
    size_t offset;
    const uint8_t *header = pdf_find_header(data, sizeof(data), &offset);
    ASSERT_NOT_NULL(header);
    ASSERT_EQ(offset, 7);
}

TEST(pdf_document_new) {
    PDFDocument *doc = pdf_document_new();
    ASSERT_NOT_NULL(doc);
    ASSERT_EQ(doc->version.major, 0);
    ASSERT_EQ(doc->version.minor, 0);
    ASSERT_NULL(doc->xref);
    ASSERT_NULL(doc->trailer);
    pdf_document_free(doc);
}

/* ============= ZIP Parser Tests ============= */

TEST(zip_find_eocd) {
    /* Create minimal valid EOCD */
    uint8_t data[22];
    memset(data, 0, sizeof(data));
    data[0] = 0x50;  /* PK signature */
    data[1] = 0x4b;
    data[2] = 0x05;
    data[3] = 0x06;
    /* Rest is zeros - valid empty EOCD */
    
    int64_t offset = zip_find_eocd(data, sizeof(data));
    ASSERT_EQ(offset, 0);
}

TEST(zip_archive_new) {
    ZipArchive *archive = zip_archive_new();
    ASSERT_NOT_NULL(archive);
    ASSERT_NOT_NULL(archive->local_headers);
    ASSERT_NOT_NULL(archive->central_dir);
    ASSERT_EQ(archive->num_local_headers, 0);
    ASSERT_EQ(archive->num_central_dir, 0);
    zip_archive_free(archive);
}

/* ============= Integration Tests ============= */

TEST(pdf_basic_parse) {
    /* Minimal PDF structure - note: this is for testing parser doesn't crash */
    /* A proper PDF would need correct offsets in the xref table */
    const char *pdf = "%PDF-1.4\n"
                      "1 0 obj\n<< /Type /Catalog >>\nendobj\n"
                      "xref\n0 1\n"
                      "0000000000 65535 f \n"
                      "trailer\n<< /Size 1 >>\n"
                      "startxref\n47\n%%EOF";
    
    PDFDocument *doc = pdf_document_new();
    ASSERT_NOT_NULL(doc);
    
    /* Just test that the parser doesn't crash on sample data */
    /* The offsets may not be perfect in this test data */
    pdf_document_parse(doc, (const uint8_t*)pdf, strlen(pdf));
    
    pdf_document_free(doc);
}

/* ============= Main ============= */

void run_core_tests(void) {
    printf("\nCore Types Tests:\n");
    RUN_TEST(byte_buffer_new);
    RUN_TEST(byte_buffer_append);
    RUN_TEST(string_buffer_new);
    RUN_TEST(string_buffer_append);
    RUN_TEST(file_stream_memory);
    RUN_TEST(parse_match_new);
    RUN_TEST(parse_match_hierarchy);
}

void run_magic_tests(void) {
    printf("\nMagic Tests:\n");
    RUN_TEST(magic_matcher_new);
    RUN_TEST(magic_unescape);
    RUN_TEST(magic_parse_numeric);
}

void run_parser_tests(void) {
    printf("\nParser Tests:\n");
    RUN_TEST(parser_registry);
    RUN_TEST(parser_registry_default);
}

void run_pdf_tests(void) {
    printf("\nPDF Parser Tests:\n");
    RUN_TEST(pdf_find_header);
    RUN_TEST(pdf_find_header_offset);
    RUN_TEST(pdf_document_new);
    RUN_TEST(pdf_basic_parse);
}

void run_zip_tests(void) {
    printf("\nZIP Parser Tests:\n");
    RUN_TEST(zip_find_eocd);
    RUN_TEST(zip_archive_new);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("LudoFile Test Suite\n");
    printf("==================\n");
    
    run_core_tests();
    run_magic_tests();
    run_parser_tests();
    run_pdf_tests();
    run_zip_tests();
    
    printf("\n==================\n");
    printf("Results: %d/%d tests passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(" (%d FAILED)", tests_failed);
    }
    printf("\n");
    
    return tests_failed > 0 ? 1 : 0;
}
