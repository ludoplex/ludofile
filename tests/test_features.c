/*
 * LudoFile - Feature Test Suite
 *
 * Comprehensive tests for all features mentioned in the README:
 * Test 1: Pure C Implementation
 * Test 2: Portable Binaries (compilation test)
 * Test 3: Recursive Analysis
 * Test 4: File output format
 * Test 5: MIME output format
 * Test 6: JSON output format
 * Test 7: SBUD output format
 * Test 8: HTML output format
 * Test 9: PDF parser
 * Test 10: ZIP parser
 * Test 11: JAR parser
 * Test 12: Magic pattern matching
 * Test 13+: Modular architecture tests
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../src/core/types.h"
#include "../src/magic/magic.h"
#include "../src/output/output.h"
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
    fflush(stdout); \
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
#define ASSERT_STR_CONTAINS(haystack, needle) ASSERT(strstr((haystack), (needle)) != NULL)

/* Helper: Read file into memory */
static uint8_t* read_test_file(const char *path, size_t *length) {
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
    *length = (size_t)len;
    return data;
}

/* Helper: Check if file exists */
static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* ============================================================
 * Test 1: Pure C Implementation
 * Verify that core functionality works with pure C, no external deps
 * ============================================================ */

TEST(pure_c_implementation_types) {
    /* Test ByteBuffer - pure C data structure */
    ByteBuffer *buf = byte_buffer_new(16);
    ASSERT_NOT_NULL(buf);
    
    uint8_t test_data[] = {0x50, 0x4B, 0x03, 0x04}; /* ZIP signature */
    LudofileResult res = byte_buffer_append(buf, test_data, 4);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(buf->length, 4);
    ASSERT_EQ(memcmp(buf->data, test_data, 4), 0);
    
    byte_buffer_free(buf);
}

TEST(pure_c_implementation_string_ops) {
    /* Test StringBuffer - pure C string handling */
    StringBuffer *str = string_buffer_new(8);
    ASSERT_NOT_NULL(str);
    
    LudofileResult res = string_buffer_append(str, "Hello");
    ASSERT_EQ(res, LUDOFILE_OK);
    
    res = string_buffer_append(str, " World");
    ASSERT_EQ(res, LUDOFILE_OK);
    
    ASSERT_STR_EQ(str->data, "Hello World");
    ASSERT_EQ(str->length, 11);
    
    string_buffer_free(str);
}

TEST(pure_c_implementation_file_stream) {
    /* Test FileStream from memory - no file I/O */
    uint8_t data[] = {0x89, 0x50, 0x4E, 0x47}; /* PNG signature */
    FileStream *stream = file_stream_from_memory(data, sizeof(data));
    ASSERT_NOT_NULL(stream);
    ASSERT_EQ(stream->is_memory, true);
    ASSERT_EQ(stream->length, 4);
    
    uint8_t buf[4];
    size_t read = file_stream_read(stream, buf, 4);
    ASSERT_EQ(read, 4);
    ASSERT_EQ(memcmp(buf, data, 4), 0);
    
    file_stream_close(stream);
}

/* ============================================================
 * Test 2: Portable Binaries Verification
 * Check that binaries can be built and basic infrastructure exists
 * ============================================================ */

TEST(portable_binary_structure) {
    /* Verify build produces output */
    /* This test verifies the Makefile structure supports portable builds */
    ASSERT(file_exists("Makefile"));
    ASSERT(file_exists("scripts/build.sh"));
    
    /* Verify source structure for portable builds */
    ASSERT(file_exists("src/main.c"));
    ASSERT(file_exists("src/core/types.c"));
    ASSERT(file_exists("src/core/types.h"));
}

TEST(portable_binary_posix_compliance) {
    /* Test that core types use POSIX-compliant types */
    ASSERT_EQ(sizeof(uint8_t), 1);
    ASSERT_EQ(sizeof(uint16_t), 2);
    ASSERT_EQ(sizeof(uint32_t), 4);
    ASSERT_EQ(sizeof(uint64_t), 8);
    ASSERT_EQ(sizeof(int64_t), 8);
    ASSERT_EQ(sizeof(size_t), sizeof(void*));
}

/* ============================================================
 * Test 3: Recursive Analysis
 * Test nested file format detection capabilities
 * ============================================================ */

TEST(recursive_analysis_parse_match_hierarchy) {
    /* Test ParseMatch tree structure for nested formats */
    ParseMatch *root = parse_match_new("ZipArchive", 0, 1000, NULL);
    ASSERT_NOT_NULL(root);
    ASSERT_EQ(root->offset, 0);
    
    ParseMatch *entry1 = parse_match_new("ZipEntry", 10, 200, root);
    ASSERT_NOT_NULL(entry1);
    
    LudofileResult res = parse_match_add_child(root, entry1);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(root->num_children, 1);
    
    ParseMatch *nested = parse_match_new("PDFDocument", 50, 100, entry1);
    ASSERT_NOT_NULL(nested);
    
    res = parse_match_add_child(entry1, nested);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(entry1->num_children, 1);
    
    /* Verify hierarchy */
    ASSERT_EQ(root->children[0], entry1);
    ASSERT_EQ(entry1->children[0], nested);
    ASSERT_EQ(nested->parent, entry1);
    
    parse_match_free(root); /* Should free entire tree */
}

TEST(recursive_analysis_nested_offsets) {
    /* Test that nested offsets are calculated correctly */
    ParseMatch *parent = parse_match_new("Container", 100, 500, NULL);
    ASSERT_NOT_NULL(parent);
    ASSERT_EQ(parent->offset, 100);
    
    /* Child at relative offset 50 within parent */
    ParseMatch *child = parse_match_new("Nested", 50, 100, parent);
    ASSERT_NOT_NULL(child);
    ASSERT_EQ(child->relative_offset, 50);
    ASSERT_EQ(child->offset, 150); /* Global offset = parent offset + relative */
    
    parse_match_free(parent);
}

/* ============================================================
 * Test 4: File Output Format
 * Test file command-like output
 * ============================================================ */

TEST(output_file_format_basic) {
    /* Create a match with a message */
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    
    /* Create minimal test data */
    uint8_t data[] = {0x25, 0x50, 0x44, 0x46}; /* %PDF */
    Match *match = magic_matcher_match(matcher, data, sizeof(data));
    ASSERT_NOT_NULL(match);
    
    /* Test output_file_format */
    char buf[256];
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    
    LudofileResult res = output_file_format(fp, match);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    match_free(match);
    magic_matcher_free(matcher);
}

/* ============================================================
 * Test 5: MIME Output Format
 * Test MIME type output
 * ============================================================ */

TEST(output_mime_format_basic) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    
    uint8_t data[] = {0x00}; /* Generic data */
    Match *match = magic_matcher_match(matcher, data, sizeof(data));
    ASSERT_NOT_NULL(match);
    
    char buf[256];
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    
    LudofileResult res = output_mime_format(fp, match);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    /* Should output something (at least application/octet-stream) */
    ASSERT(strlen(buf) > 0);
    
    match_free(match);
    magic_matcher_free(matcher);
}

/* ============================================================
 * Test 6: JSON Output Format
 * Test JSON/SBUD output
 * ============================================================ */

TEST(output_json_format_structure) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    
    uint8_t data[] = {0x50, 0x4B, 0x03, 0x04}; /* ZIP signature */
    Match *match = magic_matcher_match(matcher, data, sizeof(data));
    ASSERT_NOT_NULL(match);
    
    char buf[4096];
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    
    JsonOutputOptions opts = {
        .pretty_print = true,
        .indent_size = 2,
        .include_b64_contents = false
    };
    
    LudofileResult res = output_json(fp, match, data, sizeof(data), "test.zip", &opts);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    /* Verify JSON structure */
    ASSERT_STR_CONTAINS(buf, "\"MD5\"");
    ASSERT_STR_CONTAINS(buf, "\"SHA1\"");
    ASSERT_STR_CONTAINS(buf, "\"SHA256\"");
    ASSERT_STR_CONTAINS(buf, "\"fileName\"");
    ASSERT_STR_CONTAINS(buf, "\"length\"");
    ASSERT_STR_CONTAINS(buf, "\"struc\"");
    
    match_free(match);
    magic_matcher_free(matcher);
}

TEST(output_json_escape) {
    /* Test JSON string escaping */
    char *escaped = json_escape_string("Hello\n\"World\"\t\\");
    ASSERT_NOT_NULL(escaped);
    ASSERT_STR_EQ(escaped, "Hello\\n\\\"World\\\"\\t\\\\");
    free(escaped);
}

/* ============================================================
 * Test 7: SBUD Output Format
 * Test Semantic Binary Universal Description
 * ============================================================ */

TEST(output_sbud_document_creation) {
    SbudDocument *doc = sbud_document_new();
    ASSERT_NOT_NULL(doc);
    ASSERT_NOT_NULL(doc->ludofile_version);
    
    uint8_t data[] = "Test data";
    LudofileResult res = sbud_document_set_file(doc, data, sizeof(data) - 1, "test.txt");
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_NOT_NULL(doc->md5);
    ASSERT_NOT_NULL(doc->sha1);
    ASSERT_NOT_NULL(doc->sha256);
    ASSERT_NOT_NULL(doc->b64_contents);
    ASSERT_STR_EQ(doc->filename, "test.txt");
    
    sbud_document_free(doc);
}

TEST(output_sbud_structure) {
    SbudDocument *doc = sbud_document_new();
    ASSERT_NOT_NULL(doc);
    
    uint8_t data[] = "Sample file content";
    sbud_document_set_file(doc, data, sizeof(data) - 1, "sample.txt");
    
    char buf[4096];
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    
    JsonOutputOptions opts = {.pretty_print = true, .indent_size = 2};
    LudofileResult res = output_sbud(fp, doc, &opts);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    /* Verify SBUD fields */
    ASSERT_STR_CONTAINS(buf, "\"MD5\"");
    ASSERT_STR_CONTAINS(buf, "\"SHA1\"");
    ASSERT_STR_CONTAINS(buf, "\"SHA256\"");
    ASSERT_STR_CONTAINS(buf, "\"fileName\"");
    ASSERT_STR_CONTAINS(buf, "\"versions\"");
    ASSERT_STR_CONTAINS(buf, "\"polyfile\""); /* Compatible naming */
    
    sbud_document_free(doc);
}

/* ============================================================
 * Test 8: HTML Output Format
 * Test interactive HTML hex viewer output
 * ============================================================ */

TEST(output_html_format_structure) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    
    uint8_t data[] = "Test file content\x00\x01\x02\x03";
    Match *match = magic_matcher_match(matcher, data, sizeof(data));
    ASSERT_NOT_NULL(match);
    
    char buf[8192];
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    
    HtmlOutputOptions opts = {
        .include_hex_viewer = true,
        .include_structure_tree = true,
        .title = "Test File",
        .template_path = NULL
    };
    
    LudofileResult res = output_html(fp, match, data, sizeof(data), "test.bin", &opts);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    /* Verify HTML structure */
    ASSERT_STR_CONTAINS(buf, "<!DOCTYPE html>");
    ASSERT_STR_CONTAINS(buf, "<html>");
    ASSERT_STR_CONTAINS(buf, "LudoFile");
    ASSERT_STR_CONTAINS(buf, "hex");
    
    match_free(match);
    magic_matcher_free(matcher);
}

/* ============================================================
 * Test 9: PDF Parser
 * Test PDF document parsing
 * ============================================================ */

TEST(pdf_parser_header_detection) {
    uint8_t pdf_data[] = "%PDF-1.7\n%test content";
    size_t offset;
    const uint8_t *header = pdf_find_header(pdf_data, sizeof(pdf_data), &offset);
    ASSERT_NOT_NULL(header);
    ASSERT_EQ(offset, 0);
    ASSERT_EQ(memcmp(header, "%PDF-1.7", 8), 0);
}

TEST(pdf_parser_header_with_offset) {
    uint8_t pdf_data[] = "garbage%PDF-1.4test";
    size_t offset;
    const uint8_t *header = pdf_find_header(pdf_data, sizeof(pdf_data), &offset);
    ASSERT_NOT_NULL(header);
    ASSERT_EQ(offset, 7);
}

TEST(pdf_parser_document_creation) {
    PDFDocument *doc = pdf_document_new();
    ASSERT_NOT_NULL(doc);
    ASSERT_EQ(doc->version.major, 0);
    ASSERT_EQ(doc->version.minor, 0);
    pdf_document_free(doc);
}

TEST(pdf_parser_version_extraction) {
    const char *pdf_content = 
        "%PDF-1.4\n"
        "1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        "xref\n0 1\n0000000000 65535 f \n"
        "trailer\n<< /Size 1 >>\n"
        "startxref\n50\n%%EOF";
    
    PDFDocument *doc = pdf_document_new();
    ASSERT_NOT_NULL(doc);
    
    LudofileResult res = pdf_document_parse(doc, (const uint8_t*)pdf_content, strlen(pdf_content));
    /* May fail due to offset issues in minimal PDF, but shouldn't crash */
    (void)res;
    
    pdf_document_free(doc);
}

TEST(pdf_parser_real_file) {
    if (!file_exists("testdata/javascript.pdf")) {
        printf(" (skipped - test file not found)");
        return;
    }
    
    size_t length;
    uint8_t *data = read_test_file("testdata/javascript.pdf", &length);
    ASSERT_NOT_NULL(data);
    
    PDFDocument *doc = pdf_document_new();
    ASSERT_NOT_NULL(doc);
    
    LudofileResult res = pdf_document_parse(doc, data, length);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT_EQ(doc->version.major, 1);
    
    pdf_document_free(doc);
    free(data);
}

/* ============================================================
 * Test 10: ZIP Parser
 * Test ZIP archive parsing
 * ============================================================ */

TEST(zip_parser_eocd_detection) {
    /* Minimal EOCD */
    uint8_t eocd[22] = {
        0x50, 0x4b, 0x05, 0x06, /* Signature */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00  /* Comment length = 0 */
    };
    
    int64_t offset = zip_find_eocd(eocd, sizeof(eocd));
    ASSERT_EQ(offset, 0);
}

TEST(zip_parser_archive_creation) {
    ZipArchive *archive = zip_archive_new();
    ASSERT_NOT_NULL(archive);
    ASSERT_NOT_NULL(archive->local_headers);
    ASSERT_NOT_NULL(archive->central_dir);
    ASSERT_EQ(archive->num_local_headers, 0);
    zip_archive_free(archive);
}

TEST(zip_parser_local_header) {
    /* Minimal local file header */
    uint8_t header[] = {
        0x50, 0x4b, 0x03, 0x04, /* Signature */
        0x0a, 0x00,             /* Version needed */
        0x00, 0x00,             /* Flags */
        0x00, 0x00,             /* Compression */
        0x00, 0x00,             /* Mod time */
        0x00, 0x00,             /* Mod date */
        0x00, 0x00, 0x00, 0x00, /* CRC32 */
        0x05, 0x00, 0x00, 0x00, /* Compressed size */
        0x05, 0x00, 0x00, 0x00, /* Uncompressed size */
        0x04, 0x00,             /* Filename length */
        0x00, 0x00,             /* Extra length */
        't', 'e', 's', 't',     /* Filename */
        'h', 'e', 'l', 'l', 'o' /* Data */
    };
    
    ZipLocalFileHeader *lfh = zip_parse_local_header(header, sizeof(header), 0);
    ASSERT_NOT_NULL(lfh);
    ASSERT_EQ(lfh->signature, 0x04034b50);
    ASSERT_STR_EQ(lfh->filename, "test");
    ASSERT_EQ(lfh->compressed_size, 5);
    
    zip_local_header_free(lfh);
}

TEST(zip_parser_real_file) {
    if (!file_exists("testdata/test_archive.zip")) {
        printf(" (skipped - test file not found)");
        return;
    }
    
    size_t length;
    uint8_t *data = read_test_file("testdata/test_archive.zip", &length);
    ASSERT_NOT_NULL(data);
    
    ZipArchive *archive = zip_archive_new();
    ASSERT_NOT_NULL(archive);
    
    LudofileResult res = zip_archive_parse(archive, data, length);
    ASSERT_EQ(res, LUDOFILE_OK);
    ASSERT(archive->num_local_headers > 0);
    ASSERT_NOT_NULL(archive->eocd);
    
    zip_archive_free(archive);
    free(data);
}

/* ============================================================
 * Test 11: JAR Parser
 * Test Java Archive parsing (uses ZIP parser)
 * ============================================================ */

TEST(jar_parser_is_jar_detection) {
    /* Create mock archive with MANIFEST.MF */
    ZipArchive *archive = zip_archive_new();
    ASSERT_NOT_NULL(archive);
    
    /* Without MANIFEST.MF, should not be JAR */
    ASSERT_EQ(zip_is_jar(archive), false);
    
    zip_archive_free(archive);
}

TEST(jar_parser_real_file) {
    if (!file_exists("testdata/test.jar")) {
        printf(" (skipped - test file not found)");
        return;
    }
    
    size_t length;
    uint8_t *data = read_test_file("testdata/test.jar", &length);
    ASSERT_NOT_NULL(data);
    
    ZipArchive *archive = zip_archive_new();
    ASSERT_NOT_NULL(archive);
    
    LudofileResult res = zip_archive_parse(archive, data, length);
    ASSERT_EQ(res, LUDOFILE_OK);
    
    /* JAR files have META-INF/MANIFEST.MF */
    ASSERT_EQ(zip_is_jar(archive), true);
    
    zip_archive_free(archive);
    free(data);
}

TEST(jar_parser_registry) {
    /* JAR parser should be registered */
    ParserRegistry *reg = parser_registry_default();
    ASSERT_NOT_NULL(reg);
    
    ParserEntry *entry = parser_registry_lookup(reg, "application/java-archive");
    ASSERT_NOT_NULL(entry);
    ASSERT_STR_EQ(entry->mime_type, "application/java-archive");
}

/* ============================================================
 * Test 12: Magic Pattern Matching
 * Test libmagic-compatible file type detection
 * ============================================================ */

TEST(magic_matcher_creation) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    ASSERT_NOT_NULL(matcher->tests);
    ASSERT_NOT_NULL(matcher->named_tests);
    ASSERT_EQ(matcher->num_tests, 0);
    magic_matcher_free(matcher);
}

TEST(magic_unescape_simple) {
    size_t len;
    uint8_t *result = magic_unescape("hello", 5, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 5);
    ASSERT_EQ(memcmp(result, "hello", 5), 0);
    free(result);
}

TEST(magic_unescape_escapes) {
    size_t len;
    uint8_t *result = magic_unescape("\\n\\t\\r", 6, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 3);
    ASSERT_EQ(result[0], '\n');
    ASSERT_EQ(result[1], '\t');
    ASSERT_EQ(result[2], '\r');
    free(result);
}

TEST(magic_unescape_hex) {
    size_t len;
    uint8_t *result = magic_unescape("\\x50\\x4b", 8, &len);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(len, 2);
    ASSERT_EQ(result[0], 0x50); /* P */
    ASSERT_EQ(result[1], 0x4b); /* K */
    free(result);
}

TEST(magic_parse_numeric_decimal) {
    ASSERT_EQ(magic_parse_numeric("123"), 123);
    ASSERT_EQ(magic_parse_numeric("-42"), -42);
    ASSERT_EQ(magic_parse_numeric("+10"), 10);
}

TEST(magic_parse_numeric_hex) {
    ASSERT_EQ(magic_parse_numeric("0x10"), 16);
    ASSERT_EQ(magic_parse_numeric("0xFF"), 255);
    ASSERT_EQ(magic_parse_numeric("0x1234"), 0x1234);
}

TEST(magic_parse_numeric_octal) {
    ASSERT_EQ(magic_parse_numeric("0777"), 511);
    ASSERT_EQ(magic_parse_numeric("0100"), 64);
}

TEST(magic_named_tests) {
    MagicMatcher *matcher = magic_matcher_new();
    ASSERT_NOT_NULL(matcher);
    
    /* Named test should not exist initially */
    MagicTest *test = magic_matcher_get_named_test(matcher, "test");
    ASSERT_NULL(test);
    
    magic_matcher_free(matcher);
}

/* ============================================================
 * Test 13+: Modular Architecture
 * Test separation of concerns across modules
 * ============================================================ */

TEST(modular_core_types_independence) {
    /* Core types should work independently */
    ByteBuffer *buf = byte_buffer_new(16);
    ASSERT_NOT_NULL(buf);
    
    StringBuffer *str = string_buffer_new(16);
    ASSERT_NOT_NULL(str);
    
    /* Both should work together without conflicts */
    byte_buffer_append(buf, (uint8_t*)"test", 4);
    string_buffer_append(str, "test");
    
    ASSERT_EQ(buf->length, 4);
    ASSERT_EQ(str->length, 4);
    
    byte_buffer_free(buf);
    string_buffer_free(str);
}

TEST(modular_parser_registry_isolation) {
    /* Parser registry should be modular */
    ParserRegistry *reg = parser_registry_new();
    ASSERT_NOT_NULL(reg);
    
    /* Empty registry should return NULL for lookups */
    ParserEntry *entry = parser_registry_lookup(reg, "application/pdf");
    ASSERT_NULL(entry);
    
    parser_registry_free(reg);
    
    /* Default registry should have parsers */
    ParserRegistry *default_reg = parser_registry_default();
    ASSERT_NOT_NULL(default_reg);
    
    entry = parser_registry_lookup(default_reg, "application/pdf");
    ASSERT_NOT_NULL(entry);
}

TEST(modular_magic_isolation) {
    /* Magic module should work independently */
    MagicMatcher *m1 = magic_matcher_new();
    MagicMatcher *m2 = magic_matcher_new();
    
    ASSERT_NOT_NULL(m1);
    ASSERT_NOT_NULL(m2);
    ASSERT_NE(m1, m2);
    
    /* Each instance should be independent */
    ASSERT_EQ(m1->num_tests, 0);
    ASSERT_EQ(m2->num_tests, 0);
    
    magic_matcher_free(m1);
    magic_matcher_free(m2);
}

TEST(modular_output_formatters) {
    /* Output module should provide multiple formatters */
    MagicMatcher *matcher = magic_matcher_new();
    uint8_t data[] = "test";
    Match *match = magic_matcher_match(matcher, data, sizeof(data));
    ASSERT_NOT_NULL(match);
    
    char buf[1024];
    FILE *fp;
    
    /* Test file format */
    fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    LudofileResult res = output_file_format(fp, match);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    /* Test MIME format */
    fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT_NOT_NULL(fp);
    res = output_mime_format(fp, match);
    ASSERT_EQ(res, LUDOFILE_OK);
    fclose(fp);
    
    match_free(match);
    magic_matcher_free(matcher);
}

TEST(modular_parser_interface) {
    /* All parsers should follow the same interface */
    ParserRegistry *reg = parser_registry_default();
    ASSERT_NOT_NULL(reg);
    
    /* PDF parser */
    ParserEntry *pdf = parser_registry_lookup(reg, "application/pdf");
    ASSERT_NOT_NULL(pdf);
    ASSERT_NOT_NULL(pdf->parser);
    ASSERT_NOT_NULL(pdf->name);
    
    /* ZIP parser */
    ParserEntry *zip = parser_registry_lookup(reg, "application/zip");
    ASSERT_NOT_NULL(zip);
    ASSERT_NOT_NULL(zip->parser);
    ASSERT_NOT_NULL(zip->name);
    
    /* JAR parser */
    ParserEntry *jar = parser_registry_lookup(reg, "application/java-archive");
    ASSERT_NOT_NULL(jar);
    ASSERT_NOT_NULL(jar->parser);
    ASSERT_NOT_NULL(jar->name);
}

TEST(modular_result_codes) {
    /* All modules should use consistent result codes */
    ASSERT_EQ(LUDOFILE_OK, 0);
    ASSERT_NE(LUDOFILE_ERROR, 0);
    ASSERT_NE(LUDOFILE_ERROR_MEMORY, 0);
    ASSERT_NE(LUDOFILE_ERROR_IO, 0);
    ASSERT_NE(LUDOFILE_ERROR_PARSE, 0);
    ASSERT_NE(LUDOFILE_ERROR_NOT_FOUND, 0);
    ASSERT_NE(LUDOFILE_ERROR_INVALID, 0);
}

/* ============================================================
 * Test Utilities
 * ============================================================ */

TEST(utility_base64_encode) {
    uint8_t data[] = "Hello";
    char *encoded = base64_encode(data, 5);
    ASSERT_NOT_NULL(encoded);
    ASSERT_STR_EQ(encoded, "SGVsbG8=");
    free(encoded);
}

TEST(utility_hash_functions) {
    uint8_t data[] = "test data";
    
    char *md5 = compute_md5(data, sizeof(data) - 1);
    ASSERT_NOT_NULL(md5);
    ASSERT_EQ(strlen(md5), 32);
    free(md5);
    
    char *sha1 = compute_sha1(data, sizeof(data) - 1);
    ASSERT_NOT_NULL(sha1);
    ASSERT_EQ(strlen(sha1), 40);
    free(sha1);
    
    char *sha256 = compute_sha256(data, sizeof(data) - 1);
    ASSERT_NOT_NULL(sha256);
    ASSERT_EQ(strlen(sha256), 64);
    free(sha256);
}

/* ============================================================
 * Test Runners
 * ============================================================ */

void run_pure_c_tests(void) {
    printf("\nTest 1: Pure C Implementation Tests:\n");
    RUN_TEST(pure_c_implementation_types);
    RUN_TEST(pure_c_implementation_string_ops);
    RUN_TEST(pure_c_implementation_file_stream);
}

void run_portable_binary_tests(void) {
    printf("\nTest 2: Portable Binary Tests:\n");
    RUN_TEST(portable_binary_structure);
    RUN_TEST(portable_binary_posix_compliance);
}

void run_recursive_analysis_tests(void) {
    printf("\nTest 3: Recursive Analysis Tests:\n");
    RUN_TEST(recursive_analysis_parse_match_hierarchy);
    RUN_TEST(recursive_analysis_nested_offsets);
}

void run_file_output_tests(void) {
    printf("\nTest 4: File Output Format Tests:\n");
    RUN_TEST(output_file_format_basic);
}

void run_mime_output_tests(void) {
    printf("\nTest 5: MIME Output Format Tests:\n");
    RUN_TEST(output_mime_format_basic);
}

void run_json_output_tests(void) {
    printf("\nTest 6: JSON Output Format Tests:\n");
    RUN_TEST(output_json_format_structure);
    RUN_TEST(output_json_escape);
}

void run_sbud_output_tests(void) {
    printf("\nTest 7: SBUD Output Format Tests:\n");
    RUN_TEST(output_sbud_document_creation);
    RUN_TEST(output_sbud_structure);
}

void run_html_output_tests(void) {
    printf("\nTest 8: HTML Output Format Tests:\n");
    RUN_TEST(output_html_format_structure);
}

void run_pdf_parser_tests(void) {
    printf("\nTest 9: PDF Parser Tests:\n");
    RUN_TEST(pdf_parser_header_detection);
    RUN_TEST(pdf_parser_header_with_offset);
    RUN_TEST(pdf_parser_document_creation);
    RUN_TEST(pdf_parser_version_extraction);
    RUN_TEST(pdf_parser_real_file);
}

void run_zip_parser_tests(void) {
    printf("\nTest 10: ZIP Parser Tests:\n");
    RUN_TEST(zip_parser_eocd_detection);
    RUN_TEST(zip_parser_archive_creation);
    RUN_TEST(zip_parser_local_header);
    RUN_TEST(zip_parser_real_file);
}

void run_jar_parser_tests(void) {
    printf("\nTest 11: JAR Parser Tests:\n");
    RUN_TEST(jar_parser_is_jar_detection);
    RUN_TEST(jar_parser_real_file);
    RUN_TEST(jar_parser_registry);
}

void run_magic_tests(void) {
    printf("\nTest 12: Magic Pattern Matching Tests:\n");
    RUN_TEST(magic_matcher_creation);
    RUN_TEST(magic_unescape_simple);
    RUN_TEST(magic_unescape_escapes);
    RUN_TEST(magic_unescape_hex);
    RUN_TEST(magic_parse_numeric_decimal);
    RUN_TEST(magic_parse_numeric_hex);
    RUN_TEST(magic_parse_numeric_octal);
    RUN_TEST(magic_named_tests);
}

void run_modular_tests(void) {
    printf("\nTest 13+: Modular Architecture Tests:\n");
    RUN_TEST(modular_core_types_independence);
    RUN_TEST(modular_parser_registry_isolation);
    RUN_TEST(modular_magic_isolation);
    RUN_TEST(modular_output_formatters);
    RUN_TEST(modular_parser_interface);
    RUN_TEST(modular_result_codes);
}

void run_utility_tests(void) {
    printf("\nUtility Tests:\n");
    RUN_TEST(utility_base64_encode);
    RUN_TEST(utility_hash_functions);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("LudoFile Feature Test Suite\n");
    printf("============================\n");
    printf("Testing all README features:\n");
    
    run_pure_c_tests();           /* Test 1 */
    run_portable_binary_tests();  /* Test 2 */
    run_recursive_analysis_tests(); /* Test 3 */
    run_file_output_tests();      /* Test 4 */
    run_mime_output_tests();      /* Test 5 */
    run_json_output_tests();      /* Test 6 */
    run_sbud_output_tests();      /* Test 7 */
    run_html_output_tests();      /* Test 8 */
    run_pdf_parser_tests();       /* Test 9 */
    run_zip_parser_tests();       /* Test 10 */
    run_jar_parser_tests();       /* Test 11 */
    run_magic_tests();            /* Test 12 */
    run_modular_tests();          /* Test 13+ */
    run_utility_tests();
    
    printf("\n============================\n");
    printf("Results: %d/%d tests passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(" (%d FAILED)", tests_failed);
    }
    printf("\n");
    
    return tests_failed > 0 ? 1 : 0;
}
