/*
 * LudoFile - Magic Pattern Matching Engine
 *
 * A Cosmopolitan C implementation of libmagic-compatible file type detection.
 * This module handles parsing magic definition files and matching them against
 * file content.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_MAGIC_MAGIC_H
#define LUDOFILE_MAGIC_MAGIC_H

#include "../core/types.h"

/*
 * Numeric comparison operators
 */
typedef enum {
    OP_EQUALS       = 0,
    OP_LESS_THAN    = 1,
    OP_GREATER_THAN = 2,
    OP_ALL_BITS_SET = 3,  /* & operator */
    OP_ALL_BITS_CLEAR = 4, /* ^ operator */
    OP_NOT_EQUAL    = 5   /* ! operator */
} NumericOperator;

/*
 * Data type categories
 */
typedef enum {
    DATA_TYPE_NUMERIC = 0,
    DATA_TYPE_STRING  = 1,
    DATA_TYPE_REGEX   = 2,
    DATA_TYPE_SEARCH  = 3,
    DATA_TYPE_DEFAULT = 4,
    DATA_TYPE_CLEAR   = 5,
    DATA_TYPE_INDIRECT = 6,
    DATA_TYPE_USE     = 7,
    DATA_TYPE_NAME    = 8,
    DATA_TYPE_OFFSET  = 9,
    DATA_TYPE_GUID    = 10,
    DATA_TYPE_JSON    = 11,
    DATA_TYPE_CSV     = 12,
    DATA_TYPE_DER     = 13
} DataTypeCategory;

/*
 * Numeric data type specification
 */
typedef struct {
    int num_bytes;
    bool is_unsigned;
    Endianness endianness;
    int64_t (*preprocess)(int64_t);
    /* For date types */
    bool is_date;
    bool is_local_time;
} NumericDataSpec;

/*
 * String test specification
 */
typedef struct {
    uint8_t *pattern;
    size_t   pattern_len;
    bool     case_insensitive_lower;
    bool     case_insensitive_upper;
    bool     compact_whitespace;
    bool     trim;
    bool     optional_blanks;
    bool     full_word_match;
    bool     is_wildcard;
    bool     is_negated;
    NumericOperator length_operator;  /* For >/<= length comparisons */
} StringTestSpec;

/*
 * Regex test specification
 */
typedef struct {
    char    *pattern;
    size_t   max_length;
    bool     case_insensitive;
    bool     match_to_start;
    bool     limit_lines;
    bool     trim;
    void    *compiled;  /* Compiled regex (implementation-specific) */
} RegexTestSpec;

/*
 * Search test specification
 */
typedef struct {
    uint8_t *pattern;
    size_t   pattern_len;
    size_t   max_range;
    bool     case_insensitive_lower;
    bool     case_insensitive_upper;
    bool     compact_whitespace;
    bool     trim;
} SearchTestSpec;

/*
 * Numeric test value
 */
typedef struct {
    int64_t value;
    NumericOperator op;
    bool is_wildcard;
} NumericTestValue;

/*
 * Data type specific test information
 */
typedef union {
    struct {
        NumericDataSpec spec;
        NumericTestValue expected;
    } numeric;
    StringTestSpec string;
    RegexTestSpec regex;
    SearchTestSpec search;
    /* For 'use' tests */
    struct {
        char *test_name;
        struct MagicTest *resolved_test;  /* Resolved after parsing */
        bool flip_endianness;
    } use;
} DataTypeData;

/*
 * Extended magic test with data type information
 */
typedef struct MagicTestExt {
    MagicTest base;
    DataTypeCategory data_type_category;
    DataTypeData data;
} MagicTestExt;

/*
 * Named test for indirect references
 */
typedef struct NamedTest {
    char *name;
    MagicTest *test;
    struct NamedTest *next;  /* For hash table chaining */
} NamedTest;

/*
 * Magic matcher - contains parsed definitions and matching state
 */
typedef struct {
    MagicTest **tests;           /* Array of top-level tests */
    size_t      num_tests;
    size_t      tests_capacity;
    
    NamedTest **named_tests;     /* Hash table of named tests */
    size_t      named_tests_size;
    
    MagicTest **text_tests;      /* Tests that match text files */
    size_t      num_text_tests;
    
    MagicTest **binary_tests;    /* Tests that match binary files */
    size_t      num_binary_tests;
    
    /* Indices for fast lookups */
    char      **mimetypes;       /* All possible MIME types */
    size_t      num_mimetypes;
    
    char      **extensions;      /* All possible extensions */
    size_t      num_extensions;
} MagicMatcher;

/*
 * Match context for a single matching operation
 */
typedef struct {
    const uint8_t *data;
    size_t         data_len;
    const char    *path;
    bool           only_match_mime;
    bool           is_executable;
} MatchContext;

/*
 * Match result collection
 */
typedef struct Match {
    MagicMatcher  *matcher;
    MatchContext  *context;
    MatchResult  **results;
    size_t         num_results;
    size_t         results_capacity;
} Match;

/*
 * Function prototypes
 */

/* Matcher creation and destruction */
MagicMatcher* magic_matcher_new(void);
void magic_matcher_free(MagicMatcher *matcher);

/* Parse magic definition files */
LudofileResult magic_matcher_parse_file(MagicMatcher *matcher, const char *path);
LudofileResult magic_matcher_parse_string(MagicMatcher *matcher, const char *content);

/* Get default matcher with built-in definitions */
MagicMatcher* magic_matcher_default(void);

/* Add a test to the matcher */
LudofileResult magic_matcher_add_test(MagicMatcher *matcher, MagicTest *test);

/* Named test operations */
LudofileResult magic_matcher_add_named_test(MagicMatcher *matcher, 
                                             const char *name, MagicTest *test);
MagicTest* magic_matcher_get_named_test(MagicMatcher *matcher, const char *name);

/* Create matcher that only matches specific MIME types */
MagicMatcher* magic_matcher_only_match(MagicMatcher *matcher, 
                                        const char **mimetypes, size_t count);

/* Matching operations */
Match* magic_matcher_match(MagicMatcher *matcher, const uint8_t *data, size_t len);
Match* magic_matcher_match_file(MagicMatcher *matcher, const char *path);
Match* magic_matcher_match_context(MagicMatcher *matcher, MatchContext *context);

/* Match result access */
const char* match_get_message(Match *match);
const char** match_get_mimetypes(Match *match, size_t *count);
const char** match_get_extensions(Match *match, size_t *count);
void match_free(Match *match);

/* MatchContext operations */
MatchContext* match_context_new(const uint8_t *data, size_t len);
MatchContext* match_context_from_file(const char *path);
void match_context_free(MatchContext *context);

/* Test parsing helpers */
MagicTest* magic_parse_test(const char *line, size_t len, 
                            MagicTest *parent, MagicMatcher *matcher,
                            const char *source_path, int line_number);

/* String unescape utility */
uint8_t* magic_unescape(const char *str, size_t len, size_t *out_len);

/* Numeric parsing utility */
int64_t magic_parse_numeric(const char *text);

#endif /* LUDOFILE_MAGIC_MAGIC_H */
