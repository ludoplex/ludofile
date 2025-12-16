/*
 * LudoFile - Core Type Definitions
 * 
 * This file defines the fundamental data types used throughout the
 * LudoFile file analysis system. Built for Cosmopolitan C compatibility.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_CORE_TYPES_H
#define LUDOFILE_CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Endianness enumeration for byte order handling
 */
typedef enum {
    ENDIAN_NATIVE = 0,
    ENDIAN_LITTLE = 1,
    ENDIAN_BIG    = 2,
    ENDIAN_PDP    = 3  /* Middle-endian (PDP-11 style) */
} Endianness;

/*
 * Test type flags for categorizing magic tests
 */
typedef enum {
    TEST_TYPE_UNKNOWN = 0,
    TEST_TYPE_BINARY  = 1,
    TEST_TYPE_TEXT    = 2
} TestType;

/*
 * Result codes for operations
 */
typedef enum {
    LUDOFILE_OK = 0,
    LUDOFILE_ERROR = -1,
    LUDOFILE_ERROR_MEMORY = -2,
    LUDOFILE_ERROR_IO = -3,
    LUDOFILE_ERROR_PARSE = -4,
    LUDOFILE_ERROR_NOT_FOUND = -5,
    LUDOFILE_ERROR_INVALID = -6
} LudofileResult;

/*
 * Byte buffer - a simple growable byte array
 */
typedef struct {
    uint8_t *data;
    size_t   length;
    size_t   capacity;
} ByteBuffer;

/*
 * String buffer - null-terminated string with length tracking
 */
typedef struct {
    char   *data;
    size_t  length;
    size_t  capacity;
} StringBuffer;

/*
 * File stream abstraction for unified file access
 */
typedef struct {
    void    *handle;          /* File handle or memory pointer */
    size_t   offset;          /* Current read position */
    size_t   length;          /* Total length of stream */
    size_t   start;           /* Start offset within parent */
    bool     is_memory;       /* True if memory-backed */
    const char *name;         /* Stream name for debugging */
} FileStream;

/*
 * Offset types for magic pattern matching
 */
typedef enum {
    OFFSET_ABSOLUTE = 0,
    OFFSET_RELATIVE = 1,
    OFFSET_INDIRECT = 2,
    OFFSET_NEGATIVE = 3
} OffsetType;

/*
 * Offset specification for magic tests
 */
typedef struct Offset {
    OffsetType type;
    int64_t    value;
    struct Offset *relative_to;  /* For indirect offsets */
    /* For indirect offsets: */
    int num_bytes;
    Endianness endianness;
    bool is_signed;
    int64_t (*post_process)(int64_t);  /* Post-processing function */
} Offset;

/*
 * Source information for debugging and error reporting
 */
typedef struct {
    const char *path;
    int         line;
    const char *original_line;
} SourceInfo;

/*
 * Match result from a magic test
 */
typedef struct MatchResult {
    bool     matched;
    size_t   offset;
    size_t   length;
    void    *value;           /* Type-specific matched value */
    struct MatchResult *parent;
    struct MagicTest   *test;
} MatchResult;

/* Forward declaration */
struct MagicTest;

/*
 * Magic test function pointer types
 */
typedef MatchResult* (*TestFunc)(struct MagicTest *test, 
                                  const uint8_t *data, 
                                  size_t data_len,
                                  size_t absolute_offset,
                                  MatchResult *parent);

/*
 * Magic test base structure
 */
typedef struct MagicTest {
    Offset      offset;
    char       *mime;
    char      **extensions;
    size_t      num_extensions;
    char       *message;
    TestType    test_type;
    bool        can_match_mime;
    bool        can_be_indirect;
    SourceInfo  source_info;
    
    struct MagicTest  *parent;
    struct MagicTest **children;
    size_t             num_children;
    size_t             children_capacity;
    
    TestFunc    test_func;    /* Type-specific test function */
    void       *type_data;    /* Type-specific data */
} MagicTest;

/*
 * MIME type match structure
 */
typedef struct {
    const char *mime_type;
    const char *match_string;
    size_t      offset;
    size_t      length;
} MimeMatch;

/*
 * List of MIME matches
 */
typedef struct {
    MimeMatch *matches;
    size_t     count;
    size_t     capacity;
} MimeMatchList;

/*
 * Parse result for structured file analysis
 */
typedef struct ParseMatch {
    const char *name;
    const char *display_name;
    size_t      relative_offset;
    size_t      offset;         /* Global offset */
    size_t      length;
    void       *match_value;
    uint8_t    *decoded;        /* Decoded content if applicable */
    size_t      decoded_length;
    const char *extension;
    struct ParseMatch  *parent;
    struct ParseMatch **children;
    size_t              num_children;
    size_t              children_capacity;
} ParseMatch;

/* 
 * Function prototypes for core operations 
 */

/* ByteBuffer operations */
ByteBuffer* byte_buffer_new(size_t initial_capacity);
void byte_buffer_free(ByteBuffer *buf);
LudofileResult byte_buffer_append(ByteBuffer *buf, const uint8_t *data, size_t len);
LudofileResult byte_buffer_resize(ByteBuffer *buf, size_t new_capacity);

/* StringBuffer operations */
StringBuffer* string_buffer_new(size_t initial_capacity);
void string_buffer_free(StringBuffer *buf);
LudofileResult string_buffer_append(StringBuffer *buf, const char *str);
LudofileResult string_buffer_append_n(StringBuffer *buf, const char *str, size_t len);

/* FileStream operations */
FileStream* file_stream_open(const char *path);
FileStream* file_stream_from_memory(const uint8_t *data, size_t length);
void file_stream_close(FileStream *stream);
size_t file_stream_read(FileStream *stream, uint8_t *buf, size_t count);
LudofileResult file_stream_seek(FileStream *stream, int64_t offset, int whence);
size_t file_stream_tell(FileStream *stream);

/* Offset operations */
int64_t offset_to_absolute(const Offset *offset, const uint8_t *data, 
                           size_t data_len, const MatchResult *last_match);

/* MatchResult operations */
MatchResult* match_result_new(MagicTest *test, size_t offset, size_t length, 
                               void *value, MatchResult *parent);
void match_result_free(MatchResult *result);

/* ParseMatch operations */
ParseMatch* parse_match_new(const char *name, size_t relative_offset, 
                            size_t length, ParseMatch *parent);
void parse_match_free(ParseMatch *match);
LudofileResult parse_match_add_child(ParseMatch *parent, ParseMatch *child);

#endif /* LUDOFILE_CORE_TYPES_H */
