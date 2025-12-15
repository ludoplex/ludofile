/*
 * LudoFile - Core Type Implementations
 * 
 * Implementation of fundamental data structures and operations.
 * Built for Cosmopolitan C compatibility.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#include "types.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Initial allocation sizes
 */
#define INITIAL_BUFFER_SIZE 256
#define BUFFER_GROWTH_FACTOR 2

/*
 * ByteBuffer implementation
 */

ByteBuffer* byte_buffer_new(size_t initial_capacity) {
    ByteBuffer *buf = malloc(sizeof(ByteBuffer));
    if (!buf) return NULL;
    
    if (initial_capacity == 0) {
        initial_capacity = INITIAL_BUFFER_SIZE;
    }
    
    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    buf->length = 0;
    buf->capacity = initial_capacity;
    return buf;
}

void byte_buffer_free(ByteBuffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

LudofileResult byte_buffer_resize(ByteBuffer *buf, size_t new_capacity) {
    if (!buf) return LUDOFILE_ERROR_INVALID;
    
    uint8_t *new_data = realloc(buf->data, new_capacity);
    if (!new_data) return LUDOFILE_ERROR_MEMORY;
    
    buf->data = new_data;
    buf->capacity = new_capacity;
    return LUDOFILE_OK;
}

LudofileResult byte_buffer_append(ByteBuffer *buf, const uint8_t *data, size_t len) {
    if (!buf || !data) return LUDOFILE_ERROR_INVALID;
    
    while (buf->length + len > buf->capacity) {
        LudofileResult res = byte_buffer_resize(buf, buf->capacity * BUFFER_GROWTH_FACTOR);
        if (res != LUDOFILE_OK) return res;
    }
    
    memcpy(buf->data + buf->length, data, len);
    buf->length += len;
    return LUDOFILE_OK;
}

/*
 * StringBuffer implementation
 */

StringBuffer* string_buffer_new(size_t initial_capacity) {
    StringBuffer *buf = malloc(sizeof(StringBuffer));
    if (!buf) return NULL;
    
    if (initial_capacity == 0) {
        initial_capacity = INITIAL_BUFFER_SIZE;
    }
    
    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    buf->data[0] = '\0';
    buf->length = 0;
    buf->capacity = initial_capacity;
    return buf;
}

void string_buffer_free(StringBuffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

LudofileResult string_buffer_append(StringBuffer *buf, const char *str) {
    if (!buf || !str) return LUDOFILE_ERROR_INVALID;
    return string_buffer_append_n(buf, str, strlen(str));
}

LudofileResult string_buffer_append_n(StringBuffer *buf, const char *str, size_t len) {
    if (!buf || !str) return LUDOFILE_ERROR_INVALID;
    
    while (buf->length + len + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * BUFFER_GROWTH_FACTOR;
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) return LUDOFILE_ERROR_MEMORY;
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->length, str, len);
    buf->length += len;
    buf->data[buf->length] = '\0';
    return LUDOFILE_OK;
}

/*
 * FileStream implementation
 */

FileStream* file_stream_open(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    
    FileStream *stream = malloc(sizeof(FileStream));
    if (!stream) {
        fclose(fp);
        return NULL;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    stream->length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    stream->handle = fp;
    stream->offset = 0;
    stream->start = 0;
    stream->is_memory = false;
    stream->name = path;
    
    return stream;
}

FileStream* file_stream_from_memory(const uint8_t *data, size_t length) {
    FileStream *stream = malloc(sizeof(FileStream));
    if (!stream) return NULL;
    
    stream->handle = (void*)data;
    stream->offset = 0;
    stream->length = length;
    stream->start = 0;
    stream->is_memory = true;
    stream->name = "<memory>";
    
    return stream;
}

void file_stream_close(FileStream *stream) {
    if (stream) {
        if (!stream->is_memory && stream->handle) {
            fclose((FILE*)stream->handle);
        }
        free(stream);
    }
}

size_t file_stream_read(FileStream *stream, uint8_t *buf, size_t count) {
    if (!stream || !buf) return 0;
    
    size_t available = stream->length - stream->offset;
    if (count > available) {
        count = available;
    }
    
    if (stream->is_memory) {
        const uint8_t *data = (const uint8_t*)stream->handle;
        memcpy(buf, data + stream->offset, count);
    } else {
        count = fread(buf, 1, count, (FILE*)stream->handle);
    }
    
    stream->offset += count;
    return count;
}

LudofileResult file_stream_seek(FileStream *stream, int64_t offset, int whence) {
    if (!stream) return LUDOFILE_ERROR_INVALID;
    
    int64_t new_offset;
    
    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = (int64_t)stream->offset + offset;
            break;
        case SEEK_END:
            new_offset = (int64_t)stream->length + offset;
            break;
        default:
            return LUDOFILE_ERROR_INVALID;
    }
    
    if (new_offset < 0 || (size_t)new_offset > stream->length) {
        return LUDOFILE_ERROR_INVALID;
    }
    
    stream->offset = (size_t)new_offset;
    
    if (!stream->is_memory) {
        fseek((FILE*)stream->handle, (long)new_offset, SEEK_SET);
    }
    
    return LUDOFILE_OK;
}

size_t file_stream_tell(FileStream *stream) {
    if (!stream) return 0;
    return stream->offset;
}

/*
 * Offset operations
 */

int64_t offset_to_absolute(const Offset *offset, const uint8_t *data,
                           size_t data_len, const MatchResult *last_match) {
    if (!offset) return -1;
    
    switch (offset->type) {
        case OFFSET_ABSOLUTE:
            return offset->value;
            
        case OFFSET_NEGATIVE:
            return (int64_t)data_len - offset->value;
            
        case OFFSET_RELATIVE:
            if (!last_match) return -1;
            if (offset->relative_to) {
                int64_t relative = offset_to_absolute(offset->relative_to, 
                                                       data, data_len, last_match);
                return (int64_t)last_match->offset + (int64_t)last_match->length + relative;
            }
            return (int64_t)last_match->offset + (int64_t)last_match->length + offset->value;
            
        case OFFSET_INDIRECT: {
            int64_t base_offset = offset_to_absolute(offset->relative_to, 
                                                      data, data_len, last_match);
            if (base_offset < 0 || (size_t)base_offset >= data_len) {
                return -1;
            }
            
            int64_t value = 0;
            size_t bytes = (size_t)offset->num_bytes;
            
            if ((size_t)base_offset + bytes > data_len) {
                return -1;
            }
            
            const uint8_t *ptr = data + base_offset;
            
            if (offset->endianness == ENDIAN_LITTLE) {
                for (size_t i = 0; i < bytes; i++) {
                    value |= ((int64_t)ptr[i]) << (i * 8);
                }
            } else {
                for (size_t i = 0; i < bytes; i++) {
                    value |= ((int64_t)ptr[i]) << ((bytes - 1 - i) * 8);
                }
            }
            
            if (offset->is_signed && (value & (1LL << (bytes * 8 - 1)))) {
                /* Sign extend */
                value |= ~((1LL << (bytes * 8)) - 1);
            }
            
            if (offset->post_process) {
                value = offset->post_process(value);
            }
            
            return value;
        }
    }
    
    return -1;
}

/*
 * MatchResult operations
 */

MatchResult* match_result_new(MagicTest *test, size_t offset, size_t length,
                               void *value, MatchResult *parent) {
    MatchResult *result = malloc(sizeof(MatchResult));
    if (!result) return NULL;
    
    result->matched = true;
    result->offset = offset;
    result->length = length;
    result->value = value;
    result->parent = parent;
    result->test = test;
    
    return result;
}

void match_result_free(MatchResult *result) {
    if (result) {
        /* Note: value is not freed here as it may be shared */
        free(result);
    }
}

/*
 * ParseMatch operations
 */

ParseMatch* parse_match_new(const char *name, size_t relative_offset,
                            size_t length, ParseMatch *parent) {
    ParseMatch *match = malloc(sizeof(ParseMatch));
    if (!match) return NULL;
    
    match->name = name;
    match->display_name = name;
    match->relative_offset = relative_offset;
    match->length = length;
    match->match_value = NULL;
    match->decoded = NULL;
    match->decoded_length = 0;
    match->extension = NULL;
    match->parent = parent;
    match->children = NULL;
    match->num_children = 0;
    match->children_capacity = 0;
    
    /* Calculate global offset */
    if (parent) {
        match->offset = parent->offset + relative_offset;
    } else {
        match->offset = relative_offset;
    }
    
    return match;
}

void parse_match_free(ParseMatch *match) {
    if (match) {
        /* Free children recursively */
        for (size_t i = 0; i < match->num_children; i++) {
            parse_match_free(match->children[i]);
        }
        free(match->children);
        free(match->decoded);
        free(match);
    }
}

LudofileResult parse_match_add_child(ParseMatch *parent, ParseMatch *child) {
    if (!parent || !child) return LUDOFILE_ERROR_INVALID;
    
    if (parent->num_children >= parent->children_capacity) {
        size_t new_capacity = parent->children_capacity == 0 ? 
                              8 : parent->children_capacity * 2;
        ParseMatch **new_children = realloc(parent->children, 
                                            new_capacity * sizeof(ParseMatch*));
        if (!new_children) return LUDOFILE_ERROR_MEMORY;
        parent->children = new_children;
        parent->children_capacity = new_capacity;
    }
    
    parent->children[parent->num_children++] = child;
    child->parent = parent;
    return LUDOFILE_OK;
}
