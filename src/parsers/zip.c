/*
 * LudoFile - ZIP Parser Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "zip.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ZIP signatures */
#define ZIP_LOCAL_FILE_SIG      0x04034b50
#define ZIP_CENTRAL_DIR_SIG     0x02014b50
#define ZIP_EOCD_SIG            0x06054b50
#define ZIP_EOCD64_LOCATOR_SIG  0x07064b50
#define ZIP_EOCD64_SIG          0x06064b50
#define ZIP_DATA_DESC_SIG       0x08074b50

/*
 * Read little-endian uint16
 */
static uint16_t read_u16(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

/*
 * Read little-endian uint32
 */
static uint32_t read_u32(const uint8_t *data) {
    return (uint32_t)data[0] | 
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

/*
 * Read little-endian uint64
 */
static uint64_t read_u64(const uint8_t *data) {
    return (uint64_t)data[0] |
           ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) |
           ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) |
           ((uint64_t)data[7] << 56);
}

/*
 * Find End of Central Directory record
 */
int64_t zip_find_eocd(const uint8_t *data, size_t len) {
    /* EOCD is at least 22 bytes, search backwards */
    if (len < 22) return -1;
    
    /* Start from end - 22 (minimum EOCD size) and search backwards */
    /* Maximum comment length is 65535, so we don't need to search further */
    size_t max_search = len < 65557 ? len : 65557;
    
    for (size_t i = 22; i <= max_search; i++) {
        size_t pos = len - i;
        if (read_u32(data + pos) == ZIP_EOCD_SIG) {
            /* Verify this is a valid EOCD by checking comment length */
            if (pos + 22 <= len) {
                uint16_t comment_len = read_u16(data + pos + 20);
                if (pos + 22 + comment_len == len || 
                    pos + 22 + comment_len <= len) {
                    return (int64_t)pos;
                }
            }
        }
    }
    return -1;
}

/*
 * Create new ZIP archive
 */
ZipArchive* zip_archive_new(void) {
    ZipArchive *archive = calloc(1, sizeof(ZipArchive));
    if (archive) {
        archive->local_headers_capacity = 16;
        archive->local_headers = malloc(16 * sizeof(ZipLocalFileHeader*));
        archive->central_dir_capacity = 16;
        archive->central_dir = malloc(16 * sizeof(ZipCentralDirEntry*));
        
        if (!archive->local_headers || !archive->central_dir) {
            free(archive->local_headers);
            free(archive->central_dir);
            free(archive);
            return NULL;
        }
    }
    return archive;
}

/*
 * Free local file header
 */
void zip_local_header_free(ZipLocalFileHeader *header) {
    if (header) {
        free(header->filename);
        free(header->extra);
        /* Note: data is not owned by header */
        free(header);
    }
}

/*
 * Free central directory entry
 */
void zip_central_dir_free(ZipCentralDirEntry *entry) {
    if (entry) {
        free(entry->filename);
        free(entry->extra);
        free(entry->comment);
        free(entry);
    }
}

/*
 * Free end of central directory
 */
void zip_eocd_free(ZipEndOfCentralDir *eocd) {
    if (eocd) {
        free(eocd->comment);
        free(eocd);
    }
}

/*
 * Free ZIP archive
 */
void zip_archive_free(ZipArchive *archive) {
    if (!archive) return;
    
    for (size_t i = 0; i < archive->num_local_headers; i++) {
        zip_local_header_free(archive->local_headers[i]);
    }
    free(archive->local_headers);
    
    for (size_t i = 0; i < archive->num_central_dir; i++) {
        zip_central_dir_free(archive->central_dir[i]);
    }
    free(archive->central_dir);
    
    zip_eocd_free(archive->eocd);
    free(archive->eocd64_locator);
    
    free(archive);
}

/*
 * Parse local file header
 */
ZipLocalFileHeader* zip_parse_local_header(const uint8_t *data, size_t len, size_t offset) {
    if (offset + 30 > len) return NULL;
    
    if (read_u32(data + offset) != ZIP_LOCAL_FILE_SIG) return NULL;
    
    ZipLocalFileHeader *header = calloc(1, sizeof(ZipLocalFileHeader));
    if (!header) return NULL;
    
    header->header_offset = offset;
    header->signature = ZIP_LOCAL_FILE_SIG;
    header->version_needed = read_u16(data + offset + 4);
    header->flags = read_u16(data + offset + 6);
    header->compression = read_u16(data + offset + 8);
    header->mod_time = read_u16(data + offset + 10);
    header->mod_date = read_u16(data + offset + 12);
    header->crc32 = read_u32(data + offset + 14);
    header->compressed_size = read_u32(data + offset + 18);
    header->uncompressed_size = read_u32(data + offset + 22);
    header->filename_len = read_u16(data + offset + 26);
    header->extra_len = read_u16(data + offset + 28);
    
    size_t pos = offset + 30;
    
    /* Read filename */
    if (header->filename_len > 0) {
        if (pos + header->filename_len > len) {
            free(header);
            return NULL;
        }
        header->filename = malloc(header->filename_len + 1);
        if (!header->filename) {
            free(header);
            return NULL;
        }
        memcpy(header->filename, data + pos, header->filename_len);
        header->filename[header->filename_len] = '\0';
        pos += header->filename_len;
    }
    
    /* Read extra field */
    if (header->extra_len > 0) {
        if (pos + header->extra_len > len) {
            free(header->filename);
            free(header);
            return NULL;
        }
        header->extra = malloc(header->extra_len);
        if (!header->extra) {
            free(header->filename);
            free(header);
            return NULL;
        }
        memcpy(header->extra, data + pos, header->extra_len);
        pos += header->extra_len;
    }
    
    header->data_offset = pos;
    /* Note: data points to the original buffer - caller must ensure buffer 
     * lifetime exceeds header lifetime. For iterator usage, the buffer is 
     * kept alive by the iterator state. */
    header->data = (uint8_t*)(data + pos);
    
    return header;
}

/*
 * Parse central directory entry
 */
ZipCentralDirEntry* zip_parse_central_dir(const uint8_t *data, size_t len, size_t offset) {
    if (offset + 46 > len) return NULL;
    
    if (read_u32(data + offset) != ZIP_CENTRAL_DIR_SIG) return NULL;
    
    ZipCentralDirEntry *entry = calloc(1, sizeof(ZipCentralDirEntry));
    if (!entry) return NULL;
    
    entry->entry_offset = offset;
    entry->signature = ZIP_CENTRAL_DIR_SIG;
    entry->version_made = read_u16(data + offset + 4);
    entry->version_needed = read_u16(data + offset + 6);
    entry->flags = read_u16(data + offset + 8);
    entry->compression = read_u16(data + offset + 10);
    entry->mod_time = read_u16(data + offset + 12);
    entry->mod_date = read_u16(data + offset + 14);
    entry->crc32 = read_u32(data + offset + 16);
    entry->compressed_size = read_u32(data + offset + 20);
    entry->uncompressed_size = read_u32(data + offset + 24);
    entry->filename_len = read_u16(data + offset + 28);
    entry->extra_len = read_u16(data + offset + 30);
    entry->comment_len = read_u16(data + offset + 32);
    entry->disk_start = read_u16(data + offset + 34);
    entry->internal_attr = read_u16(data + offset + 36);
    entry->external_attr = read_u32(data + offset + 38);
    entry->local_header_offset = read_u32(data + offset + 42);
    
    size_t pos = offset + 46;
    
    /* Read filename */
    if (entry->filename_len > 0) {
        if (pos + entry->filename_len > len) {
            free(entry);
            return NULL;
        }
        entry->filename = malloc(entry->filename_len + 1);
        if (!entry->filename) {
            free(entry);
            return NULL;
        }
        memcpy(entry->filename, data + pos, entry->filename_len);
        entry->filename[entry->filename_len] = '\0';
        pos += entry->filename_len;
    }
    
    /* Read extra field */
    if (entry->extra_len > 0) {
        if (pos + entry->extra_len > len) {
            free(entry->filename);
            free(entry);
            return NULL;
        }
        entry->extra = malloc(entry->extra_len);
        if (!entry->extra) {
            free(entry->filename);
            free(entry);
            return NULL;
        }
        memcpy(entry->extra, data + pos, entry->extra_len);
        pos += entry->extra_len;
    }
    
    /* Read comment */
    if (entry->comment_len > 0) {
        if (pos + entry->comment_len > len) {
            free(entry->extra);
            free(entry->filename);
            free(entry);
            return NULL;
        }
        entry->comment = malloc(entry->comment_len + 1);
        if (!entry->comment) {
            free(entry->extra);
            free(entry->filename);
            free(entry);
            return NULL;
        }
        memcpy(entry->comment, data + pos, entry->comment_len);
        entry->comment[entry->comment_len] = '\0';
    }
    
    return entry;
}

/*
 * Parse end of central directory
 */
ZipEndOfCentralDir* zip_parse_eocd(const uint8_t *data, size_t len, size_t offset) {
    if (offset + 22 > len) return NULL;
    
    if (read_u32(data + offset) != ZIP_EOCD_SIG) return NULL;
    
    ZipEndOfCentralDir *eocd = calloc(1, sizeof(ZipEndOfCentralDir));
    if (!eocd) return NULL;
    
    eocd->record_offset = offset;
    eocd->signature = ZIP_EOCD_SIG;
    eocd->disk_num = read_u16(data + offset + 4);
    eocd->cd_disk = read_u16(data + offset + 6);
    eocd->disk_entries = read_u16(data + offset + 8);
    eocd->total_entries = read_u16(data + offset + 10);
    eocd->cd_size = read_u32(data + offset + 12);
    eocd->cd_offset = read_u32(data + offset + 16);
    eocd->comment_len = read_u16(data + offset + 20);
    
    /* Read comment */
    if (eocd->comment_len > 0) {
        if (offset + 22 + eocd->comment_len > len) {
            free(eocd);
            return NULL;
        }
        eocd->comment = malloc(eocd->comment_len + 1);
        if (!eocd->comment) {
            free(eocd);
            return NULL;
        }
        memcpy(eocd->comment, data + offset + 22, eocd->comment_len);
        eocd->comment[eocd->comment_len] = '\0';
    }
    
    return eocd;
}

/*
 * Check if archive is a JAR file
 */
bool zip_is_jar(ZipArchive *archive) {
    if (!archive) return false;
    
    /* Check for META-INF/MANIFEST.MF or Java marker in extra field */
    for (size_t i = 0; i < archive->num_local_headers; i++) {
        ZipLocalFileHeader *h = archive->local_headers[i];
        if (h->filename) {
            if (strcmp(h->filename, "META-INF/MANIFEST.MF") == 0) {
                return true;
            }
        }
        /* Check for Java marker 0xCAFE in extra field */
        if (h->extra_len >= 4 && h->extra) {
            if (h->extra[0] == 0xFE && h->extra[1] == 0xCA) {
                return true;
            }
        }
    }
    return false;
}

/*
 * Parse ZIP archive
 */
LudofileResult zip_archive_parse(ZipArchive *archive, const uint8_t *data, size_t len) {
    if (!archive || !data || len == 0) return LUDOFILE_ERROR_INVALID;
    
    archive->data = data;
    archive->data_len = len;
    
    /* Find EOCD */
    int64_t eocd_offset = zip_find_eocd(data, len);
    if (eocd_offset < 0) return LUDOFILE_ERROR_PARSE;
    
    /* Parse EOCD */
    archive->eocd = zip_parse_eocd(data, len, (size_t)eocd_offset);
    if (!archive->eocd) return LUDOFILE_ERROR_PARSE;
    
    /* Parse central directory */
    size_t cd_offset = archive->eocd->cd_offset;
    for (uint16_t i = 0; i < archive->eocd->total_entries; i++) {
        ZipCentralDirEntry *entry = zip_parse_central_dir(data, len, cd_offset);
        if (!entry) break;
        
        /* Add to array */
        if (archive->num_central_dir >= archive->central_dir_capacity) {
            size_t new_cap = archive->central_dir_capacity * 2;
            ZipCentralDirEntry **new_arr = realloc(archive->central_dir, 
                                                   new_cap * sizeof(ZipCentralDirEntry*));
            if (!new_arr) {
                zip_central_dir_free(entry);
                break;
            }
            archive->central_dir = new_arr;
            archive->central_dir_capacity = new_cap;
        }
        
        archive->central_dir[archive->num_central_dir++] = entry;
        
        /* Move to next entry */
        cd_offset = entry->entry_offset + 46 + entry->filename_len + 
                    entry->extra_len + entry->comment_len;
    }
    
    /* Parse local file headers from central directory references */
    for (size_t i = 0; i < archive->num_central_dir; i++) {
        ZipCentralDirEntry *cd = archive->central_dir[i];
        
        ZipLocalFileHeader *header = zip_parse_local_header(data, len, 
                                                            cd->local_header_offset);
        if (!header) continue;
        
        /* Add to array */
        if (archive->num_local_headers >= archive->local_headers_capacity) {
            size_t new_cap = archive->local_headers_capacity * 2;
            ZipLocalFileHeader **new_arr = realloc(archive->local_headers,
                                                   new_cap * sizeof(ZipLocalFileHeader*));
            if (!new_arr) {
                zip_local_header_free(header);
                break;
            }
            archive->local_headers = new_arr;
            archive->local_headers_capacity = new_cap;
        }
        
        archive->local_headers[archive->num_local_headers++] = header;
    }
    
    return LUDOFILE_OK;
}

/*
 * ZIP parser iterator state
 */
typedef struct {
    ZipArchive *archive;
    uint8_t *data;            /* Data buffer ownership */
    size_t current_item;
    ParseMatch *parent;
    ParseMatch **matches;
    size_t num_matches;
    size_t matches_capacity;
} ZipParserState;

/*
 * Iterator next function
 */
static ParseMatch* zip_parser_next(ParseMatchIterator *iter) {
    if (!iter || !iter->state) return NULL;
    
    ZipParserState *state = (ZipParserState*)iter->state;
    
    if (state->current_item >= state->num_matches) {
        return NULL;
    }
    
    return state->matches[state->current_item++];
}

/*
 * Iterator free function
 */
static void zip_parser_free_iter(ParseMatchIterator *iter) {
    if (!iter) return;
    
    ZipParserState *state = (ZipParserState*)iter->state;
    if (state) {
        if (state->archive) zip_archive_free(state->archive);
        free(state->data);  /* Free the data buffer */
        free(state->matches);
        free(state);
    }
    free(iter);
}

/*
 * ZIP parser entry point
 */
ParseMatchIterator* zip_parser(FileStream *stream, ParseMatch *parent) {
    if (!stream) return NULL;
    
    /* Read file data */
    uint8_t *data = malloc(stream->length);
    if (!data) return NULL;
    
    file_stream_seek(stream, 0, SEEK_SET);
    size_t bytes_read = file_stream_read(stream, data, stream->length);
    if (bytes_read != stream->length) {
        free(data);
        return NULL;
    }
    
    /* Create ZIP archive */
    ZipArchive *archive = zip_archive_new();
    if (!archive) {
        free(data);
        return NULL;
    }
    
    /* Parse archive */
    LudofileResult result = zip_archive_parse(archive, data, bytes_read);
    if (result != LUDOFILE_OK) {
        zip_archive_free(archive);
        free(data);
        return NULL;
    }
    
    /* Create iterator state */
    ZipParserState *state = calloc(1, sizeof(ZipParserState));
    if (!state) {
        zip_archive_free(archive);
        free(data);
        return NULL;
    }
    
    state->archive = archive;
    state->data = data;  /* Track data buffer for cleanup */
    state->parent = parent;
    state->matches_capacity = 64;
    state->matches = malloc(64 * sizeof(ParseMatch*));
    if (!state->matches) {
        free(state);
        zip_archive_free(archive);
        free(data);
        return NULL;
    }
    
    size_t base_offset = parent ? parent->offset : 0;
    
    /* Generate matches for local file headers */
    for (size_t i = 0; i < archive->num_local_headers; i++) {
        ZipLocalFileHeader *h = archive->local_headers[i];
        
        size_t header_size = 30 + h->filename_len + h->extra_len;
        ParseMatch *match = parse_match_new("ZipLocalFileHeader",
                                            h->header_offset - base_offset,
                                            header_size,
                                            parent);
        if (match && state->num_matches < state->matches_capacity) {
            state->matches[state->num_matches++] = match;
        }
        
        /* Add match for file data */
        if (h->compressed_size > 0) {
            ParseMatch *data_match = parse_match_new("ZipFileData",
                                                     h->data_offset - base_offset,
                                                     h->compressed_size,
                                                     parent);
            if (data_match && state->num_matches < state->matches_capacity) {
                state->matches[state->num_matches++] = data_match;
            }
        }
    }
    
    /* Generate matches for central directory entries */
    for (size_t i = 0; i < archive->num_central_dir; i++) {
        ZipCentralDirEntry *cd = archive->central_dir[i];
        
        size_t entry_size = 46 + cd->filename_len + cd->extra_len + cd->comment_len;
        ParseMatch *match = parse_match_new("ZipCentralDirEntry",
                                            cd->entry_offset - base_offset,
                                            entry_size,
                                            parent);
        if (match && state->num_matches < state->matches_capacity) {
            state->matches[state->num_matches++] = match;
        }
    }
    
    /* Generate match for EOCD */
    if (archive->eocd) {
        size_t eocd_size = 22 + archive->eocd->comment_len;
        ParseMatch *match = parse_match_new("ZipEndOfCentralDir",
                                            archive->eocd->record_offset - base_offset,
                                            eocd_size,
                                            parent);
        if (match && state->num_matches < state->matches_capacity) {
            state->matches[state->num_matches++] = match;
        }
    }
    
    /* Create iterator */
    ParseMatchIterator *iter = malloc(sizeof(ParseMatchIterator));
    if (!iter) {
        free(state->matches);
        free(state->data);
        free(state);
        zip_archive_free(archive);
        return NULL;
    }
    
    iter->state = state;
    iter->next = zip_parser_next;
    iter->free = zip_parser_free_iter;
    
    return iter;
}
