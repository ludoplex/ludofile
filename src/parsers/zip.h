/*
 * LudoFile - ZIP Parser
 *
 * A Cosmopolitan C implementation for parsing ZIP archive structure.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_PARSERS_ZIP_H
#define LUDOFILE_PARSERS_ZIP_H

#include "../core/types.h"
#include "parser.h"

/*
 * ZIP Compression methods
 */
typedef enum {
    ZIP_STORED = 0,
    ZIP_SHRUNK = 1,
    ZIP_REDUCED1 = 2,
    ZIP_REDUCED2 = 3,
    ZIP_REDUCED3 = 4,
    ZIP_REDUCED4 = 5,
    ZIP_IMPLODED = 6,
    ZIP_DEFLATED = 8,
    ZIP_DEFLATE64 = 9,
    ZIP_BZIP2 = 12,
    ZIP_LZMA = 14,
    ZIP_ZSTD = 93,
    ZIP_XZ = 95,
    ZIP_AES = 99
} ZipCompressionMethod;

/*
 * ZIP Local File Header
 */
typedef struct {
    uint32_t signature;           /* 0x04034b50 */
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_len;
    char    *filename;
    uint8_t *extra;
    uint8_t *data;
    size_t   header_offset;
    size_t   data_offset;
} ZipLocalFileHeader;

/*
 * ZIP Central Directory Entry
 */
typedef struct {
    uint32_t signature;           /* 0x02014b50 */
    uint16_t version_made;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_len;
    uint16_t comment_len;
    uint16_t disk_start;
    uint16_t internal_attr;
    uint32_t external_attr;
    uint32_t local_header_offset;
    char    *filename;
    uint8_t *extra;
    char    *comment;
    size_t   entry_offset;
} ZipCentralDirEntry;

/*
 * ZIP End of Central Directory
 */
typedef struct {
    uint32_t signature;           /* 0x06054b50 */
    uint16_t disk_num;
    uint16_t cd_disk;
    uint16_t disk_entries;
    uint16_t total_entries;
    uint32_t cd_size;
    uint32_t cd_offset;
    uint16_t comment_len;
    char    *comment;
    size_t   record_offset;
} ZipEndOfCentralDir;

/*
 * ZIP64 End of Central Directory Locator
 */
typedef struct {
    uint32_t signature;           /* 0x07064b50 */
    uint32_t cd_disk;
    uint64_t eocd64_offset;
    uint32_t total_disks;
} Zip64EndLocator;

/*
 * ZIP Archive
 */
typedef struct {
    ZipLocalFileHeader   **local_headers;
    size_t                  num_local_headers;
    size_t                  local_headers_capacity;
    
    ZipCentralDirEntry   **central_dir;
    size_t                  num_central_dir;
    size_t                  central_dir_capacity;
    
    ZipEndOfCentralDir    *eocd;
    Zip64EndLocator       *eocd64_locator;
    
    const uint8_t         *data;
    size_t                  data_len;
} ZipArchive;

/*
 * Function prototypes
 */

/* Archive management */
ZipArchive* zip_archive_new(void);
void zip_archive_free(ZipArchive *archive);
LudofileResult zip_archive_parse(ZipArchive *archive, const uint8_t *data, size_t len);

/* Component parsing */
ZipLocalFileHeader* zip_parse_local_header(const uint8_t *data, size_t len, size_t offset);
ZipCentralDirEntry* zip_parse_central_dir(const uint8_t *data, size_t len, size_t offset);
ZipEndOfCentralDir* zip_parse_eocd(const uint8_t *data, size_t len, size_t offset);

/* Component cleanup */
void zip_local_header_free(ZipLocalFileHeader *header);
void zip_central_dir_free(ZipCentralDirEntry *entry);
void zip_eocd_free(ZipEndOfCentralDir *eocd);

/* Utility functions */
int64_t zip_find_eocd(const uint8_t *data, size_t len);
bool zip_is_jar(ZipArchive *archive);

/* Parser registration function */
ParseMatchIterator* zip_parser(FileStream *stream, ParseMatch *parent);

#endif /* LUDOFILE_PARSERS_ZIP_H */
