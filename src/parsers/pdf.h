/*
 * LudoFile - PDF Parser
 *
 * A Cosmopolitan C implementation for parsing PDF document structure.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_PARSERS_PDF_H
#define LUDOFILE_PARSERS_PDF_H

#include "../core/types.h"
#include "parser.h"

/*
 * PDF Version
 */
typedef struct {
    int major;
    int minor;
} PDFVersion;

/*
 * PDF Object Types
 */
typedef enum {
    PDF_OBJ_NULL = 0,
    PDF_OBJ_BOOLEAN,
    PDF_OBJ_INTEGER,
    PDF_OBJ_REAL,
    PDF_OBJ_STRING,
    PDF_OBJ_NAME,
    PDF_OBJ_ARRAY,
    PDF_OBJ_DICTIONARY,
    PDF_OBJ_STREAM,
    PDF_OBJ_REFERENCE
} PDFObjectType;

/*
 * PDF Object
 */
typedef struct PDFObject {
    PDFObjectType type;
    size_t offset;
    size_t length;
    union {
        bool boolean_val;
        int64_t integer_val;
        double real_val;
        struct {
            char *data;
            size_t len;
            bool is_hex;
        } string_val;
        char *name_val;
        struct {
            struct PDFObject **items;
            size_t count;
            size_t capacity;
        } array_val;
        struct {
            char **keys;
            struct PDFObject **values;
            size_t count;
            size_t capacity;
        } dict_val;
        struct {
            struct PDFObject *dict;
            uint8_t *data;
            size_t data_len;
            uint8_t *decoded;
            size_t decoded_len;
        } stream_val;
        struct {
            int obj_num;
            int gen_num;
        } ref_val;
    } value;
} PDFObject;

/*
 * PDF XRef Entry
 */
typedef struct {
    int obj_num;
    size_t offset;
    int gen_num;
    bool in_use;
} PDFXRefEntry;

/*
 * PDF XRef Table
 */
typedef struct {
    PDFXRefEntry *entries;
    size_t count;
    size_t capacity;
} PDFXRefTable;

/*
 * PDF Document
 */
typedef struct {
    PDFVersion version;
    PDFXRefTable *xref;
    PDFObject *trailer;
    PDFObject *catalog;
    size_t file_size;
    const uint8_t *data;
    size_t data_len;
} PDFDocument;

/*
 * Function prototypes
 */

/* PDF parsing */
PDFDocument* pdf_document_new(void);
void pdf_document_free(PDFDocument *doc);
LudofileResult pdf_document_parse(PDFDocument *doc, const uint8_t *data, size_t len);

/* Object parsing */
PDFObject* pdf_parse_object(const uint8_t *data, size_t len, size_t *offset);
void pdf_object_free(PDFObject *obj);

/* XRef parsing */
PDFXRefTable* pdf_parse_xref(const uint8_t *data, size_t len, size_t offset);
void pdf_xref_free(PDFXRefTable *xref);

/* Trailer parsing */
PDFObject* pdf_parse_trailer(const uint8_t *data, size_t len, size_t offset);

/* Stream decoding */
LudofileResult pdf_decode_stream(PDFObject *stream);

/* Parser registration function */
ParseMatchIterator* pdf_parser(FileStream *stream, ParseMatch *parent);

/* Utility functions */
int64_t pdf_find_startxref(const uint8_t *data, size_t len);
const uint8_t* pdf_find_header(const uint8_t *data, size_t len, size_t *offset);

#endif /* LUDOFILE_PARSERS_PDF_H */
