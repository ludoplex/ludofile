/*
 * LudoFile - Output Formatters
 *
 * This module provides output formatting for various formats
 * (JSON/SBUD, HTML, etc.)
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_OUTPUT_OUTPUT_H
#define LUDOFILE_OUTPUT_OUTPUT_H

#include <stdio.h>
#include "../core/types.h"
#include "../magic/magic.h"

/*
 * JSON output options
 */
typedef struct {
    bool pretty_print;
    int indent_size;
    bool include_b64_contents;
} JsonOutputOptions;

/*
 * HTML output options
 */
typedef struct {
    bool include_hex_viewer;
    bool include_structure_tree;
    const char *title;
    const char *template_path;
} HtmlOutputOptions;

/*
 * SBUD (Semantic Binary Universal Description) document
 */
typedef struct {
    char    *md5;
    char    *sha1;
    char    *sha256;
    char    *b64_contents;
    char    *filename;
    size_t   length;
    char    *ludofile_version;
    ParseMatch **matches;
    size_t       num_matches;
} SbudDocument;

/*
 * Function prototypes
 */

/* JSON output */
LudofileResult output_json(FILE *out, Match *match, const uint8_t *data, 
                           size_t data_len, const char *filename,
                           const JsonOutputOptions *options);

LudofileResult output_sbud(FILE *out, SbudDocument *doc, 
                           const JsonOutputOptions *options);

/* HTML output */
LudofileResult output_html(FILE *out, Match *match, const uint8_t *data,
                           size_t data_len, const char *filename,
                           const HtmlOutputOptions *options);

/* Simple format outputs */
LudofileResult output_file_format(FILE *out, Match *match);
LudofileResult output_mime_format(FILE *out, Match *match);
LudofileResult output_explain_format(FILE *out, Match *match);

/* SBUD document creation and manipulation */
SbudDocument* sbud_document_new(void);
void sbud_document_free(SbudDocument *doc);
LudofileResult sbud_document_set_file(SbudDocument *doc, const uint8_t *data,
                                       size_t length, const char *filename);
LudofileResult sbud_document_add_match(SbudDocument *doc, ParseMatch *match);

/* Utility functions */
char* compute_md5(const uint8_t *data, size_t length);
char* compute_sha1(const uint8_t *data, size_t length);
char* compute_sha256(const uint8_t *data, size_t length);
char* base64_encode(const uint8_t *data, size_t length);

/* JSON escaping utilities */
char* json_escape_string(const char *str);
void json_write_string(FILE *out, const char *str);

#endif /* LUDOFILE_OUTPUT_OUTPUT_H */
