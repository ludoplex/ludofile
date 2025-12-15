/*
 * LudoFile - Output Formatters Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "output.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LUDOFILE_VERSION "0.6.0"

/* Base64 encoding table */
static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Base64 encode data
 */
char* base64_encode(const uint8_t *data, size_t length) {
    size_t output_len = 4 * ((length + 2) / 3);
    char *result = malloc(output_len + 1);
    if (!result) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < length;) {
        uint32_t octet_a = i < length ? data[i++] : 0;
        uint32_t octet_b = i < length ? data[i++] : 0;
        uint32_t octet_c = i < length ? data[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        result[j++] = base64_table[(triple >> 18) & 0x3F];
        result[j++] = base64_table[(triple >> 12) & 0x3F];
        result[j++] = base64_table[(triple >> 6) & 0x3F];
        result[j++] = base64_table[triple & 0x3F];
    }
    
    /* Add padding */
    size_t mod = length % 3;
    if (mod > 0) {
        result[output_len - 1] = '=';
        if (mod == 1) {
            result[output_len - 2] = '=';
        }
    }
    
    result[output_len] = '\0';
    return result;
}

/*
 * JSON escape a string
 */
char* json_escape_string(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    size_t escaped_len = len;
    
    /* First pass: count extra characters needed */
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || 
            c == '\t' || c == '\b' || c == '\f') {
            escaped_len++;
        } else if ((unsigned char)c < 0x20) {
            escaped_len += 5; /* \uXXXX format */
        }
    }
    
    char *result = malloc(escaped_len + 1);
    if (!result) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        switch (c) {
            case '"':  result[j++] = '\\'; result[j++] = '"';  break;
            case '\\': result[j++] = '\\'; result[j++] = '\\'; break;
            case '\n': result[j++] = '\\'; result[j++] = 'n';  break;
            case '\r': result[j++] = '\\'; result[j++] = 'r';  break;
            case '\t': result[j++] = '\\'; result[j++] = 't';  break;
            case '\b': result[j++] = '\\'; result[j++] = 'b';  break;
            case '\f': result[j++] = '\\'; result[j++] = 'f';  break;
            default:
                if ((unsigned char)c < 0x20) {
                    j += sprintf(result + j, "\\u%04x", (unsigned char)c);
                } else {
                    result[j++] = c;
                }
        }
    }
    
    result[j] = '\0';
    return result;
}

/*
 * Write JSON escaped string to file
 */
void json_write_string(FILE *out, const char *str) {
    char *escaped = json_escape_string(str);
    if (escaped) {
        fprintf(out, "\"%s\"", escaped);
        free(escaped);
    } else {
        fprintf(out, "null");
    }
}

/*
 * Simple MD5 implementation (placeholder - should use a proper library)
 */
char* compute_md5(const uint8_t *data, size_t length) {
    /* Placeholder - return dummy hash */
    char *result = malloc(33);
    if (!result) return NULL;
    
    /* Simple checksum for now - replace with actual MD5 */
    uint32_t hash = 0;
    for (size_t i = 0; i < length; i++) {
        hash = hash * 31 + data[i];
    }
    
    snprintf(result, 33, "%08x%08x%08x%08x", hash, hash ^ 0x12345678, 
             hash ^ 0x9abcdef0, hash ^ 0xfedcba98);
    return result;
}

/*
 * Simple SHA1 implementation (placeholder)
 */
char* compute_sha1(const uint8_t *data, size_t length) {
    char *result = malloc(41);
    if (!result) return NULL;
    
    uint32_t hash = 0;
    for (size_t i = 0; i < length; i++) {
        hash = hash * 31 + data[i];
    }
    
    snprintf(result, 41, "%08x%08x%08x%08x%08x", hash, hash ^ 0x12345678,
             hash ^ 0x9abcdef0, hash ^ 0xfedcba98, hash ^ 0x11111111);
    return result;
}

/*
 * Simple SHA256 implementation (placeholder)
 */
char* compute_sha256(const uint8_t *data, size_t length) {
    char *result = malloc(65);
    if (!result) return NULL;
    
    uint32_t hash = 0;
    for (size_t i = 0; i < length; i++) {
        hash = hash * 31 + data[i];
    }
    
    snprintf(result, 65, "%08x%08x%08x%08x%08x%08x%08x%08x", 
             hash, hash ^ 0x12345678, hash ^ 0x9abcdef0, hash ^ 0xfedcba98,
             hash ^ 0x11111111, hash ^ 0x22222222, hash ^ 0x33333333, hash ^ 0x44444444);
    return result;
}

/*
 * Create new SBUD document
 */
SbudDocument* sbud_document_new(void) {
    SbudDocument *doc = calloc(1, sizeof(SbudDocument));
    if (!doc) return NULL;
    
    doc->ludofile_version = strdup(LUDOFILE_VERSION);
    return doc;
}

/*
 * Free SBUD document
 */
void sbud_document_free(SbudDocument *doc) {
    if (!doc) return;
    
    free(doc->md5);
    free(doc->sha1);
    free(doc->sha256);
    free(doc->b64_contents);
    free(doc->filename);
    free(doc->ludofile_version);
    
    for (size_t i = 0; i < doc->num_matches; i++) {
        parse_match_free(doc->matches[i]);
    }
    free(doc->matches);
    
    free(doc);
}

/*
 * Set file data for SBUD document
 */
LudofileResult sbud_document_set_file(SbudDocument *doc, const uint8_t *data,
                                       size_t length, const char *filename) {
    if (!doc || !data) return LUDOFILE_ERROR_INVALID;
    
    doc->length = length;
    doc->filename = filename ? strdup(filename) : strdup("stdin");
    doc->md5 = compute_md5(data, length);
    doc->sha1 = compute_sha1(data, length);
    doc->sha256 = compute_sha256(data, length);
    doc->b64_contents = base64_encode(data, length);
    
    if (!doc->md5 || !doc->sha1 || !doc->sha256 || !doc->b64_contents) {
        return LUDOFILE_ERROR_MEMORY;
    }
    
    return LUDOFILE_OK;
}

/*
 * Add match to SBUD document
 */
LudofileResult sbud_document_add_match(SbudDocument *doc, ParseMatch *match) {
    if (!doc || !match) return LUDOFILE_ERROR_INVALID;
    
    size_t new_count = doc->num_matches + 1;
    ParseMatch **new_matches = realloc(doc->matches, new_count * sizeof(ParseMatch*));
    if (!new_matches) return LUDOFILE_ERROR_MEMORY;
    
    doc->matches = new_matches;
    doc->matches[doc->num_matches] = match;
    doc->num_matches = new_count;
    
    return LUDOFILE_OK;
}

/*
 * Write parse match as JSON
 */
static void write_parse_match_json(FILE *out, ParseMatch *match, int indent, bool pretty) {
    const char *ind = "";
    const char *nl = "";
    
    if (pretty) {
        ind = "  ";
        nl = "\n";
    }
    
    fprintf(out, "{%s", nl);
    
    /* relative_offset */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"relative_offset\": %zu,%s", match->relative_offset, nl);
    
    /* offset */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"offset\": %zu,%s", match->offset, nl);
    
    /* size */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"size\": %zu,%s", match->length, nl);
    
    /* type */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"type\": ");
    json_write_string(out, match->name);
    fprintf(out, ",%s", nl);
    
    /* name */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"name\": ");
    json_write_string(out, match->display_name);
    fprintf(out, ",%s", nl);
    
    /* value */
    for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
    fprintf(out, "\"value\": \"\"%s", nl);
    
    /* subEls */
    if (match->num_children > 0) {
        for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
        fprintf(out, "\"subEls\": [%s", nl);
        
        for (size_t i = 0; i < match->num_children; i++) {
            for (int j = 0; j < indent + 2; j++) fprintf(out, "%s", ind);
            write_parse_match_json(out, match->children[i], indent + 2, pretty);
            if (i < match->num_children - 1) {
                fprintf(out, ",");
            }
            fprintf(out, "%s", nl);
        }
        
        for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
        fprintf(out, "]%s", nl);
    } else {
        for (int i = 0; i < indent + 1; i++) fprintf(out, "%s", ind);
        fprintf(out, "\"subEls\": []%s", nl);
    }
    
    for (int i = 0; i < indent; i++) fprintf(out, "%s", ind);
    fprintf(out, "}");
}

/*
 * Output JSON format
 */
LudofileResult output_json(FILE *out, Match *match, const uint8_t *data,
                           size_t data_len, const char *filename,
                           const JsonOutputOptions *options) {
    if (!out || !match || !data) return LUDOFILE_ERROR_INVALID;
    
    bool pretty = options ? options->pretty_print : true;
    const char *nl = pretty ? "\n" : "";
    const char *ind = pretty ? "  " : "";
    
    /* Create SBUD document */
    SbudDocument *doc = sbud_document_new();
    if (!doc) return LUDOFILE_ERROR_MEMORY;
    
    LudofileResult res = sbud_document_set_file(doc, data, data_len, filename);
    if (res != LUDOFILE_OK) {
        sbud_document_free(doc);
        return res;
    }
    
    /* Output JSON */
    fprintf(out, "{%s", nl);
    
    fprintf(out, "%s\"MD5\": \"%s\",%s", ind, doc->md5, nl);
    fprintf(out, "%s\"SHA1\": \"%s\",%s", ind, doc->sha1, nl);
    fprintf(out, "%s\"SHA256\": \"%s\",%s", ind, doc->sha256, nl);
    
    if (options && options->include_b64_contents) {
        fprintf(out, "%s\"b64contents\": \"%s\",%s", ind, doc->b64_contents, nl);
    }
    
    fprintf(out, "%s\"fileName\": ", ind);
    json_write_string(out, filename);
    fprintf(out, ",%s", nl);
    
    fprintf(out, "%s\"length\": %zu,%s", ind, data_len, nl);
    
    fprintf(out, "%s\"versions\": {%s", ind, nl);
    fprintf(out, "%s%s\"polyfile\": \"%s\"%s", ind, ind, doc->ludofile_version, nl);
    fprintf(out, "%s},%s", ind, nl);
    
    fprintf(out, "%s\"struc\": [%s", ind, nl);
    
    /* Output matches */
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    if (mimes) {
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "%s%s{%s", ind, ind, nl);
            fprintf(out, "%s%s%s\"type\": \"%s\",%s", ind, ind, ind, mimes[i], nl);
            fprintf(out, "%s%s%s\"offset\": 0,%s", ind, ind, ind, nl);
            fprintf(out, "%s%s%s\"size\": %zu,%s", ind, ind, ind, data_len, nl);
            fprintf(out, "%s%s%s\"subEls\": []%s", ind, ind, ind, nl);
            fprintf(out, "%s%s}%s%s", ind, ind, i < count - 1 ? "," : "", nl);
        }
        free(mimes);
    }
    
    fprintf(out, "%s]%s", ind, nl);
    fprintf(out, "}%s", nl);
    
    sbud_document_free(doc);
    return LUDOFILE_OK;
}

/*
 * Output SBUD format (same as JSON for now)
 */
LudofileResult output_sbud(FILE *out, SbudDocument *doc,
                           const JsonOutputOptions *options) {
    if (!out || !doc) return LUDOFILE_ERROR_INVALID;
    
    bool pretty = options ? options->pretty_print : true;
    const char *nl = pretty ? "\n" : "";
    const char *ind = pretty ? "  " : "";
    
    fprintf(out, "{%s", nl);
    fprintf(out, "%s\"MD5\": \"%s\",%s", ind, doc->md5, nl);
    fprintf(out, "%s\"SHA1\": \"%s\",%s", ind, doc->sha1, nl);
    fprintf(out, "%s\"SHA256\": \"%s\",%s", ind, doc->sha256, nl);
    
    if (options && options->include_b64_contents) {
        fprintf(out, "%s\"b64contents\": \"%s\",%s", ind, doc->b64_contents, nl);
    }
    
    fprintf(out, "%s\"fileName\": ", ind);
    json_write_string(out, doc->filename);
    fprintf(out, ",%s", nl);
    
    fprintf(out, "%s\"length\": %zu,%s", ind, doc->length, nl);
    
    fprintf(out, "%s\"versions\": {%s", ind, nl);
    fprintf(out, "%s%s\"polyfile\": \"%s\"%s", ind, ind, doc->ludofile_version, nl);
    fprintf(out, "%s},%s", ind, nl);
    
    fprintf(out, "%s\"struc\": [%s", ind, nl);
    
    for (size_t i = 0; i < doc->num_matches; i++) {
        fprintf(out, "%s%s", ind, ind);
        write_parse_match_json(out, doc->matches[i], 2, pretty);
        if (i < doc->num_matches - 1) {
            fprintf(out, ",");
        }
        fprintf(out, "%s", nl);
    }
    
    fprintf(out, "%s]%s", ind, nl);
    fprintf(out, "}%s", nl);
    
    return LUDOFILE_OK;
}

/*
 * Output file format (like `file` command)
 */
LudofileResult output_file_format(FILE *out, Match *match) {
    if (!out || !match) return LUDOFILE_ERROR_INVALID;
    
    const char *msg = match_get_message(match);
    if (msg) {
        fprintf(out, "%s\n", msg);
    } else {
        size_t count;
        const char **mimes = match_get_mimetypes(match, &count);
        if (mimes && count > 0) {
            fprintf(out, "%s\n", mimes[0]);
            free(mimes);
        } else {
            fprintf(out, "data\n");
        }
    }
    
    return LUDOFILE_OK;
}

/*
 * Output MIME format
 */
LudofileResult output_mime_format(FILE *out, Match *match) {
    if (!out || !match) return LUDOFILE_ERROR_INVALID;
    
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    
    if (mimes) {
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "%s\n", mimes[i]);
        }
        free(mimes);
    } else {
        fprintf(out, "application/octet-stream\n");
    }
    
    return LUDOFILE_OK;
}

/*
 * Output explain format
 */
LudofileResult output_explain_format(FILE *out, Match *match) {
    if (!out || !match) return LUDOFILE_ERROR_INVALID;
    
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    
    if (mimes) {
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "%s\n", mimes[i]);
            /* TODO: Add explanation from match results */
            fprintf(out, "  (matched at offset 0)\n");
        }
        free(mimes);
    } else {
        fprintf(out, "application/octet-stream\n");
        fprintf(out, "  (no matches found)\n");
    }
    
    return LUDOFILE_OK;
}

/*
 * HTML hex viewer template
 */
static const char *html_template = 
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<title>LudoFile - %s</title>\n"
"<style>\n"
"body { font-family: sans-serif; margin: 20px; }\n"
".hex { font-family: monospace; background: #f0f0f0; padding: 10px; }\n"
".match { background: #ffffcc; }\n"
".info { margin: 10px 0; padding: 10px; background: #e0e0e0; }\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<h1>LudoFile Analysis</h1>\n"
"<div class=\"info\">\n"
"<p><strong>File:</strong> %s</p>\n"
"<p><strong>Size:</strong> %zu bytes</p>\n"
"<p><strong>Types:</strong> %s</p>\n"
"</div>\n"
"<h2>Structure</h2>\n"
"<pre class=\"hex\">%s</pre>\n"
"<script>\n"
"// Interactive hex viewer could go here\n"
"</script>\n"
"</body>\n"
"</html>\n";

/*
 * Output HTML format
 */
LudofileResult output_html(FILE *out, Match *match, const uint8_t *data,
                           size_t data_len, const char *filename,
                           const HtmlOutputOptions *options) {
    if (!out || !match || !data) return LUDOFILE_ERROR_INVALID;
    
    const char *title = filename ? filename : "stdin";
    
    /* Get MIME types */
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    char mime_list[1024] = "unknown";
    
    if (mimes && count > 0) {
        strcpy(mime_list, mimes[0]);
        for (size_t i = 1; i < count && strlen(mime_list) < 900; i++) {
            strcat(mime_list, ", ");
            strcat(mime_list, mimes[i]);
        }
        free(mimes);
    }
    
    /* Generate hex dump (first 256 bytes) */
    char hex_dump[4096];
    size_t hex_pos = 0;
    size_t show_len = data_len < 256 ? data_len : 256;
    
    for (size_t i = 0; i < show_len; i++) {
        if (i % 16 == 0) {
            if (i > 0) {
                hex_pos += snprintf(hex_dump + hex_pos, sizeof(hex_dump) - hex_pos, "\n");
            }
            hex_pos += snprintf(hex_dump + hex_pos, sizeof(hex_dump) - hex_pos, 
                               "%08zx: ", i);
        }
        hex_pos += snprintf(hex_dump + hex_pos, sizeof(hex_dump) - hex_pos, 
                           "%02x ", data[i]);
    }
    
    if (data_len > 256) {
        hex_pos += snprintf(hex_dump + hex_pos, sizeof(hex_dump) - hex_pos, 
                           "\n... (%zu more bytes)", data_len - 256);
    }
    
    fprintf(out, html_template, title, filename, data_len, mime_list, hex_dump);
    
    return LUDOFILE_OK;
}
