/*
 * LudoFile - PDF Parser Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "pdf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
 * Helper: Skip whitespace
 */
static void skip_whitespace(const uint8_t *data, size_t len, size_t *offset) {
    while (*offset < len) {
        uint8_t c = data[*offset];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || 
            c == '\f' || c == '\0') {
            (*offset)++;
        } else if (c == '%') {
            /* Skip comment until end of line */
            while (*offset < len && data[*offset] != '\r' && data[*offset] != '\n') {
                (*offset)++;
            }
        } else {
            break;
        }
    }
}

/*
 * Helper: Check if character is delimiter
 */
static bool is_delimiter(uint8_t c) {
    return c == '(' || c == ')' || c == '<' || c == '>' ||
           c == '[' || c == ']' || c == '{' || c == '}' ||
           c == '/' || c == '%';
}

/*
 * Helper: Check if character is whitespace
 */
static bool is_ws(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || 
           c == '\f' || c == '\0';
}

/*
 * Find PDF header
 */
const uint8_t* pdf_find_header(const uint8_t *data, size_t len, size_t *offset) {
    for (size_t i = 0; i + 5 <= len; i++) {
        if (memcmp(data + i, "%PDF-", 5) == 0) {
            *offset = i;
            return data + i;
        }
    }
    return NULL;
}

/*
 * Find startxref offset
 */
int64_t pdf_find_startxref(const uint8_t *data, size_t len) {
    /* Search backwards for "startxref" */
    const char *marker = "startxref";
    size_t marker_len = 9;
    
    if (len < marker_len + 10) return -1;
    
    for (size_t i = len - marker_len - 1; i > 0; i--) {
        if (memcmp(data + i, marker, marker_len) == 0) {
            /* Found startxref, now find the offset value */
            size_t pos = i + marker_len;
            skip_whitespace(data, len, &pos);
            
            /* Parse the offset */
            int64_t offset = 0;
            while (pos < len && isdigit(data[pos])) {
                offset = offset * 10 + (data[pos] - '0');
                pos++;
            }
            return offset;
        }
    }
    return -1;
}

/*
 * Create new PDF document
 */
PDFDocument* pdf_document_new(void) {
    PDFDocument *doc = calloc(1, sizeof(PDFDocument));
    return doc;
}

/*
 * Free PDF document
 */
void pdf_document_free(PDFDocument *doc) {
    if (!doc) return;
    
    if (doc->xref) pdf_xref_free(doc->xref);
    if (doc->trailer) pdf_object_free(doc->trailer);
    if (doc->catalog) pdf_object_free(doc->catalog);
    
    free(doc);
}

/*
 * Create new PDF object
 */
static PDFObject* pdf_object_new(PDFObjectType type) {
    PDFObject *obj = calloc(1, sizeof(PDFObject));
    if (obj) obj->type = type;
    return obj;
}

/*
 * Free PDF object
 */
void pdf_object_free(PDFObject *obj) {
    if (!obj) return;
    
    switch (obj->type) {
        case PDF_OBJ_STRING:
            free(obj->value.string_val.data);
            break;
        case PDF_OBJ_NAME:
            free(obj->value.name_val);
            break;
        case PDF_OBJ_ARRAY:
            for (size_t i = 0; i < obj->value.array_val.count; i++) {
                pdf_object_free(obj->value.array_val.items[i]);
            }
            free(obj->value.array_val.items);
            break;
        case PDF_OBJ_DICTIONARY:
            for (size_t i = 0; i < obj->value.dict_val.count; i++) {
                free(obj->value.dict_val.keys[i]);
                pdf_object_free(obj->value.dict_val.values[i]);
            }
            free(obj->value.dict_val.keys);
            free(obj->value.dict_val.values);
            break;
        case PDF_OBJ_STREAM:
            if (obj->value.stream_val.dict) {
                pdf_object_free(obj->value.stream_val.dict);
            }
            free(obj->value.stream_val.data);
            free(obj->value.stream_val.decoded);
            break;
        default:
            break;
    }
    
    free(obj);
}

/*
 * Parse PDF name object
 */
static PDFObject* pdf_parse_name(const uint8_t *data, size_t len, size_t *offset) {
    if (*offset >= len || data[*offset] != '/') return NULL;
    (*offset)++;  /* Skip '/' */
    
    size_t start = *offset;
    while (*offset < len && !is_ws(data[*offset]) && !is_delimiter(data[*offset])) {
        (*offset)++;
    }
    
    size_t name_len = *offset - start;
    PDFObject *obj = pdf_object_new(PDF_OBJ_NAME);
    if (!obj) return NULL;
    
    obj->value.name_val = malloc(name_len + 1);
    if (!obj->value.name_val) {
        free(obj);
        return NULL;
    }
    
    /* Handle #XX escape sequences */
    size_t j = 0;
    for (size_t i = 0; i < name_len; i++) {
        if (data[start + i] == '#' && i + 2 < name_len) {
            char hex[3] = { (char)data[start + i + 1], (char)data[start + i + 2], 0 };
            obj->value.name_val[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            obj->value.name_val[j++] = (char)data[start + i];
        }
    }
    obj->value.name_val[j] = '\0';
    
    return obj;
}

/*
 * Parse PDF string object
 */
static PDFObject* pdf_parse_string(const uint8_t *data, size_t len, size_t *offset) {
    if (*offset >= len) return NULL;
    
    PDFObject *obj = pdf_object_new(PDF_OBJ_STRING);
    if (!obj) return NULL;
    
    if (data[*offset] == '(') {
        /* Literal string */
        (*offset)++;
        size_t start = *offset;
        int paren_depth = 1;
        
        while (*offset < len && paren_depth > 0) {
            if (data[*offset] == '\\' && *offset + 1 < len) {
                (*offset) += 2;  /* Skip escaped character */
            } else if (data[*offset] == '(') {
                paren_depth++;
                (*offset)++;
            } else if (data[*offset] == ')') {
                paren_depth--;
                if (paren_depth > 0) (*offset)++;
            } else {
                (*offset)++;
            }
        }
        
        size_t str_len = *offset - start;
        obj->value.string_val.data = malloc(str_len + 1);
        if (!obj->value.string_val.data) {
            free(obj);
            return NULL;
        }
        memcpy(obj->value.string_val.data, data + start, str_len);
        obj->value.string_val.data[str_len] = '\0';
        obj->value.string_val.len = str_len;
        obj->value.string_val.is_hex = false;
        
        (*offset)++;  /* Skip closing ')' */
        
    } else if (data[*offset] == '<' && *offset + 1 < len && data[*offset + 1] != '<') {
        /* Hexadecimal string */
        (*offset)++;
        size_t start = *offset;
        
        while (*offset < len && data[*offset] != '>') {
            (*offset)++;
        }
        
        size_t hex_len = *offset - start;
        size_t str_len = (hex_len + 1) / 2;
        obj->value.string_val.data = malloc(str_len + 1);
        if (!obj->value.string_val.data) {
            free(obj);
            return NULL;
        }
        
        /* Convert hex to bytes */
        size_t j = 0;
        for (size_t i = 0; i < hex_len && j < str_len; i += 2) {
            char hex[3] = {0, 0, 0};
            hex[0] = (char)data[start + i];
            if (i + 1 < hex_len) hex[1] = (char)data[start + i + 1];
            else hex[1] = '0';
            obj->value.string_val.data[j++] = (char)strtol(hex, NULL, 16);
        }
        obj->value.string_val.data[j] = '\0';
        obj->value.string_val.len = j;
        obj->value.string_val.is_hex = true;
        
        (*offset)++;  /* Skip closing '>' */
    } else {
        free(obj);
        return NULL;
    }
    
    return obj;
}

/*
 * Parse PDF number
 */
static PDFObject* pdf_parse_number(const uint8_t *data, size_t len, size_t *offset) {
    size_t start = *offset;
    bool has_decimal = false;
    bool negative = false;
    
    if (data[*offset] == '-' || data[*offset] == '+') {
        negative = (data[*offset] == '-');
        (*offset)++;
    }
    
    while (*offset < len) {
        if (isdigit(data[*offset])) {
            (*offset)++;
        } else if (data[*offset] == '.' && !has_decimal) {
            has_decimal = true;
            (*offset)++;
        } else {
            break;
        }
    }
    
    if (*offset == start || (*offset == start + 1 && (data[start] == '-' || data[start] == '+'))) {
        return NULL;
    }
    
    PDFObject *obj;
    if (has_decimal) {
        obj = pdf_object_new(PDF_OBJ_REAL);
        if (!obj) return NULL;
        char *num_str = malloc(*offset - start + 1);
        if (!num_str) { free(obj); return NULL; }
        memcpy(num_str, data + start, *offset - start);
        num_str[*offset - start] = '\0';
        obj->value.real_val = atof(num_str);
        free(num_str);
    } else {
        obj = pdf_object_new(PDF_OBJ_INTEGER);
        if (!obj) return NULL;
        int64_t val = 0;
        for (size_t i = (negative || data[start] == '+') ? start + 1 : start; i < *offset; i++) {
            val = val * 10 + (data[i] - '0');
        }
        obj->value.integer_val = negative ? -val : val;
    }
    
    return obj;
}

/*
 * Forward declaration
 */
static PDFObject* pdf_parse_dict(const uint8_t *data, size_t len, size_t *offset);
static PDFObject* pdf_parse_array(const uint8_t *data, size_t len, size_t *offset);

/*
 * Parse PDF object (generic)
 */
PDFObject* pdf_parse_object(const uint8_t *data, size_t len, size_t *offset) {
    skip_whitespace(data, len, offset);
    if (*offset >= len) return NULL;
    
    size_t start_offset = *offset;
    
    /* Check for dictionary */
    if (*offset + 1 < len && data[*offset] == '<' && data[*offset + 1] == '<') {
        PDFObject *obj = pdf_parse_dict(data, len, offset);
        if (obj) {
            obj->offset = start_offset;
            obj->length = *offset - start_offset;
            
            /* Check for stream */
            skip_whitespace(data, len, offset);
            if (*offset + 6 < len && memcmp(data + *offset, "stream", 6) == 0) {
                *offset += 6;
                /* Skip to start of stream data */
                if (*offset < len && data[*offset] == '\r') (*offset)++;
                if (*offset < len && data[*offset] == '\n') (*offset)++;
                
                /* Get stream length from dictionary */
                size_t stream_len = 0;
                for (size_t i = 0; i < obj->value.dict_val.count; i++) {
                    if (strcmp(obj->value.dict_val.keys[i], "Length") == 0) {
                        PDFObject *len_obj = obj->value.dict_val.values[i];
                        if (len_obj->type == PDF_OBJ_INTEGER) {
                            stream_len = (size_t)len_obj->value.integer_val;
                        }
                        break;
                    }
                }
                
                /* Create stream object */
                PDFObject *stream = pdf_object_new(PDF_OBJ_STREAM);
                if (stream) {
                    stream->value.stream_val.dict = obj;
                    stream->value.stream_val.data = malloc(stream_len);
                    if (stream->value.stream_val.data && *offset + stream_len <= len) {
                        memcpy(stream->value.stream_val.data, data + *offset, stream_len);
                        stream->value.stream_val.data_len = stream_len;
                    }
                    *offset += stream_len;
                    
                    /* Skip "endstream" */
                    skip_whitespace(data, len, offset);
                    if (*offset + 9 <= len && memcmp(data + *offset, "endstream", 9) == 0) {
                        *offset += 9;
                    }
                    
                    stream->offset = start_offset;
                    stream->length = *offset - start_offset;
                    return stream;
                }
            }
        }
        return obj;
    }
    
    /* Check for array */
    if (data[*offset] == '[') {
        PDFObject *obj = pdf_parse_array(data, len, offset);
        if (obj) {
            obj->offset = start_offset;
            obj->length = *offset - start_offset;
        }
        return obj;
    }
    
    /* Check for name */
    if (data[*offset] == '/') {
        PDFObject *obj = pdf_parse_name(data, len, offset);
        if (obj) {
            obj->offset = start_offset;
            obj->length = *offset - start_offset;
        }
        return obj;
    }
    
    /* Check for string */
    if (data[*offset] == '(' || (data[*offset] == '<' && 
        (*offset + 1 >= len || data[*offset + 1] != '<'))) {
        PDFObject *obj = pdf_parse_string(data, len, offset);
        if (obj) {
            obj->offset = start_offset;
            obj->length = *offset - start_offset;
        }
        return obj;
    }
    
    /* Check for boolean or null */
    if (*offset + 4 <= len) {
        if (memcmp(data + *offset, "true", 4) == 0) {
            *offset += 4;
            PDFObject *obj = pdf_object_new(PDF_OBJ_BOOLEAN);
            if (obj) {
                obj->value.boolean_val = true;
                obj->offset = start_offset;
                obj->length = 4;
            }
            return obj;
        }
        if (memcmp(data + *offset, "null", 4) == 0) {
            *offset += 4;
            PDFObject *obj = pdf_object_new(PDF_OBJ_NULL);
            if (obj) {
                obj->offset = start_offset;
                obj->length = 4;
            }
            return obj;
        }
    }
    if (*offset + 5 <= len && memcmp(data + *offset, "false", 5) == 0) {
        *offset += 5;
        PDFObject *obj = pdf_object_new(PDF_OBJ_BOOLEAN);
        if (obj) {
            obj->value.boolean_val = false;
            obj->offset = start_offset;
            obj->length = 5;
        }
        return obj;
    }
    
    /* Check for number (may be reference) */
    if (isdigit(data[*offset]) || data[*offset] == '-' || data[*offset] == '+' || data[*offset] == '.') {
        PDFObject *num1 = pdf_parse_number(data, len, offset);
        if (!num1) return NULL;
        
        /* Check if this might be an indirect reference */
        if (num1->type == PDF_OBJ_INTEGER) {
            size_t saved_offset = *offset;
            skip_whitespace(data, len, offset);
            
            PDFObject *num2 = pdf_parse_number(data, len, offset);
            if (num2 && num2->type == PDF_OBJ_INTEGER) {
                skip_whitespace(data, len, offset);
                if (*offset < len && data[*offset] == 'R') {
                    (*offset)++;
                    /* It's an indirect reference */
                    PDFObject *ref = pdf_object_new(PDF_OBJ_REFERENCE);
                    if (ref) {
                        ref->value.ref_val.obj_num = (int)num1->value.integer_val;
                        ref->value.ref_val.gen_num = (int)num2->value.integer_val;
                        ref->offset = start_offset;
                        ref->length = *offset - start_offset;
                    }
                    pdf_object_free(num1);
                    pdf_object_free(num2);
                    return ref;
                }
            }
            
            if (num2) pdf_object_free(num2);
            *offset = saved_offset;
        }
        
        num1->offset = start_offset;
        num1->length = *offset - start_offset;
        return num1;
    }
    
    return NULL;
}

/*
 * Parse PDF dictionary
 */
static PDFObject* pdf_parse_dict(const uint8_t *data, size_t len, size_t *offset) {
    if (*offset + 1 >= len || data[*offset] != '<' || data[*offset + 1] != '<') {
        return NULL;
    }
    *offset += 2;
    
    PDFObject *dict = pdf_object_new(PDF_OBJ_DICTIONARY);
    if (!dict) return NULL;
    
    dict->value.dict_val.capacity = 8;
    dict->value.dict_val.keys = malloc(8 * sizeof(char*));
    dict->value.dict_val.values = malloc(8 * sizeof(PDFObject*));
    if (!dict->value.dict_val.keys || !dict->value.dict_val.values) {
        pdf_object_free(dict);
        return NULL;
    }
    
    while (1) {
        skip_whitespace(data, len, offset);
        if (*offset + 1 < len && data[*offset] == '>' && data[*offset + 1] == '>') {
            *offset += 2;
            break;
        }
        
        /* Parse key (must be a name) */
        PDFObject *key = pdf_parse_name(data, len, offset);
        if (!key) break;
        
        /* Parse value */
        skip_whitespace(data, len, offset);
        PDFObject *value = pdf_parse_object(data, len, offset);
        if (!value) {
            pdf_object_free(key);
            break;
        }
        
        /* Add to dictionary */
        if (dict->value.dict_val.count >= dict->value.dict_val.capacity) {
            size_t new_cap = dict->value.dict_val.capacity * 2;
            char **new_keys = realloc(dict->value.dict_val.keys, new_cap * sizeof(char*));
            PDFObject **new_vals = realloc(dict->value.dict_val.values, new_cap * sizeof(PDFObject*));
            if (!new_keys || !new_vals) {
                pdf_object_free(key);
                pdf_object_free(value);
                break;
            }
            dict->value.dict_val.keys = new_keys;
            dict->value.dict_val.values = new_vals;
            dict->value.dict_val.capacity = new_cap;
        }
        
        dict->value.dict_val.keys[dict->value.dict_val.count] = key->value.name_val;
        key->value.name_val = NULL;  /* Transfer ownership */
        dict->value.dict_val.values[dict->value.dict_val.count] = value;
        dict->value.dict_val.count++;
        
        pdf_object_free(key);
    }
    
    return dict;
}

/*
 * Parse PDF array
 */
static PDFObject* pdf_parse_array(const uint8_t *data, size_t len, size_t *offset) {
    if (*offset >= len || data[*offset] != '[') return NULL;
    (*offset)++;
    
    PDFObject *arr = pdf_object_new(PDF_OBJ_ARRAY);
    if (!arr) return NULL;
    
    arr->value.array_val.capacity = 8;
    arr->value.array_val.items = malloc(8 * sizeof(PDFObject*));
    if (!arr->value.array_val.items) {
        free(arr);
        return NULL;
    }
    
    while (1) {
        skip_whitespace(data, len, offset);
        if (*offset >= len || data[*offset] == ']') {
            (*offset)++;
            break;
        }
        
        PDFObject *item = pdf_parse_object(data, len, offset);
        if (!item) break;
        
        if (arr->value.array_val.count >= arr->value.array_val.capacity) {
            size_t new_cap = arr->value.array_val.capacity * 2;
            PDFObject **new_items = realloc(arr->value.array_val.items, 
                                            new_cap * sizeof(PDFObject*));
            if (!new_items) {
                pdf_object_free(item);
                break;
            }
            arr->value.array_val.items = new_items;
            arr->value.array_val.capacity = new_cap;
        }
        
        arr->value.array_val.items[arr->value.array_val.count++] = item;
    }
    
    return arr;
}

/*
 * Create XRef table
 */
PDFXRefTable* pdf_xref_table_new(void) {
    PDFXRefTable *xref = calloc(1, sizeof(PDFXRefTable));
    if (xref) {
        xref->capacity = 64;
        xref->entries = malloc(64 * sizeof(PDFXRefEntry));
        if (!xref->entries) {
            free(xref);
            return NULL;
        }
    }
    return xref;
}

/*
 * Free XRef table
 */
void pdf_xref_free(PDFXRefTable *xref) {
    if (xref) {
        free(xref->entries);
        free(xref);
    }
}

/*
 * Parse XRef table
 */
PDFXRefTable* pdf_parse_xref(const uint8_t *data, size_t len, size_t offset) {
    if (offset + 4 > len) return NULL;
    
    /* Skip "xref" keyword */
    if (memcmp(data + offset, "xref", 4) != 0) return NULL;
    offset += 4;
    skip_whitespace(data, len, &offset);
    
    PDFXRefTable *xref = pdf_xref_table_new();
    if (!xref) return NULL;
    
    while (offset < len && isdigit(data[offset])) {
        /* Parse subsection header: first_obj count */
        int first_obj = 0;
        while (offset < len && isdigit(data[offset])) {
            first_obj = first_obj * 10 + (data[offset] - '0');
            offset++;
        }
        skip_whitespace(data, len, &offset);
        
        int count = 0;
        while (offset < len && isdigit(data[offset])) {
            count = count * 10 + (data[offset] - '0');
            offset++;
        }
        skip_whitespace(data, len, &offset);
        
        /* Parse entries */
        for (int i = 0; i < count; i++) {
            if (offset + 20 > len) break;
            
            /* Parse offset (10 digits) */
            size_t obj_offset = 0;
            for (int j = 0; j < 10; j++) {
                if (isdigit(data[offset + j])) {
                    obj_offset = obj_offset * 10 + (data[offset + j] - '0');
                }
            }
            offset += 10;
            skip_whitespace(data, len, &offset);
            
            /* Parse generation (5 digits) */
            int gen = 0;
            for (int j = 0; j < 5; j++) {
                if (isdigit(data[offset + j])) {
                    gen = gen * 10 + (data[offset + j] - '0');
                }
            }
            offset += 5;
            skip_whitespace(data, len, &offset);
            
            /* Parse in-use flag */
            bool in_use = (data[offset] == 'n');
            offset++;
            skip_whitespace(data, len, &offset);
            
            /* Add entry */
            if (xref->count >= xref->capacity) {
                size_t new_cap = xref->capacity * 2;
                PDFXRefEntry *new_entries = realloc(xref->entries, 
                                                    new_cap * sizeof(PDFXRefEntry));
                if (!new_entries) break;
                xref->entries = new_entries;
                xref->capacity = new_cap;
            }
            
            xref->entries[xref->count].obj_num = first_obj + i;
            xref->entries[xref->count].offset = obj_offset;
            xref->entries[xref->count].gen_num = gen;
            xref->entries[xref->count].in_use = in_use;
            xref->count++;
        }
    }
    
    return xref;
}

/*
 * Parse trailer dictionary
 */
PDFObject* pdf_parse_trailer(const uint8_t *data, size_t len, size_t offset) {
    /* Find "trailer" keyword */
    while (offset + 7 < len) {
        if (memcmp(data + offset, "trailer", 7) == 0) {
            offset += 7;
            skip_whitespace(data, len, &offset);
            return pdf_parse_object(data, len, &offset);
        }
        offset++;
    }
    return NULL;
}

/*
 * Parse PDF document
 */
LudofileResult pdf_document_parse(PDFDocument *doc, const uint8_t *data, size_t len) {
    if (!doc || !data || len == 0) return LUDOFILE_ERROR_INVALID;
    
    doc->data = data;
    doc->data_len = len;
    doc->file_size = len;
    
    /* Find PDF header */
    size_t header_offset = 0;
    const uint8_t *header = pdf_find_header(data, len, &header_offset);
    if (!header) return LUDOFILE_ERROR_PARSE;
    
    /* Parse version */
    if (header_offset + 8 <= len) {
        doc->version.major = header[5] - '0';
        doc->version.minor = header[7] - '0';
    }
    
    /* Find startxref */
    int64_t startxref = pdf_find_startxref(data, len);
    if (startxref < 0 || (size_t)startxref >= len) {
        return LUDOFILE_ERROR_PARSE;
    }
    
    /* Parse XRef table or stream */
    doc->xref = pdf_parse_xref(data, len, (size_t)startxref);
    
    /* Parse trailer */
    if (doc->xref) {
        doc->trailer = pdf_parse_trailer(data, len, (size_t)startxref);
    }
    
    return LUDOFILE_OK;
}

/*
 * PDF parser iterator state
 */
typedef struct {
    PDFDocument *doc;
    uint8_t *data;            /* Data buffer ownership */
    size_t current_obj;
    ParseMatch *parent;
    ParseMatch **matches;
    size_t num_matches;
    size_t matches_capacity;
} PDFParserState;

/*
 * Create ParseMatch from PDF object
 */
static ParseMatch* pdf_object_to_match(PDFObject *obj, ParseMatch *parent, size_t base_offset) {
    if (!obj) return NULL;
    
    const char *type_name;
    switch (obj->type) {
        case PDF_OBJ_NULL: type_name = "PDFNull"; break;
        case PDF_OBJ_BOOLEAN: type_name = "PDFBoolean"; break;
        case PDF_OBJ_INTEGER: type_name = "PDFInteger"; break;
        case PDF_OBJ_REAL: type_name = "PDFReal"; break;
        case PDF_OBJ_STRING: type_name = "PDFString"; break;
        case PDF_OBJ_NAME: type_name = "PDFName"; break;
        case PDF_OBJ_ARRAY: type_name = "PDFArray"; break;
        case PDF_OBJ_DICTIONARY: type_name = "PDFDictionary"; break;
        case PDF_OBJ_STREAM: type_name = "PDFStream"; break;
        case PDF_OBJ_REFERENCE: type_name = "PDFReference"; break;
        default: type_name = "PDFUnknown"; break;
    }
    
    ParseMatch *match = parse_match_new(type_name, obj->offset - base_offset, 
                                        obj->length, parent);
    return match;
}

/*
 * Iterator next function
 */
static ParseMatch* pdf_parser_next(ParseMatchIterator *iter) {
    if (!iter || !iter->state) return NULL;
    
    PDFParserState *state = (PDFParserState*)iter->state;
    
    if (state->current_obj >= state->num_matches) {
        return NULL;
    }
    
    return state->matches[state->current_obj++];
}

/*
 * Iterator free function
 */
static void pdf_parser_free(ParseMatchIterator *iter) {
    if (!iter) return;
    
    PDFParserState *state = (PDFParserState*)iter->state;
    if (state) {
        if (state->doc) pdf_document_free(state->doc);
        free(state->data);  /* Free the data buffer */
        /* Matches are owned by caller, don't free them */
        free(state->matches);
        free(state);
    }
    free(iter);
}

/*
 * PDF parser entry point
 */
ParseMatchIterator* pdf_parser(FileStream *stream, ParseMatch *parent) {
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
    
    /* Create PDF document */
    PDFDocument *doc = pdf_document_new();
    if (!doc) {
        free(data);
        return NULL;
    }
    
    /* Parse document */
    LudofileResult result = pdf_document_parse(doc, data, bytes_read);
    if (result != LUDOFILE_OK) {
        pdf_document_free(doc);
        free(data);
        return NULL;
    }
    
    /* Create iterator state */
    PDFParserState *state = calloc(1, sizeof(PDFParserState));
    if (!state) {
        pdf_document_free(doc);
        free(data);
        return NULL;
    }
    
    state->doc = doc;
    state->data = data;  /* Track data buffer for cleanup */
    state->parent = parent;
    state->matches_capacity = 64;
    state->matches = malloc(64 * sizeof(ParseMatch*));
    if (!state->matches) {
        free(state);
        pdf_document_free(doc);
        free(data);
        return NULL;
    }
    
    /* Generate matches for XRef entries */
    if (doc->xref) {
        for (size_t i = 0; i < doc->xref->count; i++) {
            PDFXRefEntry *entry = &doc->xref->entries[i];
            if (!entry->in_use || entry->offset >= bytes_read) continue;
            
            /* Parse object at this offset */
            size_t offset = entry->offset;
            
            /* Skip "N M obj" header */
            skip_whitespace(data, bytes_read, &offset);
            while (offset < bytes_read && isdigit(data[offset])) offset++;
            skip_whitespace(data, bytes_read, &offset);
            while (offset < bytes_read && isdigit(data[offset])) offset++;
            skip_whitespace(data, bytes_read, &offset);
            if (offset + 3 <= bytes_read && memcmp(data + offset, "obj", 3) == 0) {
                offset += 3;
            }
            
            PDFObject *obj = pdf_parse_object(data, bytes_read, &offset);
            if (obj) {
                char display_name[64];
                snprintf(display_name, sizeof(display_name), "PDFObject %d %d", 
                         entry->obj_num, entry->gen_num);
                
                ParseMatch *match = parse_match_new("PDFObject", 
                                                    entry->offset - (parent ? parent->offset : 0),
                                                    offset - entry->offset,
                                                    parent);
                if (match) {
                    /* Add to matches array */
                    if (state->num_matches >= state->matches_capacity) {
                        size_t new_cap = state->matches_capacity * 2;
                        ParseMatch **new_matches = realloc(state->matches, 
                                                          new_cap * sizeof(ParseMatch*));
                        if (new_matches) {
                            state->matches = new_matches;
                            state->matches_capacity = new_cap;
                        }
                    }
                    
                    if (state->num_matches < state->matches_capacity) {
                        state->matches[state->num_matches++] = match;
                    }
                }
                
                pdf_object_free(obj);
            }
        }
    }
    
    /* Create iterator */
    ParseMatchIterator *iter = malloc(sizeof(ParseMatchIterator));
    if (!iter) {
        free(state->matches);
        free(state->data);
        free(state);
        pdf_document_free(doc);
        return NULL;
    }
    
    iter->state = state;
    iter->next = pdf_parser_next;
    iter->free = pdf_parser_free;
    
    return iter;
}
