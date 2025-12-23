/*
 * LudoFile - Binary Structure Parsing DSL Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "structs.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Structure definition
 * ============================================================================ */

StructDef *struct_def_new(const char *name) {
    StructDef *def = malloc(sizeof(StructDef));
    if (!def) {
        return NULL;
    }
    
    memset(def, 0, sizeof(*def));
    if (name) {
        def->name = strdup(name);
    }
    
    return def;
}

void struct_def_free(StructDef *def) {
    if (!def) {
        return;
    }
    
    if (def->name) {
        free((void *)def->name);
    }
    
    if (def->fields) {
        free(def->fields);
    }
    
    free(def);
}

int struct_def_add_field(StructDef *def, const StructField *field) {
    if (!def || !field) {
        return -1;
    }
    
    /* Grow fields array */
    size_t new_count = def->num_fields + 1;
    StructField *new_fields = realloc(def->fields, sizeof(StructField) * new_count);
    if (!new_fields) {
        return -1;
    }
    
    new_fields[def->num_fields] = *field;
    def->fields = new_fields;
    def->num_fields = new_count;
    
    return 0;
}

/* ============================================================================
 * Structure reading
 * ============================================================================ */

void *struct_read(const StructDef *def, const uint8_t *data, size_t data_len) {
    if (!def || !data) {
        return NULL;
    }
    
    /* Allocate result structure - simplified, returns NULL for now */
    (void)data_len;
    
    return NULL;
}

void struct_free_data(void *data) {
    if (data) {
        free(data);
    }
}
