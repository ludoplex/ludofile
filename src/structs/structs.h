/*
 * LudoFile - Binary Structure Parsing DSL
 *
 * Simple DSL for defining and parsing binary structures.
 * Similar to PolyFile's structs.py but in C.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_STRUCTS_H
#define LUDOFILE_STRUCTS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../core/types.h"  /* For Endianness */

/* ============================================================================
 * Type definitions
 * ============================================================================ */

typedef enum {
    STRUCT_FIELD_U8 = 0,
    STRUCT_FIELD_U16,
    STRUCT_FIELD_U32,
    STRUCT_FIELD_U64,
    STRUCT_FIELD_S8,
    STRUCT_FIELD_S16,
    STRUCT_FIELD_S32,
    STRUCT_FIELD_S64,
    STRUCT_FIELD_F32,
    STRUCT_FIELD_F64,
    STRUCT_FIELD_BYTES,
    STRUCT_FIELD_STRING,
    STRUCT_FIELD_STRUCT
} StructFieldType;

typedef struct StructDef StructDef;

typedef struct {
    const char *name;
    StructFieldType type;
    size_t offset;       /* Static offset or SIZE_MAX for dynamic */
    size_t size;         /* Field size (for BYTES/STRING) */
    Endianness endian;
    const StructDef *nested_struct;  /* For STRUCT_FIELD_STRUCT */
} StructField;

struct StructDef {
    const char *name;
    StructField *fields;
    size_t num_fields;
};

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Create structure definition
 */
StructDef *struct_def_new(const char *name);
void struct_def_free(StructDef *def);

/*
 * Add fields to structure
 */
int struct_def_add_field(StructDef *def, const StructField *field);

/*
 * Read structure from data
 */
void *struct_read(const StructDef *def, const uint8_t *data, size_t data_len);
void struct_free_data(void *data);

#endif /* LUDOFILE_STRUCTS_H */
