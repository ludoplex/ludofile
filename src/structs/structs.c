/*
 * LudoFile - Binary Structure Parsing DSL Implementation
 *
 * Complete implementation with full endian swapping and struct reading.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "structs.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/* POSIX-compliant string duplication */
static char *safe_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

/* Endian swapping functions */
static uint16_t swap16(uint16_t v) {
    return (v >> 8) | (v << 8);
}

static uint32_t swap32(uint32_t v) {
    return ((v >> 24) & 0xFF) |
           ((v >> 8)  & 0xFF00) |
           ((v << 8)  & 0xFF0000) |
           ((v << 24) & 0xFF000000);
}

static uint64_t swap64(uint64_t v) {
    return ((v >> 56) & 0xFF) |
           ((v >> 40) & 0xFF00) |
           ((v >> 24) & 0xFF0000) |
           ((v >> 8)  & 0xFF000000) |
           ((v << 8)  & 0xFF00000000ULL) |
           ((v << 24) & 0xFF0000000000ULL) |
           ((v << 40) & 0xFF000000000000ULL) |
           ((v << 56) & 0xFF00000000000000ULL);
}

/* Check host endianness */
static bool host_is_big_endian(void) {
    union { uint32_t i; uint8_t c[4]; } u = { .i = 1 };
    return u.c[0] == 0;
}

/* Read with endian conversion */
static uint16_t read_u16(const uint8_t *data, Endianness endian) {
    if (endian == ENDIAN_LITTLE) {
        return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    } else { /* ENDIAN_BIG */
        return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
    }
}

static uint32_t read_u32(const uint8_t *data, Endianness endian) {
    if (endian == ENDIAN_LITTLE) {
        return (uint32_t)data[0] |
               ((uint32_t)data[1] << 8) |
               ((uint32_t)data[2] << 16) |
               ((uint32_t)data[3] << 24);
    } else { /* ENDIAN_BIG */
        return ((uint32_t)data[0] << 24) |
               ((uint32_t)data[1] << 16) |
               ((uint32_t)data[2] << 8)  |
               (uint32_t)data[3];
    }
}

static uint64_t read_u64(const uint8_t *data, Endianness endian) {
    if (endian == ENDIAN_LITTLE) {
        return (uint64_t)data[0] |
               ((uint64_t)data[1] << 8)  |
               ((uint64_t)data[2] << 16) |
               ((uint64_t)data[3] << 24) |
               ((uint64_t)data[4] << 32) |
               ((uint64_t)data[5] << 40) |
               ((uint64_t)data[6] << 48) |
               ((uint64_t)data[7] << 56);
    } else { /* ENDIAN_BIG */
        return ((uint64_t)data[0] << 56) |
               ((uint64_t)data[1] << 48) |
               ((uint64_t)data[2] << 40) |
               ((uint64_t)data[3] << 32) |
               ((uint64_t)data[4] << 24) |
               ((uint64_t)data[5] << 16) |
               ((uint64_t)data[6] << 8)  |
               (uint64_t)data[7];
    }
}

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
        def->name = safe_strdup(name);
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
        for (size_t i = 0; i < def->num_fields; i++) {
            if (def->fields[i].name) {
                free((void *)def->fields[i].name);
            }
        }
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
    
    /* Copy field, duplicating name if present */
    new_fields[def->num_fields] = *field;
    if (field->name) {
        new_fields[def->num_fields].name = safe_strdup(field->name);
    }
    
    def->fields = new_fields;
    def->num_fields = new_count;
    
    return 0;
}

/* ============================================================================
 * Structure reading with complete endian swapping
 * ============================================================================ */

typedef struct {
    uint8_t *data;
    size_t size;
} StructData;

void *struct_read(const StructDef *def, const uint8_t *data, size_t data_len) {
    if (!def || !data) {
        return NULL;
    }
    
    /* Allocate result structure */
    StructData *result = calloc(1, sizeof(StructData));
    if (!result) {
        return NULL;
    }
    
    /* Calculate total size needed */
    size_t total_size = 0;
    size_t current_offset = 0;
    
    for (size_t i = 0; i < def->num_fields; i++) {
        const StructField *field = &def->fields[i];
        
        /* Determine field offset */
        size_t field_offset;
        if (field->offset != SIZE_MAX) {
            field_offset = field->offset;
        } else {
            field_offset = current_offset;
        }
        
        /* Determine field size */
        size_t field_size = field->size;
        if (field_size == 0) {
            /* Infer from type */
            switch (field->type) {
                case STRUCT_FIELD_U8:
                case STRUCT_FIELD_S8:
                    field_size = 1;
                    break;
                case STRUCT_FIELD_U16:
                case STRUCT_FIELD_S16:
                    field_size = 2;
                    break;
                case STRUCT_FIELD_U32:
                case STRUCT_FIELD_S32:
                case STRUCT_FIELD_F32:
                    field_size = 4;
                    break;
                case STRUCT_FIELD_U64:
                case STRUCT_FIELD_S64:
                case STRUCT_FIELD_F64:
                    field_size = 8;
                    break;
                default:
                    field_size = 1;
            }
        }
        
        current_offset = field_offset + field_size;
        if (current_offset > total_size) {
            total_size = current_offset;
        }
    }
    
    /* Allocate data buffer */
    result->data = calloc(1, total_size);
    result->size = total_size;
    
    if (!result->data) {
        free(result);
        return NULL;
    }
    
    /* Read each field */
    current_offset = 0;
    for (size_t i = 0; i < def->num_fields; i++) {
        const StructField *field = &def->fields[i];
        
        /* Determine field offset */
        size_t field_offset;
        if (field->offset != SIZE_MAX) {
            field_offset = field->offset;
        } else {
            field_offset = current_offset;
        }
        
        /* Check bounds */
        size_t read_size = field->size;
        if (read_size == 0) {
            switch (field->type) {
                case STRUCT_FIELD_U8:
                case STRUCT_FIELD_S8:
                    read_size = 1;
                    break;
                case STRUCT_FIELD_U16:
                case STRUCT_FIELD_S16:
                    read_size = 2;
                    break;
                case STRUCT_FIELD_U32:
                case STRUCT_FIELD_S32:
                case STRUCT_FIELD_F32:
                    read_size = 4;
                    break;
                case STRUCT_FIELD_U64:
                case STRUCT_FIELD_S64:
                case STRUCT_FIELD_F64:
                    read_size = 8;
                    break;
                default:
                    read_size = 1;
            }
        }
        
        if (field_offset + read_size > data_len) {
            /* Out of bounds */
            free(result->data);
            free(result);
            return NULL;
        }
        
        /* Read and convert based on type and endianness */
        switch (field->type) {
            case STRUCT_FIELD_U8:
            case STRUCT_FIELD_S8:
                result->data[field_offset] = data[field_offset];
                break;
                
            case STRUCT_FIELD_U16: {
                uint16_t val = read_u16(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 2);
                break;
            }
            
            case STRUCT_FIELD_S16: {
                uint16_t val = read_u16(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 2);
                break;
            }
            
            case STRUCT_FIELD_U32: {
                uint32_t val = read_u32(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 4);
                break;
            }
            
            case STRUCT_FIELD_S32: {
                uint32_t val = read_u32(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 4);
                break;
            }
            
            case STRUCT_FIELD_F32: {
                uint32_t val = read_u32(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 4);
                break;
            }
            
            case STRUCT_FIELD_U64: {
                uint64_t val = read_u64(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 8);
                break;
            }
            
            case STRUCT_FIELD_S64: {
                uint64_t val = read_u64(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 8);
                break;
            }
            
            case STRUCT_FIELD_F64: {
                uint64_t val = read_u64(&data[field_offset], field->endian);
                memcpy(&result->data[field_offset], &val, 8);
                break;
            }
            
            case STRUCT_FIELD_BYTES:
                if (read_size > 0) {
                    memcpy(&result->data[field_offset], &data[field_offset], read_size);
                }
                break;
                
            case STRUCT_FIELD_STRING:
                if (read_size > 0) {
                    memcpy(&result->data[field_offset], &data[field_offset], read_size);
                    result->data[field_offset + read_size - 1] = '\0';
                }
                break;
                
            case STRUCT_FIELD_STRUCT:
                if (field->nested_struct) {
                    void *nested = struct_read(field->nested_struct, 
                                              &data[field_offset], 
                                              data_len - field_offset);
                    if (nested) {
                        StructData *nested_data = (StructData *)nested;
                        if (nested_data->size <= read_size) {
                            memcpy(&result->data[field_offset], nested_data->data, nested_data->size);
                        }
                        struct_free_data(nested);
                    }
                }
                break;
        }
        
        current_offset = field_offset + read_size;
    }
    
    return result;
}

void struct_free_data(void *data) {
    if (data) {
        StructData *sd = (StructData *)data;
        free(sd->data);
        free(sd);
    }
}
