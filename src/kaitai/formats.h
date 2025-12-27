/*
 * LudoFile - Kaitai Format Registry
 *
 * Pre-compiled bytecode for common file formats.
 * Integrates with the VM for parsing.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_FORMATS_H
#define LUDOFILE_FORMATS_H

#include <stdint.h>
#include <stddef.h>
#include "../vm/vm.h"

/* ============================================================================
 * Format definition
 * ============================================================================ */

typedef struct {
    const char *mime_type;      /* MIME type */
    const char *ksy_name;       /* KSY name */
    const uint8_t *bytecode;    /* Compiled bytecode */
    size_t bytecode_len;        /* Bytecode length */
    const VMTypeDef *types;     /* Type definitions */
    size_t num_types;           /* Number of types */
} KaitaiFormatDef;

/* ============================================================================
 * Format registry
 * ============================================================================ */

extern const KaitaiFormatDef KAITAI_FORMATS[];
extern const size_t KAITAI_FORMATS_COUNT;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Find format by MIME type
 */
const KaitaiFormatDef *kaitai_find_format(const char *mime_type);

/*
 * Load format into VM
 */
int kaitai_load_format(VM *vm, const KaitaiFormatDef *format);

/*
 * Load format by MIME type
 */
int kaitai_load_by_mime(VM *vm, const char *mime_type);

#endif /* LUDOFILE_FORMATS_H */
