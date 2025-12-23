/*
 * LudoFile - KSY Bytecode Compiler
 *
 * Compiles Kaitai Struct YAML definitions to VM bytecode.
 * Supports essential Kaitai features for binary parsing.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_COMPILER_H
#define LUDOFILE_COMPILER_H

#include <stdint.h>
#include <stddef.h>
#include "vm.h"

/* ============================================================================
 * Compiled KSY representation
 * ============================================================================ */

typedef struct {
    const char *ksy_path;     /* Source KSY file path */
    uint8_t *bytecode;        /* Compiled bytecode */
    size_t bytecode_len;      /* Bytecode length */
    VMTypeDef *types;         /* Type definitions */
    size_t num_types;         /* Number of types */
    
    /* Memory management */
    void *user_data;
    void *(*alloc)(void *ctx, size_t size);
    void  (*free)(void *ctx, void *ptr);
} CompiledKSY;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Compile KSY from string content
 */
CompiledKSY *ksy_compile(const char *ksy_content);

/*
 * Compile KSY from file
 */
CompiledKSY *ksy_compile_file(const char *path);

/*
 * Free compiled KSY
 */
void ksy_free(CompiledKSY *compiled);

/*
 * Load compiled bytecode into VM
 */
int ksy_load_into_vm(CompiledKSY *compiled, VM *vm);

#endif /* LUDOFILE_COMPILER_H */
