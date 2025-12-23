/*
 * LudoFile - KSY Bytecode Compiler Implementation
 *
 * Simplified KSY compiler - compiles basic type definitions to bytecode.
 * Full YAML parsing and expression evaluation can be added incrementally.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "compiler.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

static void *default_alloc(void *ctx, size_t size) {
    (void)ctx;
    return malloc(size);
}

static void default_free(void *ctx, void *ptr) {
    (void)ctx;
    free(ptr);
}

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

/* ============================================================================
 * Compilation
 * ============================================================================ */

CompiledKSY *ksy_compile(const char *ksy_content) {
    if (!ksy_content) {
        return NULL;
    }
    
    CompiledKSY *compiled = malloc(sizeof(CompiledKSY));
    if (!compiled) {
        return NULL;
    }
    
    memset(compiled, 0, sizeof(*compiled));
    compiled->alloc = default_alloc;
    compiled->free = default_free;
    
    /* TODO: Parse YAML and generate bytecode
     * For now, this is a placeholder that returns empty bytecode
     */
    (void)ksy_content;
    
    return compiled;
}

CompiledKSY *ksy_compile_file(const char *path) {
    if (!path) {
        return NULL;
    }
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    
    /* Read file content */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (size < 0 || size > 10 * 1024 * 1024) {  /* 10MB limit */
        fclose(fp);
        return NULL;
    }
    
    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }
    
    size_t read = fread(content, 1, (size_t)size, fp);
    content[read] = '\0';
    fclose(fp);
    
    CompiledKSY *compiled = ksy_compile(content);
    free(content);
    
    if (compiled) {
        compiled->ksy_path = safe_strdup(path);
    }
    
    return compiled;
}

void ksy_free(CompiledKSY *compiled) {
    if (!compiled) {
        return;
    }
    
    if (compiled->ksy_path) {
        compiled->free(compiled->user_data, (void *)compiled->ksy_path);
    }
    
    if (compiled->bytecode) {
        compiled->free(compiled->user_data, compiled->bytecode);
    }
    
    if (compiled->types) {
        for (size_t i = 0; i < compiled->num_types; i++) {
            if (compiled->types[i].fields) {
                compiled->free(compiled->user_data, compiled->types[i].fields);
            }
        }
        compiled->free(compiled->user_data, compiled->types);
    }
    
    free(compiled);
}

int ksy_load_into_vm(CompiledKSY *compiled, VM *vm) {
    if (!compiled || !vm) {
        return -1;
    }
    
    /* Register types */
    for (size_t i = 0; i < compiled->num_types; i++) {
        if (vm_register_type(vm, &compiled->types[i]) < 0) {
            return -1;
        }
    }
    
    /* Load bytecode */
    if (compiled->bytecode && compiled->bytecode_len > 0) {
        vm_set_bytecode(vm, compiled->bytecode, compiled->bytecode_len);
    }
    
    return 0;
}
