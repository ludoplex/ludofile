/*
 * LudoFile - Interactive REPL
 *
 * Command-line REPL for interactive file analysis.
 * Integrates VM, debugger, taint tracking, and parsing.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_REPL_H
#define LUDOFILE_REPL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../vm/vm.h"
#include "../debug/debugger.h"
#include "../taint/taint.h"
#include "../magic/magic.h"
#include "../core/types.h"

/* ============================================================================
 * REPL Context
 * ============================================================================ */

typedef struct {
    /* File context */
    const char *current_file;
    uint8_t *file_data;
    size_t file_size;
    
    /* Analysis components */
    VM *vm;
    DebuggerContext *debugger;
    TaintDAG *taint_dag;
    MagicMatcher *matcher;
    
    /* State */
    bool running;
    bool interactive;
    
    /* Memory management */
    void *user_data;
    void *(*alloc)(void *ctx, size_t size);
    void  (*free)(void *ctx, void *ptr);
} REPLContext;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Lifecycle
 */
REPLContext *repl_new(void);
void repl_free(REPLContext *ctx);

/*
 * Run REPL
 */
int repl_run(REPLContext *ctx);
int repl_run_command(REPLContext *ctx, const char *command);

/*
 * Commands
 */
int repl_cmd_open(REPLContext *ctx, const char *path);
int repl_cmd_close(REPLContext *ctx);
int repl_cmd_analyze(REPLContext *ctx);
int repl_cmd_matches(REPLContext *ctx);
int repl_cmd_parse(REPLContext *ctx, const char *mime_type);
int repl_cmd_help(REPLContext *ctx);
int repl_cmd_quit(REPLContext *ctx);

#endif /* LUDOFILE_REPL_H */
