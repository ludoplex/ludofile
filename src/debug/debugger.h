/*
 * LudoFile - Interactive Debugger
 *
 * GDB-style debugger for binary parsing and magic test execution.
 * Provides interactive stepping, breakpoints, and inspection.
 *
 * Design principles:
 * - Pure POSIX C, no external dependencies
 * - Minimal memory footprint
 * - Integration with VM and magic matcher
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_DEBUGGER_H
#define LUDOFILE_DEBUGGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../vm/vm.h"
#include "../magic/magic.h"

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define DEBUG_MAX_BREAKPOINTS  64   /* Max breakpoints */
#define DEBUG_MAX_CALL_DEPTH   64   /* Max call stack depth */

/* ============================================================================
 * Type definitions
 * ============================================================================ */

/*
 * Debugger state
 */
typedef enum {
    DEBUG_STATE_IDLE = 0,      /* Not running */
    DEBUG_STATE_RUNNING,       /* Executing */
    DEBUG_STATE_STEPPING,      /* Single-step mode */
    DEBUG_STATE_BREAKPOINT,    /* Hit breakpoint */
    DEBUG_STATE_ERROR,         /* Error occurred */
    DEBUG_STATE_FINISHED       /* Execution complete */
} DebuggerState;

/*
 * Breakpoint type
 */
typedef enum {
    BP_TYPE_OFFSET = 0,        /* Break at byte offset */
    BP_TYPE_MIME,              /* Break on MIME type match */
    BP_TYPE_OPCODE,            /* Break on VM opcode */
    BP_TYPE_PATTERN            /* Break on pattern match */
} BreakpointType;

/*
 * Breakpoint
 */
typedef struct {
    BreakpointType type;
    bool enabled;
    union {
        uint64_t offset;       /* For BP_TYPE_OFFSET */
        char *mime_type;       /* For BP_TYPE_MIME */
        uint8_t opcode;        /* For BP_TYPE_OPCODE */
        char *pattern;         /* For BP_TYPE_PATTERN */
    } data;
    uint32_t hit_count;        /* Number of times hit */
} Breakpoint;

/*
 * Call frame for stack traces
 */
typedef struct {
    const char *function_name;
    size_t offset;
    const char *mime_type;
} CallFrame;

/*
 * Profiling data
 */
typedef struct {
    uint64_t total_instructions;
    uint64_t total_bytes_read;
    uint64_t total_matches;
    uint64_t start_time_us;
    uint64_t end_time_us;
} ProfilingData;

/*
 * Debugger context
 */
typedef struct DebuggerContext {
    /* State */
    DebuggerState state;
    
    /* Execution context */
    VM *vm;
    MagicMatcher *matcher;
    const uint8_t *data;
    size_t data_size;
    
    /* Breakpoints */
    Breakpoint breakpoints[DEBUG_MAX_BREAKPOINTS];
    size_t num_breakpoints;
    
    /* Call stack */
    CallFrame call_stack[DEBUG_MAX_CALL_DEPTH];
    size_t call_depth;
    
    /* Current position */
    size_t current_offset;
    const char *current_mime_type;
    
    /* Profiling */
    ProfilingData profile;
    bool profiling_enabled;
    
    /* Environment variables */
    bool show_bytecode;
    bool show_stack;
    bool verbose;
    
    /* Memory management */
    void *user_data;
    void *(*alloc)(void *ctx, size_t size);
    void  (*free)(void *ctx, void *ptr);
} DebuggerContext;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Lifecycle
 */
DebuggerContext *debugger_new(void);
void debugger_free(DebuggerContext *ctx);
void debugger_reset(DebuggerContext *ctx);

/*
 * Configuration
 */
void debugger_set_vm(DebuggerContext *ctx, VM *vm);
void debugger_set_matcher(DebuggerContext *ctx, MagicMatcher *matcher);
void debugger_set_data(DebuggerContext *ctx, const uint8_t *data, size_t size);
void debugger_enable_profiling(DebuggerContext *ctx, bool enable);

/*
 * Breakpoint management
 */
int debugger_add_breakpoint_offset(DebuggerContext *ctx, uint64_t offset);
int debugger_add_breakpoint_mime(DebuggerContext *ctx, const char *mime_type);
int debugger_add_breakpoint_opcode(DebuggerContext *ctx, uint8_t opcode);
int debugger_add_breakpoint_pattern(DebuggerContext *ctx, const char *pattern);
int debugger_remove_breakpoint(DebuggerContext *ctx, int id);
int debugger_enable_breakpoint(DebuggerContext *ctx, int id, bool enable);
void debugger_list_breakpoints(DebuggerContext *ctx);

/*
 * Execution control
 */
int debugger_continue(DebuggerContext *ctx);
int debugger_step(DebuggerContext *ctx);
int debugger_next(DebuggerContext *ctx);
int debugger_finish(DebuggerContext *ctx);

/*
 * Inspection
 */
void debugger_print_offset(DebuggerContext *ctx);
void debugger_print_stack(DebuggerContext *ctx);
void debugger_print_backtrace(DebuggerContext *ctx);
void debugger_print_bytecode(DebuggerContext *ctx, size_t count);
void debugger_print_data(DebuggerContext *ctx, size_t offset, size_t len);

/*
 * Profiling
 */
void debugger_profile_start(DebuggerContext *ctx);
void debugger_profile_stop(DebuggerContext *ctx);
void debugger_profile_print(DebuggerContext *ctx);

/*
 * Environment
 */
void debugger_set_var(DebuggerContext *ctx, const char *name, const char *value);
const char *debugger_get_var(DebuggerContext *ctx, const char *name);
void debugger_show_vars(DebuggerContext *ctx);

/*
 * Command interface
 */
int debugger_execute_command(DebuggerContext *ctx, const char *command);

#endif /* LUDOFILE_DEBUGGER_H */
