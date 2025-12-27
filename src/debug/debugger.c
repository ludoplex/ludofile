/*
 * LudoFile - Interactive Debugger Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "debugger.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

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

static uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

DebuggerContext *debugger_new(void) {
    DebuggerContext *ctx = malloc(sizeof(DebuggerContext));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->alloc = default_alloc;
    ctx->free = default_free;
    ctx->state = DEBUG_STATE_IDLE;
    
    return ctx;
}

void debugger_free(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    /* Free breakpoints */
    for (size_t i = 0; i < ctx->num_breakpoints; i++) {
        Breakpoint *bp = &ctx->breakpoints[i];
        if (bp->type == BP_TYPE_MIME && bp->data.mime_type) {
            ctx->free(ctx->user_data, bp->data.mime_type);
        } else if (bp->type == BP_TYPE_PATTERN && bp->data.pattern) {
            ctx->free(ctx->user_data, bp->data.pattern);
        }
    }
    
    free(ctx);
}

void debugger_reset(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    ctx->state = DEBUG_STATE_IDLE;
    ctx->call_depth = 0;
    ctx->current_offset = 0;
    ctx->current_mime_type = NULL;
    memset(&ctx->profile, 0, sizeof(ctx->profile));
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void debugger_set_vm(DebuggerContext *ctx, VM *vm) {
    if (ctx) {
        ctx->vm = vm;
    }
}

void debugger_set_matcher(DebuggerContext *ctx, MagicMatcher *matcher) {
    if (ctx) {
        ctx->matcher = matcher;
    }
}

void debugger_set_data(DebuggerContext *ctx, const uint8_t *data, size_t size) {
    if (ctx) {
        ctx->data = data;
        ctx->data_size = size;
    }
}

void debugger_enable_profiling(DebuggerContext *ctx, bool enable) {
    if (ctx) {
        ctx->profiling_enabled = enable;
    }
}

/* ============================================================================
 * Breakpoint management
 * ============================================================================ */

int debugger_add_breakpoint_offset(DebuggerContext *ctx, uint64_t offset) {
    if (!ctx || ctx->num_breakpoints >= DEBUG_MAX_BREAKPOINTS) {
        return -1;
    }
    
    int id = (int)ctx->num_breakpoints;
    Breakpoint *bp = &ctx->breakpoints[id];
    
    bp->type = BP_TYPE_OFFSET;
    bp->enabled = true;
    bp->data.offset = offset;
    bp->hit_count = 0;
    
    ctx->num_breakpoints++;
    return id;
}

int debugger_add_breakpoint_mime(DebuggerContext *ctx, const char *mime_type) {
    if (!ctx || !mime_type || ctx->num_breakpoints >= DEBUG_MAX_BREAKPOINTS) {
        return -1;
    }
    
    int id = (int)ctx->num_breakpoints;
    Breakpoint *bp = &ctx->breakpoints[id];
    
    bp->type = BP_TYPE_MIME;
    bp->enabled = true;
    bp->hit_count = 0;
    
    size_t len = strlen(mime_type) + 1;
    bp->data.mime_type = ctx->alloc(ctx->user_data, len);
    if (bp->data.mime_type) {
        memcpy(bp->data.mime_type, mime_type, len);
    }
    
    ctx->num_breakpoints++;
    return id;
}

int debugger_add_breakpoint_opcode(DebuggerContext *ctx, uint8_t opcode) {
    if (!ctx || ctx->num_breakpoints >= DEBUG_MAX_BREAKPOINTS) {
        return -1;
    }
    
    int id = (int)ctx->num_breakpoints;
    Breakpoint *bp = &ctx->breakpoints[id];
    
    bp->type = BP_TYPE_OPCODE;
    bp->enabled = true;
    bp->data.opcode = opcode;
    bp->hit_count = 0;
    
    ctx->num_breakpoints++;
    return id;
}

int debugger_add_breakpoint_pattern(DebuggerContext *ctx, const char *pattern) {
    if (!ctx || !pattern || ctx->num_breakpoints >= DEBUG_MAX_BREAKPOINTS) {
        return -1;
    }
    
    int id = (int)ctx->num_breakpoints;
    Breakpoint *bp = &ctx->breakpoints[id];
    
    bp->type = BP_TYPE_PATTERN;
    bp->enabled = true;
    bp->hit_count = 0;
    
    size_t len = strlen(pattern) + 1;
    bp->data.pattern = ctx->alloc(ctx->user_data, len);
    if (bp->data.pattern) {
        memcpy(bp->data.pattern, pattern, len);
    }
    
    ctx->num_breakpoints++;
    return id;
}

int debugger_remove_breakpoint(DebuggerContext *ctx, int id) {
    if (!ctx || id < 0 || (size_t)id >= ctx->num_breakpoints) {
        return -1;
    }
    
    Breakpoint *bp = &ctx->breakpoints[id];
    
    /* Free allocated data */
    if (bp->type == BP_TYPE_MIME && bp->data.mime_type) {
        ctx->free(ctx->user_data, bp->data.mime_type);
    } else if (bp->type == BP_TYPE_PATTERN && bp->data.pattern) {
        ctx->free(ctx->user_data, bp->data.pattern);
    }
    
    /* Shift remaining breakpoints */
    for (size_t i = id; i < ctx->num_breakpoints - 1; i++) {
        ctx->breakpoints[i] = ctx->breakpoints[i + 1];
    }
    
    ctx->num_breakpoints--;
    return 0;
}

int debugger_enable_breakpoint(DebuggerContext *ctx, int id, bool enable) {
    if (!ctx || id < 0 || (size_t)id >= ctx->num_breakpoints) {
        return -1;
    }
    
    ctx->breakpoints[id].enabled = enable;
    return 0;
}

void debugger_list_breakpoints(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    printf("Breakpoints:\n");
    for (size_t i = 0; i < ctx->num_breakpoints; i++) {
        Breakpoint *bp = &ctx->breakpoints[i];
        printf("  [%zu] %s ", i, bp->enabled ? "enabled" : "disabled");
        
        switch (bp->type) {
            case BP_TYPE_OFFSET:
                printf("offset=0x%lx", (unsigned long)bp->data.offset);
                break;
            case BP_TYPE_MIME:
                printf("mime=%s", bp->data.mime_type);
                break;
            case BP_TYPE_OPCODE:
                printf("opcode=0x%02x", bp->data.opcode);
                break;
            case BP_TYPE_PATTERN:
                printf("pattern=\"%s\"", bp->data.pattern);
                break;
        }
        
        printf(" (hits=%u)\n", bp->hit_count);
    }
}

/* ============================================================================
 * Execution control
 * ============================================================================ */

int debugger_continue(DebuggerContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    ctx->state = DEBUG_STATE_RUNNING;
    
    /* Resume VM execution if available */
    if (ctx->vm) {
        return vm_run(ctx->vm);
    }
    
    return 0;
}

int debugger_step(DebuggerContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    ctx->state = DEBUG_STATE_STEPPING;
    
    /* Execute one VM instruction if available */
    if (ctx->vm) {
        return vm_step(ctx->vm);
    }
    
    return 0;
}

int debugger_next(DebuggerContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    /* Step over function calls */
    size_t initial_depth = ctx->call_depth;
    
    do {
        if (debugger_step(ctx) < 0) {
            return -1;
        }
    } while (ctx->call_depth > initial_depth);
    
    return 0;
}

int debugger_finish(DebuggerContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    /* Run until function returns */
    size_t initial_depth = ctx->call_depth;
    
    do {
        if (debugger_step(ctx) < 0) {
            return -1;
        }
    } while (ctx->call_depth >= initial_depth && ctx->call_depth > 0);
    
    return 0;
}

/* ============================================================================
 * Inspection
 * ============================================================================ */

void debugger_print_offset(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    printf("Current offset: 0x%lx (%zu)\n",
           (unsigned long)ctx->current_offset,
           ctx->current_offset);
}

void debugger_print_stack(DebuggerContext *ctx) {
    if (!ctx || !ctx->vm) {
        return;
    }
    
    printf("VM Stack:\n");
    vm_dump_stack(ctx->vm);
}

void debugger_print_backtrace(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    printf("Call stack:\n");
    for (size_t i = 0; i < ctx->call_depth; i++) {
        CallFrame *frame = &ctx->call_stack[i];
        printf("  #%zu %s at offset 0x%lx",
               i,
               frame->function_name ? frame->function_name : "<unknown>",
               (unsigned long)frame->offset);
        
        if (frame->mime_type) {
            printf(" (%s)", frame->mime_type);
        }
        
        printf("\n");
    }
}

void debugger_print_bytecode(DebuggerContext *ctx, size_t count) {
    if (!ctx || !ctx->vm || !ctx->vm->ip) {
        return;
    }
    
    printf("Bytecode:\n");
    const uint8_t *ip = ctx->vm->ip;
    
    for (size_t i = 0; i < count && ip < ctx->vm->code + ctx->vm->code_len; i++) {
        printf("  0x%04lx: %02x  %s\n",
               (unsigned long)(ip - ctx->vm->code),
               *ip,
               vm_opcode_name((VMOpcode)*ip));
        ip++;
    }
}

void debugger_print_data(DebuggerContext *ctx, size_t offset, size_t len) {
    if (!ctx || !ctx->data) {
        return;
    }
    
    if (offset >= ctx->data_size) {
        printf("Offset out of range\n");
        return;
    }
    
    if (offset + len > ctx->data_size) {
        len = ctx->data_size - offset;
    }
    
    printf("Data at offset 0x%lx:\n", (unsigned long)offset);
    
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04lx: ", (unsigned long)(offset + i));
        
        /* Hex dump */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            printf("%02x ", ctx->data[offset + i + j]);
        }
        
        /* ASCII dump */
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = ctx->data[offset + i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

/* ============================================================================
 * Profiling
 * ============================================================================ */

void debugger_profile_start(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    ctx->profiling_enabled = true;
    ctx->profile.start_time_us = get_time_us();
}

void debugger_profile_stop(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    ctx->profile.end_time_us = get_time_us();
}

void debugger_profile_print(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    uint64_t elapsed = ctx->profile.end_time_us - ctx->profile.start_time_us;
    
    printf("Profiling results:\n");
    printf("  Total instructions: %lu\n",
           (unsigned long)ctx->profile.total_instructions);
    printf("  Total bytes read: %lu\n",
           (unsigned long)ctx->profile.total_bytes_read);
    printf("  Total matches: %lu\n",
           (unsigned long)ctx->profile.total_matches);
    printf("  Elapsed time: %lu us (%.3f ms)\n",
           (unsigned long)elapsed,
           elapsed / 1000.0);
}

/* ============================================================================
 * Environment
 * ============================================================================ */

void debugger_set_var(DebuggerContext *ctx, const char *name, const char *value) {
    if (!ctx || !name) {
        return;
    }
    
    if (strcmp(name, "bytecode") == 0) {
        ctx->show_bytecode = (value && strcmp(value, "1") == 0);
    } else if (strcmp(name, "stack") == 0) {
        ctx->show_stack = (value && strcmp(value, "1") == 0);
    } else if (strcmp(name, "verbose") == 0) {
        ctx->verbose = (value && strcmp(value, "1") == 0);
    }
}

const char *debugger_get_var(DebuggerContext *ctx, const char *name) {
    if (!ctx || !name) {
        return NULL;
    }
    
    if (strcmp(name, "bytecode") == 0) {
        return ctx->show_bytecode ? "1" : "0";
    } else if (strcmp(name, "stack") == 0) {
        return ctx->show_stack ? "1" : "0";
    } else if (strcmp(name, "verbose") == 0) {
        return ctx->verbose ? "1" : "0";
    }
    
    return NULL;
}

void debugger_show_vars(DebuggerContext *ctx) {
    if (!ctx) {
        return;
    }
    
    printf("Environment variables:\n");
    printf("  bytecode = %s\n", ctx->show_bytecode ? "1" : "0");
    printf("  stack = %s\n", ctx->show_stack ? "1" : "0");
    printf("  verbose = %s\n", ctx->verbose ? "1" : "0");
}

/* ============================================================================
 * Command interface
 * ============================================================================ */

int debugger_execute_command(DebuggerContext *ctx, const char *command) {
    if (!ctx || !command) {
        return -1;
    }
    
    /* Parse command - simplified for now */
    if (strcmp(command, "continue") == 0 || strcmp(command, "c") == 0) {
        return debugger_continue(ctx);
    } else if (strcmp(command, "step") == 0 || strcmp(command, "s") == 0) {
        return debugger_step(ctx);
    } else if (strcmp(command, "next") == 0 || strcmp(command, "n") == 0) {
        return debugger_next(ctx);
    } else if (strcmp(command, "finish") == 0 || strcmp(command, "f") == 0) {
        return debugger_finish(ctx);
    } else if (strcmp(command, "backtrace") == 0 || strcmp(command, "bt") == 0) {
        debugger_print_backtrace(ctx);
        return 0;
    } else if (strcmp(command, "stack") == 0) {
        debugger_print_stack(ctx);
        return 0;
    } else if (strcmp(command, "where") == 0) {
        debugger_print_offset(ctx);
        return 0;
    } else if (strcmp(command, "breakpoints") == 0 || strcmp(command, "b") == 0) {
        debugger_list_breakpoints(ctx);
        return 0;
    } else if (strcmp(command, "vars") == 0) {
        debugger_show_vars(ctx);
        return 0;
    } else if (strcmp(command, "profile") == 0) {
        debugger_profile_print(ctx);
        return 0;
    }
    
    printf("Unknown command: %s\n", command);
    return -1;
}
