/*
 * LudoFile - Interactive REPL Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "repl.h"
#include "../kaitai/formats.h"
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

static void print_prompt(void) {
    printf("ludofile> ");
    fflush(stdout);
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

REPLContext *repl_new(void) {
    REPLContext *ctx = malloc(sizeof(REPLContext));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->alloc = default_alloc;
    ctx->free = default_free;
    ctx->interactive = true;
    
    return ctx;
}

void repl_free(REPLContext *ctx) {
    if (!ctx) {
        return;
    }
    
    if (ctx->current_file) {
        ctx->free(ctx->user_data, (void *)ctx->current_file);
    }
    
    if (ctx->file_data) {
        ctx->free(ctx->user_data, ctx->file_data);
    }
    
    if (ctx->vm) {
        vm_free(ctx->vm);
    }
    
    if (ctx->debugger) {
        debugger_free(ctx->debugger);
    }
    
    if (ctx->taint_dag) {
        taint_dag_free(ctx->taint_dag);
    }
    
    free(ctx);
}

/* ============================================================================
 * Command execution
 * ============================================================================ */

int repl_run_command(REPLContext *ctx, const char *command) {
    if (!ctx || !command) {
        return -1;
    }
    
    /* Skip empty commands */
    if (command[0] == '\0' || command[0] == '\n') {
        return 0;
    }
    
    /* Parse command */
    char cmd[256] = {0};
    char arg[1024] = {0};
    sscanf(command, "%255s %1023[^\n]", cmd, arg);
    
    /* Execute command */
    if (strcmp(cmd, "open") == 0) {
        return repl_cmd_open(ctx, arg);
    } else if (strcmp(cmd, "close") == 0) {
        return repl_cmd_close(ctx);
    } else if (strcmp(cmd, "analyze") == 0) {
        return repl_cmd_analyze(ctx);
    } else if (strcmp(cmd, "matches") == 0) {
        return repl_cmd_matches(ctx);
    } else if (strcmp(cmd, "parse") == 0) {
        return repl_cmd_parse(ctx, arg);
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        return repl_cmd_help(ctx);
    } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
        return repl_cmd_quit(ctx);
    } else {
        printf("Unknown command: %s (type 'help' for help)\n", cmd);
        return -1;
    }
}

int repl_run(REPLContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    printf("LudoFile Interactive REPL\n");
    printf("Type 'help' for available commands\n\n");
    
    ctx->running = true;
    
    while (ctx->running) {
        print_prompt();
        
        char line[2048];
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        
        repl_run_command(ctx, line);
    }
    
    return 0;
}

/* ============================================================================
 * Command implementations
 * ============================================================================ */

int repl_cmd_open(REPLContext *ctx, const char *path) {
    if (!ctx || !path || path[0] == '\0') {
        printf("Usage: open <file>\n");
        return -1;
    }
    
    /* Close existing file */
    repl_cmd_close(ctx);
    
    /* Open new file */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf("Error: cannot open file '%s'\n", path);
        return -1;
    }
    
    /* Read file data */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (size < 0) {
        printf("Error: cannot determine file size\n");
        fclose(fp);
        return -1;
    }
    
    ctx->file_data = ctx->alloc(ctx->user_data, (size_t)size);
    if (!ctx->file_data) {
        printf("Error: cannot allocate memory\n");
        fclose(fp);
        return -1;
    }
    
    size_t read = fread(ctx->file_data, 1, (size_t)size, fp);
    fclose(fp);
    
    ctx->file_size = read;
    ctx->current_file = safe_strdup(path);
    
    printf("Opened '%s' (%zu bytes)\n", path, ctx->file_size);
    
    return 0;
}

int repl_cmd_close(REPLContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    if (ctx->current_file) {
        ctx->free(ctx->user_data, (void *)ctx->current_file);
        ctx->current_file = NULL;
    }
    
    if (ctx->file_data) {
        ctx->free(ctx->user_data, ctx->file_data);
        ctx->file_data = NULL;
    }
    
    ctx->file_size = 0;
    
    return 0;
}

int repl_cmd_analyze(REPLContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    if (!ctx->file_data) {
        printf("No file open (use 'open <file>' first)\n");
        return -1;
    }
    
    printf("Analyzing '%s'...\n", ctx->current_file);
    printf("  Size: %zu bytes\n", ctx->file_size);
    
    /* Initialize components if not already done */
    if (!ctx->vm) {
        ctx->vm = malloc(sizeof(VM));
        if (ctx->vm) {
            vm_init(ctx->vm);
            vm_set_stream(ctx->vm, ctx->file_data, ctx->file_size);
        }
    }
    
    if (!ctx->taint_dag) {
        ctx->taint_dag = taint_dag_new();
        if (ctx->taint_dag) {
            /* Add file as taint source */
            taint_dag_add_source(ctx->taint_dag, ctx->current_file, ctx->file_size, NULL);
        }
    }
    
    if (!ctx->debugger) {
        ctx->debugger = debugger_new();
        if (ctx->debugger) {
            debugger_set_vm(ctx->debugger, ctx->vm);
            debugger_set_data(ctx->debugger, ctx->file_data, ctx->file_size);
        }
    }
    
    /* Perform analysis */
    printf("  Components initialized:\n");
    if (ctx->vm) printf("    - VM ready\n");
    if (ctx->taint_dag) printf("    - Taint tracking enabled (%zu taints)\n", taint_dag_count(ctx->taint_dag));
    if (ctx->debugger) printf("    - Debugger attached\n");
    
    printf("  Analysis complete\n");
    
    return 0;
}

int repl_cmd_matches(REPLContext *ctx) {
    if (!ctx) {
        return -1;
    }
    
    if (!ctx->file_data) {
        printf("No file open (use 'open <file>' first)\n");
        return -1;
    }
    
    printf("MIME type matches for '%s':\n", ctx->current_file);
    
    /* Check all known formats */
    for (size_t i = 0; i < KAITAI_FORMATS_COUNT; i++) {
        const KaitaiFormatDef *format = &KAITAI_FORMATS[i];
        
        /* Simple heuristic check - verify first few bytes */
        bool matches = false;
        
        if (strcmp(format->mime_type, "image/gif") == 0 && ctx->file_size >= 6) {
            matches = (memcmp(ctx->file_data, "GIF", 3) == 0);
        } else if (strcmp(format->mime_type, "image/png") == 0 && ctx->file_size >= 8) {
            const uint8_t png_sig[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
            matches = (memcmp(ctx->file_data, png_sig, 8) == 0);
        } else if (strcmp(format->mime_type, "image/jpeg") == 0 && ctx->file_size >= 2) {
            matches = (ctx->file_data[0] == 0xFF && ctx->file_data[1] == 0xD8);
        } else if (strcmp(format->mime_type, "application/pdf") == 0 && ctx->file_size >= 5) {
            matches = (memcmp(ctx->file_data, "%PDF-", 5) == 0);
        } else if (strcmp(format->mime_type, "application/zip") == 0 && ctx->file_size >= 4) {
            matches = (ctx->file_data[0] == 0x50 && ctx->file_data[1] == 0x4B &&
                      ctx->file_data[2] == 0x03 && ctx->file_data[3] == 0x04);
        } else if (strcmp(format->mime_type, "application/x-executable") == 0 && ctx->file_size >= 4) {
            matches = (ctx->file_data[0] == 0x7F && ctx->file_data[1] == 'E' &&
                      ctx->file_data[2] == 'L' && ctx->file_data[3] == 'F');
        } else if (strcmp(format->mime_type, "application/x-dosexec") == 0 && ctx->file_size >= 2) {
            matches = (ctx->file_data[0] == 'M' && ctx->file_data[1] == 'Z');
        } else if (strcmp(format->mime_type, "application/x-mach-binary") == 0 && ctx->file_size >= 4) {
            uint32_t magic = (uint32_t)ctx->file_data[0] |
                            ((uint32_t)ctx->file_data[1] << 8) |
                            ((uint32_t)ctx->file_data[2] << 16) |
                            ((uint32_t)ctx->file_data[3] << 24);
            matches = (magic == 0xFEEDFACE || magic == 0xFEEDFACF ||
                      magic == 0xCEFAEDFE || magic == 0xCFFAEDFE);
        }
        
        if (matches) {
            printf("  ✓ %s (%s)\n", format->mime_type, format->ksy_name);
        }
    }
    
    return 0;
}

int repl_cmd_parse(REPLContext *ctx, const char *mime_type) {
    if (!ctx) {
        return -1;
    }
    
    if (!ctx->file_data) {
        printf("No file open (use 'open <file>' first)\n");
        return -1;
    }
    
    if (!mime_type || mime_type[0] == '\0') {
        printf("Usage: parse <mime-type>\n");
        return -1;
    }
    
    printf("Parsing '%s' as '%s'...\n", ctx->current_file, mime_type);
    
    /* Initialize VM if needed */
    if (!ctx->vm) {
        ctx->vm = malloc(sizeof(VM));
        if (!ctx->vm) {
            printf("Error: Failed to allocate VM\n");
            return -1;
        }
        vm_init(ctx->vm);
        vm_set_stream(ctx->vm, ctx->file_data, ctx->file_size);
    }
    
    /* Load format */
    int result = kaitai_load_by_mime(ctx->vm, mime_type);
    if (result < 0) {
        printf("Error: Format not found or failed to load\n");
        return -1;
    }
    
    printf("  Format loaded successfully\n");
    
    /* Initialize debugger if needed */
    if (!ctx->debugger) {
        ctx->debugger = debugger_new();
        if (ctx->debugger) {
            debugger_set_vm(ctx->debugger, ctx->vm);
            debugger_set_data(ctx->debugger, ctx->file_data, ctx->file_size);
            debugger_enable_profiling(ctx->debugger, true);
        }
    }
    
    /* Run VM with profiling */
    if (ctx->debugger) {
        debugger_profile_start(ctx->debugger);
    }
    
    result = vm_run(ctx->vm);
    
    if (ctx->debugger) {
        debugger_profile_stop(ctx->debugger);
    }
    
    if (result < 0) {
        printf("Error: Parsing failed (VM error code: %d)\n", ctx->vm->error);
        if (ctx->vm->error_msg) {
            printf("  %s\n", ctx->vm->error_msg);
        }
        return -1;
    }
    
    printf("  Parsing complete\n");
    printf("  VM stack depth: %zu\n", ctx->vm->sp);
    printf("  Stream position: %zu / %zu bytes\n", 
           vm_stream_pos(ctx->vm), vm_stream_size(ctx->vm));
    
    if (ctx->debugger) {
        printf("\n");
        debugger_profile_print(ctx->debugger);
    }
    
    return 0;
}

int repl_cmd_help(REPLContext *ctx) {
    (void)ctx;
    
    printf("Available commands:\n");
    printf("  open <file>        Open a file for analysis\n");
    printf("  close              Close the current file\n");
    printf("  analyze            Run full analysis on current file\n");
    printf("  matches            Show all MIME type matches\n");
    printf("  parse <mime-type>  Parse file as specific MIME type\n");
    printf("  help, ?            Show this help\n");
    printf("  quit, exit, q      Exit REPL\n");
    
    return 0;
}

int repl_cmd_quit(REPLContext *ctx) {
    if (ctx) {
        ctx->running = false;
    }
    return 0;
}
