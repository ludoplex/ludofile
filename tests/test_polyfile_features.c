/*
 * LudoFile - PolyFile Feature Parity Tests
 *
 * Tests for new modules: taint, debugger, compiler, formats, structs, repl
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/taint/taint.h"
#include "../src/debug/debugger.h"
#include "../src/vm/vm.h"
#include "../src/vm/compiler.h"
#include "../src/kaitai/formats.h"
#include "../src/structs/structs.h"
#include "../src/repl/repl.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros */
#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s...", #name); \
    tests_run++; \
    test_##name(); \
    tests_passed++; \
    printf(" PASSED\n"); \
} while(0)

#define ASSERT(expr) do { \
    if (!(expr)) { \
        printf(" FAILED\n"); \
        printf("    Assertion failed: %s\n", #expr); \
        printf("    At %s:%d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(a) ASSERT((a) == NULL)
#define ASSERT_NOT_NULL(a) ASSERT((a) != NULL)

/* ============= Taint Tracking Tests ============= */

TEST(taint_dag_new) {
    TaintDAG *dag = taint_dag_new();
    ASSERT_NOT_NULL(dag);
    ASSERT_EQ(taint_dag_count(dag), 0);
    taint_dag_free(dag);
}

TEST(taint_dag_add_source) {
    TaintDAG *dag = taint_dag_new();
    ASSERT_NOT_NULL(dag);
    
    uint32_t source_id = taint_dag_add_source(dag, "test.bin", 100, NULL);
    ASSERT_EQ(source_id, 0);
    
    TaintSource *src = taint_dag_get_source(dag, source_id);
    ASSERT_NOT_NULL(src);
    ASSERT_EQ(src->size, 100);
    
    taint_dag_free(dag);
}

TEST(taint_dag_create_labels) {
    TaintDAG *dag = taint_dag_new();
    ASSERT_NOT_NULL(dag);
    
    uint32_t source_id = taint_dag_add_source(dag, "test.bin", 100, NULL);
    
    taint_label_t label1 = taint_dag_create_source_label(dag, source_id, 10);
    ASSERT_NE(label1, TAINT_LABEL_NONE);
    
    taint_label_t label2 = taint_dag_create_range_label(dag, source_id, 0, 10);
    ASSERT_NE(label2, TAINT_LABEL_NONE);
    ASSERT_NE(label1, label2);
    
    ASSERT_EQ(taint_dag_count(dag), 2);
    
    taint_dag_free(dag);
}

TEST(taint_dag_union) {
    TaintDAG *dag = taint_dag_new();
    ASSERT_NOT_NULL(dag);
    
    uint32_t source_id = taint_dag_add_source(dag, "test.bin", 100, NULL);
    
    taint_label_t label1 = taint_dag_create_source_label(dag, source_id, 10);
    taint_label_t label2 = taint_dag_create_source_label(dag, source_id, 20);
    
    taint_label_t union_label = taint_dag_union(dag, label1, label2);
    ASSERT_NE(union_label, TAINT_LABEL_NONE);
    ASSERT_EQ(taint_dag_count(dag), 3);
    
    Taint *taint = taint_dag_get_taint(dag, union_label);
    ASSERT_NOT_NULL(taint);
    ASSERT_EQ(taint->type, TAINT_UNION);
    
    taint_dag_free(dag);
}

/* ============= Debugger Tests ============= */

TEST(debugger_new) {
    DebuggerContext *ctx = debugger_new();
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->state, DEBUG_STATE_IDLE);
    debugger_free(ctx);
}

TEST(debugger_breakpoints) {
    DebuggerContext *ctx = debugger_new();
    ASSERT_NOT_NULL(ctx);
    
    int bp_id = debugger_add_breakpoint_offset(ctx, 0x1000);
    ASSERT_EQ(bp_id, 0);
    
    bp_id = debugger_add_breakpoint_mime(ctx, "application/pdf");
    ASSERT_EQ(bp_id, 1);
    
    ASSERT_EQ(ctx->num_breakpoints, 2);
    
    debugger_free(ctx);
}

/* ============= Compiler Tests ============= */

TEST(ksy_compile_empty) {
    CompiledKSY *compiled = ksy_compile("");
    ASSERT_NOT_NULL(compiled);
    ksy_free(compiled);
}

/* ============= Kaitai Formats Tests ============= */

TEST(kaitai_find_format) {
    const KaitaiFormatDef *format = kaitai_find_format("image/gif");
    ASSERT_NOT_NULL(format);
    ASSERT_NOT_NULL(format->mime_type);
    ASSERT_NOT_NULL(format->ksy_name);
}

TEST(kaitai_formats_count) {
    ASSERT_EQ(KAITAI_FORMATS_COUNT, 8);  /* GIF, PNG, JPEG, PDF, ZIP, ELF, PE, Mach-O */
}

/* ============= Structs Tests ============= */

TEST(struct_def_new) {
    StructDef *def = struct_def_new("test_struct");
    ASSERT_NOT_NULL(def);
    ASSERT_EQ(def->num_fields, 0);
    struct_def_free(def);
}

TEST(struct_def_add_field) {
    StructDef *def = struct_def_new("test_struct");
    ASSERT_NOT_NULL(def);
    
    StructField field = {
        .name = "field1",
        .type = STRUCT_FIELD_U32,
        .offset = 0,
        .size = 4,
        .endian = ENDIAN_LITTLE,
        .nested_struct = NULL
    };
    
    int result = struct_def_add_field(def, &field);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(def->num_fields, 1);
    
    struct_def_free(def);
}

/* ============= REPL Tests ============= */

TEST(repl_new) {
    REPLContext *ctx = repl_new();
    ASSERT_NOT_NULL(ctx);
    ASSERT_NULL(ctx->current_file);
    repl_free(ctx);
}

TEST(repl_help_command) {
    REPLContext *ctx = repl_new();
    ASSERT_NOT_NULL(ctx);
    
    int result = repl_cmd_help(ctx);
    ASSERT_EQ(result, 0);
    
    repl_free(ctx);
}

/* ============= Main ============= */

int main(void) {
    printf("Running PolyFile Feature Parity Tests\n");
    printf("======================================\n\n");
    
    printf("Taint Tracking Tests:\n");
    RUN_TEST(taint_dag_new);
    RUN_TEST(taint_dag_add_source);
    RUN_TEST(taint_dag_create_labels);
    RUN_TEST(taint_dag_union);
    
    printf("\nDebugger Tests:\n");
    RUN_TEST(debugger_new);
    RUN_TEST(debugger_breakpoints);
    
    printf("\nCompiler Tests:\n");
    RUN_TEST(ksy_compile_empty);
    
    printf("\nKaitai Formats Tests:\n");
    RUN_TEST(kaitai_find_format);
    RUN_TEST(kaitai_formats_count);
    
    printf("\nStructs Tests:\n");
    RUN_TEST(struct_def_new);
    RUN_TEST(struct_def_add_field);
    
    printf("\nREPL Tests:\n");
    RUN_TEST(repl_new);
    RUN_TEST(repl_help_command);
    
    printf("\n======================================\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        return 1;
    }
    
    printf("\nAll tests passed!\n");
    return 0;
}
