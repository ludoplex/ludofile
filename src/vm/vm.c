/*
 * LudoFile - Minimalist Kaitai Virtual Machine Implementation
 *
 * A minimal, reusable bytecode VM for parsing binary structures.
 * Pure POSIX C, no external dependencies.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "vm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/*
 * Default allocator using malloc/free
 */
static void *default_alloc(void *ctx, size_t size) {
    (void)ctx;
    return malloc(size);
}

static void default_free(void *ctx, void *ptr) {
    (void)ctx;
    free(ptr);
}

/*
 * Allocate memory through VM allocator
 */
static void *vm_alloc(VM *vm, size_t size) {
    return vm->alloc(vm->user_data, size);
}

/*
 * Free memory through VM allocator
 */
static void vm_dealloc(VM *vm, void *ptr) {
    vm->free(vm->user_data, ptr);
}

/*
 * Set error state
 */
static void vm_error(VM *vm, int code, const char *msg) {
    vm->error = code;
    vm->error_msg = msg;
    vm->halted = true;
}

/*
 * Check if enough bytes remain in stream
 */
static bool vm_stream_has(VM *vm, size_t n) {
    return vm->stream.pos + n <= vm->stream.size;
}

/*
 * Read bytes from stream (no endian swap)
 */
static int vm_stream_read_raw(VM *vm, uint8_t *buf, size_t len) {
    if (!vm_stream_has(vm, len)) {
        vm_error(vm, VM_ERR_EOF, "unexpected end of stream");
        return -1;
    }
    memcpy(buf, vm->stream.data + vm->stream.pos, len);
    vm->stream.pos += len;
    return 0;
}

/*
 * Swap bytes for endianness
 */
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

/*
 * Detect host endianness
 */
static bool host_is_big_endian(void) {
    union { uint32_t i; uint8_t c[4]; } u = { .i = 1 };
    return u.c[0] == 0;
}

/*
 * Read immediate values from bytecode
 */
static uint8_t read_imm8(VM *vm) {
    return *vm->ip++;
}

static uint16_t read_imm16(VM *vm) {
    uint16_t v = (uint16_t)vm->ip[0] | ((uint16_t)vm->ip[1] << 8);
    vm->ip += 2;
    return v;
}

static uint32_t read_imm32(VM *vm) {
    uint32_t v = (uint32_t)vm->ip[0] |
                 ((uint32_t)vm->ip[1] << 8) |
                 ((uint32_t)vm->ip[2] << 16) |
                 ((uint32_t)vm->ip[3] << 24);
    vm->ip += 4;
    return v;
}

static int64_t read_imm64(VM *vm) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)vm->ip[i] << (i * 8);
    }
    vm->ip += 8;
    return (int64_t)v;
}

/* ============================================================================
 * Initialization and cleanup
 * ============================================================================ */

void vm_init(VM *vm) {
    memset(vm, 0, sizeof(*vm));
    vm->alloc = default_alloc;
    vm->free = default_free;
}

void vm_free(VM *vm) {
    /* Free type definitions */
    for (size_t i = 0; i < vm->num_types; i++) {
        if (vm->types[i].fields) {
            vm_dealloc(vm, vm->types[i].fields);
        }
    }
    if (vm->types) {
        vm_dealloc(vm, vm->types);
    }
    
    /* Free any remaining stack values */
    for (size_t i = 0; i < vm->sp; i++) {
        VMValue *v = &vm->stack[i];
        if (v->type == VAL_BYTES && v->as.bytes.data) {
            vm_dealloc(vm, v->as.bytes.data);
        } else if (v->type == VAL_STRING && v->as.str.data) {
            vm_dealloc(vm, v->as.str.data);
        }
    }
    
    memset(vm, 0, sizeof(*vm));
}

void vm_reset(VM *vm) {
    vm->ip = vm->code;
    vm->sp = 0;
    vm->fp = 0;
    vm->stream.pos = 0;
    vm->halted = false;
    vm->error = 0;
    vm->error_msg = NULL;
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void vm_set_allocator(VM *vm,
                      void *(*alloc)(void *, size_t),
                      void (*vfree)(void *, void *),
                      void *user_data) {
    vm->alloc = alloc ? alloc : default_alloc;
    vm->free = vfree ? vfree : default_free;
    vm->user_data = user_data;
}

void vm_set_stream(VM *vm, const uint8_t *data, size_t size) {
    vm->stream.data = data;
    vm->stream.size = size;
    vm->stream.pos = 0;
    vm->stream.base = 0;
}

void vm_set_bytecode(VM *vm, const uint8_t *code, size_t len) {
    vm->code = code;
    vm->code_len = len;
    vm->ip = code;
}

/* ============================================================================
 * Type registration
 * ============================================================================ */

int vm_register_type(VM *vm, const VMTypeDef *type) {
    if (vm->num_types >= VM_MAX_TYPES) {
        return -1;
    }
    
    if (!vm->types) {
        vm->types = vm_alloc(vm, sizeof(VMTypeDef) * VM_MAX_TYPES);
        if (!vm->types) {
            return -1;
        }
        memset(vm->types, 0, sizeof(VMTypeDef) * VM_MAX_TYPES);
    }
    
    /* Copy type definition */
    VMTypeDef *t = &vm->types[vm->num_types];
    t->name = type->name;
    t->num_fields = type->num_fields;
    t->flags = type->flags;
    t->bytecode = type->bytecode;
    t->bytecode_len = type->bytecode_len;
    
    /* Copy field definitions */
    if (type->num_fields > 0) {
        t->fields = vm_alloc(vm, sizeof(VMFieldDef) * type->num_fields);
        if (!t->fields) {
            return -1;
        }
        memcpy(t->fields, type->fields, sizeof(VMFieldDef) * type->num_fields);
    }
    
    return (int)vm->num_types++;
}

const VMTypeDef *vm_get_type(VM *vm, const char *name) {
    for (size_t i = 0; i < vm->num_types; i++) {
        if (strcmp(vm->types[i].name, name) == 0) {
            return &vm->types[i];
        }
    }
    return NULL;
}

const VMTypeDef *vm_get_type_by_id(VM *vm, uint16_t id) {
    if (id >= vm->num_types) {
        return NULL;
    }
    return &vm->types[id];
}

/* ============================================================================
 * Stack operations
 * ============================================================================ */

int vm_push(VM *vm, VMValue val) {
    if (vm->sp >= VM_STACK_SIZE) {
        vm_error(vm, VM_ERR_STACK_OVER, "stack overflow");
        return -1;
    }
    vm->stack[vm->sp++] = val;
    return 0;
}

int vm_push_int(VM *vm, int64_t val) {
    VMValue v = { .type = VAL_INT, .as.i64 = val };
    return vm_push(vm, v);
}

int vm_push_uint(VM *vm, uint64_t val) {
    VMValue v = { .type = VAL_UINT, .as.u64 = val };
    return vm_push(vm, v);
}

int vm_push_float(VM *vm, double val) {
    VMValue v = { .type = VAL_FLOAT, .as.f64 = val };
    return vm_push(vm, v);
}

int vm_push_bytes(VM *vm, const uint8_t *data, size_t len) {
    VMValue v = { .type = VAL_BYTES };
    v.as.bytes.data = vm_alloc(vm, len);
    if (!v.as.bytes.data) {
        vm_error(vm, VM_ERR_MEMORY, "allocation failed");
        return -1;
    }
    memcpy(v.as.bytes.data, data, len);
    v.as.bytes.len = len;
    return vm_push(vm, v);
}

int vm_push_string(VM *vm, const char *str, size_t len) {
    VMValue v = { .type = VAL_STRING };
    v.as.str.data = vm_alloc(vm, len + 1);
    if (!v.as.str.data) {
        vm_error(vm, VM_ERR_MEMORY, "allocation failed");
        return -1;
    }
    memcpy(v.as.str.data, str, len);
    v.as.str.data[len] = '\0';
    v.as.str.len = len;
    return vm_push(vm, v);
}

VMValue vm_pop(VM *vm) {
    if (vm->sp == 0) {
        vm_error(vm, VM_ERR_STACK_UNDER, "stack underflow");
        VMValue v = { .type = VAL_NONE };
        return v;
    }
    return vm->stack[--vm->sp];
}

VMValue vm_peek(VM *vm, size_t depth) {
    if (depth >= vm->sp) {
        VMValue v = { .type = VAL_NONE };
        return v;
    }
    return vm->stack[vm->sp - 1 - depth];
}

/* ============================================================================
 * Stream operations
 * ============================================================================ */

size_t vm_stream_pos(VM *vm) {
    return vm->stream.pos;
}

size_t vm_stream_size(VM *vm) {
    return vm->stream.size;
}

int vm_stream_seek(VM *vm, size_t pos) {
    if (pos > vm->stream.size) {
        vm_error(vm, VM_ERR_BOUNDS, "seek out of bounds");
        return -1;
    }
    vm->stream.pos = pos;
    return 0;
}

int vm_stream_read(VM *vm, uint8_t *buf, size_t len) {
    return vm_stream_read_raw(vm, buf, len);
}

/* ============================================================================
 * Binary read helpers
 * ============================================================================ */

uint8_t vm_read_u8(VM *vm) {
    if (!vm_stream_has(vm, 1)) {
        vm_error(vm, VM_ERR_EOF, "unexpected eof");
        return 0;
    }
    return vm->stream.data[vm->stream.pos++];
}

uint16_t vm_read_u16(VM *vm) {
    uint8_t buf[2];
    if (vm_stream_read_raw(vm, buf, 2) < 0) {
        return 0;
    }
    uint16_t v;
    if (vm->big_endian) {
        /* Big-endian: MSB first */
        v = ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
    } else {
        /* Little-endian: LSB first */
        v = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    }
    return v;
}

uint32_t vm_read_u32(VM *vm) {
    uint8_t buf[4];
    if (vm_stream_read_raw(vm, buf, 4) < 0) {
        return 0;
    }
    uint32_t v;
    if (vm->big_endian) {
        /* Big-endian: MSB first */
        v = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
            ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
    } else {
        /* Little-endian: LSB first */
        v = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
            ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    }
    return v;
}

uint64_t vm_read_u64(VM *vm) {
    uint8_t buf[8];
    if (vm_stream_read_raw(vm, buf, 8) < 0) {
        return 0;
    }
    uint64_t v;
    if (vm->big_endian) {
        /* Big-endian: MSB first */
        v = ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
            ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
            ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
            ((uint64_t)buf[6] << 8)  | (uint64_t)buf[7];
    } else {
        /* Little-endian: LSB first */
        v = (uint64_t)buf[0] | ((uint64_t)buf[1] << 8) |
            ((uint64_t)buf[2] << 16) | ((uint64_t)buf[3] << 24) |
            ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
            ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
    }
    return v;
}

int8_t vm_read_s8(VM *vm) {
    return (int8_t)vm_read_u8(vm);
}

int16_t vm_read_s16(VM *vm) {
    return (int16_t)vm_read_u16(vm);
}

int32_t vm_read_s32(VM *vm) {
    return (int32_t)vm_read_u32(vm);
}

int64_t vm_read_s64(VM *vm) {
    return (int64_t)vm_read_u64(vm);
}

float vm_read_f32(VM *vm) {
    union { uint32_t i; float f; } u;
    u.i = vm_read_u32(vm);
    return u.f;
}

double vm_read_f64(VM *vm) {
    union { uint64_t i; double f; } u;
    u.i = vm_read_u64(vm);
    return u.f;
}

/* ============================================================================
 * Instruction execution
 * ============================================================================ */

int vm_step(VM *vm) {
    if (vm->halted) {
        return -1;
    }
    
    if (vm->ip >= vm->code + vm->code_len) {
        vm->halted = true;
        return 0;
    }
    
    uint8_t op = *vm->ip++;
    VMValue a, b, r;
    
    switch (op) {
    /* Stack operations */
    case OP_NOP:
        break;
        
    case OP_PUSH:
        vm_push_int(vm, read_imm64(vm));
        break;
        
    case OP_POP:
        vm_pop(vm);
        break;
        
    case OP_DUP:
        a = vm_peek(vm, 0);
        vm_push(vm, a);
        break;
        
    case OP_SWAP:
        a = vm_pop(vm);
        b = vm_pop(vm);
        vm_push(vm, a);
        vm_push(vm, b);
        break;
    
    /* Arithmetic */
    case OP_ADD:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 + a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_SUB:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 - a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_MUL:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 * a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_DIV:
        a = vm_pop(vm);
        b = vm_pop(vm);
        if (a.as.i64 == 0) {
            vm_error(vm, VM_ERR_BOUNDS, "division by zero");
            return -1;
        }
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 / a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_MOD:
        a = vm_pop(vm);
        b = vm_pop(vm);
        if (a.as.i64 == 0) {
            vm_error(vm, VM_ERR_BOUNDS, "modulo by zero");
            return -1;
        }
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 % a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_NEG:
        a = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = -a.as.i64;
        vm_push(vm, r);
        break;
    
    /* Bitwise */
    case OP_AND:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 & a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_OR:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 | a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_XOR:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 ^ a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_NOT:
        a = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = ~a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_SHL:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 << a.as.i64;
        vm_push(vm, r);
        break;
        
    case OP_SHR:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_UINT;
        r.as.u64 = b.as.u64 >> a.as.u64;
        vm_push(vm, r);
        break;
        
    case OP_SAR:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = b.as.i64 >> a.as.i64;
        vm_push(vm, r);
        break;
    
    /* Comparison */
    case OP_EQ:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 == a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
        
    case OP_NE:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 != a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
        
    case OP_LT:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 < a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
        
    case OP_LEQ:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 <= a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
        
    case OP_GT:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 > a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
        
    case OP_GEQ:
        a = vm_pop(vm);
        b = vm_pop(vm);
        r.type = VAL_INT;
        r.as.i64 = (b.as.i64 >= a.as.i64) ? 1 : 0;
        vm_push(vm, r);
        break;
    
    /* Control flow */
    case OP_JMP: {
        int32_t off = (int32_t)read_imm32(vm);
        if (off < 0 || (size_t)off >= vm->code_len) {
            vm_error(vm, VM_ERR_BOUNDS, "jump target out of bounds");
            return -1;
        }
        vm->ip = vm->code + off;
        break;
    }
    
    case OP_JZ: {
        int32_t off = (int32_t)read_imm32(vm);
        if (off < 0 || (size_t)off >= vm->code_len) {
            vm_error(vm, VM_ERR_BOUNDS, "jump target out of bounds");
            return -1;
        }
        a = vm_pop(vm);
        if (a.as.i64 == 0) {
            vm->ip = vm->code + off;
        }
        break;
    }
    
    case OP_JNZ: {
        int32_t off = (int32_t)read_imm32(vm);
        if (off < 0 || (size_t)off >= vm->code_len) {
            vm_error(vm, VM_ERR_BOUNDS, "jump target out of bounds");
            return -1;
        }
        a = vm_pop(vm);
        if (a.as.i64 != 0) {
            vm->ip = vm->code + off;
        }
        break;
    }
    
    case OP_CALL: {
        if (vm->fp >= VM_CALL_DEPTH) {
            vm_error(vm, VM_ERR_CALL_DEPTH, "call stack overflow");
            return -1;
        }
        int32_t off = (int32_t)read_imm32(vm);
        if (off < 0 || (size_t)off >= vm->code_len) {
            vm_error(vm, VM_ERR_BOUNDS, "call target out of bounds");
            return -1;
        }
        vm->frames[vm->fp].ret_addr = vm->ip;
        vm->frames[vm->fp].stack_base = vm->sp;
        vm->fp++;
        vm->ip = vm->code + off;
        break;
    }
    
    case OP_RET:
        if (vm->fp == 0) {
            vm->halted = true;
            return 0;
        }
        vm->fp--;
        vm->ip = vm->frames[vm->fp].ret_addr;
        break;
        
    case OP_HALT:
        vm->halted = true;
        return 0;
    
    /* Binary read operations */
    case OP_READ_U8:
        vm_push_uint(vm, vm_read_u8(vm));
        break;
        
    case OP_READ_U16:
        vm_push_uint(vm, vm_read_u16(vm));
        break;
        
    case OP_READ_U32:
        vm_push_uint(vm, vm_read_u32(vm));
        break;
        
    case OP_READ_U64:
        vm_push_uint(vm, vm_read_u64(vm));
        break;
        
    case OP_READ_S8:
        vm_push_int(vm, vm_read_s8(vm));
        break;
        
    case OP_READ_S16:
        vm_push_int(vm, vm_read_s16(vm));
        break;
        
    case OP_READ_S32:
        vm_push_int(vm, vm_read_s32(vm));
        break;
        
    case OP_READ_S64:
        vm_push_int(vm, vm_read_s64(vm));
        break;
        
    case OP_READ_F32:
        vm_push_float(vm, vm_read_f32(vm));
        break;
        
    case OP_READ_F64:
        vm_push_float(vm, vm_read_f64(vm));
        break;
        
    case OP_READ_BYTES: {
        a = vm_pop(vm);
        size_t len = (size_t)a.as.u64;
        if (!vm_stream_has(vm, len)) {
            vm_error(vm, VM_ERR_EOF, "unexpected eof");
            return -1;
        }
        vm_push_bytes(vm, vm->stream.data + vm->stream.pos, len);
        vm->stream.pos += len;
        break;
    }
    
    case OP_READ_STR: {
        /* Read null-terminated string */
        size_t start = vm->stream.pos;
        while (vm->stream.pos < vm->stream.size && 
               vm->stream.data[vm->stream.pos] != 0) {
            vm->stream.pos++;
        }
        size_t len = vm->stream.pos - start;
        vm_push_string(vm, (const char *)vm->stream.data + start, len);
        if (vm->stream.pos < vm->stream.size) {
            vm->stream.pos++; /* Skip null terminator */
        }
        break;
    }
    
    case OP_READ_STRZ: {
        /* Read string with specified terminator */
        uint8_t term = read_imm8(vm);
        size_t start = vm->stream.pos;
        while (vm->stream.pos < vm->stream.size && 
               vm->stream.data[vm->stream.pos] != term) {
            vm->stream.pos++;
        }
        size_t len = vm->stream.pos - start;
        vm_push_string(vm, (const char *)vm->stream.data + start, len);
        if (vm->stream.pos < vm->stream.size) {
            vm->stream.pos++; /* Skip terminator */
        }
        break;
    }
    
    /* Stream operations */
    case OP_SEEK:
        a = vm_pop(vm);
        vm_stream_seek(vm, (size_t)a.as.u64);
        break;
        
    case OP_TELL:
        vm_push_uint(vm, vm_stream_pos(vm));
        break;
        
    case OP_SIZE:
        vm_push_uint(vm, vm_stream_size(vm));
        break;
        
    case OP_EOF:
        vm_push_int(vm, vm->stream.pos >= vm->stream.size ? 1 : 0);
        break;
        
    case OP_SUBSTREAM: {
        /* Create substream: [size] -> [] */
        a = vm_pop(vm);
        size_t size = (size_t)a.as.u64;
        /* Just adjust limits for substream (simplified) */
        if (vm->stream.pos + size > vm->stream.size) {
            vm_error(vm, VM_ERR_BOUNDS, "substream out of bounds");
            return -1;
        }
        vm->stream.base = vm->stream.pos;
        break;
    }
    
    /* Endian control */
    case OP_ENDIAN_LE: /* little-endian */
        vm->big_endian = false;
        break;
        
    case OP_ENDIAN_BE: /* big-endian */
        vm->big_endian = true;
        break;
    
    /* Debug */
    case OP_DEBUG:
        vm_dump_stack(vm);
        break;
        
    default:
        vm_error(vm, VM_ERR_BAD_OP, "invalid opcode");
        return -1;
    }
    
    return vm->error ? -1 : 1;
}

int vm_run(VM *vm) {
    while (!vm->halted && vm->error == 0) {
        if (vm_step(vm) < 0) {
            break;
        }
    }
    return vm->error;
}

int vm_call_type(VM *vm, const VMTypeDef *type) {
    if (!type || !type->bytecode) {
        return -1;
    }
    
    /* Save current state and set new bytecode */
    const uint8_t *old_code = vm->code;
    size_t old_len = vm->code_len;
    const uint8_t *old_ip = vm->ip;
    
    vm_set_bytecode(vm, type->bytecode, type->bytecode_len);
    int result = vm_run(vm);
    
    /* Restore state */
    vm->code = old_code;
    vm->code_len = old_len;
    vm->ip = old_ip;
    
    return result;
}

/* ============================================================================
 * Result access
 * ============================================================================ */

VMStruct *vm_get_result(VM *vm) {
    if (vm->sp == 0) {
        return NULL;
    }
    VMValue v = vm_peek(vm, 0);
    if (v.type != VAL_STRUCT) {
        return NULL;
    }
    return v.as.struc;
}

VMValue *vm_struct_field(VMStruct *s, const char *name) {
    if (!s || !s->type) {
        return NULL;
    }
    for (uint16_t i = 0; i < s->type->num_fields; i++) {
        if (strcmp(s->type->fields[i].name, name) == 0) {
            return &s->values[i];
        }
    }
    return NULL;
}

VMValue *vm_array_elem(VMArray *a, size_t index) {
    if (!a || index >= a->count) {
        return NULL;
    }
    return &a->elements[index];
}

/* ============================================================================
 * Debug utilities
 * ============================================================================ */

static const char *opcode_names[] = {
    [OP_NOP]       = "NOP",
    [OP_PUSH]      = "PUSH",
    [OP_POP]       = "POP",
    [OP_DUP]       = "DUP",
    [OP_SWAP]      = "SWAP",
    [OP_ADD]       = "ADD",
    [OP_SUB]       = "SUB",
    [OP_MUL]       = "MUL",
    [OP_DIV]       = "DIV",
    [OP_MOD]       = "MOD",
    [OP_NEG]       = "NEG",
    [OP_AND]       = "AND",
    [OP_OR]        = "OR",
    [OP_XOR]       = "XOR",
    [OP_NOT]       = "NOT",
    [OP_SHL]       = "SHL",
    [OP_SHR]       = "SHR",
    [OP_SAR]       = "SAR",
    [OP_EQ]        = "EQ",
    [OP_NE]        = "NE",
    [OP_LT]        = "LT",
    [OP_LEQ]       = "LEQ",
    [OP_GT]        = "GT",
    [OP_GEQ]       = "GEQ",
    [OP_JMP]       = "JMP",
    [OP_JZ]        = "JZ",
    [OP_JNZ]       = "JNZ",
    [OP_CALL]      = "CALL",
    [OP_RET]       = "RET",
    [OP_HALT]      = "HALT",
    [OP_READ_U8]   = "READ_U8",
    [OP_READ_U16]  = "READ_U16",
    [OP_READ_U32]  = "READ_U32",
    [OP_READ_U64]  = "READ_U64",
    [OP_READ_S8]   = "READ_S8",
    [OP_READ_S16]  = "READ_S16",
    [OP_READ_S32]  = "READ_S32",
    [OP_READ_S64]  = "READ_S64",
    [OP_READ_F32]  = "READ_F32",
    [OP_READ_F64]  = "READ_F64",
    [OP_READ_BYTES]= "READ_BYTES",
    [OP_READ_STR]  = "READ_STR",
    [OP_READ_STRZ] = "READ_STRZ",
    [OP_SEEK]      = "SEEK",
    [OP_TELL]      = "TELL",
    [OP_SIZE]      = "SIZE",
    [OP_EOF]       = "EOF",
    [OP_SUBSTREAM] = "SUBSTREAM",
    [OP_ENDIAN_LE] = "ENDIAN_LE",
    [OP_ENDIAN_BE] = "ENDIAN_BE",
    [OP_DEBUG]     = "DEBUG",
};

const char *vm_opcode_name(VMOpcode op) {
    if (op < sizeof(opcode_names)/sizeof(opcode_names[0]) && opcode_names[op]) {
        return opcode_names[op];
    }
    return "???";
}

void vm_dump_stack(VM *vm) {
    fprintf(stderr, "=== VM Stack (sp=%zu) ===\n", vm->sp);
    for (size_t i = 0; i < vm->sp; i++) {
        VMValue *v = &vm->stack[i];
        fprintf(stderr, "[%zu] ", i);
        switch (v->type) {
        case VAL_NONE:
            fprintf(stderr, "NONE\n");
            break;
        case VAL_INT:
            fprintf(stderr, "INT: %lld\n", (long long)v->as.i64);
            break;
        case VAL_UINT:
            fprintf(stderr, "UINT: %llu\n", (unsigned long long)v->as.u64);
            break;
        case VAL_FLOAT:
            fprintf(stderr, "FLOAT: %g\n", v->as.f64);
            break;
        case VAL_BYTES:
            fprintf(stderr, "BYTES[%zu]\n", v->as.bytes.len);
            break;
        case VAL_STRING:
            fprintf(stderr, "STRING: \"%s\"\n", v->as.str.data);
            break;
        case VAL_STRUCT:
            fprintf(stderr, "STRUCT: %s\n", 
                    v->as.struc ? v->as.struc->type->name : "(null)");
            break;
        case VAL_ARRAY:
            fprintf(stderr, "ARRAY[%zu]\n", 
                    v->as.arr ? v->as.arr->count : 0);
            break;
        }
    }
    fprintf(stderr, "========================\n");
}

void vm_dump_stream(VM *vm, size_t len) {
    fprintf(stderr, "=== VM Stream (pos=%zu, size=%zu) ===\n", 
            vm->stream.pos, vm->stream.size);
    
    size_t start = vm->stream.pos;
    size_t end = start + len;
    if (end > vm->stream.size) {
        end = vm->stream.size;
    }
    
    for (size_t i = start; i < end; i += 16) {
        fprintf(stderr, "%08zx: ", i);
        for (size_t j = 0; j < 16 && i + j < end; j++) {
            fprintf(stderr, "%02x ", vm->stream.data[i + j]);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "====================================\n");
}
