/*
 * LudoFile - Minimalist Kaitai Virtual Machine
 *
 * A minimal, reusable bytecode VM for parsing binary structures.
 * Designed for Cosmopolitan C / APE compatibility.
 *
 * Design principles (from style guide):
 * - Pure POSIX C, no external dependencies
 * - Minimal instruction set (< 32 opcodes)
 * - Stack-based execution model
 * - Direct memory access for binary parsing
 * - Reentrant and thread-safe
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_VM_H
#define LUDOFILE_VM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define VM_STACK_SIZE      256   /* Value stack depth */
#define VM_CALL_DEPTH      64    /* Max call stack depth */
#define VM_MAX_FIELDS      256   /* Max fields per struct */
#define VM_MAX_TYPES       128   /* Max type definitions */

/* ============================================================================
 * Opcodes - Minimal instruction set for binary parsing
 * ============================================================================ */

typedef enum {
    /* Stack operations */
    OP_NOP       = 0x00,  /* No operation */
    OP_PUSH      = 0x01,  /* Push immediate value */
    OP_POP       = 0x02,  /* Pop value */
    OP_DUP       = 0x03,  /* Duplicate top */
    OP_SWAP      = 0x04,  /* Swap top two */
    
    /* Arithmetic */
    OP_ADD       = 0x10,  /* Add top two */
    OP_SUB       = 0x11,  /* Subtract */
    OP_MUL       = 0x12,  /* Multiply */
    OP_DIV       = 0x13,  /* Divide */
    OP_MOD       = 0x14,  /* Modulo */
    OP_NEG       = 0x15,  /* Negate */
    
    /* Bitwise */
    OP_AND       = 0x20,  /* Bitwise AND */
    OP_OR        = 0x21,  /* Bitwise OR */
    OP_XOR       = 0x22,  /* Bitwise XOR */
    OP_NOT       = 0x23,  /* Bitwise NOT */
    OP_SHL       = 0x24,  /* Shift left */
    OP_SHR       = 0x25,  /* Shift right (logical) */
    OP_SAR       = 0x26,  /* Shift right (arithmetic) */
    
    /* Comparison */
    OP_EQ        = 0x30,  /* Equal */
    OP_NE        = 0x31,  /* Not equal */
    OP_LT        = 0x32,  /* Less than */
    OP_LEQ       = 0x33,  /* Less or equal */
    OP_GT        = 0x34,  /* Greater than */
    OP_GEQ       = 0x35,  /* Greater or equal */
    
    /* Control flow */
    OP_JMP       = 0x40,  /* Unconditional jump */
    OP_JZ        = 0x41,  /* Jump if zero */
    OP_JNZ       = 0x42,  /* Jump if not zero */
    OP_CALL      = 0x43,  /* Call subroutine */
    OP_RET       = 0x44,  /* Return */
    OP_HALT      = 0x4F,  /* Stop execution */
    
    /* Binary read operations (Kaitai core) */
    OP_READ_U8   = 0x50,  /* Read uint8 */
    OP_READ_U16  = 0x51,  /* Read uint16 (endian from mode) */
    OP_READ_U32  = 0x52,  /* Read uint32 */
    OP_READ_U64  = 0x53,  /* Read uint64 */
    OP_READ_S8   = 0x54,  /* Read int8 */
    OP_READ_S16  = 0x55,  /* Read int16 */
    OP_READ_S32  = 0x56,  /* Read int32 */
    OP_READ_S64  = 0x57,  /* Read int64 */
    OP_READ_F32  = 0x58,  /* Read float32 */
    OP_READ_F64  = 0x59,  /* Read float64 */
    OP_READ_BYTES= 0x5A,  /* Read N bytes */
    OP_READ_STR  = 0x5B,  /* Read null-terminated string */
    OP_READ_STRZ = 0x5C,  /* Read string with terminator */
    
    /* Stream operations */
    OP_SEEK      = 0x60,  /* Seek to position */
    OP_TELL      = 0x61,  /* Get current position */
    OP_SIZE      = 0x62,  /* Get stream size */
    OP_EOF       = 0x63,  /* Check end of stream */
    OP_SUBSTREAM = 0x64,  /* Create sub-stream */
    
    /* Structure operations */
    OP_STRUCT    = 0x70,  /* Begin struct */
    OP_END       = 0x71,  /* End struct */
    OP_FIELD     = 0x72,  /* Define field */
    OP_ARRAY     = 0x73,  /* Begin array */
    OP_SWITCH    = 0x74,  /* Switch on value */
    OP_CASE      = 0x75,  /* Case branch */
    
    /* Endian control */
    OP_ENDIAN_LE = 0x80,  /* Set little-endian mode */
    OP_ENDIAN_BE = 0x81,  /* Set big-endian mode */
    
    /* Debug */
    OP_DEBUG     = 0xFE,  /* Debug breakpoint */
    OP_INVALID   = 0xFF   /* Invalid opcode */
} VMOpcode;

/* ============================================================================
 * Value types
 * ============================================================================ */

typedef enum {
    VAL_NONE     = 0,
    VAL_INT      = 1,
    VAL_UINT     = 2,
    VAL_FLOAT    = 3,
    VAL_BYTES    = 4,
    VAL_STRING   = 5,
    VAL_STRUCT   = 6,
    VAL_ARRAY    = 7
} VMValueType;

/*
 * VM Value - tagged union for stack values
 */
typedef struct VMValue {
    VMValueType type;
    union {
        int64_t     i64;
        uint64_t    u64;
        double      f64;
        struct {
            uint8_t *data;
            size_t   len;
        } bytes;
        struct {
            char    *data;
            size_t   len;
        } str;
        struct VMStruct *struc;
        struct VMArray  *arr;
    } as;
} VMValue;

/* ============================================================================
 * Field and struct definitions
 * ============================================================================ */

/*
 * Field definition - describes one field in a struct
 */
typedef struct {
    const char *name;      /* Field name */
    uint16_t    type_id;   /* Type index or primitive */
    uint16_t    flags;     /* Field flags */
    uint32_t    offset;    /* Bytecode offset for computation */
} VMFieldDef;

/*
 * Type definition - describes a struct type
 */
typedef struct {
    const char  *name;           /* Type name */
    VMFieldDef  *fields;         /* Field definitions */
    uint16_t     num_fields;     /* Number of fields */
    uint16_t     flags;          /* Type flags */
    const uint8_t *bytecode;     /* Parsing bytecode */
    size_t       bytecode_len;   /* Bytecode length */
} VMTypeDef;

/*
 * Parsed struct instance
 */
typedef struct VMStruct {
    const VMTypeDef *type;       /* Type definition */
    VMValue         *values;     /* Field values */
    size_t           offset;     /* Offset in source data */
    size_t           size;       /* Total size parsed */
} VMStruct;

/*
 * Parsed array instance
 */
typedef struct VMArray {
    VMValueType  elem_type;      /* Element type */
    VMValue     *elements;       /* Array elements */
    size_t       count;          /* Number of elements */
    size_t       capacity;       /* Allocated capacity */
} VMArray;

/* ============================================================================
 * VM State
 * ============================================================================ */

/*
 * Stream state - tracks position in binary data
 */
typedef struct {
    const uint8_t *data;         /* Binary data pointer */
    size_t         size;         /* Total size */
    size_t         pos;          /* Current position */
    size_t         base;         /* Base offset (for substreams) */
} VMStream;

/*
 * Call frame - for function calls
 */
typedef struct {
    const uint8_t *ret_addr;     /* Return address */
    size_t         stack_base;   /* Stack base for this frame */
    const VMTypeDef *type;       /* Current type being parsed */
} VMFrame;

/*
 * VM execution state - fully reentrant
 */
typedef struct {
    /* Bytecode */
    const uint8_t *code;         /* Bytecode pointer */
    size_t         code_len;     /* Bytecode length */
    const uint8_t *ip;           /* Instruction pointer */
    
    /* Value stack */
    VMValue        stack[VM_STACK_SIZE];
    size_t         sp;           /* Stack pointer */
    
    /* Call stack */
    VMFrame        frames[VM_CALL_DEPTH];
    size_t         fp;           /* Frame pointer */
    
    /* Binary stream */
    VMStream       stream;
    
    /* Type registry */
    VMTypeDef     *types;        /* Type definitions */
    size_t         num_types;    /* Number of types */
    
    /* State flags */
    bool           big_endian;   /* Current endianness */
    bool           halted;       /* Execution halted */
    int            error;        /* Error code (0 = ok) */
    const char    *error_msg;    /* Error message */
    
    /* Memory management */
    void          *user_data;    /* User context */
    void *(*alloc)(void *ctx, size_t size);
    void  (*free)(void *ctx, void *ptr);
} VM;

/* ============================================================================
 * Error codes
 * ============================================================================ */

#define VM_OK              0
#define VM_ERR_STACK_OVER  1
#define VM_ERR_STACK_UNDER 2
#define VM_ERR_BAD_OP      3
#define VM_ERR_EOF         4
#define VM_ERR_MEMORY      5
#define VM_ERR_TYPE        6
#define VM_ERR_BOUNDS      7
#define VM_ERR_CALL_DEPTH  8

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Initialization and cleanup
 */
void vm_init(VM *vm);
void vm_free(VM *vm);
void vm_reset(VM *vm);

/*
 * Configuration
 */
void vm_set_allocator(VM *vm, 
                      void *(*alloc)(void *, size_t),
                      void (*free)(void *, void *),
                      void *user_data);
void vm_set_stream(VM *vm, const uint8_t *data, size_t size);
void vm_set_bytecode(VM *vm, const uint8_t *code, size_t len);

/*
 * Type registration
 */
int vm_register_type(VM *vm, const VMTypeDef *type);
const VMTypeDef *vm_get_type(VM *vm, const char *name);
const VMTypeDef *vm_get_type_by_id(VM *vm, uint16_t id);

/*
 * Execution
 */
int vm_run(VM *vm);
int vm_step(VM *vm);
int vm_call_type(VM *vm, const VMTypeDef *type);

/*
 * Stack operations
 */
int vm_push(VM *vm, VMValue val);
int vm_push_int(VM *vm, int64_t val);
int vm_push_uint(VM *vm, uint64_t val);
int vm_push_float(VM *vm, double val);
int vm_push_bytes(VM *vm, const uint8_t *data, size_t len);
int vm_push_string(VM *vm, const char *str, size_t len);
VMValue vm_pop(VM *vm);
VMValue vm_peek(VM *vm, size_t depth);

/*
 * Stream operations
 */
size_t vm_stream_pos(VM *vm);
size_t vm_stream_size(VM *vm);
int vm_stream_seek(VM *vm, size_t pos);
int vm_stream_read(VM *vm, uint8_t *buf, size_t len);

/*
 * Binary read helpers
 */
uint8_t  vm_read_u8(VM *vm);
uint16_t vm_read_u16(VM *vm);
uint32_t vm_read_u32(VM *vm);
uint64_t vm_read_u64(VM *vm);
int8_t   vm_read_s8(VM *vm);
int16_t  vm_read_s16(VM *vm);
int32_t  vm_read_s32(VM *vm);
int64_t  vm_read_s64(VM *vm);
float    vm_read_f32(VM *vm);
double   vm_read_f64(VM *vm);

/*
 * Result access
 */
VMStruct *vm_get_result(VM *vm);
VMValue *vm_struct_field(VMStruct *s, const char *name);
VMValue *vm_array_elem(VMArray *a, size_t index);

/*
 * Debug
 */
const char *vm_opcode_name(VMOpcode op);
void vm_dump_stack(VM *vm);
void vm_dump_stream(VM *vm, size_t len);

#endif /* LUDOFILE_VM_H */
