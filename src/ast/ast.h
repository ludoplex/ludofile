/*
 * LudoFile - Abstract Syntax Tree Module
 *
 * AST representation for parser definitions and magic patterns.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_AST_AST_H
#define LUDOFILE_AST_AST_H

#include "../core/types.h"
#include "../core/arena.h"
#include "../core/hashtable.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * AST node types
 */
typedef enum {
    AST_NODE_ROOT = 0,          /* Root node of AST */
    AST_NODE_MAGIC_DEF,         /* Magic definition block */
    AST_NODE_MAGIC_TEST,        /* Individual magic test */
    AST_NODE_OFFSET,            /* Offset specification */
    AST_NODE_TYPE,              /* Data type specification */
    AST_NODE_VALUE,             /* Test value */
    AST_NODE_MESSAGE,           /* Message/description */
    AST_NODE_MIME,              /* MIME type */
    AST_NODE_EXTENSION,         /* File extension */
    AST_NODE_STRENGTH,          /* Match strength modifier */
    AST_NODE_PARSER,            /* Parser definition */
    AST_NODE_FIELD,             /* Structure field */
    AST_NODE_STRUCT,            /* Structure definition */
    AST_NODE_ENUM,              /* Enumeration */
    AST_NODE_UNION,             /* Union type */
    AST_NODE_ARRAY,             /* Array type */
    AST_NODE_SWITCH,            /* Switch expression */
    AST_NODE_CASE,              /* Case clause */
    AST_NODE_REPEAT,            /* Repeat construct */
    AST_NODE_IF,                /* Conditional */
    AST_NODE_EXPRESSION,        /* Expression */
    AST_NODE_LITERAL,           /* Literal value */
    AST_NODE_IDENTIFIER,        /* Identifier */
    AST_NODE_BINARY_OP,         /* Binary operation */
    AST_NODE_UNARY_OP,          /* Unary operation */
    AST_NODE_CALL,              /* Function/method call */
    AST_NODE_MEMBER,            /* Member access */
    AST_NODE_INDEX,             /* Array index */
    AST_NODE_TERNARY,           /* Ternary expression */
    AST_NODE_COMMENT            /* Comment node */
} AstNodeType;

/*
 * Value types for literals
 */
typedef enum {
    AST_VALUE_NULL = 0,
    AST_VALUE_BOOL,
    AST_VALUE_INT,
    AST_VALUE_UINT,
    AST_VALUE_FLOAT,
    AST_VALUE_STRING,
    AST_VALUE_BYTES,
    AST_VALUE_REGEX
} AstValueType;

/*
 * Binary operators
 */
typedef enum {
    AST_OP_ADD = 0,             /* + */
    AST_OP_SUB,                 /* - */
    AST_OP_MUL,                 /* * */
    AST_OP_DIV,                 /* / */
    AST_OP_MOD,                 /* % */
    AST_OP_AND,                 /* && */
    AST_OP_OR,                  /* || */
    AST_OP_BAND,                /* & */
    AST_OP_BOR,                 /* | */
    AST_OP_BXOR,                /* ^ */
    AST_OP_SHL,                 /* << */
    AST_OP_SHR,                 /* >> */
    AST_OP_EQ,                  /* == */
    AST_OP_NE,                  /* != */
    AST_OP_LT,                  /* < */
    AST_OP_LE,                  /* <= */
    AST_OP_GT,                  /* > */
    AST_OP_GE                   /* >= */
} AstBinaryOp;

/*
 * Unary operators
 */
typedef enum {
    AST_OP_NEG = 0,             /* - (negation) */
    AST_OP_NOT,                 /* ! */
    AST_OP_BNOT,                /* ~ */
    AST_OP_DEREF,               /* * (dereference) */
    AST_OP_ADDR                 /* & (address-of) */
} AstUnaryOp;

/*
 * Source location
 */
typedef struct {
    const char *file;           /* Source file name */
    int line;                   /* Line number (1-based) */
    int column;                 /* Column number (1-based) */
    size_t offset;              /* Byte offset from start */
} AstLocation;

/*
 * AST value (for literals)
 */
typedef struct {
    AstValueType type;
    union {
        bool bool_val;
        int64_t int_val;
        uint64_t uint_val;
        double float_val;
        struct {
            char *data;
            size_t length;
        } string;
        struct {
            uint8_t *data;
            size_t length;
        } bytes;
    } data;
} AstValue;

/*
 * Forward declaration
 */
typedef struct AstNode AstNode;

/*
 * AST node structure
 */
struct AstNode {
    AstNodeType type;           /* Node type */
    AstLocation location;       /* Source location */
    AstNode *parent;            /* Parent node */
    AstNode **children;         /* Child nodes */
    size_t num_children;        /* Number of children */
    size_t children_capacity;   /* Capacity of children array */
    
    /* Type-specific data */
    union {
        /* For AST_NODE_LITERAL */
        AstValue value;
        
        /* For AST_NODE_IDENTIFIER, AST_NODE_MESSAGE, AST_NODE_MIME, etc. */
        struct {
            char *name;
            size_t name_length;
        } ident;
        
        /* For AST_NODE_BINARY_OP */
        struct {
            AstBinaryOp op;
        } binary;
        
        /* For AST_NODE_UNARY_OP */
        struct {
            AstUnaryOp op;
        } unary;
        
        /* For AST_NODE_OFFSET */
        struct {
            OffsetType type;
            int64_t value;
            bool indirect;
            int num_bytes;
            Endianness endianness;
        } offset;
        
        /* For AST_NODE_TYPE */
        struct {
            char *type_name;
            bool is_array;
            bool is_pointer;
            int size;
            Endianness endianness;
        } type_spec;
        
        /* For AST_NODE_FIELD */
        struct {
            char *name;
            char *type_name;
            bool optional;
            bool repeated;
        } field;
        
        /* For AST_NODE_MAGIC_TEST */
        struct {
            int level;              /* Indentation level */
            bool is_continuation;   /* Continuation of parent test */
        } magic;
        
        /* For AST_NODE_STRENGTH */
        struct {
            int modifier;           /* Strength adjustment */
        } strength;
        
        /* For AST_NODE_CALL */
        struct {
            char *function_name;
        } call;
        
        /* For AST_NODE_COMMENT */
        struct {
            char *text;
            bool is_doc_comment;
        } comment;
    } data;
    
    /* Attributes (key-value pairs) */
    StringHashTable attributes;
};

/*
 * AST context for building trees
 */
typedef struct {
    Arena *arena;               /* Memory arena */
    AstNode *root;              /* Root node */
    AstNode *current;           /* Current node for building */
    StringHashTable symbols;    /* Symbol table */
    const char *source_file;    /* Current source file */
    int error_count;            /* Number of errors */
    char *last_error;           /* Last error message */
} AstContext;

/*
 * Visitor function type
 */
typedef bool (*AstVisitorFunc)(AstNode *node, void *user_data);

/*
 * Context creation and management
 */

/*
 * Create new AST context.
 * 
 * @param arena  Memory arena (optional, will create if NULL)
 * @return       New context, or NULL on error
 */
AstContext *ast_context_new(Arena *arena);

/*
 * Free AST context and all nodes.
 * 
 * @param ctx  Context to free
 */
void ast_context_free(AstContext *ctx);

/*
 * Set source file for error reporting.
 * 
 * @param ctx   Context
 * @param file  Source file path
 */
void ast_context_set_source(AstContext *ctx, const char *file);

/*
 * Node creation
 */

/*
 * Create new AST node.
 * 
 * @param ctx   AST context
 * @param type  Node type
 * @param loc   Source location (can be NULL)
 * @return      New node, or NULL on error
 */
AstNode *ast_node_new(AstContext *ctx, AstNodeType type, const AstLocation *loc);

/*
 * Create identifier node.
 * 
 * @param ctx   AST context
 * @param name  Identifier name
 * @param loc   Source location
 * @return      New node
 */
AstNode *ast_node_identifier(AstContext *ctx, const char *name, const AstLocation *loc);

/*
 * Create literal node.
 * 
 * @param ctx    AST context
 * @param value  Literal value
 * @param loc    Source location
 * @return       New node
 */
AstNode *ast_node_literal(AstContext *ctx, const AstValue *value, const AstLocation *loc);

/*
 * Create string literal node.
 * 
 * @param ctx   AST context
 * @param str   String value
 * @param len   String length
 * @param loc   Source location
 * @return      New node
 */
AstNode *ast_node_string(AstContext *ctx, const char *str, size_t len, const AstLocation *loc);

/*
 * Create integer literal node.
 * 
 * @param ctx    AST context
 * @param value  Integer value
 * @param loc    Source location
 * @return       New node
 */
AstNode *ast_node_integer(AstContext *ctx, int64_t value, const AstLocation *loc);

/*
 * Create binary operation node.
 * 
 * @param ctx    AST context
 * @param op     Operator
 * @param left   Left operand
 * @param right  Right operand
 * @param loc    Source location
 * @return       New node
 */
AstNode *ast_node_binary_op(AstContext *ctx, AstBinaryOp op, 
                            AstNode *left, AstNode *right, const AstLocation *loc);

/*
 * Create unary operation node.
 * 
 * @param ctx      AST context
 * @param op       Operator
 * @param operand  Operand
 * @param loc      Source location
 * @return         New node
 */
AstNode *ast_node_unary_op(AstContext *ctx, AstUnaryOp op,
                           AstNode *operand, const AstLocation *loc);

/*
 * Create magic test node.
 * 
 * @param ctx    AST context
 * @param level  Indentation level
 * @param loc    Source location
 * @return       New node
 */
AstNode *ast_node_magic_test(AstContext *ctx, int level, const AstLocation *loc);

/*
 * Create offset node.
 * 
 * @param ctx    AST context
 * @param type   Offset type
 * @param value  Offset value
 * @param loc    Source location
 * @return       New node
 */
AstNode *ast_node_offset(AstContext *ctx, OffsetType type, 
                         int64_t value, const AstLocation *loc);

/*
 * Create field node.
 * 
 * @param ctx   AST context
 * @param name  Field name
 * @param type  Field type
 * @param loc   Source location
 * @return      New node
 */
AstNode *ast_node_field(AstContext *ctx, const char *name,
                        const char *type, const AstLocation *loc);

/*
 * Tree manipulation
 */

/*
 * Add child to node.
 * 
 * @param parent  Parent node
 * @param child   Child to add
 * @return        true on success
 */
bool ast_node_add_child(AstNode *parent, AstNode *child);

/*
 * Insert child at specific index.
 * 
 * @param parent  Parent node
 * @param child   Child to insert
 * @param index   Index to insert at
 * @return        true on success
 */
bool ast_node_insert_child(AstNode *parent, AstNode *child, size_t index);

/*
 * Remove child from node.
 * 
 * @param parent  Parent node
 * @param child   Child to remove
 * @return        true if removed
 */
bool ast_node_remove_child(AstNode *parent, AstNode *child);

/*
 * Get child by index.
 * 
 * @param node   Node
 * @param index  Child index
 * @return       Child node, or NULL
 */
AstNode *ast_node_get_child(const AstNode *node, size_t index);

/*
 * Find child by type.
 * 
 * @param node  Node to search
 * @param type  Node type to find
 * @return      First matching child, or NULL
 */
AstNode *ast_node_find_child(const AstNode *node, AstNodeType type);

/*
 * Attributes
 */

/*
 * Set node attribute.
 * 
 * @param ctx    AST context
 * @param node   Node
 * @param name   Attribute name
 * @param value  Attribute value
 * @return       true on success
 */
bool ast_node_set_attr(AstContext *ctx, AstNode *node, 
                       const char *name, const char *value);

/*
 * Get node attribute.
 * 
 * @param node  Node
 * @param name  Attribute name
 * @return      Attribute value, or NULL
 */
const char *ast_node_get_attr(const AstNode *node, const char *name);

/*
 * Traversal
 */

/*
 * Visit all nodes depth-first (pre-order).
 * 
 * @param node      Starting node
 * @param visitor   Visitor function
 * @param user_data User data passed to visitor
 * @return          true if all visits returned true
 */
bool ast_node_visit_preorder(AstNode *node, AstVisitorFunc visitor, void *user_data);

/*
 * Visit all nodes depth-first (post-order).
 * 
 * @param node      Starting node
 * @param visitor   Visitor function
 * @param user_data User data passed to visitor
 * @return          true if all visits returned true
 */
bool ast_node_visit_postorder(AstNode *node, AstVisitorFunc visitor, void *user_data);

/*
 * Visit nodes breadth-first.
 * 
 * @param node      Starting node
 * @param visitor   Visitor function
 * @param user_data User data passed to visitor
 * @return          true if all visits returned true
 */
bool ast_node_visit_bfs(AstNode *node, AstVisitorFunc visitor, void *user_data);

/*
 * Utilities
 */

/*
 * Get node type name as string.
 * 
 * @param type  Node type
 * @return      Type name string
 */
const char *ast_node_type_name(AstNodeType type);

/*
 * Get operator name as string.
 * 
 * @param op  Binary operator
 * @return    Operator string
 */
const char *ast_binary_op_string(AstBinaryOp op);

/*
 * Get unary operator name as string.
 * 
 * @param op  Unary operator
 * @return    Operator string
 */
const char *ast_unary_op_string(AstUnaryOp op);

/*
 * Count total nodes in tree.
 * 
 * @param node  Root node
 * @return      Total node count
 */
size_t ast_node_count(const AstNode *node);

/*
 * Get tree depth.
 * 
 * @param node  Root node
 * @return      Maximum depth
 */
size_t ast_node_depth(const AstNode *node);

/*
 * Clone a node (shallow copy).
 * 
 * @param ctx   AST context
 * @param node  Node to clone
 * @return      Cloned node
 */
AstNode *ast_node_clone(AstContext *ctx, const AstNode *node);

/*
 * Clone a node tree (deep copy).
 * 
 * @param ctx   AST context
 * @param node  Root node to clone
 * @return      Cloned tree
 */
AstNode *ast_node_clone_tree(AstContext *ctx, const AstNode *node);

/*
 * Print AST tree (for debugging).
 * 
 * @param node    Root node
 * @param indent  Initial indentation
 */
void ast_node_print(const AstNode *node, int indent);

/*
 * Symbol table operations
 */

/*
 * Define symbol in context.
 * 
 * @param ctx   AST context
 * @param name  Symbol name
 * @param node  Associated node
 * @return      true on success
 */
bool ast_define_symbol(AstContext *ctx, const char *name, AstNode *node);

/*
 * Look up symbol in context.
 * 
 * @param ctx   AST context
 * @param name  Symbol name
 * @return      Associated node, or NULL
 */
AstNode *ast_lookup_symbol(AstContext *ctx, const char *name);

/*
 * Check if symbol is defined.
 * 
 * @param ctx   AST context
 * @param name  Symbol name
 * @return      true if defined
 */
bool ast_has_symbol(AstContext *ctx, const char *name);

#endif /* LUDOFILE_AST_AST_H */
