/*
 * LudoFile - Abstract Syntax Tree Implementation
 *
 * AST representation for parser definitions and magic patterns.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L  /* For strdup */

#include "ast.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/*
 * Initial child array capacity
 */
#define INITIAL_CHILDREN_CAPACITY 8

/*
 * Node type names
 */
static const char *node_type_names[] = {
    [AST_NODE_ROOT] = "ROOT",
    [AST_NODE_MAGIC_DEF] = "MAGIC_DEF",
    [AST_NODE_MAGIC_TEST] = "MAGIC_TEST",
    [AST_NODE_OFFSET] = "OFFSET",
    [AST_NODE_TYPE] = "TYPE",
    [AST_NODE_VALUE] = "VALUE",
    [AST_NODE_MESSAGE] = "MESSAGE",
    [AST_NODE_MIME] = "MIME",
    [AST_NODE_EXTENSION] = "EXTENSION",
    [AST_NODE_STRENGTH] = "STRENGTH",
    [AST_NODE_PARSER] = "PARSER",
    [AST_NODE_FIELD] = "FIELD",
    [AST_NODE_STRUCT] = "STRUCT",
    [AST_NODE_ENUM] = "ENUM",
    [AST_NODE_UNION] = "UNION",
    [AST_NODE_ARRAY] = "ARRAY",
    [AST_NODE_SWITCH] = "SWITCH",
    [AST_NODE_CASE] = "CASE",
    [AST_NODE_REPEAT] = "REPEAT",
    [AST_NODE_IF] = "IF",
    [AST_NODE_EXPRESSION] = "EXPRESSION",
    [AST_NODE_LITERAL] = "LITERAL",
    [AST_NODE_IDENTIFIER] = "IDENTIFIER",
    [AST_NODE_BINARY_OP] = "BINARY_OP",
    [AST_NODE_UNARY_OP] = "UNARY_OP",
    [AST_NODE_CALL] = "CALL",
    [AST_NODE_MEMBER] = "MEMBER",
    [AST_NODE_INDEX] = "INDEX",
    [AST_NODE_TERNARY] = "TERNARY",
    [AST_NODE_COMMENT] = "COMMENT"
};

/*
 * Binary operator strings
 */
static const char *binary_op_strings[] = {
    [AST_OP_ADD] = "+",
    [AST_OP_SUB] = "-",
    [AST_OP_MUL] = "*",
    [AST_OP_DIV] = "/",
    [AST_OP_MOD] = "%",
    [AST_OP_AND] = "&&",
    [AST_OP_OR] = "||",
    [AST_OP_BAND] = "&",
    [AST_OP_BOR] = "|",
    [AST_OP_BXOR] = "^",
    [AST_OP_SHL] = "<<",
    [AST_OP_SHR] = ">>",
    [AST_OP_EQ] = "==",
    [AST_OP_NE] = "!=",
    [AST_OP_LT] = "<",
    [AST_OP_LE] = "<=",
    [AST_OP_GT] = ">",
    [AST_OP_GE] = ">="
};

/*
 * Unary operator strings
 */
static const char *unary_op_strings[] = {
    [AST_OP_NEG] = "-",
    [AST_OP_NOT] = "!",
    [AST_OP_BNOT] = "~",
    [AST_OP_DEREF] = "*",
    [AST_OP_ADDR] = "&"
};

/*
 * Allocate memory (from arena or malloc)
 */
static void *ast_alloc(AstContext *ctx, size_t size) {
    if (ctx && ctx->arena) {
        return arena_alloc(ctx->arena, size, 8);
    }
    return malloc(size);
}

/*
 * Duplicate string (from arena or strdup)
 */
static char *ast_strdup(AstContext *ctx, const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    if (ctx && ctx->arena) {
        char *dup = arena_alloc(ctx->arena, len + 1, 1);
        if (dup) {
            memcpy(dup, str, len + 1);
        }
        return dup;
    }
    return strdup(str);
}

/*
 * Create new context
 */
AstContext *ast_context_new(Arena *arena) {
    AstContext *ctx;
    
    if (arena) {
        ctx = arena_alloc(arena, sizeof(AstContext), _Alignof(AstContext));
    } else {
        ctx = malloc(sizeof(AstContext));
    }
    
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(AstContext));
    
    /* Create arena if not provided */
    if (!arena) {
        ctx->arena = malloc(sizeof(Arena));
        if (!ctx->arena) {
            free(ctx);
            return NULL;
        }
        arena_init(ctx->arena, 0);
    } else {
        ctx->arena = arena;
    }
    
    /* Initialize symbol table */
    sht_init(&ctx->symbols, 64, ctx->arena);
    
    /* Create root node */
    ctx->root = ast_node_new(ctx, AST_NODE_ROOT, NULL);
    ctx->current = ctx->root;
    
    return ctx;
}

/*
 * Free context
 */
void ast_context_free(AstContext *ctx) {
    if (!ctx) return;
    
    sht_free(&ctx->symbols);
    
    /* If we own the arena, free it */
    if (ctx->arena) {
        arena_free(ctx->arena);
        free(ctx->arena);
    }
    
    free(ctx);
}

/*
 * Set source file
 */
void ast_context_set_source(AstContext *ctx, const char *file) {
    if (ctx) {
        ctx->source_file = file;
    }
}

/*
 * Create new node
 */
AstNode *ast_node_new(AstContext *ctx, AstNodeType type, const AstLocation *loc) {
    AstNode *node = ast_alloc(ctx, sizeof(AstNode));
    if (!node) return NULL;
    
    memset(node, 0, sizeof(AstNode));
    node->type = type;
    
    if (loc) {
        node->location = *loc;
    } else if (ctx && ctx->source_file) {
        node->location.file = ctx->source_file;
    }
    
    /* Initialize attributes hash table */
    sht_init(&node->attributes, 8, ctx ? ctx->arena : NULL);
    
    return node;
}

/*
 * Create identifier node
 */
AstNode *ast_node_identifier(AstContext *ctx, const char *name, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_IDENTIFIER, loc);
    if (node && name) {
        node->data.ident.name = ast_strdup(ctx, name);
        node->data.ident.name_length = strlen(name);
    }
    return node;
}

/*
 * Create literal node
 */
AstNode *ast_node_literal(AstContext *ctx, const AstValue *value, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_LITERAL, loc);
    if (node && value) {
        node->data.value = *value;
        
        /* Deep copy string/bytes data */
        if (value->type == AST_VALUE_STRING && value->data.string.data) {
            node->data.value.data.string.data = ast_alloc(ctx, value->data.string.length + 1);
            if (node->data.value.data.string.data) {
                memcpy(node->data.value.data.string.data, 
                       value->data.string.data, value->data.string.length);
                node->data.value.data.string.data[value->data.string.length] = '\0';
            }
        } else if (value->type == AST_VALUE_BYTES && value->data.bytes.data) {
            node->data.value.data.bytes.data = ast_alloc(ctx, value->data.bytes.length);
            if (node->data.value.data.bytes.data) {
                memcpy(node->data.value.data.bytes.data,
                       value->data.bytes.data, value->data.bytes.length);
            }
        }
    }
    return node;
}

/*
 * Create string literal node
 */
AstNode *ast_node_string(AstContext *ctx, const char *str, size_t len, const AstLocation *loc) {
    AstValue value = {
        .type = AST_VALUE_STRING,
        .data.string = { .data = (char *)str, .length = len }
    };
    return ast_node_literal(ctx, &value, loc);
}

/*
 * Create integer literal node
 */
AstNode *ast_node_integer(AstContext *ctx, int64_t value, const AstLocation *loc) {
    AstValue val = {
        .type = AST_VALUE_INT,
        .data.int_val = value
    };
    return ast_node_literal(ctx, &val, loc);
}

/*
 * Create binary operation node
 */
AstNode *ast_node_binary_op(AstContext *ctx, AstBinaryOp op,
                            AstNode *left, AstNode *right, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_BINARY_OP, loc);
    if (node) {
        node->data.binary.op = op;
        if (left) ast_node_add_child(node, left);
        if (right) ast_node_add_child(node, right);
    }
    return node;
}

/*
 * Create unary operation node
 */
AstNode *ast_node_unary_op(AstContext *ctx, AstUnaryOp op,
                           AstNode *operand, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_UNARY_OP, loc);
    if (node) {
        node->data.unary.op = op;
        if (operand) ast_node_add_child(node, operand);
    }
    return node;
}

/*
 * Create magic test node
 */
AstNode *ast_node_magic_test(AstContext *ctx, int level, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_MAGIC_TEST, loc);
    if (node) {
        node->data.magic.level = level;
        node->data.magic.is_continuation = false;
    }
    return node;
}

/*
 * Create offset node
 */
AstNode *ast_node_offset(AstContext *ctx, OffsetType type,
                         int64_t value, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_OFFSET, loc);
    if (node) {
        node->data.offset.type = type;
        node->data.offset.value = value;
        node->data.offset.indirect = false;
        node->data.offset.num_bytes = 4;
        node->data.offset.endianness = ENDIAN_NATIVE;
    }
    return node;
}

/*
 * Create field node
 */
AstNode *ast_node_field(AstContext *ctx, const char *name,
                        const char *type, const AstLocation *loc) {
    AstNode *node = ast_node_new(ctx, AST_NODE_FIELD, loc);
    if (node) {
        node->data.field.name = ast_strdup(ctx, name);
        node->data.field.type_name = ast_strdup(ctx, type);
        node->data.field.optional = false;
        node->data.field.repeated = false;
    }
    return node;
}

/*
 * Add child to node
 */
bool ast_node_add_child(AstNode *parent, AstNode *child) {
    if (!parent || !child) return false;
    
    /* Grow array if needed */
    if (parent->num_children >= parent->children_capacity) {
        size_t new_capacity = parent->children_capacity == 0 ?
                              INITIAL_CHILDREN_CAPACITY :
                              parent->children_capacity * 2;
        AstNode **new_children = realloc(parent->children,
                                         new_capacity * sizeof(AstNode *));
        if (!new_children) return false;
        parent->children = new_children;
        parent->children_capacity = new_capacity;
    }
    
    parent->children[parent->num_children++] = child;
    child->parent = parent;
    return true;
}

/*
 * Insert child at index
 */
bool ast_node_insert_child(AstNode *parent, AstNode *child, size_t index) {
    if (!parent || !child || index > parent->num_children) return false;
    
    /* Ensure capacity */
    if (parent->num_children >= parent->children_capacity) {
        size_t new_capacity = parent->children_capacity == 0 ?
                              INITIAL_CHILDREN_CAPACITY :
                              parent->children_capacity * 2;
        AstNode **new_children = realloc(parent->children,
                                         new_capacity * sizeof(AstNode *));
        if (!new_children) return false;
        parent->children = new_children;
        parent->children_capacity = new_capacity;
    }
    
    /* Shift existing children */
    for (size_t i = parent->num_children; i > index; i--) {
        parent->children[i] = parent->children[i - 1];
    }
    
    parent->children[index] = child;
    parent->num_children++;
    child->parent = parent;
    return true;
}

/*
 * Remove child from node
 */
bool ast_node_remove_child(AstNode *parent, AstNode *child) {
    if (!parent || !child) return false;
    
    for (size_t i = 0; i < parent->num_children; i++) {
        if (parent->children[i] == child) {
            /* Shift remaining children */
            for (size_t j = i; j < parent->num_children - 1; j++) {
                parent->children[j] = parent->children[j + 1];
            }
            parent->num_children--;
            child->parent = NULL;
            return true;
        }
    }
    
    return false;
}

/*
 * Get child by index
 */
AstNode *ast_node_get_child(const AstNode *node, size_t index) {
    if (!node || index >= node->num_children) return NULL;
    return node->children[index];
}

/*
 * Find child by type
 */
AstNode *ast_node_find_child(const AstNode *node, AstNodeType type) {
    if (!node) return NULL;
    
    for (size_t i = 0; i < node->num_children; i++) {
        if (node->children[i]->type == type) {
            return node->children[i];
        }
    }
    
    return NULL;
}

/*
 * Set node attribute
 */
bool ast_node_set_attr(AstContext *ctx, AstNode *node,
                       const char *name, const char *value) {
    if (!node || !name || !value) return false;
    
    char *val_copy = ast_strdup(ctx, value);
    if (!val_copy) return false;
    
    return sht_insert(&node->attributes, ast_strdup(ctx, name), val_copy);
}

/*
 * Get node attribute
 */
const char *ast_node_get_attr(const AstNode *node, const char *name) {
    if (!node || !name) return NULL;
    return sht_lookup((StringHashTable *)&node->attributes, name);
}

/*
 * Visit nodes pre-order
 */
bool ast_node_visit_preorder(AstNode *node, AstVisitorFunc visitor, void *user_data) {
    if (!node || !visitor) return true;
    
    /* Visit current node first */
    if (!visitor(node, user_data)) return false;
    
    /* Then visit children */
    for (size_t i = 0; i < node->num_children; i++) {
        if (!ast_node_visit_preorder(node->children[i], visitor, user_data)) {
            return false;
        }
    }
    
    return true;
}

/*
 * Visit nodes post-order
 */
bool ast_node_visit_postorder(AstNode *node, AstVisitorFunc visitor, void *user_data) {
    if (!node || !visitor) return true;
    
    /* Visit children first */
    for (size_t i = 0; i < node->num_children; i++) {
        if (!ast_node_visit_postorder(node->children[i], visitor, user_data)) {
            return false;
        }
    }
    
    /* Then visit current node */
    return visitor(node, user_data);
}

/*
 * Visit nodes breadth-first
 */
bool ast_node_visit_bfs(AstNode *node, AstVisitorFunc visitor, void *user_data) {
    if (!node || !visitor) return true;
    
    /* Simple BFS using dynamic array as queue */
    size_t capacity = 64;
    size_t front = 0, back = 0;
    AstNode **queue = malloc(capacity * sizeof(AstNode *));
    if (!queue) return false;
    
    queue[back++] = node;
    
    while (front < back) {
        AstNode *current = queue[front++];
        
        if (!visitor(current, user_data)) {
            free(queue);
            return false;
        }
        
        /* Enqueue children */
        for (size_t i = 0; i < current->num_children; i++) {
            if (back >= capacity) {
                capacity *= 2;
                AstNode **new_queue = realloc(queue, capacity * sizeof(AstNode *));
                if (!new_queue) {
                    free(queue);
                    return false;
                }
                queue = new_queue;
            }
            queue[back++] = current->children[i];
        }
    }
    
    free(queue);
    return true;
}

/*
 * Get node type name
 */
const char *ast_node_type_name(AstNodeType type) {
    if ((size_t)type < sizeof(node_type_names) / sizeof(node_type_names[0])) {
        return node_type_names[type];
    }
    return "UNKNOWN";
}

/*
 * Get binary operator string
 */
const char *ast_binary_op_string(AstBinaryOp op) {
    if ((size_t)op < sizeof(binary_op_strings) / sizeof(binary_op_strings[0])) {
        return binary_op_strings[op];
    }
    return "?";
}

/*
 * Get unary operator string
 */
const char *ast_unary_op_string(AstUnaryOp op) {
    if ((size_t)op < sizeof(unary_op_strings) / sizeof(unary_op_strings[0])) {
        return unary_op_strings[op];
    }
    return "?";
}

/*
 * Count nodes in tree
 */
static bool count_visitor(AstNode *node, void *user_data) {
    (void)node;
    (*(size_t *)user_data)++;
    return true;
}

size_t ast_node_count(const AstNode *node) {
    size_t count = 0;
    ast_node_visit_preorder((AstNode *)node, count_visitor, &count);
    return count;
}

/*
 * Get tree depth
 */
static size_t depth_helper(const AstNode *node) {
    if (!node || node->num_children == 0) return 1;
    
    size_t max_depth = 0;
    for (size_t i = 0; i < node->num_children; i++) {
        size_t child_depth = depth_helper(node->children[i]);
        if (child_depth > max_depth) {
            max_depth = child_depth;
        }
    }
    
    return max_depth + 1;
}

size_t ast_node_depth(const AstNode *node) {
    return depth_helper(node);
}

/*
 * Clone node (shallow)
 */
AstNode *ast_node_clone(AstContext *ctx, const AstNode *node) {
    if (!node) return NULL;
    
    AstNode *clone = ast_node_new(ctx, node->type, &node->location);
    if (!clone) return NULL;
    
    /* Copy type-specific data */
    memcpy(&clone->data, &node->data, sizeof(node->data));
    
    return clone;
}

/*
 * Clone tree (deep)
 */
AstNode *ast_node_clone_tree(AstContext *ctx, const AstNode *node) {
    if (!node) return NULL;
    
    AstNode *clone = ast_node_clone(ctx, node);
    if (!clone) return NULL;
    
    /* Clone children recursively */
    for (size_t i = 0; i < node->num_children; i++) {
        AstNode *child_clone = ast_node_clone_tree(ctx, node->children[i]);
        if (!child_clone) return NULL;  /* Should free partial clone */
        ast_node_add_child(clone, child_clone);
    }
    
    return clone;
}

/*
 * Print AST tree
 */
void ast_node_print(const AstNode *node, int indent) {
    if (!node) return;
    
    /* Print indentation */
    for (int i = 0; i < indent; i++) {
        printf("  ");
    }
    
    /* Print node type */
    printf("%s", ast_node_type_name(node->type));
    
    /* Print type-specific info */
    switch (node->type) {
        case AST_NODE_IDENTIFIER:
            if (node->data.ident.name) {
                printf(" \"%s\"", node->data.ident.name);
            }
            break;
        case AST_NODE_LITERAL:
            switch (node->data.value.type) {
                case AST_VALUE_INT:
                    printf(" %ld", (long)node->data.value.data.int_val);
                    break;
                case AST_VALUE_STRING:
                    if (node->data.value.data.string.data) {
                        printf(" \"%s\"", node->data.value.data.string.data);
                    }
                    break;
                case AST_VALUE_BOOL:
                    printf(" %s", node->data.value.data.bool_val ? "true" : "false");
                    break;
                default:
                    break;
            }
            break;
        case AST_NODE_BINARY_OP:
            printf(" %s", ast_binary_op_string(node->data.binary.op));
            break;
        case AST_NODE_UNARY_OP:
            printf(" %s", ast_unary_op_string(node->data.unary.op));
            break;
        case AST_NODE_OFFSET:
            printf(" type=%d value=%ld", node->data.offset.type,
                   (long)node->data.offset.value);
            break;
        case AST_NODE_FIELD:
            if (node->data.field.name) {
                printf(" %s", node->data.field.name);
            }
            if (node->data.field.type_name) {
                printf(" : %s", node->data.field.type_name);
            }
            break;
        case AST_NODE_MAGIC_TEST:
            printf(" level=%d", node->data.magic.level);
            break;
        default:
            break;
    }
    
    /* Print location if available */
    if (node->location.line > 0) {
        printf(" [%d:%d]", node->location.line, node->location.column);
    }
    
    printf("\n");
    
    /* Print children */
    for (size_t i = 0; i < node->num_children; i++) {
        ast_node_print(node->children[i], indent + 1);
    }
}

/*
 * Define symbol
 */
bool ast_define_symbol(AstContext *ctx, const char *name, AstNode *node) {
    if (!ctx || !name) return false;
    return sht_insert(&ctx->symbols, ast_strdup(ctx, name), node);
}

/*
 * Look up symbol
 */
AstNode *ast_lookup_symbol(AstContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    return sht_lookup(&ctx->symbols, name);
}

/*
 * Check if symbol exists
 */
bool ast_has_symbol(AstContext *ctx, const char *name) {
    if (!ctx || !name) return false;
    return sht_contains(&ctx->symbols, name);
}
