/*
 * LudoFile - Taint Tracking System
 *
 * PolyTracker-compatible taint DAG implementation in pure C.
 * Tracks data flow and control flow dependencies for binary parsing.
 *
 * Design principles:
 * - Pure POSIX C, no external dependencies
 * - Thread-safe taint label generation
 * - Memory-efficient storage with arena allocation
 * - Compatible with PolyTracker .tdag format
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_TAINT_H
#define LUDOFILE_TAINT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define TAINT_INITIAL_CAPACITY  1024    /* Initial taint storage capacity */
#define TAINT_MAX_SOURCES       256     /* Max input sources */

/* ============================================================================
 * Type definitions
 * ============================================================================ */

/*
 * Taint label - unique identifier for a taint
 */
typedef uint32_t taint_label_t;

#define TAINT_LABEL_NONE  0             /* No taint */

/*
 * Taint type - classification of taint origin
 */
typedef enum {
    TAINT_SOURCE = 0,  /* Direct input byte */
    TAINT_RANGE  = 1,  /* Range of input bytes */
    TAINT_UNION  = 2   /* Union of multiple taints */
} TaintType;

/*
 * Taint source - identifies an input source (file, stream, etc.)
 */
typedef struct {
    uint32_t    source_id;    /* Unique source identifier */
    const char *name;          /* Source name (filename, etc.) */
    size_t      size;          /* Source size in bytes */
    uint8_t    *hash;          /* SHA256 hash (32 bytes) */
} TaintSource;

/*
 * Source taint - single input byte
 */
typedef struct {
    uint32_t source_id;       /* Source identifier */
    uint64_t offset;          /* Byte offset in source */
} SourceTaint;

/*
 * Range taint - contiguous byte range
 */
typedef struct {
    uint32_t source_id;       /* Source identifier */
    uint64_t start;           /* Start offset (inclusive) */
    uint64_t end;             /* End offset (exclusive) */
} RangeTaint;

/*
 * Union taint - combination of multiple taints
 */
typedef struct {
    taint_label_t left;       /* Left operand */
    taint_label_t right;      /* Right operand */
} UnionTaint;

/*
 * Taint node - entry in the taint DAG
 */
typedef struct {
    TaintType type;
    bool affects_control_flow;  /* Influences control flow decisions */
    union {
        SourceTaint source;
        RangeTaint  range;
        UnionTaint  tunion;
    } data;
} Taint;

/* ============================================================================
 * Taint DAG - Directed Acyclic Graph of taints
 * ============================================================================ */

/*
 * Taint storage - dynamic array of taint nodes
 */
typedef struct {
    Taint  *nodes;          /* Taint node array */
    size_t  count;          /* Number of nodes */
    size_t  capacity;       /* Allocated capacity */
} TaintStorage;

/*
 * Taint DAG - main data structure
 */
typedef struct TaintDAG {
    TaintStorage    storage;      /* Taint node storage */
    TaintSource    *sources;      /* Input sources */
    size_t          num_sources;  /* Number of sources */
    size_t          source_cap;   /* Source capacity */
    taint_label_t   next_label;   /* Next available label (atomic) */
    
    /* Memory management */
    void           *user_data;
    void *(*alloc)(void *ctx, size_t size);
    void  (*free)(void *ctx, void *ptr);
} TaintDAG;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/*
 * Lifecycle
 */
TaintDAG *taint_dag_new(void);
void taint_dag_free(TaintDAG *dag);
void taint_dag_reset(TaintDAG *dag);

/*
 * Configuration
 */
void taint_dag_set_allocator(TaintDAG *dag,
                              void *(*alloc)(void *, size_t),
                              void (*free)(void *, void *),
                              void *user_data);

/*
 * Source management
 */
uint32_t taint_dag_add_source(TaintDAG *dag, const char *name, 
                               size_t size, const uint8_t *hash);
TaintSource *taint_dag_get_source(TaintDAG *dag, uint32_t source_id);

/*
 * Taint creation
 */
taint_label_t taint_dag_create_source_label(TaintDAG *dag, 
                                             uint32_t source_id,
                                             uint64_t offset);
taint_label_t taint_dag_create_range_label(TaintDAG *dag,
                                            uint32_t source_id,
                                            uint64_t start,
                                            uint64_t end);
taint_label_t taint_dag_union(TaintDAG *dag, 
                               taint_label_t left,
                               taint_label_t right);

/*
 * Taint operations
 */
Taint *taint_dag_get_taint(TaintDAG *dag, taint_label_t label);
void taint_dag_set_affects_cf(TaintDAG *dag, taint_label_t label);
bool taint_dag_affects_control_flow(TaintDAG *dag, taint_label_t label);

/*
 * Taint queries
 */
size_t taint_dag_count(TaintDAG *dag);
bool taint_dag_is_tainted(taint_label_t label);

/*
 * Serialization - PolyTracker .tdag format
 */
int taint_dag_save(TaintDAG *dag, const char *path);
TaintDAG *taint_dag_load(const char *path);

/*
 * Debug
 */
void taint_dag_print(TaintDAG *dag, taint_label_t label);
void taint_dag_dump(TaintDAG *dag);

#endif /* LUDOFILE_TAINT_H */
