/*
 * LudoFile - Taint Tracking System Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "taint.h"
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
 * Allocate memory through DAG allocator
 */
static void *dag_alloc(TaintDAG *dag, size_t size) {
    return dag->alloc(dag->user_data, size);
}

/*
 * Free memory through DAG allocator
 */
static void dag_free(TaintDAG *dag, void *ptr) {
    dag->free(dag->user_data, ptr);
}

/*
 * Grow taint storage capacity
 */
static int storage_grow(TaintDAG *dag) {
    size_t new_capacity = dag->storage.capacity * 2;
    if (new_capacity < TAINT_INITIAL_CAPACITY) {
        new_capacity = TAINT_INITIAL_CAPACITY;
    }
    
    Taint *new_nodes = dag_alloc(dag, sizeof(Taint) * new_capacity);
    if (!new_nodes) {
        return -1;
    }
    
    if (dag->storage.nodes) {
        memcpy(new_nodes, dag->storage.nodes, 
               sizeof(Taint) * dag->storage.count);
        dag_free(dag, dag->storage.nodes);
    }
    
    dag->storage.nodes = new_nodes;
    dag->storage.capacity = new_capacity;
    return 0;
}

/*
 * Add a taint node to storage
 */
static taint_label_t storage_add(TaintDAG *dag, const Taint *taint) {
    if (dag->storage.count >= dag->storage.capacity) {
        if (storage_grow(dag) < 0) {
            return TAINT_LABEL_NONE;
        }
    }
    
    taint_label_t label = dag->next_label++;
    dag->storage.nodes[dag->storage.count] = *taint;
    dag->storage.count++;
    
    return label;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

TaintDAG *taint_dag_new(void) {
    TaintDAG *dag = malloc(sizeof(TaintDAG));
    if (!dag) {
        return NULL;
    }
    
    memset(dag, 0, sizeof(*dag));
    dag->alloc = default_alloc;
    dag->free = default_free;
    dag->next_label = 1;  /* 0 is reserved for TAINT_LABEL_NONE */
    
    return dag;
}

void taint_dag_free(TaintDAG *dag) {
    if (!dag) {
        return;
    }
    
    /* Free taint storage */
    if (dag->storage.nodes) {
        dag_free(dag, dag->storage.nodes);
    }
    
    /* Free sources */
    for (size_t i = 0; i < dag->num_sources; i++) {
        if (dag->sources[i].name) {
            dag_free(dag, (void *)dag->sources[i].name);
        }
        if (dag->sources[i].hash) {
            dag_free(dag, dag->sources[i].hash);
        }
    }
    if (dag->sources) {
        dag_free(dag, dag->sources);
    }
    
    free(dag);
}

void taint_dag_reset(TaintDAG *dag) {
    if (!dag) {
        return;
    }
    
    dag->storage.count = 0;
    dag->num_sources = 0;
    dag->next_label = 1;
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void taint_dag_set_allocator(TaintDAG *dag,
                              void *(*alloc)(void *, size_t),
                              void (*vfree)(void *, void *),
                              void *user_data) {
    if (!dag) {
        return;
    }
    
    dag->alloc = alloc ? alloc : default_alloc;
    dag->free = vfree ? vfree : default_free;
    dag->user_data = user_data;
}

/* ============================================================================
 * Source management
 * ============================================================================ */

uint32_t taint_dag_add_source(TaintDAG *dag, const char *name,
                               size_t size, const uint8_t *hash) {
    if (!dag) {
        return 0;
    }
    
    /* Grow sources array if needed */
    if (dag->num_sources >= dag->source_cap) {
        size_t new_cap = dag->source_cap * 2;
        if (new_cap < TAINT_MAX_SOURCES) {
            new_cap = TAINT_MAX_SOURCES;
        }
        
        TaintSource *new_sources = dag_alloc(dag, sizeof(TaintSource) * new_cap);
        if (!new_sources) {
            return 0;
        }
        
        if (dag->sources) {
            memcpy(new_sources, dag->sources,
                   sizeof(TaintSource) * dag->num_sources);
            dag_free(dag, dag->sources);
        }
        
        dag->sources = new_sources;
        dag->source_cap = new_cap;
    }
    
    /* Create new source */
    uint32_t source_id = (uint32_t)dag->num_sources;
    TaintSource *src = &dag->sources[source_id];
    
    src->source_id = source_id;
    src->size = size;
    
    /* Copy name */
    if (name) {
        size_t name_len = strlen(name) + 1;
        char *name_copy = dag_alloc(dag, name_len);
        if (name_copy) {
            memcpy(name_copy, name, name_len);
            src->name = name_copy;
        }
    }
    
    /* Copy hash */
    if (hash) {
        uint8_t *hash_copy = dag_alloc(dag, 32);
        if (hash_copy) {
            memcpy(hash_copy, hash, 32);
            src->hash = hash_copy;
        }
    }
    
    dag->num_sources++;
    return source_id;
}

TaintSource *taint_dag_get_source(TaintDAG *dag, uint32_t source_id) {
    if (!dag || source_id >= dag->num_sources) {
        return NULL;
    }
    return &dag->sources[source_id];
}

/* ============================================================================
 * Taint creation
 * ============================================================================ */

taint_label_t taint_dag_create_source_label(TaintDAG *dag,
                                             uint32_t source_id,
                                             uint64_t offset) {
    if (!dag) {
        return TAINT_LABEL_NONE;
    }
    
    Taint taint = {
        .type = TAINT_SOURCE,
        .affects_control_flow = false,
        .data.source = {
            .source_id = source_id,
            .offset = offset
        }
    };
    
    return storage_add(dag, &taint);
}

taint_label_t taint_dag_create_range_label(TaintDAG *dag,
                                            uint32_t source_id,
                                            uint64_t start,
                                            uint64_t end) {
    if (!dag) {
        return TAINT_LABEL_NONE;
    }
    
    Taint taint = {
        .type = TAINT_RANGE,
        .affects_control_flow = false,
        .data.range = {
            .source_id = source_id,
            .start = start,
            .end = end
        }
    };
    
    return storage_add(dag, &taint);
}

taint_label_t taint_dag_union(TaintDAG *dag,
                               taint_label_t left,
                               taint_label_t right) {
    if (!dag) {
        return TAINT_LABEL_NONE;
    }
    
    /* Handle trivial cases */
    if (left == TAINT_LABEL_NONE) return right;
    if (right == TAINT_LABEL_NONE) return left;
    if (left == right) return left;
    
    Taint taint = {
        .type = TAINT_UNION,
        .affects_control_flow = false,
        .data.tunion = {
            .left = left,
            .right = right
        }
    };
    
    return storage_add(dag, &taint);
}

/* ============================================================================
 * Taint operations
 * ============================================================================ */

Taint *taint_dag_get_taint(TaintDAG *dag, taint_label_t label) {
    if (!dag || label == TAINT_LABEL_NONE || label >= dag->next_label) {
        return NULL;
    }
    
    /* Labels are 1-indexed, storage is 0-indexed */
    size_t index = label - 1;
    if (index >= dag->storage.count) {
        return NULL;
    }
    
    return &dag->storage.nodes[index];
}

void taint_dag_set_affects_cf(TaintDAG *dag, taint_label_t label) {
    Taint *taint = taint_dag_get_taint(dag, label);
    if (taint) {
        taint->affects_control_flow = true;
    }
}

bool taint_dag_affects_control_flow(TaintDAG *dag, taint_label_t label) {
    Taint *taint = taint_dag_get_taint(dag, label);
    return taint ? taint->affects_control_flow : false;
}

/* ============================================================================
 * Taint queries
 * ============================================================================ */

size_t taint_dag_count(TaintDAG *dag) {
    return dag ? dag->storage.count : 0;
}

bool taint_dag_is_tainted(taint_label_t label) {
    return label != TAINT_LABEL_NONE;
}

/* ============================================================================
 * Serialization - PolyTracker .tdag format
 * ============================================================================ */

int taint_dag_save(TaintDAG *dag, const char *path) {
    if (!dag || !path) {
        return -1;
    }
    
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    
    /* Write header: magic + version */
    const char magic[] = "TDAG";
    fwrite(magic, 1, 4, fp);
    
    uint32_t version = 1;
    fwrite(&version, sizeof(uint32_t), 1, fp);
    
    /* Write sources */
    uint32_t num_sources = (uint32_t)dag->num_sources;
    fwrite(&num_sources, sizeof(uint32_t), 1, fp);
    
    for (size_t i = 0; i < dag->num_sources; i++) {
        TaintSource *src = &dag->sources[i];
        
        /* Write source ID and size */
        fwrite(&src->source_id, sizeof(uint32_t), 1, fp);
        fwrite(&src->size, sizeof(size_t), 1, fp);
        
        /* Write name */
        uint32_t name_len = src->name ? (uint32_t)strlen(src->name) : 0;
        fwrite(&name_len, sizeof(uint32_t), 1, fp);
        if (name_len > 0) {
            fwrite(src->name, 1, name_len, fp);
        }
        
        /* Write hash */
        if (src->hash) {
            fwrite(src->hash, 1, 32, fp);
        } else {
            uint8_t zero_hash[32] = {0};
            fwrite(zero_hash, 1, 32, fp);
        }
    }
    
    /* Write taints */
    uint32_t num_taints = (uint32_t)dag->storage.count;
    fwrite(&num_taints, sizeof(uint32_t), 1, fp);
    
    for (size_t i = 0; i < dag->storage.count; i++) {
        Taint *taint = &dag->storage.nodes[i];
        
        fwrite(&taint->type, sizeof(TaintType), 1, fp);
        fwrite(&taint->affects_control_flow, sizeof(bool), 1, fp);
        
        switch (taint->type) {
            case TAINT_SOURCE:
                fwrite(&taint->data.source, sizeof(SourceTaint), 1, fp);
                break;
            case TAINT_RANGE:
                fwrite(&taint->data.range, sizeof(RangeTaint), 1, fp);
                break;
            case TAINT_UNION:
                fwrite(&taint->data.tunion, sizeof(UnionTaint), 1, fp);
                break;
        }
    }
    
    fclose(fp);
    return 0;
}

TaintDAG *taint_dag_load(const char *path) {
    if (!path) {
        return NULL;
    }
    
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    
    /* Read and verify header */
    char magic[4];
    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, "TDAG", 4) != 0) {
        fclose(fp);
        return NULL;
    }
    
    uint32_t version;
    if (fread(&version, sizeof(uint32_t), 1, fp) != 1 || version != 1) {
        fclose(fp);
        return NULL;
    }
    
    /* Create DAG */
    TaintDAG *dag = taint_dag_new();
    if (!dag) {
        fclose(fp);
        return NULL;
    }
    
    /* Read sources */
    uint32_t num_sources;
    if (fread(&num_sources, sizeof(uint32_t), 1, fp) != 1) {
        taint_dag_free(dag);
        fclose(fp);
        return NULL;
    }
    
    for (uint32_t i = 0; i < num_sources; i++) {
        uint32_t source_id;
        size_t size;
        uint32_t name_len;
        uint8_t hash[32];
        
        fread(&source_id, sizeof(uint32_t), 1, fp);
        fread(&size, sizeof(size_t), 1, fp);
        fread(&name_len, sizeof(uint32_t), 1, fp);
        
        char *name = NULL;
        if (name_len > 0) {
            name = malloc(name_len + 1);
            if (name) {
                fread(name, 1, name_len, fp);
                name[name_len] = '\0';
            }
        }
        
        fread(hash, 1, 32, fp);
        
        taint_dag_add_source(dag, name, size, hash);
        
        if (name) {
            free(name);
        }
    }
    
    /* Read taints */
    uint32_t num_taints;
    if (fread(&num_taints, sizeof(uint32_t), 1, fp) != 1) {
        taint_dag_free(dag);
        fclose(fp);
        return NULL;
    }
    
    for (uint32_t i = 0; i < num_taints; i++) {
        Taint taint;
        
        fread(&taint.type, sizeof(TaintType), 1, fp);
        fread(&taint.affects_control_flow, sizeof(bool), 1, fp);
        
        switch (taint.type) {
            case TAINT_SOURCE:
                fread(&taint.data.source, sizeof(SourceTaint), 1, fp);
                break;
            case TAINT_RANGE:
                fread(&taint.data.range, sizeof(RangeTaint), 1, fp);
                break;
            case TAINT_UNION:
                fread(&taint.data.tunion, sizeof(UnionTaint), 1, fp);
                break;
        }
        
        storage_add(dag, &taint);
    }
    
    fclose(fp);
    return dag;
}

/* ============================================================================
 * Debug
 * ============================================================================ */

void taint_dag_print(TaintDAG *dag, taint_label_t label) {
    Taint *taint = taint_dag_get_taint(dag, label);
    if (!taint) {
        printf("Taint %u: <invalid>\n", label);
        return;
    }
    
    printf("Taint %u: ", label);
    
    switch (taint->type) {
        case TAINT_SOURCE:
            printf("SOURCE(source=%u, offset=%lu)",
                   taint->data.source.source_id,
                   (unsigned long)taint->data.source.offset);
            break;
        case TAINT_RANGE:
            printf("RANGE(source=%u, start=%lu, end=%lu)",
                   taint->data.range.source_id,
                   (unsigned long)taint->data.range.start,
                   (unsigned long)taint->data.range.end);
            break;
        case TAINT_UNION:
            printf("UNION(left=%u, right=%u)",
                   taint->data.tunion.left,
                   taint->data.tunion.right);
            break;
    }
    
    if (taint->affects_control_flow) {
        printf(" [affects_cf]");
    }
    
    printf("\n");
}

void taint_dag_dump(TaintDAG *dag) {
    if (!dag) {
        printf("TaintDAG: <null>\n");
        return;
    }
    
    printf("TaintDAG:\n");
    printf("  Sources: %zu\n", dag->num_sources);
    for (size_t i = 0; i < dag->num_sources; i++) {
        TaintSource *src = &dag->sources[i];
        printf("    [%u] %s (size=%zu)\n",
               src->source_id,
               src->name ? src->name : "<unnamed>",
               src->size);
    }
    
    printf("  Taints: %zu\n", dag->storage.count);
    for (size_t i = 0; i < dag->storage.count; i++) {
        printf("    ");
        taint_dag_print(dag, (taint_label_t)(i + 1));
    }
}
