/*
 * LudoFile - Arena Allocator Implementation
 *
 * A bump allocator with dynamic extension for efficient memory management.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#include "arena.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * Helper: Round up to next power of 2
 */
static size_t next_pow2(size_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFF
    n |= n >> 32;
#endif
    return n + 1;
}

/*
 * Helper: Round up to page alignment
 */
static size_t page_align(size_t size) {
    return (size + ARENA_PAGE_SIZE - 1) & ~(ARENA_PAGE_SIZE - 1);
}

/*
 * Helper: Create a new chunk
 */
static ArenaChunk *chunk_new(size_t size) {
    size = page_align(size);
    
    /* Allocate chunk header + data together for cache locality */
    ArenaChunk *chunk = malloc(sizeof(ArenaChunk) + size);
    if (!chunk) return NULL;
    
    chunk->base = (uint8_t *)(chunk + 1);
    chunk->size = size;
    chunk->used = 0;
    chunk->next = NULL;
    
    return chunk;
}

/*
 * Initialize arena
 */
void arena_init(Arena *arena, size_t default_size) {
    assert(arena != NULL);
    
    arena->current = NULL;
    arena->default_chunk_size = (default_size == 0) ? 
                                 ARENA_DEFAULT_CHUNK_SIZE : 
                                 page_align(default_size);
    arena->total_allocated = 0;
    arena->total_used = 0;
}

/*
 * Allocate from arena
 */
void *arena_alloc(Arena *arena, size_t size, size_t align) {
    assert(arena != NULL);
    assert(size > 0);
    assert(align > 0 && (align & (align - 1)) == 0);  /* Power of 2 */
    
    ArenaChunk *chunk = arena->current;
    uintptr_t ptr = 0;
    size_t aligned_offset = 0;
    
    if (chunk) {
        /* Calculate aligned position in current chunk */
        ptr = (uintptr_t)(chunk->base + chunk->used);
        ptr = (ptr + align - 1) & ~(align - 1);
        aligned_offset = (size_t)(ptr - (uintptr_t)chunk->base);
    }
    
    /* Check if current chunk has space */
    if (!chunk || aligned_offset + size > chunk->size) {
        /* Need a new chunk */
        size_t chunk_size = size > arena->default_chunk_size ? 
                           next_pow2(size + sizeof(ArenaChunk)) : 
                           arena->default_chunk_size;
        
        ArenaChunk *new_chunk = chunk_new(chunk_size);
        if (!new_chunk) return NULL;
        
        new_chunk->next = arena->current;
        arena->current = new_chunk;
        arena->total_allocated += new_chunk->size;
        
        chunk = new_chunk;
        ptr = (uintptr_t)chunk->base;
        ptr = (ptr + align - 1) & ~(align - 1);
        aligned_offset = (size_t)(ptr - (uintptr_t)chunk->base);
    }
    
    chunk->used = aligned_offset + size;
    arena->total_used += size;
    
    return (void *)ptr;
}

/*
 * Allocate zeroed memory
 */
void *arena_calloc(Arena *arena, size_t size, size_t align) {
    void *ptr = arena_alloc(arena, size, align);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Allocate array
 */
void *arena_alloc_array(Arena *arena, size_t count, size_t size, size_t align) {
    /* Check for overflow */
    if (count > 0 && size > SIZE_MAX / count) {
        return NULL;
    }
    return arena_alloc(arena, count * size, align);
}

/*
 * Duplicate string
 */
char *arena_strdup(Arena *arena, const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str) + 1;
    char *dup = arena_alloc(arena, len, 1);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

/*
 * Duplicate string with max length
 */
char *arena_strndup(Arena *arena, const char *str, size_t maxlen) {
    if (!str) return NULL;
    
    size_t len = 0;
    while (len < maxlen && str[len]) {
        len++;
    }
    
    char *dup = arena_alloc(arena, len + 1, 1);
    if (dup) {
        memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}

/*
 * Reset arena (keeps chunks for reuse)
 */
void arena_reset(Arena *arena) {
    assert(arena != NULL);
    
    ArenaChunk *chunk = arena->current;
    while (chunk) {
        chunk->used = 0;
        chunk = chunk->next;
    }
    arena->total_used = 0;
}

/*
 * Free arena
 */
void arena_free(Arena *arena) {
    if (!arena) return;
    
    ArenaChunk *chunk = arena->current;
    while (chunk) {
        ArenaChunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    
    arena->current = NULL;
    arena->total_allocated = 0;
    arena->total_used = 0;
}

/*
 * Get arena statistics
 */
void arena_stats(const Arena *arena, size_t *total_allocated, 
                 size_t *total_used, size_t *num_chunks) {
    if (!arena) return;
    
    if (total_allocated) *total_allocated = arena->total_allocated;
    if (total_used) *total_used = arena->total_used;
    
    if (num_chunks) {
        size_t count = 0;
        ArenaChunk *chunk = arena->current;
        while (chunk) {
            count++;
            chunk = chunk->next;
        }
        *num_chunks = count;
    }
}

/*
 * Check if arena is valid
 */
bool arena_is_valid(const Arena *arena) {
    return arena != NULL && arena->default_chunk_size > 0;
}
