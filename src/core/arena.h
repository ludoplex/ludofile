/*
 * LudoFile - Arena Allocator
 *
 * A bump allocator with dynamic extension for efficient memory management.
 * All allocations are aligned and allocation is O(1) in the common case.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_CORE_ARENA_H
#define LUDOFILE_CORE_ARENA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Arena chunk - a block of memory within the arena
 */
typedef struct ArenaChunk {
    uint8_t *base;              /* Base address of chunk data */
    size_t size;                /* Total size of chunk */
    size_t used;                /* Bytes used in chunk */
    struct ArenaChunk *next;    /* Next chunk in chain */
} ArenaChunk;

/*
 * Arena allocator - manages a chain of memory chunks
 */
typedef struct {
    ArenaChunk *current;        /* Current active chunk */
    size_t default_chunk_size;  /* Default size for new chunks (e.g., 64KB) */
    size_t total_allocated;     /* Total bytes allocated across all chunks */
    size_t total_used;          /* Total bytes used */
} Arena;

/*
 * Default chunk size (64KB, page-aligned friendly)
 */
#define ARENA_DEFAULT_CHUNK_SIZE (64 * 1024)

/*
 * Page size for alignment (4KB typical)
 */
#define ARENA_PAGE_SIZE 4096

/*
 * Initialize an arena with specified default chunk size.
 * 
 * @param arena         Arena to initialize
 * @param default_size  Default chunk size (0 uses ARENA_DEFAULT_CHUNK_SIZE)
 */
void arena_init(Arena *arena, size_t default_size);

/*
 * Allocate memory from the arena.
 * 
 * @param arena  Arena to allocate from
 * @param size   Size in bytes to allocate (must be > 0)
 * @param align  Alignment requirement (must be power of 2)
 * @return       Pointer to allocated memory, or NULL on failure
 */
void *arena_alloc(Arena *arena, size_t size, size_t align);

/*
 * Allocate zeroed memory from the arena.
 * 
 * @param arena  Arena to allocate from
 * @param size   Size in bytes to allocate
 * @param align  Alignment requirement (must be power of 2)
 * @return       Pointer to zeroed memory, or NULL on failure
 */
void *arena_calloc(Arena *arena, size_t size, size_t align);

/*
 * Allocate memory for an array from the arena.
 * 
 * @param arena  Arena to allocate from
 * @param count  Number of elements
 * @param size   Size of each element
 * @param align  Alignment requirement
 * @return       Pointer to allocated memory, or NULL on failure
 */
void *arena_alloc_array(Arena *arena, size_t count, size_t size, size_t align);

/*
 * Duplicate a string into the arena.
 * 
 * @param arena  Arena to allocate from
 * @param str    String to duplicate
 * @return       Pointer to duplicated string, or NULL on failure
 */
char *arena_strdup(Arena *arena, const char *str);

/*
 * Duplicate a string with maximum length into the arena.
 * 
 * @param arena  Arena to allocate from
 * @param str    String to duplicate
 * @param maxlen Maximum length to copy
 * @return       Pointer to duplicated string, or NULL on failure
 */
char *arena_strndup(Arena *arena, const char *str, size_t maxlen);

/*
 * Reset the arena for reuse (keeps allocated chunks).
 * All previous allocations become invalid.
 * 
 * @param arena  Arena to reset
 */
void arena_reset(Arena *arena);

/*
 * Free all memory associated with the arena.
 * 
 * @param arena  Arena to free
 */
void arena_free(Arena *arena);

/*
 * Get arena statistics.
 * 
 * @param arena           Arena to query
 * @param total_allocated Output: total bytes allocated
 * @param total_used      Output: total bytes used
 * @param num_chunks      Output: number of chunks
 */
void arena_stats(const Arena *arena, size_t *total_allocated, 
                 size_t *total_used, size_t *num_chunks);

/*
 * Check if an arena is valid (initialized and usable).
 * 
 * @param arena  Arena to check
 * @return       true if valid, false otherwise
 */
bool arena_is_valid(const Arena *arena);

/*
 * Convenience macro for type-safe allocation
 */
#define ARENA_ALLOC(arena, type) \
    ((type *)arena_alloc((arena), sizeof(type), _Alignof(type)))

#define ARENA_ALLOC_ARRAY(arena, type, count) \
    ((type *)arena_alloc_array((arena), (count), sizeof(type), _Alignof(type)))

#endif /* LUDOFILE_CORE_ARENA_H */
