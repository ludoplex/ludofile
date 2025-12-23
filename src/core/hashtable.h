/*
 * LudoFile - Hash Table
 *
 * A low-latency hash table with Robin Hood probing and optional SIMD
 * acceleration for fast lookups.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_CORE_HASHTABLE_H
#define LUDOFILE_CORE_HASHTABLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "arena.h"

/*
 * Sentinel value for empty slots
 */
#define HT_EMPTY_KEY UINT32_MAX
#define HT_DELETED_KEY (UINT32_MAX - 1)

/*
 * Hash table entry for integer keys
 */
typedef struct {
    uint32_t key;           /* Key (HT_EMPTY_KEY = empty slot) */
    void *value;            /* Value pointer */
    uint8_t probe_distance; /* Distance from ideal slot (Robin Hood) */
} HTEntry;

/*
 * Hash table entry for string keys
 */
typedef struct {
    const char *key;        /* Key string (NULL = empty slot) */
    void *value;            /* Value pointer */
    uint32_t hash;          /* Cached hash value */
    uint8_t probe_distance; /* Distance from ideal slot */
} HTStringEntry;

/*
 * Integer-keyed hash table
 */
typedef struct {
    HTEntry *entries;       /* Entry array */
    size_t capacity;        /* Total slots */
    size_t mask;            /* capacity - 1 (for fast modulo) */
    size_t count;           /* Number of entries */
    size_t tombstones;      /* Number of deleted entries */
    Arena *arena;           /* Optional arena for allocation */
    bool owns_memory;       /* True if we should free entries */
} HashTable;

/*
 * String-keyed hash table
 */
typedef struct {
    HTStringEntry *entries; /* Entry array */
    size_t capacity;        /* Total slots */
    size_t mask;            /* capacity - 1 */
    size_t count;           /* Number of entries */
    size_t tombstones;      /* Number of deleted entries */
    Arena *arena;           /* Optional arena */
    bool owns_memory;       /* True if we should free entries */
} StringHashTable;

/*
 * Hash table iterator
 */
typedef struct {
    void *table;            /* HashTable or StringHashTable */
    size_t index;           /* Current index */
    bool is_string_table;   /* Type flag */
} HTIterator;

/*
 * Default initial capacity
 */
#define HT_DEFAULT_CAPACITY 256

/*
 * Maximum load factor (percent)
 */
#define HT_MAX_LOAD_PERCENT 70

/*
 * Integer hash table operations
 */

/*
 * Initialize a hash table.
 * 
 * @param ht              Hash table to initialize
 * @param initial_capacity Initial capacity (0 uses default)
 * @param arena           Optional arena for allocation (NULL uses malloc)
 * @return                true on success, false on failure
 */
bool ht_init(HashTable *ht, size_t initial_capacity, Arena *arena);

/*
 * Free hash table resources.
 * 
 * @param ht  Hash table to free
 */
void ht_free(HashTable *ht);

/*
 * Insert or update a key-value pair.
 * 
 * @param ht     Hash table
 * @param key    Key (cannot be HT_EMPTY_KEY or HT_DELETED_KEY)
 * @param value  Value to store
 * @return       true on success, false on failure
 */
bool ht_insert(HashTable *ht, uint32_t key, void *value);

/*
 * Look up a value by key.
 * 
 * @param ht   Hash table
 * @param key  Key to look up
 * @return     Value pointer, or NULL if not found
 */
void *ht_lookup(HashTable *ht, uint32_t key);

/*
 * Remove an entry by key.
 * 
 * @param ht   Hash table
 * @param key  Key to remove
 * @return     true if removed, false if not found
 */
bool ht_remove(HashTable *ht, uint32_t key);

/*
 * Check if key exists.
 * 
 * @param ht   Hash table
 * @param key  Key to check
 * @return     true if key exists
 */
bool ht_contains(HashTable *ht, uint32_t key);

/*
 * Get number of entries.
 * 
 * @param ht  Hash table
 * @return    Number of entries
 */
size_t ht_count(const HashTable *ht);

/*
 * Clear all entries (keeps capacity).
 * 
 * @param ht  Hash table
 */
void ht_clear(HashTable *ht);

/*
 * String hash table operations
 */

/*
 * Initialize a string hash table.
 * 
 * @param ht              Hash table to initialize
 * @param initial_capacity Initial capacity (0 uses default)
 * @param arena           Optional arena for allocation
 * @return                true on success, false on failure
 */
bool sht_init(StringHashTable *ht, size_t initial_capacity, Arena *arena);

/*
 * Free string hash table resources.
 * 
 * @param ht  Hash table to free
 */
void sht_free(StringHashTable *ht);

/*
 * Insert or update a string key-value pair.
 * 
 * @param ht     Hash table
 * @param key    Key string (must remain valid)
 * @param value  Value to store
 * @return       true on success, false on failure
 */
bool sht_insert(StringHashTable *ht, const char *key, void *value);

/*
 * Look up a value by string key.
 * 
 * @param ht   Hash table
 * @param key  Key string to look up
 * @return     Value pointer, or NULL if not found
 */
void *sht_lookup(StringHashTable *ht, const char *key);

/*
 * Remove an entry by string key.
 * 
 * @param ht   Hash table
 * @param key  Key to remove
 * @return     true if removed, false if not found
 */
bool sht_remove(StringHashTable *ht, const char *key);

/*
 * Check if string key exists.
 * 
 * @param ht   Hash table
 * @param key  Key to check
 * @return     true if key exists
 */
bool sht_contains(StringHashTable *ht, const char *key);

/*
 * Get number of entries in string hash table.
 * 
 * @param ht  Hash table
 * @return    Number of entries
 */
size_t sht_count(const StringHashTable *ht);

/*
 * Clear all entries in string hash table.
 * 
 * @param ht  Hash table
 */
void sht_clear(StringHashTable *ht);

/*
 * Hash functions
 */

/*
 * Hash a 32-bit integer (good avalanche properties).
 * 
 * @param key  Key to hash
 * @return     Hash value
 */
uint64_t hash_uint32(uint32_t key);

/*
 * Hash a 64-bit integer.
 * 
 * @param key  Key to hash
 * @return     Hash value
 */
uint64_t hash_uint64(uint64_t key);

/*
 * Hash a string (FNV-1a).
 * 
 * @param str  String to hash
 * @return     Hash value
 */
uint32_t hash_string(const char *str);

/*
 * Hash a byte buffer.
 * 
 * @param data  Data to hash
 * @param len   Length in bytes
 * @return      Hash value
 */
uint32_t hash_bytes(const uint8_t *data, size_t len);

/*
 * Iterator operations
 */

/*
 * Initialize iterator for hash table.
 * 
 * @param iter  Iterator to initialize
 * @param ht    Hash table to iterate
 */
void ht_iter_init(HTIterator *iter, HashTable *ht);

/*
 * Initialize iterator for string hash table.
 * 
 * @param iter  Iterator to initialize
 * @param ht    String hash table to iterate
 */
void sht_iter_init(HTIterator *iter, StringHashTable *ht);

/*
 * Get next entry from iterator.
 * 
 * @param iter   Iterator
 * @param key    Output: key (cast appropriately for table type)
 * @param value  Output: value pointer
 * @return       true if entry found, false if iteration complete
 */
bool ht_iter_next(HTIterator *iter, void *key, void **value);

#endif /* LUDOFILE_CORE_HASHTABLE_H */
