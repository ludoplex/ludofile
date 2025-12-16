/*
 * LudoFile - Hash Table Implementation
 *
 * Robin Hood hashing with SIMD-accelerated probing where available.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hashtable.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Check for SIMD support */
#if defined(__AVX2__)
#include <immintrin.h>
#define HT_USE_AVX2 1
#elif defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define HT_USE_NEON 1
#endif

/*
 * Helper: Next power of 2
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
 * Hash a 32-bit integer with good avalanche
 */
uint64_t hash_uint32(uint32_t key) {
    uint64_t x = key;
    x ^= x >> 17;
    x *= 0xed5ad4bbULL;
    x ^= x >> 11;
    x *= 0xac4c1b51ULL;
    x ^= x >> 15;
    x *= 0x31848babULL;
    x ^= x >> 14;
    return x;
}

/*
 * Hash a 64-bit integer
 */
uint64_t hash_uint64(uint64_t key) {
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return key;
}

/*
 * FNV-1a hash for strings
 */
uint32_t hash_string(const char *str) {
    if (!str) return 0;
    
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;        /* FNV prime */
    }
    return hash;
}

/*
 * FNV-1a hash for byte buffers
 */
uint32_t hash_bytes(const uint8_t *data, size_t len) {
    if (!data || len == 0) return 0;
    
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

/*
 * Initialize integer hash table
 */
bool ht_init(HashTable *ht, size_t initial_capacity, Arena *arena) {
    assert(ht != NULL);
    
    initial_capacity = (initial_capacity == 0) ? HT_DEFAULT_CAPACITY : 
                       next_pow2(initial_capacity * 2);  /* Load factor ~0.5 */
    
    if (arena) {
        ht->entries = arena_alloc(arena, initial_capacity * sizeof(HTEntry), 
                                  _Alignof(HTEntry));
        ht->owns_memory = false;
    } else {
        ht->entries = malloc(initial_capacity * sizeof(HTEntry));
        ht->owns_memory = true;
    }
    
    if (!ht->entries) return false;
    
    ht->capacity = initial_capacity;
    ht->mask = initial_capacity - 1;
    ht->count = 0;
    ht->tombstones = 0;
    ht->arena = arena;
    
    /* Initialize all slots as empty */
    for (size_t i = 0; i < initial_capacity; i++) {
        ht->entries[i].key = HT_EMPTY_KEY;
        ht->entries[i].value = NULL;
        ht->entries[i].probe_distance = 0;
    }
    
    return true;
}

/*
 * Free integer hash table
 */
void ht_free(HashTable *ht) {
    if (!ht) return;
    
    if (ht->owns_memory && ht->entries) {
        free(ht->entries);
    }
    
    ht->entries = NULL;
    ht->capacity = 0;
    ht->count = 0;
}

/*
 * Resize hash table (internal)
 */
static bool ht_resize(HashTable *ht, size_t new_capacity) {
    HTEntry *old_entries = ht->entries;
    size_t old_capacity = ht->capacity;
    
    /* Allocate new array */
    HTEntry *new_entries;
    if (ht->arena) {
        new_entries = arena_alloc(ht->arena, new_capacity * sizeof(HTEntry),
                                  _Alignof(HTEntry));
    } else {
        new_entries = malloc(new_capacity * sizeof(HTEntry));
    }
    
    if (!new_entries) return false;
    
    /* Initialize new array */
    for (size_t i = 0; i < new_capacity; i++) {
        new_entries[i].key = HT_EMPTY_KEY;
        new_entries[i].value = NULL;
        new_entries[i].probe_distance = 0;
    }
    
    ht->entries = new_entries;
    ht->capacity = new_capacity;
    ht->mask = new_capacity - 1;
    ht->count = 0;
    ht->tombstones = 0;
    
    /* Re-insert all entries */
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].key != HT_EMPTY_KEY && 
            old_entries[i].key != HT_DELETED_KEY) {
            ht_insert(ht, old_entries[i].key, old_entries[i].value);
        }
    }
    
    /* Free old array if we own it */
    if (ht->owns_memory && old_entries && !ht->arena) {
        free(old_entries);
    }
    
    return true;
}

/*
 * Insert with Robin Hood probing
 */
bool ht_insert(HashTable *ht, uint32_t key, void *value) {
    assert(ht != NULL);
    assert(key != HT_EMPTY_KEY && key != HT_DELETED_KEY);
    
    /* Check load factor and resize if needed */
    if ((ht->count + ht->tombstones) * 100 / ht->capacity > HT_MAX_LOAD_PERCENT) {
        if (!ht_resize(ht, ht->capacity * 2)) {
            return false;
        }
    }
    
    uint64_t hash = hash_uint32(key);
    size_t idx = (size_t)hash & ht->mask;
    uint8_t distance = 0;
    
    HTEntry entry = { .key = key, .value = value, .probe_distance = 0 };
    
    while (true) {
        HTEntry *slot = &ht->entries[idx];
        
        /* Empty or deleted slot - insert here */
        if (slot->key == HT_EMPTY_KEY || slot->key == HT_DELETED_KEY) {
            if (slot->key == HT_DELETED_KEY) {
                ht->tombstones--;
            }
            entry.probe_distance = distance;
            *slot = entry;
            ht->count++;
            return true;
        }
        
        /* Same key - update value */
        if (slot->key == key) {
            slot->value = value;
            return true;
        }
        
        /* Robin Hood: swap if this entry has traveled further */
        if (distance > slot->probe_distance) {
            entry.probe_distance = distance;
            HTEntry tmp = *slot;
            *slot = entry;
            entry = tmp;
            distance = entry.probe_distance;
        }
        
        idx = (idx + 1) & ht->mask;
        distance++;
    }
}

/*
 * Lookup with optional SIMD acceleration
 */
#if HT_USE_AVX2
static void *ht_lookup_avx2(HashTable *ht, uint32_t key) {
    uint64_t hash = hash_uint32(key);
    size_t idx = (size_t)hash & ht->mask;
    
    /* AVX2: Compare 8 keys at once */
    __m256i target = _mm256_set1_epi32((int32_t)key);
    __m256i empty = _mm256_set1_epi32((int32_t)HT_EMPTY_KEY);
    
    for (size_t probed = 0; probed < ht->capacity; probed += 8) {
        /* Load 8 entries (need to extract keys) */
        size_t check_idx = idx;
        uint32_t keys[8];
        
        for (int i = 0; i < 8 && check_idx + i < ht->capacity; i++) {
            keys[i] = ht->entries[(check_idx + i) & ht->mask].key;
        }
        
        __m256i loaded = _mm256_loadu_si256((const __m256i *)keys);
        __m256i cmp_eq = _mm256_cmpeq_epi32(loaded, target);
        __m256i cmp_empty = _mm256_cmpeq_epi32(loaded, empty);
        
        int mask_eq = _mm256_movemask_ps(_mm256_castsi256_ps(cmp_eq));
        int mask_empty = _mm256_movemask_ps(_mm256_castsi256_ps(cmp_empty));
        
        if (mask_eq) {
            int bit = __builtin_ctz(mask_eq);
            return ht->entries[(idx + bit) & ht->mask].value;
        }
        
        if (mask_empty) {
            return NULL;  /* Hit empty slot */
        }
        
        idx = (idx + 8) & ht->mask;
    }
    
    return NULL;
}
#endif

#if HT_USE_NEON
static void *ht_lookup_neon(HashTable *ht, uint32_t key) {
    uint64_t hash = hash_uint32(key);
    size_t idx = (size_t)hash & ht->mask;
    
    /* NEON: Compare 4 keys at once */
    uint32x4_t target = vdupq_n_u32(key);
    uint32x4_t empty = vdupq_n_u32(HT_EMPTY_KEY);
    
    for (size_t probed = 0; probed < ht->capacity; probed += 4) {
        uint32_t keys[4];
        for (int i = 0; i < 4; i++) {
            keys[i] = ht->entries[(idx + i) & ht->mask].key;
        }
        
        uint32x4_t loaded = vld1q_u32(keys);
        uint32x4_t cmp_eq = vceqq_u32(loaded, target);
        uint32x4_t cmp_empty = vceqq_u32(loaded, empty);
        
        /* Check results */
        uint32_t eq_bits = vgetq_lane_u32(cmp_eq, 0) | 
                          (vgetq_lane_u32(cmp_eq, 1) ? 2 : 0) |
                          (vgetq_lane_u32(cmp_eq, 2) ? 4 : 0) |
                          (vgetq_lane_u32(cmp_eq, 3) ? 8 : 0);
        
        if (eq_bits) {
            int bit = __builtin_ctz(eq_bits);
            return ht->entries[(idx + bit) & ht->mask].value;
        }
        
        uint32_t empty_bits = vgetq_lane_u32(cmp_empty, 0);
        if (empty_bits) {
            return NULL;
        }
        
        idx = (idx + 4) & ht->mask;
    }
    
    return NULL;
}
#endif

/*
 * Scalar lookup (branchless where possible)
 */
static void *ht_lookup_scalar(HashTable *ht, uint32_t key) {
    uint64_t hash = hash_uint32(key);
    size_t idx = (size_t)hash & ht->mask;
    
    for (size_t probed = 0; probed < ht->capacity; probed++) {
        HTEntry *slot = &ht->entries[idx];
        
        if (slot->key == HT_EMPTY_KEY) {
            return NULL;
        }
        
        if (slot->key == key) {
            return slot->value;
        }
        
        idx = (idx + 1) & ht->mask;
    }
    
    return NULL;
}

/*
 * Public lookup function
 */
void *ht_lookup(HashTable *ht, uint32_t key) {
    assert(ht != NULL);
    
    if (ht->count == 0) return NULL;
    
#if HT_USE_AVX2
    return ht_lookup_avx2(ht, key);
#elif HT_USE_NEON
    return ht_lookup_neon(ht, key);
#else
    return ht_lookup_scalar(ht, key);
#endif
}

/*
 * Remove entry
 */
bool ht_remove(HashTable *ht, uint32_t key) {
    assert(ht != NULL);
    
    uint64_t hash = hash_uint32(key);
    size_t idx = (size_t)hash & ht->mask;
    
    for (size_t probed = 0; probed < ht->capacity; probed++) {
        HTEntry *slot = &ht->entries[idx];
        
        if (slot->key == HT_EMPTY_KEY) {
            return false;
        }
        
        if (slot->key == key) {
            slot->key = HT_DELETED_KEY;
            slot->value = NULL;
            ht->count--;
            ht->tombstones++;
            return true;
        }
        
        idx = (idx + 1) & ht->mask;
    }
    
    return false;
}

/*
 * Check if key exists
 */
bool ht_contains(HashTable *ht, uint32_t key) {
    return ht_lookup(ht, key) != NULL;
}

/*
 * Get count
 */
size_t ht_count(const HashTable *ht) {
    return ht ? ht->count : 0;
}

/*
 * Clear all entries
 */
void ht_clear(HashTable *ht) {
    if (!ht) return;
    
    for (size_t i = 0; i < ht->capacity; i++) {
        ht->entries[i].key = HT_EMPTY_KEY;
        ht->entries[i].value = NULL;
        ht->entries[i].probe_distance = 0;
    }
    
    ht->count = 0;
    ht->tombstones = 0;
}

/*
 * String hash table implementation
 */

bool sht_init(StringHashTable *ht, size_t initial_capacity, Arena *arena) {
    assert(ht != NULL);
    
    initial_capacity = (initial_capacity == 0) ? HT_DEFAULT_CAPACITY :
                       next_pow2(initial_capacity * 2);
    
    if (arena) {
        ht->entries = arena_alloc(arena, initial_capacity * sizeof(HTStringEntry),
                                  _Alignof(HTStringEntry));
        ht->owns_memory = false;
    } else {
        ht->entries = malloc(initial_capacity * sizeof(HTStringEntry));
        ht->owns_memory = true;
    }
    
    if (!ht->entries) return false;
    
    ht->capacity = initial_capacity;
    ht->mask = initial_capacity - 1;
    ht->count = 0;
    ht->tombstones = 0;
    ht->arena = arena;
    
    for (size_t i = 0; i < initial_capacity; i++) {
        ht->entries[i].key = NULL;
        ht->entries[i].value = NULL;
        ht->entries[i].hash = 0;
        ht->entries[i].probe_distance = 0;
    }
    
    return true;
}

void sht_free(StringHashTable *ht) {
    if (!ht) return;
    
    if (ht->owns_memory && ht->entries) {
        free(ht->entries);
    }
    
    ht->entries = NULL;
    ht->capacity = 0;
    ht->count = 0;
}

static bool sht_resize(StringHashTable *ht, size_t new_capacity) {
    HTStringEntry *old_entries = ht->entries;
    size_t old_capacity = ht->capacity;
    
    HTStringEntry *new_entries;
    if (ht->arena) {
        new_entries = arena_alloc(ht->arena, new_capacity * sizeof(HTStringEntry),
                                  _Alignof(HTStringEntry));
    } else {
        new_entries = malloc(new_capacity * sizeof(HTStringEntry));
    }
    
    if (!new_entries) return false;
    
    for (size_t i = 0; i < new_capacity; i++) {
        new_entries[i].key = NULL;
        new_entries[i].value = NULL;
        new_entries[i].hash = 0;
        new_entries[i].probe_distance = 0;
    }
    
    ht->entries = new_entries;
    ht->capacity = new_capacity;
    ht->mask = new_capacity - 1;
    ht->count = 0;
    ht->tombstones = 0;
    
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].key != NULL) {
            sht_insert(ht, old_entries[i].key, old_entries[i].value);
        }
    }
    
    if (ht->owns_memory && old_entries && !ht->arena) {
        free(old_entries);
    }
    
    return true;
}

bool sht_insert(StringHashTable *ht, const char *key, void *value) {
    assert(ht != NULL);
    assert(key != NULL);
    
    if ((ht->count + ht->tombstones) * 100 / ht->capacity > HT_MAX_LOAD_PERCENT) {
        if (!sht_resize(ht, ht->capacity * 2)) {
            return false;
        }
    }
    
    uint32_t hash = hash_string(key);
    size_t idx = hash & ht->mask;
    uint8_t distance = 0;
    
    HTStringEntry entry = { 
        .key = key, 
        .value = value, 
        .hash = hash,
        .probe_distance = 0 
    };
    
    while (true) {
        HTStringEntry *slot = &ht->entries[idx];
        
        if (slot->key == NULL) {
            entry.probe_distance = distance;
            *slot = entry;
            ht->count++;
            return true;
        }
        
        if (slot->hash == hash && strcmp(slot->key, key) == 0) {
            slot->value = value;
            return true;
        }
        
        if (distance > slot->probe_distance) {
            entry.probe_distance = distance;
            HTStringEntry tmp = *slot;
            *slot = entry;
            entry = tmp;
            distance = entry.probe_distance;
        }
        
        idx = (idx + 1) & ht->mask;
        distance++;
    }
}

void *sht_lookup(StringHashTable *ht, const char *key) {
    assert(ht != NULL);
    
    if (!key || ht->count == 0) return NULL;
    
    uint32_t hash = hash_string(key);
    size_t idx = hash & ht->mask;
    
    for (size_t probed = 0; probed < ht->capacity; probed++) {
        HTStringEntry *slot = &ht->entries[idx];
        
        if (slot->key == NULL) {
            return NULL;
        }
        
        if (slot->hash == hash && strcmp(slot->key, key) == 0) {
            return slot->value;
        }
        
        idx = (idx + 1) & ht->mask;
    }
    
    return NULL;
}

bool sht_remove(StringHashTable *ht, const char *key) {
    assert(ht != NULL);
    
    if (!key) return false;
    
    uint32_t hash = hash_string(key);
    size_t idx = hash & ht->mask;
    
    for (size_t probed = 0; probed < ht->capacity; probed++) {
        HTStringEntry *slot = &ht->entries[idx];
        
        if (slot->key == NULL) {
            return false;
        }
        
        if (slot->hash == hash && strcmp(slot->key, key) == 0) {
            slot->key = NULL;
            slot->value = NULL;
            ht->count--;
            ht->tombstones++;
            return true;
        }
        
        idx = (idx + 1) & ht->mask;
    }
    
    return false;
}

bool sht_contains(StringHashTable *ht, const char *key) {
    return sht_lookup(ht, key) != NULL;
}

size_t sht_count(const StringHashTable *ht) {
    return ht ? ht->count : 0;
}

void sht_clear(StringHashTable *ht) {
    if (!ht) return;
    
    for (size_t i = 0; i < ht->capacity; i++) {
        ht->entries[i].key = NULL;
        ht->entries[i].value = NULL;
        ht->entries[i].hash = 0;
        ht->entries[i].probe_distance = 0;
    }
    
    ht->count = 0;
    ht->tombstones = 0;
}

/*
 * Iterator implementation
 */

void ht_iter_init(HTIterator *iter, HashTable *ht) {
    assert(iter != NULL);
    iter->table = ht;
    iter->index = 0;
    iter->is_string_table = false;
}

void sht_iter_init(HTIterator *iter, StringHashTable *ht) {
    assert(iter != NULL);
    iter->table = ht;
    iter->index = 0;
    iter->is_string_table = true;
}

bool ht_iter_next(HTIterator *iter, void *key, void **value) {
    if (!iter || !iter->table) return false;
    
    if (iter->is_string_table) {
        StringHashTable *ht = (StringHashTable *)iter->table;
        while (iter->index < ht->capacity) {
            HTStringEntry *entry = &ht->entries[iter->index++];
            if (entry->key != NULL) {
                if (key) *(const char **)key = entry->key;
                if (value) *value = entry->value;
                return true;
            }
        }
    } else {
        HashTable *ht = (HashTable *)iter->table;
        while (iter->index < ht->capacity) {
            HTEntry *entry = &ht->entries[iter->index++];
            if (entry->key != HT_EMPTY_KEY && entry->key != HT_DELETED_KEY) {
                if (key) *(uint32_t *)key = entry->key;
                if (value) *value = entry->value;
                return true;
            }
        }
    }
    
    return false;
}
