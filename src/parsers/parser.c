/*
 * LudoFile - Parser Interface Implementation
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#include "parser.h"
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 16

/*
 * NOTE: The following parser functions are declared but not yet implemented.
 * They will be implemented in separate files when the full parser support
 * is added. The declarations are kept here for documentation purposes.
 *
 * extern ParseMatchIterator* pdf_parser(FileStream *stream, ParseMatch *parent);
 * extern ParseMatchIterator* zip_parser(FileStream *stream, ParseMatch *parent);
 */

/*
 * Create new parser registry
 */
ParserRegistry* parser_registry_new(void) {
    ParserRegistry *registry = malloc(sizeof(ParserRegistry));
    if (!registry) return NULL;
    
    registry->entries = malloc(INITIAL_CAPACITY * sizeof(ParserEntry));
    if (!registry->entries) {
        free(registry);
        return NULL;
    }
    
    registry->count = 0;
    registry->capacity = INITIAL_CAPACITY;
    
    return registry;
}

/*
 * Free parser registry
 */
void parser_registry_free(ParserRegistry *registry) {
    if (registry) {
        free(registry->entries);
        free(registry);
    }
}

/*
 * Register a parser
 */
LudofileResult parser_registry_register(ParserRegistry *registry,
                                         const char *mime_type,
                                         ParserFunc parser,
                                         const char *name,
                                         const char *description) {
    if (!registry || !mime_type || !parser) {
        return LUDOFILE_ERROR_INVALID;
    }
    
    if (registry->count >= registry->capacity) {
        size_t new_capacity = registry->capacity * 2;
        ParserEntry *new_entries = realloc(registry->entries, 
                                           new_capacity * sizeof(ParserEntry));
        if (!new_entries) return LUDOFILE_ERROR_MEMORY;
        registry->entries = new_entries;
        registry->capacity = new_capacity;
    }
    
    ParserEntry *entry = &registry->entries[registry->count++];
    entry->mime_type = mime_type;
    entry->parser = parser;
    entry->name = name;
    entry->description = description;
    
    return LUDOFILE_OK;
}

/*
 * Look up parser by MIME type
 */
ParserEntry* parser_registry_lookup(ParserRegistry *registry, const char *mime_type) {
    if (!registry || !mime_type) return NULL;
    
    for (size_t i = 0; i < registry->count; i++) {
        if (strcmp(registry->entries[i].mime_type, mime_type) == 0) {
            return &registry->entries[i];
        }
    }
    
    return NULL;
}

/*
 * Get default registry with built-in parsers
 */
static ParserRegistry *default_registry = NULL;

ParserRegistry* parser_registry_default(void) {
    if (default_registry) return default_registry;
    
    default_registry = parser_registry_new();
    if (!default_registry) return NULL;
    
    /* Register built-in parsers */
    /* Note: These are placeholders - actual parsers to be implemented */
    
    /*
    parser_registry_register(default_registry, "application/pdf",
                             pdf_parser, "PDF Parser",
                             "Parses PDF document structure");
    
    parser_registry_register(default_registry, "application/zip",
                             zip_parser, "ZIP Parser",
                             "Parses ZIP archive structure");
    
    parser_registry_register(default_registry, "application/java-archive",
                             zip_parser, "JAR Parser",
                             "Parses Java archive structure (ZIP-based)");
    */
    
    return default_registry;
}

/*
 * Iterator next operation
 */
ParseMatch* parse_match_iterator_next(ParseMatchIterator *iter) {
    if (!iter || !iter->next) return NULL;
    return iter->next(iter);
}

/*
 * Free iterator
 */
void parse_match_iterator_free(ParseMatchIterator *iter) {
    if (iter && iter->free) {
        iter->free(iter);
    }
}

/*
 * Array iterator state
 */
typedef struct {
    ParseMatch **matches;
    size_t count;
    size_t current;
} ArrayIteratorState;

static ParseMatch* array_iterator_next(ParseMatchIterator *iter) {
    ArrayIteratorState *state = (ArrayIteratorState*)iter->state;
    if (state->current >= state->count) return NULL;
    return state->matches[state->current++];
}

static void array_iterator_free(ParseMatchIterator *iter) {
    free(iter->state);
    free(iter);
}

/*
 * Create iterator from array
 */
ParseMatchIterator* parse_match_iterator_from_array(ParseMatch **matches,
                                                     size_t count) {
    ParseMatchIterator *iter = malloc(sizeof(ParseMatchIterator));
    if (!iter) return NULL;
    
    ArrayIteratorState *state = malloc(sizeof(ArrayIteratorState));
    if (!state) {
        free(iter);
        return NULL;
    }
    
    state->matches = matches;
    state->count = count;
    state->current = 0;
    
    iter->state = state;
    iter->next = array_iterator_next;
    iter->free = array_iterator_free;
    
    return iter;
}
