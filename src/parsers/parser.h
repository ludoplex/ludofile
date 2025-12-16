/*
 * LudoFile - Parser Interface
 *
 * This header defines the interface for file format parsers.
 * Each parser module implements this interface to provide
 * semantic structure mapping for specific file formats.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_PARSERS_PARSER_H
#define LUDOFILE_PARSERS_PARSER_H

#include "../core/types.h"
#include "../magic/magic.h"

/*
 * Parser callback function type
 * Returns an iterator/generator over ParseMatch objects
 */
typedef struct ParseMatchIterator {
    void *state;
    ParseMatch* (*next)(struct ParseMatchIterator *iter);
    void (*free)(struct ParseMatchIterator *iter);
} ParseMatchIterator;

/*
 * Parser function signature
 */
typedef ParseMatchIterator* (*ParserFunc)(FileStream *stream, ParseMatch *parent);

/*
 * Parser registration entry
 */
typedef struct {
    const char *mime_type;
    ParserFunc  parser;
    const char *name;
    const char *description;
} ParserEntry;

/*
 * Parser registry
 */
typedef struct {
    ParserEntry *entries;
    size_t       count;
    size_t       capacity;
} ParserRegistry;

/*
 * Function prototypes
 */

/* Registry management */
ParserRegistry* parser_registry_new(void);
void parser_registry_free(ParserRegistry *registry);
LudofileResult parser_registry_register(ParserRegistry *registry, 
                                         const char *mime_type,
                                         ParserFunc parser,
                                         const char *name,
                                         const char *description);
ParserEntry* parser_registry_lookup(ParserRegistry *registry, const char *mime_type);

/* Get default registry with built-in parsers */
ParserRegistry* parser_registry_default(void);

/* Iterator operations */
ParseMatch* parse_match_iterator_next(ParseMatchIterator *iter);
void parse_match_iterator_free(ParseMatchIterator *iter);

/* Utility: create simple iterator from array */
ParseMatchIterator* parse_match_iterator_from_array(ParseMatch **matches, 
                                                     size_t count);

#endif /* LUDOFILE_PARSERS_PARSER_H */
