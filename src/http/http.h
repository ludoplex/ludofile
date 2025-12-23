/*
 * LudoFile - HTTP Protocol Module
 *
 * HTTP/1.1 request/response parsing and header handling.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LUDOFILE_HTTP_HTTP_H
#define LUDOFILE_HTTP_HTTP_H

#include "../core/types.h"
#include "../core/arena.h"
#include "../core/hashtable.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * HTTP method enumeration
 */
typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_PATCH
} HttpMethod;

/*
 * HTTP version
 */
typedef enum {
    HTTP_VERSION_UNKNOWN = 0,
    HTTP_VERSION_0_9,
    HTTP_VERSION_1_0,
    HTTP_VERSION_1_1,
    HTTP_VERSION_2_0
} HttpVersion;

/*
 * HTTP status code categories
 */
typedef enum {
    HTTP_STATUS_INFORMATIONAL = 1,  /* 1xx */
    HTTP_STATUS_SUCCESS = 2,        /* 2xx */
    HTTP_STATUS_REDIRECTION = 3,    /* 3xx */
    HTTP_STATUS_CLIENT_ERROR = 4,   /* 4xx */
    HTTP_STATUS_SERVER_ERROR = 5    /* 5xx */
} HttpStatusCategory;

/*
 * HTTP header
 */
typedef struct HttpHeader {
    char *name;                     /* Header name */
    char *value;                    /* Header value */
    struct HttpHeader *next;        /* Next header (linked list) */
} HttpHeader;

/*
 * HTTP request
 */
typedef struct {
    HttpMethod method;              /* Request method */
    HttpVersion version;            /* HTTP version */
    char *uri;                      /* Request URI */
    char *path;                     /* Path component */
    char *query;                    /* Query string */
    char *fragment;                 /* Fragment identifier */
    HttpHeader *headers;            /* Header list */
    StringHashTable header_map;     /* Headers by name (case-insensitive) */
    uint8_t *body;                  /* Request body */
    size_t body_length;             /* Body length */
    size_t content_length;          /* Content-Length header value */
    bool chunked;                   /* Transfer-Encoding: chunked */
} HttpRequest;

/*
 * HTTP response
 */
typedef struct {
    HttpVersion version;            /* HTTP version */
    int status_code;                /* Status code (e.g., 200) */
    char *reason_phrase;            /* Reason phrase (e.g., "OK") */
    HttpHeader *headers;            /* Header list */
    StringHashTable header_map;     /* Headers by name */
    uint8_t *body;                  /* Response body */
    size_t body_length;             /* Body length */
    size_t content_length;          /* Content-Length header value */
    bool chunked;                   /* Transfer-Encoding: chunked */
} HttpResponse;

/*
 * HTTP parser state
 */
typedef enum {
    HTTP_PARSE_START,
    HTTP_PARSE_REQUEST_LINE,
    HTTP_PARSE_RESPONSE_LINE,
    HTTP_PARSE_HEADERS,
    HTTP_PARSE_BODY,
    HTTP_PARSE_CHUNK_SIZE,
    HTTP_PARSE_CHUNK_DATA,
    HTTP_PARSE_TRAILER,
    HTTP_PARSE_COMPLETE,
    HTTP_PARSE_ERROR
} HttpParseState;

/*
 * HTTP parser result
 */
typedef enum {
    HTTP_PARSE_OK = 0,
    HTTP_PARSE_INCOMPLETE,          /* Need more data */
    HTTP_PARSE_ERROR_SYNTAX,        /* Syntax error */
    HTTP_PARSE_ERROR_VERSION,       /* Invalid version */
    HTTP_PARSE_ERROR_METHOD,        /* Invalid method */
    HTTP_PARSE_ERROR_HEADER,        /* Invalid header */
    HTTP_PARSE_ERROR_LENGTH,        /* Length mismatch */
    HTTP_PARSE_ERROR_MEMORY         /* Memory allocation error */
} HttpParseResult;

/*
 * HTTP parser context
 */
typedef struct {
    HttpParseState state;           /* Current parse state */
    size_t bytes_consumed;          /* Bytes processed */
    size_t header_count;            /* Number of headers parsed */
    size_t max_headers;             /* Maximum headers allowed */
    size_t max_header_size;         /* Maximum header line size */
    size_t max_body_size;           /* Maximum body size */
    Arena *arena;                   /* Optional arena for allocation */
} HttpParser;

/*
 * Structured header item types (RFC 8941)
 */
typedef enum {
    SH_TYPE_INTEGER,
    SH_TYPE_DECIMAL,
    SH_TYPE_STRING,
    SH_TYPE_TOKEN,
    SH_TYPE_BINARY,
    SH_TYPE_BOOLEAN,
    SH_TYPE_LIST,
    SH_TYPE_DICT,
    SH_TYPE_INNER_LIST
} ShItemType;

/*
 * Structured header item
 */
typedef struct ShItem {
    ShItemType type;
    union {
        int64_t integer;
        double decimal;
        char *string;
        char *token;
        uint8_t *binary;
        bool boolean;
        struct ShItem *list;
        struct {
            char *key;
            struct ShItem *value;
        } *dict;
    } value;
    size_t length;                  /* For string/binary/list */
    struct ShItem *params;          /* Parameters */
    struct ShItem *next;            /* Next item in list */
} ShItem;

/*
 * HTTP parser initialization/cleanup
 */

/*
 * Initialize HTTP parser.
 * 
 * @param parser  Parser to initialize
 * @param arena   Optional arena for allocations
 */
void http_parser_init(HttpParser *parser, Arena *arena);

/*
 * Reset parser for reuse.
 * 
 * @param parser  Parser to reset
 */
void http_parser_reset(HttpParser *parser);

/*
 * Request/Response parsing
 */

/*
 * Parse HTTP request from buffer.
 * 
 * @param parser   Parser context
 * @param data     Input buffer
 * @param length   Buffer length
 * @param request  Output request structure
 * @return         Parse result
 */
HttpParseResult http_parse_request(HttpParser *parser, const uint8_t *data,
                                   size_t length, HttpRequest *request);

/*
 * Parse HTTP response from buffer.
 * 
 * @param parser    Parser context
 * @param data      Input buffer
 * @param length    Buffer length
 * @param response  Output response structure
 * @return          Parse result
 */
HttpParseResult http_parse_response(HttpParser *parser, const uint8_t *data,
                                    size_t length, HttpResponse *response);

/*
 * Request/Response creation
 */

/*
 * Create new HTTP request.
 * 
 * @param arena   Optional arena for allocation
 * @return        New request, or NULL on error
 */
HttpRequest *http_request_new(Arena *arena);

/*
 * Free HTTP request.
 * 
 * @param request  Request to free
 */
void http_request_free(HttpRequest *request);

/*
 * Create new HTTP response.
 * 
 * @param arena   Optional arena for allocation
 * @return        New response, or NULL on error
 */
HttpResponse *http_response_new(Arena *arena);

/*
 * Free HTTP response.
 * 
 * @param response  Response to free
 */
void http_response_free(HttpResponse *response);

/*
 * Header operations
 */

/*
 * Get header value by name (case-insensitive).
 * 
 * @param request  HTTP request
 * @param name     Header name
 * @return         Header value, or NULL if not found
 */
const char *http_request_get_header(const HttpRequest *request, const char *name);

/*
 * Get header value from response.
 * 
 * @param response  HTTP response
 * @param name      Header name
 * @return          Header value, or NULL if not found
 */
const char *http_response_get_header(const HttpResponse *response, const char *name);

/*
 * Add header to request.
 * 
 * @param request  HTTP request
 * @param name     Header name
 * @param value    Header value
 * @param arena    Optional arena for allocation
 * @return         true on success
 */
bool http_request_add_header(HttpRequest *request, const char *name,
                             const char *value, Arena *arena);

/*
 * Add header to response.
 * 
 * @param response  HTTP response
 * @param name      Header name
 * @param value     Header value
 * @param arena     Optional arena for allocation
 * @return          true on success
 */
bool http_response_add_header(HttpResponse *response, const char *name,
                              const char *value, Arena *arena);

/*
 * Serialization
 */

/*
 * Serialize request to buffer.
 * 
 * @param request  HTTP request
 * @param buffer   Output buffer
 * @param size     Buffer size
 * @return         Bytes written, or 0 on error
 */
size_t http_request_serialize(const HttpRequest *request, char *buffer, size_t size);

/*
 * Serialize response to buffer.
 * 
 * @param response  HTTP response
 * @param buffer    Output buffer
 * @param size      Buffer size
 * @return          Bytes written, or 0 on error
 */
size_t http_response_serialize(const HttpResponse *response, char *buffer, size_t size);

/*
 * Utility functions
 */

/*
 * Get method string.
 * 
 * @param method  HTTP method
 * @return        Method string
 */
const char *http_method_string(HttpMethod method);

/*
 * Parse method from string.
 * 
 * @param str     Method string
 * @param len     String length
 * @return        HTTP method
 */
HttpMethod http_method_parse(const char *str, size_t len);

/*
 * Get status category.
 * 
 * @param status_code  HTTP status code
 * @return             Status category
 */
HttpStatusCategory http_status_category(int status_code);

/*
 * Get default reason phrase for status code.
 * 
 * @param status_code  HTTP status code
 * @return             Reason phrase
 */
const char *http_status_reason(int status_code);

/*
 * Parse content type header.
 * 
 * @param value      Content-Type header value
 * @param media_type Output: media type
 * @param charset    Output: charset parameter (NULL if not present)
 * @param boundary   Output: boundary parameter (NULL if not present)
 * @return           true on success
 */
bool http_parse_content_type(const char *value, char **media_type,
                             char **charset, char **boundary);

/*
 * Structured headers (RFC 8941)
 */

/*
 * Parse structured header field.
 * 
 * @param value   Header value
 * @param arena   Arena for allocation
 * @return        Parsed item, or NULL on error
 */
ShItem *http_parse_structured_field(const char *value, Arena *arena);

/*
 * Free structured header item.
 * 
 * @param item  Item to free
 */
void sh_item_free(ShItem *item);

/*
 * HTTP content matching (for file type detection)
 */

/*
 * Check if data looks like HTTP request.
 * 
 * @param data    Data to check
 * @param length  Data length
 * @return        true if data appears to be HTTP request
 */
bool http_is_request(const uint8_t *data, size_t length);

/*
 * Check if data looks like HTTP response.
 * 
 * @param data    Data to check
 * @param length  Data length
 * @return        true if data appears to be HTTP response
 */
bool http_is_response(const uint8_t *data, size_t length);

#endif /* LUDOFILE_HTTP_HTTP_H */
