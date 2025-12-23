/*
 * LudoFile - HTTP Protocol Implementation
 *
 * HTTP/1.1 request/response parsing and header handling.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L  /* For strdup, strncasecmp */

#include "http.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* For strncasecmp on some platforms */
#include <ctype.h>
#include <stdio.h>
#include <assert.h>

/*
 * Default limits
 */
#define HTTP_MAX_HEADERS 100
#define HTTP_MAX_HEADER_SIZE 8192
#define HTTP_MAX_BODY_SIZE (16 * 1024 * 1024)  /* 16MB */

/*
 * HTTP methods table
 */
static const struct {
    const char *name;
    size_t len;
    HttpMethod method;
} http_methods[] = {
    { "GET", 3, HTTP_METHOD_GET },
    { "HEAD", 4, HTTP_METHOD_HEAD },
    { "POST", 4, HTTP_METHOD_POST },
    { "PUT", 3, HTTP_METHOD_PUT },
    { "DELETE", 6, HTTP_METHOD_DELETE },
    { "CONNECT", 7, HTTP_METHOD_CONNECT },
    { "OPTIONS", 7, HTTP_METHOD_OPTIONS },
    { "TRACE", 5, HTTP_METHOD_TRACE },
    { "PATCH", 5, HTTP_METHOD_PATCH },
    { NULL, 0, HTTP_METHOD_UNKNOWN }
};

/*
 * HTTP status codes and reasons
 */
static const struct {
    int code;
    const char *reason;
} http_status_codes[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 204, "No Content" },
    { 206, "Partial Content" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 307, "Temporary Redirect" },
    { 308, "Permanent Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 413, "Payload Too Large" },
    { 414, "URI Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Range Not Satisfiable" },
    { 429, "Too Many Requests" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Timeout" },
    { 505, "HTTP Version Not Supported" },
    { 0, NULL }
};

/*
 * Case-insensitive string comparison for headers
 */
static int strcasecmp_n(const char *s1, const char *s2, size_t n) {
    while (n-- > 0) {
        int c1 = tolower((unsigned char)*s1++);
        int c2 = tolower((unsigned char)*s2++);
        if (c1 != c2) return c1 - c2;
        if (c1 == 0) return 0;
    }
    return 0;
}

/*
 * Skip whitespace
 */
static const uint8_t *skip_ws(const uint8_t *p, const uint8_t *end) {
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    return p;
}

/*
 * Find end of line (CRLF)
 */
static const uint8_t *find_eol(const uint8_t *p, const uint8_t *end) {
    while (p + 1 < end) {
        if (p[0] == '\r' && p[1] == '\n') return p;
        p++;
    }
    return NULL;
}

/*
 * Allocate memory (arena or malloc)
 */
static void *http_alloc(Arena *arena, size_t size) {
    if (arena) {
        return arena_alloc(arena, size, 8);
    }
    return malloc(size);
}

/*
 * Duplicate string (arena or strdup)
 */
static char *http_strdup(Arena *arena, const char *s, size_t len) {
    if (arena) {
        char *dup = arena_alloc(arena, len + 1, 1);
        if (dup) {
            memcpy(dup, s, len);
            dup[len] = '\0';
        }
        return dup;
    }
    char *dup = malloc(len + 1);
    if (dup) {
        memcpy(dup, s, len);
        dup[len] = '\0';
    }
    return dup;
}

/*
 * Initialize parser
 */
void http_parser_init(HttpParser *parser, Arena *arena) {
    assert(parser != NULL);
    
    parser->state = HTTP_PARSE_START;
    parser->bytes_consumed = 0;
    parser->header_count = 0;
    parser->max_headers = HTTP_MAX_HEADERS;
    parser->max_header_size = HTTP_MAX_HEADER_SIZE;
    parser->max_body_size = HTTP_MAX_BODY_SIZE;
    parser->arena = arena;
}

/*
 * Reset parser
 */
void http_parser_reset(HttpParser *parser) {
    if (!parser) return;
    
    Arena *arena = parser->arena;
    http_parser_init(parser, arena);
}

/*
 * Parse HTTP method
 */
HttpMethod http_method_parse(const char *str, size_t len) {
    for (int i = 0; http_methods[i].name != NULL; i++) {
        if (len == http_methods[i].len && 
            memcmp(str, http_methods[i].name, len) == 0) {
            return http_methods[i].method;
        }
    }
    return HTTP_METHOD_UNKNOWN;
}

/*
 * Get method string
 */
const char *http_method_string(HttpMethod method) {
    for (int i = 0; http_methods[i].name != NULL; i++) {
        if (http_methods[i].method == method) {
            return http_methods[i].name;
        }
    }
    return "UNKNOWN";
}

/*
 * Get status category
 */
HttpStatusCategory http_status_category(int status_code) {
    return (HttpStatusCategory)(status_code / 100);
}

/*
 * Get status reason
 */
const char *http_status_reason(int status_code) {
    for (int i = 0; http_status_codes[i].reason != NULL; i++) {
        if (http_status_codes[i].code == status_code) {
            return http_status_codes[i].reason;
        }
    }
    return "Unknown";
}

/*
 * Parse HTTP version
 */
static HttpVersion parse_version(const uint8_t *p, const uint8_t *end) {
    if (end - p < 8) return HTTP_VERSION_UNKNOWN;
    
    if (memcmp(p, "HTTP/1.1", 8) == 0) return HTTP_VERSION_1_1;
    if (memcmp(p, "HTTP/1.0", 8) == 0) return HTTP_VERSION_1_0;
    if (memcmp(p, "HTTP/2", 6) == 0) return HTTP_VERSION_2_0;
    if (memcmp(p, "HTTP/0.9", 8) == 0) return HTTP_VERSION_0_9;
    
    return HTTP_VERSION_UNKNOWN;
}

/*
 * Parse headers
 */
static HttpParseResult parse_headers(HttpParser *parser, const uint8_t *data,
                                     size_t length, HttpHeader **headers,
                                     StringHashTable *header_map,
                                     size_t *content_length, bool *chunked) {
    const uint8_t *p = data;
    const uint8_t *end = data + length;
    HttpHeader *head = NULL;
    HttpHeader *tail = NULL;
    
    *content_length = 0;
    *chunked = false;
    
    while (p < end) {
        /* Check for end of headers (empty line) */
        if (p + 1 < end && p[0] == '\r' && p[1] == '\n') {
            parser->bytes_consumed = (size_t)(p + 2 - data);
            *headers = head;
            return HTTP_PARSE_OK;
        }
        
        /* Find end of header line */
        const uint8_t *eol = find_eol(p, end);
        if (!eol) {
            return HTTP_PARSE_INCOMPLETE;
        }
        
        /* Check header count */
        if (parser->header_count >= parser->max_headers) {
            return HTTP_PARSE_ERROR_HEADER;
        }
        
        /* Find colon separator */
        const uint8_t *colon = p;
        while (colon < eol && *colon != ':') colon++;
        if (colon >= eol) {
            return HTTP_PARSE_ERROR_HEADER;
        }
        
        /* Extract name and value */
        size_t name_len = (size_t)(colon - p);
        const uint8_t *val_start = skip_ws(colon + 1, eol);
        const uint8_t *val_end = eol;
        while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) {
            val_end--;
        }
        size_t val_len = (size_t)(val_end - val_start);
        
        /* Create header */
        HttpHeader *hdr = http_alloc(parser->arena, sizeof(HttpHeader));
        if (!hdr) return HTTP_PARSE_ERROR_MEMORY;
        
        hdr->name = http_strdup(parser->arena, (const char *)p, name_len);
        hdr->value = http_strdup(parser->arena, (const char *)val_start, val_len);
        hdr->next = NULL;
        
        if (!hdr->name || !hdr->value) {
            return HTTP_PARSE_ERROR_MEMORY;
        }
        
        /* Add to list */
        if (tail) {
            tail->next = hdr;
            tail = hdr;
        } else {
            head = tail = hdr;
        }
        
        /* Add to hash map */
        if (header_map) {
            /* Convert name to lowercase for lookup */
            char *lower_name = http_strdup(parser->arena, hdr->name, name_len);
            if (lower_name) {
                for (char *c = lower_name; *c; c++) {
                    *c = (char)tolower((unsigned char)*c);
                }
                sht_insert(header_map, lower_name, hdr->value);
            }
        }
        
        /* Check for special headers */
        if (strcasecmp_n(hdr->name, "content-length", 14) == 0) {
            *content_length = (size_t)strtoul(hdr->value, NULL, 10);
        } else if (strcasecmp_n(hdr->name, "transfer-encoding", 17) == 0) {
            if (strstr(hdr->value, "chunked")) {
                *chunked = true;
            }
        }
        
        parser->header_count++;
        p = eol + 2;  /* Skip CRLF */
    }
    
    *headers = head;
    return HTTP_PARSE_INCOMPLETE;
}

/*
 * Parse HTTP request
 */
HttpParseResult http_parse_request(HttpParser *parser, const uint8_t *data,
                                   size_t length, HttpRequest *request) {
    assert(parser != NULL);
    assert(data != NULL);
    assert(request != NULL);
    
    const uint8_t *p = data;
    const uint8_t *end = data + length;
    
    /* Initialize request */
    memset(request, 0, sizeof(HttpRequest));
    sht_init(&request->header_map, 32, parser->arena);
    
    /* Parse request line */
    const uint8_t *eol = find_eol(p, end);
    if (!eol) {
        return HTTP_PARSE_INCOMPLETE;
    }
    
    /* Parse method */
    const uint8_t *method_end = p;
    while (method_end < eol && *method_end != ' ') method_end++;
    request->method = http_method_parse((const char *)p, (size_t)(method_end - p));
    if (request->method == HTTP_METHOD_UNKNOWN) {
        return HTTP_PARSE_ERROR_METHOD;
    }
    
    /* Parse URI */
    p = method_end + 1;
    const uint8_t *uri_start = p;
    while (p < eol && *p != ' ') p++;
    
    size_t uri_len = (size_t)(p - uri_start);
    request->uri = http_strdup(parser->arena, (const char *)uri_start, uri_len);
    if (!request->uri) {
        return HTTP_PARSE_ERROR_MEMORY;
    }
    
    /* Extract path, query, fragment */
    char *query = strchr(request->uri, '?');
    char *fragment = strchr(request->uri, '#');
    
    if (query) {
        *query++ = '\0';
        if (fragment) {
            *fragment++ = '\0';
            request->fragment = fragment;
        }
        request->query = query;
    } else if (fragment) {
        *fragment++ = '\0';
        request->fragment = fragment;
    }
    request->path = request->uri;
    
    /* Parse version */
    p++;
    request->version = parse_version(p, eol);
    if (request->version == HTTP_VERSION_UNKNOWN) {
        return HTTP_PARSE_ERROR_VERSION;
    }
    
    /* Parse headers */
    p = eol + 2;
    size_t request_line_len = (size_t)(p - data);
    
    HttpParseResult result = parse_headers(parser, p, (size_t)(end - p),
                                           &request->headers,
                                           &request->header_map,
                                           &request->content_length,
                                           &request->chunked);
    
    if (result != HTTP_PARSE_OK) {
        return result;
    }
    
    /* parser->bytes_consumed from parse_headers is relative to header start */
    parser->bytes_consumed = request_line_len + parser->bytes_consumed;
    
    /* Parse body if present */
    if (request->content_length > 0 || request->chunked) {
        const uint8_t *body_start = data + parser->bytes_consumed;
        size_t remaining = length - parser->bytes_consumed;
        
        if (request->chunked) {
            /* TODO: Chunked transfer decoding */
            parser->state = HTTP_PARSE_CHUNK_SIZE;
        } else if (remaining >= request->content_length) {
            request->body = (uint8_t *)body_start;
            request->body_length = request->content_length;
            parser->bytes_consumed += request->content_length;
        } else {
            return HTTP_PARSE_INCOMPLETE;
        }
    }
    
    parser->state = HTTP_PARSE_COMPLETE;
    return HTTP_PARSE_OK;
}

/*
 * Parse HTTP response
 */
HttpParseResult http_parse_response(HttpParser *parser, const uint8_t *data,
                                    size_t length, HttpResponse *response) {
    assert(parser != NULL);
    assert(data != NULL);
    assert(response != NULL);
    
    const uint8_t *p = data;
    const uint8_t *end = data + length;
    
    /* Initialize response */
    memset(response, 0, sizeof(HttpResponse));
    sht_init(&response->header_map, 32, parser->arena);
    
    /* Parse status line */
    const uint8_t *eol = find_eol(p, end);
    if (!eol) {
        return HTTP_PARSE_INCOMPLETE;
    }
    
    /* Parse version */
    response->version = parse_version(p, eol);
    if (response->version == HTTP_VERSION_UNKNOWN) {
        return HTTP_PARSE_ERROR_VERSION;
    }
    p += 8;  /* Skip "HTTP/X.X" */
    
    /* Skip space */
    if (*p != ' ') {
        return HTTP_PARSE_ERROR_SYNTAX;
    }
    p++;
    
    /* Parse status code */
    if (end - p < 3 || !isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2])) {
        return HTTP_PARSE_ERROR_SYNTAX;
    }
    response->status_code = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    p += 3;
    
    /* Skip space and parse reason phrase */
    if (p < eol && *p == ' ') {
        p++;
        size_t reason_len = (size_t)(eol - p);
        response->reason_phrase = http_strdup(parser->arena, (const char *)p, reason_len);
    } else {
        response->reason_phrase = http_strdup(parser->arena, 
                                              http_status_reason(response->status_code),
                                              strlen(http_status_reason(response->status_code)));
    }
    
    /* Parse headers */
    p = eol + 2;
    size_t status_line_len = (size_t)(p - data);
    
    HttpParseResult result = parse_headers(parser, p, (size_t)(end - p),
                                           &response->headers,
                                           &response->header_map,
                                           &response->content_length,
                                           &response->chunked);
    
    if (result != HTTP_PARSE_OK) {
        return result;
    }
    
    /* parser->bytes_consumed from parse_headers is relative to header start */
    parser->bytes_consumed = status_line_len + parser->bytes_consumed;
    
    /* Parse body if present */
    if (response->content_length > 0 || response->chunked) {
        const uint8_t *body_start = data + parser->bytes_consumed;
        size_t remaining = length - parser->bytes_consumed;
        
        if (response->chunked) {
            parser->state = HTTP_PARSE_CHUNK_SIZE;
        } else if (remaining >= response->content_length) {
            response->body = (uint8_t *)body_start;
            response->body_length = response->content_length;
            parser->bytes_consumed += response->content_length;
        } else {
            return HTTP_PARSE_INCOMPLETE;
        }
    }
    
    parser->state = HTTP_PARSE_COMPLETE;
    return HTTP_PARSE_OK;
}

/*
 * Create new request
 */
HttpRequest *http_request_new(Arena *arena) {
    HttpRequest *req = http_alloc(arena, sizeof(HttpRequest));
    if (req) {
        memset(req, 0, sizeof(HttpRequest));
        sht_init(&req->header_map, 32, arena);
    }
    return req;
}

/*
 * Free request
 */
void http_request_free(HttpRequest *request) {
    if (!request) return;
    
    /* Free headers */
    HttpHeader *hdr = request->headers;
    while (hdr) {
        HttpHeader *next = hdr->next;
        free(hdr->name);
        free(hdr->value);
        free(hdr);
        hdr = next;
    }
    
    sht_free(&request->header_map);
    free(request->uri);
    free(request);
}

/*
 * Create new response
 */
HttpResponse *http_response_new(Arena *arena) {
    HttpResponse *resp = http_alloc(arena, sizeof(HttpResponse));
    if (resp) {
        memset(resp, 0, sizeof(HttpResponse));
        sht_init(&resp->header_map, 32, arena);
    }
    return resp;
}

/*
 * Free response
 */
void http_response_free(HttpResponse *response) {
    if (!response) return;
    
    HttpHeader *hdr = response->headers;
    while (hdr) {
        HttpHeader *next = hdr->next;
        free(hdr->name);
        free(hdr->value);
        free(hdr);
        hdr = next;
    }
    
    sht_free(&response->header_map);
    free(response->reason_phrase);
    free(response);
}

/*
 * Get request header
 */
const char *http_request_get_header(const HttpRequest *request, const char *name) {
    if (!request || !name) return NULL;
    
    /* Convert name to lowercase */
    char lower[128];
    size_t len = strlen(name);
    if (len >= sizeof(lower)) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)name[i]);
    }
    lower[len] = '\0';
    
    return sht_lookup((StringHashTable *)&request->header_map, lower);
}

/*
 * Get response header
 */
const char *http_response_get_header(const HttpResponse *response, const char *name) {
    if (!response || !name) return NULL;
    
    char lower[128];
    size_t len = strlen(name);
    if (len >= sizeof(lower)) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)name[i]);
    }
    lower[len] = '\0';
    
    return sht_lookup((StringHashTable *)&response->header_map, lower);
}

/*
 * Add header to request
 */
bool http_request_add_header(HttpRequest *request, const char *name,
                             const char *value, Arena *arena) {
    if (!request || !name || !value) return false;
    
    HttpHeader *hdr = http_alloc(arena, sizeof(HttpHeader));
    if (!hdr) return false;
    
    hdr->name = http_strdup(arena, name, strlen(name));
    hdr->value = http_strdup(arena, value, strlen(value));
    hdr->next = request->headers;
    request->headers = hdr;
    
    /* Add to map */
    char lower[128];
    size_t len = strlen(name);
    if (len < sizeof(lower)) {
        for (size_t i = 0; i < len; i++) {
            lower[i] = (char)tolower((unsigned char)name[i]);
        }
        lower[len] = '\0';
        sht_insert(&request->header_map, http_strdup(arena, lower, len), hdr->value);
    }
    
    return true;
}

/*
 * Add header to response
 */
bool http_response_add_header(HttpResponse *response, const char *name,
                              const char *value, Arena *arena) {
    if (!response || !name || !value) return false;
    
    HttpHeader *hdr = http_alloc(arena, sizeof(HttpHeader));
    if (!hdr) return false;
    
    hdr->name = http_strdup(arena, name, strlen(name));
    hdr->value = http_strdup(arena, value, strlen(value));
    hdr->next = response->headers;
    response->headers = hdr;
    
    char lower[128];
    size_t len = strlen(name);
    if (len < sizeof(lower)) {
        for (size_t i = 0; i < len; i++) {
            lower[i] = (char)tolower((unsigned char)name[i]);
        }
        lower[len] = '\0';
        sht_insert(&response->header_map, http_strdup(arena, lower, len), hdr->value);
    }
    
    return true;
}

/*
 * Serialize request
 */
size_t http_request_serialize(const HttpRequest *request, char *buffer, size_t size) {
    if (!request || !buffer || size == 0) return 0;
    
    int written = snprintf(buffer, size, "%s %s HTTP/1.1\r\n",
                          http_method_string(request->method),
                          request->uri ? request->uri : "/");
    
    if (written < 0 || (size_t)written >= size) return 0;
    
    size_t total = (size_t)written;
    
    /* Write headers */
    for (HttpHeader *hdr = request->headers; hdr && total < size; hdr = hdr->next) {
        written = snprintf(buffer + total, size - total, "%s: %s\r\n",
                          hdr->name, hdr->value);
        if (written < 0) return 0;
        total += (size_t)written;
    }
    
    /* End headers */
    if (total + 2 <= size) {
        buffer[total++] = '\r';
        buffer[total++] = '\n';
    }
    
    /* Write body */
    if (request->body && request->body_length > 0) {
        if (total + request->body_length <= size) {
            memcpy(buffer + total, request->body, request->body_length);
            total += request->body_length;
        }
    }
    
    return total;
}

/*
 * Serialize response
 */
size_t http_response_serialize(const HttpResponse *response, char *buffer, size_t size) {
    if (!response || !buffer || size == 0) return 0;
    
    const char *version = "HTTP/1.1";
    if (response->version == HTTP_VERSION_1_0) version = "HTTP/1.0";
    
    int written = snprintf(buffer, size, "%s %d %s\r\n",
                          version, response->status_code,
                          response->reason_phrase ? response->reason_phrase : 
                          http_status_reason(response->status_code));
    
    if (written < 0 || (size_t)written >= size) return 0;
    
    size_t total = (size_t)written;
    
    for (HttpHeader *hdr = response->headers; hdr && total < size; hdr = hdr->next) {
        written = snprintf(buffer + total, size - total, "%s: %s\r\n",
                          hdr->name, hdr->value);
        if (written < 0) return 0;
        total += (size_t)written;
    }
    
    if (total + 2 <= size) {
        buffer[total++] = '\r';
        buffer[total++] = '\n';
    }
    
    if (response->body && response->body_length > 0) {
        if (total + response->body_length <= size) {
            memcpy(buffer + total, response->body, response->body_length);
            total += response->body_length;
        }
    }
    
    return total;
}

/*
 * Parse Content-Type header
 */
bool http_parse_content_type(const char *value, char **media_type,
                             char **charset, char **boundary) {
    if (!value || !media_type) return false;
    
    *media_type = NULL;
    if (charset) *charset = NULL;
    if (boundary) *boundary = NULL;
    
    /* Find end of media type */
    const char *p = value;
    while (*p && *p != ';' && *p != ' ') p++;
    
    size_t mt_len = (size_t)(p - value);
    *media_type = malloc(mt_len + 1);
    if (!*media_type) return false;
    memcpy(*media_type, value, mt_len);
    (*media_type)[mt_len] = '\0';
    
    /* Parse parameters */
    while (*p) {
        while (*p == ';' || *p == ' ') p++;
        if (!*p) break;
        
        const char *param_start = p;
        while (*p && *p != '=') p++;
        if (!*p) break;
        
        size_t param_len = (size_t)(p - param_start);
        p++;  /* Skip '=' */
        
        const char *val_start = p;
        if (*p == '"') {
            p++;
            val_start = p;
            while (*p && *p != '"') p++;
        } else {
            while (*p && *p != ';' && *p != ' ') p++;
        }
        size_t val_len = (size_t)(p - val_start);
        if (*p == '"') p++;
        
        /* Check for charset parameter (must match exact length) */
        if (charset && param_len == 7 && strncasecmp(param_start, "charset", 7) == 0) {
            *charset = malloc(val_len + 1);
            if (*charset) {
                memcpy(*charset, val_start, val_len);
                (*charset)[val_len] = '\0';
            }
        /* Check for boundary parameter (must match exact length) */
        } else if (boundary && param_len == 8 && strncasecmp(param_start, "boundary", 8) == 0) {
            *boundary = malloc(val_len + 1);
            if (*boundary) {
                memcpy(*boundary, val_start, val_len);
                (*boundary)[val_len] = '\0';
            }
        }
    }
    
    return true;
}

/*
 * Check if data looks like HTTP request
 */
bool http_is_request(const uint8_t *data, size_t length) {
    if (!data || length < 10) return false;
    
    /* Check for common HTTP methods */
    for (int i = 0; http_methods[i].name != NULL; i++) {
        if (length >= http_methods[i].len + 1 &&
            memcmp(data, http_methods[i].name, http_methods[i].len) == 0 &&
            data[http_methods[i].len] == ' ') {
            return true;
        }
    }
    
    return false;
}

/*
 * Check if data looks like HTTP response
 */
bool http_is_response(const uint8_t *data, size_t length) {
    if (!data || length < 12) return false;
    
    /* Check for "HTTP/X.X " prefix */
    if (memcmp(data, "HTTP/", 5) == 0 &&
        isdigit(data[5]) && data[6] == '.' && isdigit(data[7]) && data[8] == ' ') {
        return true;
    }
    
    return false;
}

/*
 * Parse structured header field (RFC 8941 - simplified)
 */
ShItem *http_parse_structured_field(const char *value, Arena *arena) {
    if (!value) return NULL;
    
    ShItem *item = http_alloc(arena, sizeof(ShItem));
    if (!item) return NULL;
    
    memset(item, 0, sizeof(ShItem));
    
    /* Skip leading whitespace */
    while (*value == ' ' || *value == '\t') value++;
    
    /* Determine type */
    if (*value == '"') {
        /* String */
        item->type = SH_TYPE_STRING;
        value++;
        const char *start = value;
        while (*value && *value != '"') value++;
        size_t len = (size_t)(value - start);
        item->value.string = http_strdup(arena, start, len);
        item->length = len;
    } else if (*value == ':') {
        /* Binary */
        item->type = SH_TYPE_BINARY;
        /* TODO: Base64 decode */
    } else if (*value == '?') {
        /* Boolean */
        item->type = SH_TYPE_BOOLEAN;
        value++;
        item->value.boolean = (*value == '1');
    } else if (*value == '-' || isdigit(*value)) {
        /* Integer or decimal */
        char *end;
        item->value.integer = strtoll(value, &end, 10);
        if (*end == '.') {
            item->type = SH_TYPE_DECIMAL;
            item->value.decimal = strtod(value, NULL);
        } else {
            item->type = SH_TYPE_INTEGER;
        }
    } else if (isalpha(*value) || *value == '*') {
        /* Token */
        item->type = SH_TYPE_TOKEN;
        const char *start = value;
        while (*value && (isalnum(*value) || strchr("!#$%&'*+-.^_`|~", *value))) {
            value++;
        }
        size_t len = (size_t)(value - start);
        item->value.token = http_strdup(arena, start, len);
        item->length = len;
    }
    
    return item;
}

/*
 * Free structured header item
 */
void sh_item_free(ShItem *item) {
    if (!item) return;
    
    switch (item->type) {
        case SH_TYPE_STRING:
            free(item->value.string);
            break;
        case SH_TYPE_TOKEN:
            free(item->value.token);
            break;
        case SH_TYPE_BINARY:
            free(item->value.binary);
            break;
        case SH_TYPE_LIST:
        case SH_TYPE_INNER_LIST:
            /* TODO: Free list items */
            break;
        default:
            break;
    }
    
    if (item->params) sh_item_free(item->params);
    if (item->next) sh_item_free(item->next);
    free(item);
}
