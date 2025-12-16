/*
 * LudoFile - Main Entry Point
 *
 * This is the main C component that provides the core file analysis
 * functionality. It is designed to be invoked by the APE shell coordinator.
 *
 * Copyright (c) 2024 LudoPlex
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "core/types.h"
#include "magic/magic.h"

#define LUDOFILE_VERSION "0.6.0"
#define LUDOFILE_COPYRIGHT "Copyright (c) 2024 LudoPlex"

/*
 * Output format types
 */
typedef enum {
    FORMAT_FILE = 0,   /* Like `file` command */
    FORMAT_MIME = 1,   /* MIME types only */
    FORMAT_JSON = 2,   /* SBUD JSON format */
    FORMAT_HTML = 3    /* Interactive HTML viewer */
} OutputFormat;

/*
 * Command line options
 */
static struct option long_options[] = {
    {"format", required_argument, 0, 'r'},
    {"output", required_argument, 0, 'o'},
    {"filetype", required_argument, 0, 'f'},
    {"list", no_argument, 0, 'l'},
    {"html", required_argument, 0, 't'},
    {"explain", no_argument, 0, 'e'},
    {"only-match-mime", no_argument, 0, 'I'},
    {"only-match", no_argument, 0, 'm'},
    {"require-match", no_argument, 0, 'R'},
    {"max-matches", required_argument, 0, 'M'},
    {"debugger", no_argument, 0, 'D'},
    {"quiet", no_argument, 0, 'q'},
    {"debug", no_argument, 0, 'd'},
    {"trace", no_argument, 0, 'T'},
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

/*
 * Print usage information
 */
static void print_usage(const char *program) {
    printf("Usage: %s [OPTIONS] [FILE]\n\n", program);
    printf("A utility to recursively map the structure of a file.\n\n");
    printf("Options:\n");
    printf("  -r, --format FORMAT   Output format (file, mime, json, html)\n");
    printf("  -o, --output PATH     Output file path\n");
    printf("  -f, --filetype TYPE   Match against specific file type\n");
    printf("  -l, --list            List supported file types\n");
    printf("  -t, --html PATH       Write interactive HTML viewer\n");
    printf("  -I, --only-match-mime Print matching MIME types only\n");
    printf("  -m, --only-match      Match only, don't parse\n");
    printf("  -R, --require-match   Exit with code 127 if no match\n");
    printf("  -M, --max-matches N   Stop after N matches\n");
    printf("  -q, --quiet           Suppress all output\n");
    printf("  -d, --debug           Print debug information\n");
    printf("  -v, --version         Print version information\n");
    printf("  -h, --help            Print this help message\n");
    printf("\nExamples:\n");
    printf("  %s document.pdf\n", program);
    printf("  %s --format json --output out.json archive.zip\n", program);
}

/*
 * Print version information
 */
static void print_version(void) {
    printf("LudoFile version %s\n", LUDOFILE_VERSION);
    printf("%s\n", LUDOFILE_COPYRIGHT);
    printf("Apache License Version 2.0\n");
}

/*
 * List supported MIME types
 */
static void list_mimetypes(MagicMatcher *matcher) {
    /* TODO: Get actual MIME types from matcher */
    printf("application/pdf\n");
    printf("application/zip\n");
    printf("application/java-archive\n");
    printf("image/png\n");
    printf("image/jpeg\n");
    printf("text/plain\n");
    /* ... more types */
}

/*
 * Output match result in file format (like `file` command)
 */
static void output_file_format(Match *match, FILE *out) {
    const char *msg = match_get_message(match);
    if (msg) {
        fprintf(out, "%s\n", msg);
    } else {
        size_t count;
        const char **mimes = match_get_mimetypes(match, &count);
        if (mimes && count > 0) {
            fprintf(out, "%s\n", mimes[0]);
            free(mimes);
        } else {
            fprintf(out, "data\n");
        }
    }
}

/*
 * Output match result in MIME format
 */
static void output_mime_format(Match *match, FILE *out) {
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    
    if (mimes) {
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "%s\n", mimes[i]);
        }
        free(mimes);
    } else {
        fprintf(out, "application/octet-stream\n");
    }
}

/*
 * Output match result in JSON format
 */
static void output_json_format(Match *match, FILE *out, const char *filename, 
                                const uint8_t *data, size_t data_len) {
    fprintf(out, "{\n");
    fprintf(out, "  \"fileName\": \"%s\",\n", filename ? filename : "stdin");
    fprintf(out, "  \"length\": %zu,\n", data_len);
    fprintf(out, "  \"versions\": {\n");
    fprintf(out, "    \"ludofile\": \"%s\"\n", LUDOFILE_VERSION);
    fprintf(out, "  },\n");
    fprintf(out, "  \"struc\": [\n");
    
    size_t count;
    const char **mimes = match_get_mimetypes(match, &count);
    if (mimes) {
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "    {\n");
            fprintf(out, "      \"type\": \"%s\",\n", mimes[i]);
            fprintf(out, "      \"offset\": 0,\n");
            fprintf(out, "      \"size\": %zu\n", data_len);
            fprintf(out, "    }%s\n", i < count - 1 ? "," : "");
        }
        free(mimes);
    }
    
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

/*
 * Read file into memory
 */
static uint8_t* read_file(const char *path, size_t *length) {
    FILE *fp;
    
    if (strcmp(path, "-") == 0) {
        fp = stdin;
    } else {
        fp = fopen(path, "rb");
        if (!fp) {
            perror(path);
            return NULL;
        }
    }
    
    /* For stdin, we need to read in chunks */
    if (fp == stdin) {
        size_t capacity = 65536;
        size_t size = 0;
        uint8_t *data = malloc(capacity);
        
        if (!data) return NULL;
        
        while (!feof(fp)) {
            if (size >= capacity) {
                capacity *= 2;
                uint8_t *new_data = realloc(data, capacity);
                if (!new_data) {
                    free(data);
                    return NULL;
                }
                data = new_data;
            }
            
            size_t read = fread(data + size, 1, capacity - size, fp);
            size += read;
        }
        
        *length = size;
        return data;
    }
    
    /* For regular files, get size first */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror(path);
        fclose(fp);
        return NULL;
    }
    
    long len = ftell(fp);
    if (len < 0) {
        perror(path);
        fclose(fp);
        return NULL;
    }
    *length = (size_t)len;
    
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror(path);
        fclose(fp);
        return NULL;
    }
    
    uint8_t *data = malloc(*length);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    
    if (fread(data, 1, *length, fp) != *length) {
        free(data);
        fclose(fp);
        return NULL;
    }
    
    fclose(fp);
    return data;
}

/*
 * Main entry point
 */
int main(int argc, char *argv[]) {
    OutputFormat format = FORMAT_FILE;
    const char *output_path = NULL;
    const char *html_path = NULL;
    const char *filetype_filter = NULL;
    int max_matches = -1;
    bool list_types = false;
    bool only_match_mime = false;
    bool only_match = false;
    bool require_match = false;
    bool quiet = false;
    bool debug = false;
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "r:o:f:lt:eImRM:qdhv", 
                               long_options, &option_index)) != -1) {
        switch (opt) {
            case 'r':
                if (strcmp(optarg, "file") == 0) {
                    format = FORMAT_FILE;
                } else if (strcmp(optarg, "mime") == 0) {
                    format = FORMAT_MIME;
                } else if (strcmp(optarg, "json") == 0 || strcmp(optarg, "sbud") == 0) {
                    format = FORMAT_JSON;
                } else if (strcmp(optarg, "html") == 0) {
                    format = FORMAT_HTML;
                } else {
                    fprintf(stderr, "Unknown format: %s\n", optarg);
                    return 1;
                }
                break;
            case 'o':
                output_path = optarg;
                break;
            case 'f':
                filetype_filter = optarg;
                break;
            case 'l':
                list_types = true;
                break;
            case 't':
                html_path = optarg;
                format = FORMAT_HTML;
                break;
            case 'e':
                /* explain mode - same as mime for now */
                format = FORMAT_MIME;
                break;
            case 'I':
                only_match_mime = true;
                format = FORMAT_MIME;
                break;
            case 'm':
                only_match = true;
                break;
            case 'R':
                require_match = true;
                break;
            case 'M':
                max_matches = atoi(optarg);
                break;
            case 'q':
                quiet = true;
                break;
            case 'd':
                debug = true;
                break;
            case 'v':
                print_version();
                return 0;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Initialize magic matcher */
    MagicMatcher *matcher = magic_matcher_new();
    if (!matcher) {
        fprintf(stderr, "Failed to initialize magic matcher\n");
        return 1;
    }
    
    /* Handle list option */
    if (list_types) {
        list_mimetypes(matcher);
        magic_matcher_free(matcher);
        return 0;
    }
    
    /* Get input file */
    const char *input_path = "-";
    if (optind < argc) {
        input_path = argv[optind];
    }
    
    /* Read input file */
    size_t data_len;
    uint8_t *data = read_file(input_path, &data_len);
    if (!data) {
        magic_matcher_free(matcher);
        return 1;
    }
    
    /* Perform matching */
    Match *match = magic_matcher_match(matcher, data, data_len);
    if (!match) {
        fprintf(stderr, "Matching failed\n");
        free(data);
        magic_matcher_free(matcher);
        return 1;
    }
    
    /* Check if match required */
    if (require_match) {
        size_t count;
        const char **mimes = match_get_mimetypes(match, &count);
        if (!mimes || count == 0) {
            match_free(match);
            free(data);
            magic_matcher_free(matcher);
            return 127;
        }
        free(mimes);
    }
    
    /* Open output file */
    FILE *out = stdout;
    if (output_path && strcmp(output_path, "-") != 0) {
        out = fopen(output_path, "w");
        if (!out) {
            perror(output_path);
            match_free(match);
            free(data);
            magic_matcher_free(matcher);
            return 1;
        }
    }
    
    /* Output results */
    if (!quiet) {
        switch (format) {
            case FORMAT_FILE:
                output_file_format(match, out);
                break;
            case FORMAT_MIME:
                output_mime_format(match, out);
                break;
            case FORMAT_JSON:
                output_json_format(match, out, input_path, data, data_len);
                break;
            case FORMAT_HTML:
                /* TODO: Implement HTML output */
                fprintf(stderr, "HTML output not yet implemented in C version\n");
                break;
        }
    }
    
    /* Cleanup */
    if (out != stdout) {
        fclose(out);
    }
    
    match_free(match);
    free(data);
    magic_matcher_free(matcher);
    
    return 0;
}
