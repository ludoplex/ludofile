#!/bin/sh
# LudoFile APE Shell Coordinator
#
# This is the main entry point for LudoFile. It orchestrates the
# various C components and provides a unified interface.
#
# Copyright (c) 2024 LudoPlex
# SPDX-License-Identifier: Apache-2.0

set -e

# Configuration
LUDOFILE_VERSION="0.6.0"

# Portable way to get the script directory
# This works on both Linux (with readlink -f) and macOS (without it)
get_script_dir() {
    local source="${1:-$0}"
    local dir=""
    
    # Resolve symlinks if possible
    if command -v readlink >/dev/null 2>&1; then
        # Try GNU readlink -f first
        if readlink -f "$source" >/dev/null 2>&1; then
            source="$(readlink -f "$source")"
        else
            # macOS: follow symlinks manually
            while [ -L "$source" ]; do
                dir="$(cd -P "$(dirname "$source")" && pwd)"
                source="$(readlink "$source")"
                [ "${source%${source#?}}" != "/" ] && source="$dir/$source"
            done
        fi
    fi
    
    cd -P "$(dirname "$source")" && pwd
}

LUDOFILE_DIR="$(get_script_dir "$0")"
LUDOFILE_DIR="$(dirname "$LUDOFILE_DIR")"  # Go up one level from scripts/
LUDOFILE_BIN="${LUDOFILE_DIR}/bin"

# Default options
OUTPUT_FORMAT="file"
OUTPUT_PATH=""
INPUT_FILE=""
FILETYPE_FILTER=""
MAX_MATCHES=-1
ONLY_MATCH_MIME=0
ONLY_MATCH=0
REQUIRE_MATCH=0
QUIET=0
DEBUG=0
LIST_TYPES=0
HTML_OUTPUT=""

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
log_info() {
    if [ "$QUIET" -eq 0 ]; then
        printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2
    fi
}

log_debug() {
    if [ "$DEBUG" -eq 1 ] && [ "$QUIET" -eq 0 ]; then
        printf "${YELLOW}[DEBUG]${NC} %s\n" "$1" >&2
    fi
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

# Print version information
print_version() {
    echo "LudoFile version ${LUDOFILE_VERSION}"
    echo "Copyright (c) 2024 LudoPlex"
    echo "Apache License Version 2.0 https://www.apache.org/licenses/"
}

# Print usage information
print_usage() {
    cat <<EOF
Usage: ludofile [OPTIONS] [FILE]

A utility to recursively map the structure of a file.

positional arguments:
  FILE                  the file to analyze; pass '-' or omit to read from STDIN

options:
  -h, --help            show this help message and exit
  --format, -r FORMAT   Output format (file, mime, json, html)
  --output, -o PATH     Output file path
  --filetype, -f TYPE   Match against specific file type
  --list, -l            List supported file types
  --html, -t PATH       Write interactive HTML viewer
  --only-match-mime, -I Print matching MIME types only
  --only-match, -m      Match only, don't parse
  --require-match       Exit with code 127 if no match
  --max-matches N       Stop after N matches
  --quiet, -q           Suppress all log output
  --debug, -d           Print debug information
  --version, -v         Print version information

Examples:
  ludofile document.pdf
  ludofile --format json --output out.json archive.zip
  ludofile --html output.html polyglot.png

For more information, see https://github.com/ludoplex/ludofile
EOF
}

# Find the C binary
find_binary() {
    LUDOFILE_CORE="${LUDOFILE_BIN}/ludofile_core"
    
    if [ -x "$LUDOFILE_CORE" ]; then
        log_debug "Using C binary: ${LUDOFILE_CORE}"
        return 0
    fi
    
    # Try to find in current directory
    if [ -x "${LUDOFILE_DIR}/ludofile_core" ]; then
        LUDOFILE_CORE="${LUDOFILE_DIR}/ludofile_core"
        log_debug "Using C binary: ${LUDOFILE_CORE}"
        return 0
    fi
    
    if [ -x "./ludofile_core" ]; then
        LUDOFILE_CORE="./ludofile_core"
        log_debug "Using C binary: ${LUDOFILE_CORE}"
        return 0
    fi
    
    log_error "ludofile_core binary not found. Please run 'make' to build."
    return 1
}

# Run the C core binary
run_core() {
    ARGS=""
    
    case "$OUTPUT_FORMAT" in
        file) ARGS="$ARGS -r file" ;;
        mime) ARGS="$ARGS -r mime" ;;
        json) ARGS="$ARGS -r json" ;;
        sbud) ARGS="$ARGS -r json" ;;
        html) ARGS="$ARGS -r html" ;;
    esac
    
    [ -n "$OUTPUT_PATH" ] && ARGS="$ARGS -o $OUTPUT_PATH"
    [ -n "$FILETYPE_FILTER" ] && ARGS="$ARGS -f $FILETYPE_FILTER"
    [ "$MAX_MATCHES" -ge 0 ] && ARGS="$ARGS -M $MAX_MATCHES"
    [ "$ONLY_MATCH_MIME" -eq 1 ] && ARGS="$ARGS -I"
    [ "$ONLY_MATCH" -eq 1 ] && ARGS="$ARGS -m"
    [ "$REQUIRE_MATCH" -eq 1 ] && ARGS="$ARGS -R"
    [ "$QUIET" -eq 1 ] && ARGS="$ARGS -q"
    [ "$DEBUG" -eq 1 ] && ARGS="$ARGS -d"
    
    log_debug "Running: ${LUDOFILE_CORE} ${ARGS} ${INPUT_FILE}"
    
    # shellcheck disable=SC2086
    exec "$LUDOFILE_CORE" $ARGS "$INPUT_FILE"
}

# List supported file types
list_types() {
    if find_binary; then
        exec "$LUDOFILE_CORE" -l
    else
        exit 1
    fi
}

# Parse command line arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--version)
                print_version
                exit 0
                ;;
            -dumpversion)
                echo "$LUDOFILE_VERSION"
                exit 0
                ;;
            -r|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_PATH="$2"
                shift 2
                ;;
            -f|--filetype)
                FILETYPE_FILTER="$2"
                shift 2
                ;;
            -l|--list)
                LIST_TYPES=1
                shift
                ;;
            -t|--html)
                HTML_OUTPUT="$2"
                OUTPUT_FORMAT="html"
                shift 2
                ;;
            -I|--only-match-mime)
                ONLY_MATCH_MIME=1
                OUTPUT_FORMAT="mime"
                shift
                ;;
            -m|--only-match)
                ONLY_MATCH=1
                shift
                ;;
            -R|--require-match)
                REQUIRE_MATCH=1
                shift
                ;;
            -M|--max-matches)
                MAX_MATCHES="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -d|--debug)
                DEBUG=1
                shift
                ;;
            -dd|--trace)
                DEBUG=1
                shift
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
            *)
                INPUT_FILE="$1"
                shift
                ;;
        esac
    done
    
    # Handle remaining positional arguments
    while [ $# -gt 0 ]; do
        if [ -z "$INPUT_FILE" ]; then
            INPUT_FILE="$1"
        fi
        shift
    done
    
    # Default to stdin if no input file specified
    if [ -z "$INPUT_FILE" ]; then
        INPUT_FILE="-"
    fi
}

# Main entry point
main() {
    parse_args "$@"
    
    log_debug "LudoFile ${LUDOFILE_VERSION}"
    log_debug "Input: ${INPUT_FILE}"
    log_debug "Format: ${OUTPUT_FORMAT}"
    
    if [ "$LIST_TYPES" -eq 1 ]; then
        list_types
        exit 0
    fi
    
    # Check if input file exists (unless reading from stdin)
    if [ "$INPUT_FILE" != "-" ] && [ ! -f "$INPUT_FILE" ]; then
        log_error "Cannot open '$INPUT_FILE' (No such file or directory)"
        exit 1
    fi
    
    # Find and run C binary
    if find_binary; then
        run_core
    else
        exit 1
    fi
}

# Run main with all arguments
main "$@"
