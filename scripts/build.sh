#!/bin/sh
# LudoFile Build Script
#
# This script builds the LudoFile C components using Cosmopolitan libc
# for portability. The resulting binary is an Actually Portable Executable (APE).
#
# Copyright (c) 2024 LudoPlex
# SPDX-License-Identifier: Apache-2.0

set -e

# Configuration
SCRIPT_DIR="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SRC_DIR="${PROJECT_ROOT}/src"
BUILD_DIR="${PROJECT_ROOT}/build"
BIN_DIR="${PROJECT_ROOT}/bin"

# Compiler settings
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2 -Wall -Wextra -pedantic}"
LDFLAGS="${LDFLAGS:-}"

# Build options
BUILD_DEBUG=0
BUILD_STATIC=0
USE_COSMOPOLITAN=0
CLEAN_BUILD=0
VERBOSE=0

# Cosmopolitan libc paths (if available)
COSMO_DIR="${COSMO_DIR:-/opt/cosmo}"
COSMO_CC="${COSMO_DIR}/o/third_party/gcc/bin/x86_64-linux-musl-gcc"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build the LudoFile C components.

Options:
  -h, --help        Show this help message
  -d, --debug       Build with debug symbols
  -s, --static      Build static binary
  -c, --cosmo       Build with Cosmopolitan libc (APE)
  --clean           Clean build directory first
  -v, --verbose     Show verbose build output

Environment Variables:
  CC                C compiler (default: cc)
  CFLAGS            Compiler flags (default: -O2 -Wall -Wextra -pedantic)
  LDFLAGS           Linker flags
  COSMO_DIR         Cosmopolitan libc directory (default: /opt/cosmo)

Examples:
  $(basename "$0")                    # Standard build
  $(basename "$0") --debug            # Debug build
  $(basename "$0") --cosmo            # APE build with Cosmopolitan
  $(basename "$0") --clean --cosmo    # Clean build with Cosmopolitan
EOF
}

# Parse command line arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            -d|--debug)
                BUILD_DEBUG=1
                CFLAGS="-g -O0 -Wall -Wextra -DDEBUG"
                shift
                ;;
            -s|--static)
                BUILD_STATIC=1
                LDFLAGS="${LDFLAGS} -static"
                shift
                ;;
            -c|--cosmo)
                USE_COSMOPOLITAN=1
                shift
                ;;
            --clean)
                CLEAN_BUILD=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Check for required tools
check_requirements() {
    log_info "Checking build requirements..."
    
    if ! command -v "$CC" >/dev/null 2>&1; then
        log_error "C compiler not found: $CC"
        exit 1
    fi
    
    if [ "$USE_COSMOPOLITAN" -eq 1 ]; then
        if [ ! -d "$COSMO_DIR" ]; then
            log_warn "Cosmopolitan directory not found: $COSMO_DIR"
            log_info "Attempting to download Cosmopolitan..."
            download_cosmopolitan
        fi
        
        if [ ! -f "${COSMO_DIR}/cosmopolitan.h" ]; then
            log_error "Cosmopolitan header not found: ${COSMO_DIR}/cosmopolitan.h"
            log_info "Please install Cosmopolitan libc or set COSMO_DIR"
            exit 1
        fi
    fi
    
    log_success "Build requirements satisfied"
}

# Download and setup Cosmopolitan (if not present)
download_cosmopolitan() {
    if [ -d "$COSMO_DIR" ]; then
        return 0
    fi
    
    log_info "Downloading Cosmopolitan libc..."
    
    mkdir -p "$(dirname "$COSMO_DIR")"
    
    # Download amalgamation
    COSMO_URL="https://justine.lol/cosmopolitan/cosmopolitan.zip"
    
    if command -v curl >/dev/null 2>&1; then
        curl -L -o /tmp/cosmopolitan.zip "$COSMO_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -O /tmp/cosmopolitan.zip "$COSMO_URL"
    else
        log_error "Neither curl nor wget available for download"
        return 1
    fi
    
    mkdir -p "$COSMO_DIR"
    unzip -q /tmp/cosmopolitan.zip -d "$COSMO_DIR"
    rm /tmp/cosmopolitan.zip
    
    log_success "Cosmopolitan libc installed to $COSMO_DIR"
}

# Clean build directory
clean_build() {
    if [ -d "$BUILD_DIR" ]; then
        log_info "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
    fi
    if [ -d "$BIN_DIR" ]; then
        log_info "Cleaning bin directory..."
        rm -rf "$BIN_DIR"
    fi
}

# Create build directories
setup_directories() {
    log_info "Setting up build directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "$BIN_DIR"
}

# Compile a C source file
compile_file() {
    SRC="$1"
    OBJ="$2"
    
    if [ "$VERBOSE" -eq 1 ]; then
        log_info "Compiling: $SRC -> $OBJ"
    fi
    
    if [ "$USE_COSMOPOLITAN" -eq 1 ]; then
        # Cosmopolitan build
        $CC $CFLAGS -include "${COSMO_DIR}/cosmopolitan.h" \
            -I"$SRC_DIR" \
            -fno-pie -nostdinc \
            -c "$SRC" -o "$OBJ"
    else
        # Standard build
        $CC $CFLAGS \
            -I"$SRC_DIR" \
            -c "$SRC" -o "$OBJ"
    fi
}

# Link object files
link_binary() {
    OUTPUT="$1"
    shift
    OBJECTS="$*"
    
    log_info "Linking: $OUTPUT"
    
    if [ "$USE_COSMOPOLITAN" -eq 1 ]; then
        # Cosmopolitan APE linking
        $CC $CFLAGS -fno-pie -nostdlib -nostdinc \
            $OBJECTS \
            -Wl,-T,"${COSMO_DIR}/ape.lds" \
            "${COSMO_DIR}/crt.o" \
            "${COSMO_DIR}/ape-no-modify-self.o" \
            "${COSMO_DIR}/cosmopolitan.a" \
            -o "$OUTPUT"
    else
        # Standard linking
        $CC $CFLAGS $LDFLAGS \
            $OBJECTS \
            -o "$OUTPUT"
    fi
}

# Build core library
build_core() {
    log_info "Building core library..."
    
    compile_file "${SRC_DIR}/core/types.c" "${BUILD_DIR}/types.o"
    
    log_success "Core library built"
}

# Build magic library
build_magic() {
    log_info "Building magic library..."
    
    compile_file "${SRC_DIR}/magic/magic.c" "${BUILD_DIR}/magic.o"
    
    log_success "Magic library built"
}

# Build main binary
build_main() {
    log_info "Building main binary..."
    
    compile_file "${SRC_DIR}/main.c" "${BUILD_DIR}/main.o"
    
    # Link everything together
    link_binary "${BIN_DIR}/ludofile_core" \
        "${BUILD_DIR}/main.o" \
        "${BUILD_DIR}/types.o" \
        "${BUILD_DIR}/magic.o"
    
    chmod +x "${BIN_DIR}/ludofile_core"
    
    log_success "Main binary built: ${BIN_DIR}/ludofile_core"
}

# Create symlink for APE shell script
create_symlink() {
    log_info "Creating symlink..."
    
    if [ ! -f "${BIN_DIR}/ludofile" ]; then
        ln -sf "../scripts/ludofile.sh" "${BIN_DIR}/ludofile"
    fi
    
    log_success "Symlink created: ${BIN_DIR}/ludofile"
}

# Run tests
run_tests() {
    log_info "Running basic tests..."
    
    if [ -f "${BIN_DIR}/ludofile_core" ]; then
        # Test version
        "${BIN_DIR}/ludofile_core" --version
        
        # Test list
        "${BIN_DIR}/ludofile_core" --list | head -5
        
        log_success "Basic tests passed"
    else
        log_warn "Binary not found, skipping tests"
    fi
}

# Print build summary
print_summary() {
    echo ""
    log_info "Build Summary"
    echo "=============="
    echo "  Compiler:    $CC"
    echo "  CFLAGS:      $CFLAGS"
    echo "  Output:      ${BIN_DIR}/ludofile_core"
    
    if [ "$USE_COSMOPOLITAN" -eq 1 ]; then
        echo "  Type:        APE (Actually Portable Executable)"
        echo "  Cosmo Dir:   $COSMO_DIR"
    else
        echo "  Type:        Native"
    fi
    
    if [ -f "${BIN_DIR}/ludofile_core" ]; then
        SIZE=$(wc -c < "${BIN_DIR}/ludofile_core" 2>/dev/null || echo "unknown")
        echo "  Size:        $SIZE bytes"
    fi
    
    echo ""
}

# Main entry point
main() {
    parse_args "$@"
    
    log_info "LudoFile Build System"
    log_info "====================="
    
    if [ "$CLEAN_BUILD" -eq 1 ]; then
        clean_build
    fi
    
    check_requirements
    setup_directories
    
    build_core
    build_magic
    build_main
    create_symlink
    
    print_summary
    
    if [ "$BUILD_DEBUG" -eq 0 ]; then
        run_tests
    fi
    
    log_success "Build completed successfully!"
}

main "$@"
