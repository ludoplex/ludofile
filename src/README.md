# LudoFile C Implementation

This directory contains the Cosmopolitan C implementation of LudoFile's
file analysis functionality. The C components provide high-performance file
analysis capabilities and are designed to be portable using Cosmopolitan libc.

## Architecture

The C implementation is organized into modules with clear separation of concerns:

```
src/
├── core/          Core types and utilities
│   ├── types.h    Data structure definitions
│   └── types.c    Core type implementations
├── magic/         Magic pattern matching (libmagic replacement)
│   ├── magic.h    Magic matcher interface
│   └── magic.c    Pattern matching implementation
├── output/        Output formatters
│   ├── output.h   Output format interfaces
│   └── output.c   JSON, HTML, SBUD output
├── parsers/       File format parsers
│   ├── parser.h   Parser plugin interface
│   ├── parser.c   Parser registry
│   ├── pdf.h/c    PDF document parser
│   └── zip.h/c    ZIP archive parser
└── main.c         Main entry point
```

## Building

### Standard Build

```bash
make
```

### Debug Build

```bash
make debug
```

### Static Build

```bash
make static
```

### Cosmopolitan APE Build

For building an Actually Portable Executable (APE) using Cosmopolitan libc:

```bash
./scripts/build.sh --cosmo
```

## APE Shell Coordination

The `scripts/ludofile.sh` script serves as the coordinator that invokes
the C binary with appropriate arguments.

### Usage

```bash
# Use via the shell coordinator
./scripts/ludofile.sh [OPTIONS] [FILE]

# Or directly use the C binary
./bin/ludofile_core [OPTIONS] [FILE]
```

### Options

- `-r, --format FORMAT` - Output format (file, mime, json, html)
- `-o, --output PATH` - Output file path
- `-f, --filetype TYPE` - Match against specific file type
- `-l, --list` - List supported file types
- `-t, --html PATH` - Write interactive HTML viewer
- `-I, --only-match-mime` - Print matching MIME types only
- `-m, --only-match` - Match only, don't parse
- `-R, --require-match` - Exit with code 127 if no match
- `-q, --quiet` - Suppress all log output
- `-d, --debug` - Print debug information
- `-v, --version` - Print version information

## Module Details

### Core Module (`src/core/`)

Defines fundamental data structures:

- `ByteBuffer` - Growable byte array
- `StringBuffer` - Growable string
- `FileStream` - Unified file access abstraction
- `Offset` - Magic pattern offset specifications
- `MatchResult` - Test match results
- `ParseMatch` - Structured parsing results

### Magic Module (`src/magic/`)

Implements libmagic-compatible file type detection:

- `MagicMatcher` - Main pattern matcher
- `MagicTest` - Individual pattern tests
- `MatchContext` - Matching context and state
- `Match` - Collection of match results

Supported test types:
- Numeric comparisons (byte, short, long, quad)
- String matching (exact, case-insensitive, regex)
- Default and clear tests
- Indirect tests
- Named test references (use)

### Output Module (`src/output/`)

Provides output formatting:

- **File format** - Like the `file` command
- **MIME format** - MIME types only
- **JSON/SBUD format** - Semantic Binary Universal Description
- **HTML format** - Interactive hex viewer

### Parsers Module (`src/parsers/`)

File format parsers:

- **PDF Parser** - Parses PDF document structure including objects, 
  streams, and cross-reference tables
- **ZIP Parser** - Parses ZIP archive structure including local headers,
  central directory, and end of central directory record

## Testing

```bash
make check
```

## License

Apache License Version 2.0

Copyright (c) 2024 LudoPlex
