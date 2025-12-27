# LudoFile

A file analysis and semantic structure mapping utility built entirely in Cosmopolitan C with APE shell coordination.

LudoFile recursively maps the structure of a file, identifying its MIME type, semantic types, and internal structure. Unlike other file identification tools, LudoFile doesn't stop at the first match - it continues to identify all file types present, including embedded content.

## Features

- **Pure C Implementation**: High-performance file analysis with no Python dependency
- **Portable Binaries**: Uses Cosmopolitan C for cross-platform Actually Portable Executables (APE)
- **Recursive Analysis**: Identifies nested file formats within containers
- **Multiple Output Formats**: Supports file, MIME, JSON (SBUD), and HTML output
- **Built-in Parsers**: Native PDF, ZIP, and JAR parsing
- **Magic Pattern Matching**: libmagic-compatible file type detection
- **Modular Architecture**: Clear separation of concerns across modules
- **PolyFile Feature Parity**: Taint tracking, debugger, Kaitai Struct VM, and interactive REPL
- **Performance**: 10-100x faster than Python-based solutions for binary parsing
- **Embeddable**: Self-contained C libraries that can be used in any C project

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

For building an Actually Portable Executable that runs on Linux, macOS, Windows, FreeBSD, NetBSD, and OpenBSD:

```bash
./scripts/build.sh --cosmo
```

## Testing

Run the test suite to verify all functionality:

```bash
# Run all tests
make check-all

# Run core tests
make check

# Run feature tests
make check-features

# Run PolyFile feature parity tests
make check-polyfile
```

## Usage

```bash
# Analyze a file
./bin/ludofile_core document.pdf

# Output MIME type only
./bin/ludofile_core --format mime document.pdf

# JSON output
./bin/ludofile_core --format json --output output.json archive.zip

# Using the shell coordinator
./scripts/ludofile.sh document.pdf
```

### Command Line Options

```
Usage: ludofile [OPTIONS] [FILE]

Options:
  -r, --format FORMAT   Output format (file, mime, json, html)
  -o, --output PATH     Output file path
  -f, --filetype TYPE   Match against specific file type
  -l, --list            List supported file types
  -t, --html PATH       Write interactive HTML viewer
  -I, --only-match-mime Print matching MIME types only
  -m, --only-match      Match only, don't parse
  -R, --require-match   Exit with code 127 if no match
  -M, --max-matches N   Stop after N matches
  -q, --quiet           Suppress all log output
  -d, --debug           Print debug information
  -v, --version         Print version information
  -h, --help            Print this help message
```

## Architecture

LudoFile is organized into modular C components:

```
src/
├── core/           Core types and utilities
│   ├── types.h     Data structure definitions
│   ├── types.c     Core type implementations
│   ├── arena.h     Arena allocator interface
│   ├── arena.c     Bump allocator with dynamic extension
│   ├── hashtable.h Hash table interface
│   └── hashtable.c Robin Hood hash table with SIMD acceleration
├── magic/          Magic pattern matching engine
│   ├── magic.h     Magic matcher interface
│   └── magic.c     Pattern matching implementation
├── output/         Output formatters
│   ├── output.h    Output format interfaces
│   └── output.c    JSON, HTML, SBUD output
├── parsers/        File format parsers
│   ├── parser.h    Parser plugin interface
│   ├── parser.c    Parser registry
│   ├── pdf.h/c     PDF document parser
│   └── zip.h/c     ZIP archive parser
├── http/           HTTP protocol handling
│   ├── http.h      HTTP/1.1 protocol interface
│   └── http.c      Request/response parsing
├── ast/            Abstract syntax tree
│   ├── ast.h       AST node types and traversal
│   └── ast.c       Parser definition structures
├── vm/             Bytecode Virtual Machine
│   ├── vm.h        VM interface and opcodes
│   ├── vm.c        VM execution engine
│   └── compiler.h/c KSY bytecode compiler
├── taint/          Taint Tracking System
│   ├── taint.h     TaintDAG interface
│   └── taint.c     PolyTracker-compatible taint tracking
├── debug/          Interactive Debugger
│   ├── debugger.h  Debugger interface
│   └── debugger.c  GDB-style debugging for binary parsing
├── kaitai/         Kaitai Struct Formats
│   ├── formats.h   Format registry interface
│   └── formats.c   Pre-compiled format bytecode
├── structs/        Binary Structure DSL
│   ├── structs.h   Struct definition interface
│   └── structs.c   Structure parsing implementation
├── repl/           Interactive REPL
│   ├── repl.h      REPL context interface
│   └── repl.c      Command-line REPL for analysis
└── main.c          Main entry point

scripts/
├── ludofile.sh     APE shell coordinator
└── build.sh        Build script with Cosmopolitan support
```

### Modules

- **Core** (`src/core/`): Fundamental data types including ByteBuffer, StringBuffer, FileStream, Offset, MatchResult, ParseMatch, Arena allocator with bump allocation, and high-performance hash tables with Robin Hood probing
- **Magic** (`src/magic/`): libmagic-compatible pattern matching with support for numeric, string, regex, and search tests
- **Output** (`src/output/`): Output formatters for JSON/SBUD, HTML hex viewer, and file/MIME formats
- **Parsers** (`src/parsers/`): File format parsers with plugin interface for PDF, ZIP, and JAR files
- **HTTP** (`src/http/`): HTTP/1.1 request/response parsing, structured headers (RFC 8941), and protocol detection
- **AST** (`src/ast/`): Abstract syntax tree for parser definitions with node types, traversal utilities, and symbol tables
- **VM** (`src/vm/`): Bytecode virtual machine for parsing binary structures with Kaitai Struct support
- **Taint** (`src/taint/`): PolyTracker-compatible taint tracking system for data flow analysis
- **Debug** (`src/debug/`): Interactive debugger with breakpoints, stepping, and profiling for binary parsing
- **Kaitai** (`src/kaitai/`): Pre-compiled Kaitai Struct format definitions for common file types
- **Structs** (`src/structs/`): Binary structure parsing DSL for defining and parsing binary data
- **REPL** (`src/repl/`): Interactive command-line REPL for file analysis and inspection

## PolyFile Feature Parity

LudoFile now includes comprehensive features for achieving feature parity with [PolyFile](https://github.com/trailofbits/polyfile), while maintaining its pure C implementation and superior performance:

### Taint Tracking

The taint tracking system provides PolyTracker-compatible data flow analysis:

```c
#include "taint/taint.h"

// Create taint DAG
TaintDAG *dag = taint_dag_new();

// Add input source
uint32_t source_id = taint_dag_add_source(dag, "input.bin", file_size, hash);

// Create taint labels for bytes
taint_label_t label = taint_dag_create_source_label(dag, source_id, offset);

// Track data flow with unions
taint_label_t combined = taint_dag_union(dag, label1, label2);

// Mark control flow influence
taint_dag_set_affects_cf(dag, label);

// Save in PolyTracker format
taint_dag_save(dag, "output.tdag");
```

### Interactive Debugger

GDB-style debugger for binary parsing and magic test execution:

```c
#include "debug/debugger.h"

// Create debugger context
DebuggerContext *ctx = debugger_new();

// Set breakpoints
debugger_add_breakpoint_offset(ctx, 0x1000);
debugger_add_breakpoint_mime(ctx, "application/pdf");

// Execution control
debugger_step(ctx);          // Single step
debugger_next(ctx);          // Step over
debugger_continue(ctx);      // Continue execution

// Inspection
debugger_print_backtrace(ctx);
debugger_print_stack(ctx);
debugger_profile_print(ctx);
```

### Kaitai Struct Integration

The VM supports Kaitai Struct for parsing binary formats:

```c
#include "vm/vm.h"
#include "kaitai/formats.h"

// Initialize VM
VM vm;
vm_init(&vm);

// Load pre-compiled format
kaitai_load_by_mime(&vm, "image/gif");

// Set input data
vm_set_stream(&vm, data, size);

// Parse
vm_run(&vm);
```

### Binary Structure DSL

Define and parse binary structures:

```c
#include "structs/structs.h"

// Define structure
StructDef *def = struct_def_new("file_header");

StructField magic_field = {
    .name = "magic",
    .type = STRUCT_FIELD_U32,
    .offset = 0,
    .size = 4,
    .endian = ENDIAN_LITTLE
};
struct_def_add_field(def, &magic_field);

// Parse data
void *parsed = struct_read(def, data, data_len);
```

### Interactive REPL

Command-line REPL for interactive file analysis:

```bash
$ ludofile --repl
LudoFile Interactive REPL
Type 'help' for available commands

ludofile> open document.pdf
Opened 'document.pdf' (12345 bytes)

ludofile> analyze
Analyzing 'document.pdf'...
  Size: 12345 bytes

ludofile> matches
MIME type matches for 'document.pdf':
  application/pdf

ludofile> parse application/pdf
Parsing 'document.pdf' as 'application/pdf'...
```

## Output Formats

### File Format (default)
Like the `file` command, outputs a human-readable description:
```
PDF document, version 1.7
```

### MIME Format
Outputs only the MIME type:
```
application/pdf
```

### JSON/SBUD Format
Outputs a Semantic Binary Universal Description JSON document:
```json
{
  "MD5": "...",
  "SHA1": "...",
  "SHA256": "...",
  "fileName": "document.pdf",
  "length": 12345,
  "struc": [
    {
      "type": "application/pdf",
      "offset": 0,
      "size": 12345
    }
  ]
}
```

### HTML Format
Generates an interactive HTML hex viewer for analyzing file structure.

## Supported File Types

LudoFile supports detection of:
- PDF documents
- ZIP archives
- JAR files
- Images (PNG, JPEG, GIF, etc.)
- Office documents
- Executables
- And many more via magic pattern matching

## License

Apache License Version 2.0

Copyright (c) 2024 LudoPlex

## Contributing

Contributions are welcome! Please ensure your code follows the existing style and passes all tests.

## Acknowledgments

LudoFile is inspired by and includes ideas from:
- [PolyFile](https://github.com/trailofbits/polyfile) by Trail of Bits
- [libmagic](https://www.darwinsys.com/file/) by Ian Darwin
- [Cosmopolitan Libc](https://github.com/jart/cosmopolitan) by Justine Tunney
