# LudoFile Makefile
#
# Build the LudoFile C components.
#
# Copyright (c) 2024 LudoPlex
# SPDX-License-Identifier: Apache-2.0

# Configuration
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c11
LDFLAGS ?=

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source files
CORE_SRCS = $(SRC_DIR)/core/types.c
MAGIC_SRCS = $(SRC_DIR)/magic/magic.c
OUTPUT_SRCS = $(SRC_DIR)/output/output.c
PARSER_SRCS = $(SRC_DIR)/parsers/parser.c
MAIN_SRCS = $(SRC_DIR)/main.c

ALL_SRCS = $(CORE_SRCS) $(MAGIC_SRCS) $(OUTPUT_SRCS) $(PARSER_SRCS) $(MAIN_SRCS)

# Object files
CORE_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))
MAGIC_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAGIC_SRCS))
OUTPUT_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(OUTPUT_SRCS))
PARSER_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(PARSER_SRCS))
MAIN_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAIN_SRCS))

ALL_OBJS = $(CORE_OBJS) $(MAGIC_OBJS) $(OUTPUT_OBJS) $(PARSER_OBJS) $(MAIN_OBJS)

# Target binary
TARGET = $(BIN_DIR)/ludofile_core

# Include directories
INCLUDES = -I$(SRC_DIR)

# Phony targets
.PHONY: all clean debug static install test help

# Default target
all: $(TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/core $(BUILD_DIR)/magic $(BUILD_DIR)/output $(BUILD_DIR)/parsers

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link final binary
$(TARGET): $(ALL_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJS) -o $@

# Debug build
debug: CFLAGS = -g -O0 -Wall -Wextra -DDEBUG
debug: clean all

# Static build
static: LDFLAGS += -static
static: all

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Install (copy to system location)
install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/ludofile_core
	install -m 755 scripts/ludofile.sh $(DESTDIR)/usr/local/bin/ludofile

# Run tests
test: all
	@echo "Running tests..."
	@./$(TARGET) --version
	@./$(TARGET) --help | head -5
	@echo "Tests passed!"

# Help
help:
	@echo "LudoFile Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the project (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  static   - Build static binary"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system"
	@echo "  test     - Run tests"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CC       - C compiler (default: cc)"
	@echo "  CFLAGS   - Compiler flags"
	@echo "  LDFLAGS  - Linker flags"
