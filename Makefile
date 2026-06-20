# fle - Zig Library Makefile
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2025 CodePros

.PHONY: all build test test-unit test-integration bench clean check fmt help dev ci
.PHONY: test-release-safe test-release-fast test-release-small test-all-optimizations
.PHONY: pre-commit-install pre-commit pre-commit-run test-fips test-dual

# Default target: build and run tests
all: build test-unit
	@echo "✅ All builds and tests completed successfully!"

# Build the library
build:
	@echo "🔨 Building fle..."
	@zig build

# Run all tests
test: test-unit test-integration
	@echo "✅ All tests completed"

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	@zig build test --summary all

# Run integration tests only
test-integration:
	@echo "🔗 Running integration tests..."
	@zig build test-integration --summary all

# Run the suite against the linked OpenSSL FIPS-140-3 provider (-Dfips=true).
# Requires the FIPS-built OpenSSL (see the `fips` package `make deps`,
# default prefix /usr/local/ssl; override with OPENSSL_PREFIX=).
test-fips:
	@echo "🔐 Running FIPS-mode tests..."
	@OPENSSL_CONF=$(or $(OPENSSL_PREFIX),/usr/local/ssl)/ssl/openssl.cnf zig build test -Dfips=true -Dopenssl_path=$(or $(OPENSSL_PREFIX),/usr/local/ssl) --summary all
	@OPENSSL_CONF=$(or $(OPENSSL_PREFIX),/usr/local/ssl)/ssl/openssl.cnf zig build test-integration -Dfips=true -Dopenssl_path=$(or $(OPENSSL_PREFIX),/usr/local/ssl) --summary all

# Run BOTH the std-shim suite (-Dfips=false) and the OpenSSL FIPS suite
# (-Dfips=true). The dual-mode gate for the FIPS/PQC consolidation.
test-dual: test test-fips
	@echo "✅ Dual-mode (-Dfips on/off) tests completed"

# Run micro-benchmarks (full module graph in ReleaseFast)
bench:
	@echo "🏎️  Running benchmarks..."
	@zig build bench -Doptimize=ReleaseFast

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf zig-cache zig-out .zig-cache

# Check for compilation errors (fast, no codegen)
check:
	@echo "🔍 Checking for compilation errors..."
	@zig build check

# Format source code
fmt:
	@echo "📝 Formatting code..."
	@zig fmt src/ tests/ build.zig

# Quick development iteration loop
dev: fmt check test-unit
	@echo "✅ Development checks passed"

# Full CI pipeline (clean slate)
ci: clean build test
	@echo "✅ CI pipeline passed"

# Release optimization level tests
test-release-safe:
	@echo "🧪 Testing with ReleaseSafe..."
	@zig build test -Doptimize=ReleaseSafe --summary all

test-release-fast:
	@echo "🧪 Testing with ReleaseFast..."
	@zig build test -Doptimize=ReleaseFast --summary all

test-release-small:
	@echo "🧪 Testing with ReleaseSmall..."
	@zig build test -Doptimize=ReleaseSmall --summary all

test-all-optimizations: test-unit test-release-safe test-release-fast test-release-small
	@echo "✅ All optimization levels passed"

# Pre-commit hook management
pre-commit-install:
	@echo "📦 Installing pre-commit hooks..."
	@pre-commit install
	@pre-commit install --hook-type commit-msg
	@pre-commit install --hook-type pre-push

pre-commit:
	@echo "🔍 Running pre-commit checks..."
	@pre-commit run --all-files

pre-commit-run: pre-commit

# Display help
help:
	@echo "fle - Zig Library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  all                  Build and run tests (default)"
	@echo "  build                Build the library"
	@echo "  dev                  Quick iteration: fmt + check + test"
	@echo "  ci                   Full CI: clean + build + test"
	@echo ""
	@echo "Testing:"
	@echo "  test                 Run all tests"
	@echo "  test-unit            Run unit tests only"
	@echo "  test-integration     Run integration tests only"
	@echo "  test-release-safe    Test with ReleaseSafe"
	@echo "  test-release-fast    Test with ReleaseFast"
	@echo "  test-release-small   Test with ReleaseSmall"
	@echo "  test-all-optimizations  Test all optimization levels"
	@echo "  bench                Run micro-benchmarks (ReleaseFast)"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt                  Format source code"
	@echo "  check                Check for compilation errors"
	@echo "  pre-commit           Run pre-commit hooks"
	@echo "  pre-commit-install   Install pre-commit hooks"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean                Remove build artifacts"
	@echo "  help                 Show this help message"
