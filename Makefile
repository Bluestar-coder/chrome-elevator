.PHONY: help build-docker build-debug build-release build-check clean docker-build docker-shell test lint format build-all build-x64 build-arm64

# Default target
help:
	@echo "Chrome Elevator - Build Targets"
	@echo "================================"
	@echo ""
	@echo "Multi-platform Docker targets (cross-compile to Windows):"
	@echo "  make build-all             - Build all Windows versions (x64 + ARM64)"
	@echo "  make build-x64             - Build Windows x64 version only"
	@echo "  make build-arm64           - Build Windows ARM64 version only"
	@echo ""
	@echo "Single-platform Docker targets:"
	@echo "  make build-docker          - Full Docker build (x64 release)"
	@echo "  make docker-build-debug    - Docker debug build"
	@echo "  make docker-shell          - Interactive Docker shell"
	@echo ""
	@echo "Local targets (macOS/Linux only):"
	@echo "  make check                 - Cargo check"
	@echo "  make build-release         - Release build (local)"
	@echo "  make build-debug           - Debug build (local)"
	@echo "  make test                  - Run tests"
	@echo "  make lint                  - Run clippy linter"
	@echo "  make format                - Format code with rustfmt"
	@echo "  make format-check          - Check code formatting"
	@echo ""
	@echo "Utility targets:"
	@echo "  make clean                 - Clean build artifacts"
	@echo "  make docker-clean          - Remove Docker image"
	@echo "  make docker-prune          - Clean Docker system"
	@echo ""

# Multi-platform targets
build-all: docker-build
	@echo "Building all Windows versions..."
	@echo ""
	@echo "Building Windows x64 (x86_64)..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --release --target x86_64-pc-windows-gnu
	@echo "✓ x64 build complete"
	@echo ""
	@echo "Building Windows ARM64 (aarch64)..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --release --target aarch64-pc-windows-gnu
	@echo "✓ ARM64 build complete"
	@echo ""
	@echo "✓ All builds complete!"
	@echo ""
	@echo "Output files:"
	@echo "  x64:   target/x86_64-pc-windows-gnu/release/chrome-elevator.exe"
	@echo "  ARM64: target/aarch64-pc-windows-gnu/release/chrome-elevator.exe"

build-x64: docker-build
	@echo "Building Windows x64 version..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --release --target x86_64-pc-windows-gnu
	@echo "✓ x64 build complete: target/x86_64-pc-windows-gnu/release/chrome-elevator.exe"

build-arm64: docker-build
	@echo "Building Windows ARM64 version..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --release --target aarch64-pc-windows-gnu
	@echo "✓ ARM64 build complete: target/aarch64-pc-windows-gnu/release/chrome-elevator.exe"

# Single-platform Docker targets
build-docker: docker-build
	@echo "Building Chrome Elevator for Windows (x86_64)..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --release --target x86_64-pc-windows-gnu
	@echo "✓ Build complete: target/x86_64-pc-windows-gnu/release/chrome-elevator.exe"

docker-build-debug: docker-build
	@echo "Building Docker image for debug build..."
	@echo "Building Chrome Elevator for Windows (Debug)..."
	docker run --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		cargo build --target x86_64-pc-windows-gnu
	@echo "✓ Build complete: target/x86_64-pc-windows-gnu/debug/chrome-elevator.exe"

docker-shell: docker-build
	@echo "Starting interactive Docker shell..."
	docker run -it --rm \
		-v $$(pwd):/workspace \
		-w /workspace \
		chrome-elevator:windows-build \
		/bin/bash

docker-build:
	@echo "Building Docker image..."
	docker build -t chrome-elevator:windows-build .
	@echo "✓ Docker image built"

docker-clean:
	@echo "Removing Docker image..."
	docker rmi chrome-elevator:windows-build 2>/dev/null || echo "Image not found"
	@echo "✓ Docker image removed"

docker-prune:
	@echo "Cleaning Docker system..."
	docker system prune -a
	@echo "✓ Docker system cleaned"

# Local targets
check:
	@echo "Running cargo check..."
	cargo check

build-release:
	@echo "Building release (local)..."
	cargo build --release

build-debug:
	@echo "Building debug (local)..."
	cargo build

test:
	@echo "Running tests..."
	cargo test

lint:
	@echo "Running clippy..."
	cargo clippy --all-targets --all-features -- -D warnings

format:
	@echo "Formatting code..."
	cargo fmt

format-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

# Utility targets
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/
	@echo "✓ Cleaned"

.PHONY: all
all: lint format check build-release
	@echo "✓ All checks passed and build successful"

# Print variables (for debugging)
.PHONY: print-%
print-%:
	@echo $* = $($*)
