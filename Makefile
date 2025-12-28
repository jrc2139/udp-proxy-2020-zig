# udp-proxy-2020 Makefile
# For convenience on systems with make installed

.PHONY: all build release debug test clean install help \
        docker-build docker-test docker-clean integration-test

# Detect OS
UNAME_S := $(shell uname -s)

# Default target
all: release

# Release build (optimized)
release:
	zig build -Doptimize=ReleaseFast

# Debug build
debug:
	zig build

# Run tests
test:
	zig build test

# Clean build artifacts
clean:
	rm -rf zig-out .zig-cache

# Install to /usr/local/bin (requires root)
install: release
	install -m 755 zig-out/bin/udp-proxy-2020 /usr/local/bin/

# Build for FreeBSD
# If already on FreeBSD, build natively. Otherwise error (cross-compile needs sysroot).
freebsd:
	# set path = ( /root/project/zig-x86_64-freebsd-0.15.2 $path )
	zig build -Doptimize=ReleaseFast

# =============================================================================
# Docker / Integration Tests
# =============================================================================

# Build Docker images
docker-build:
	docker compose build

# Run integration tests in Docker
docker-test: docker-build
	docker compose up -d proxy
	docker compose run --rm test-runner
	docker compose down -v

# Alias for docker-test
integration-test: docker-test

# Clean Docker resources
docker-clean:
	docker compose down -v --rmi local
	docker system prune -f

# =============================================================================
# Help
# =============================================================================

# Show help
help:
	@echo "udp-proxy-2020 build targets:"
	@echo ""
	@echo "  Building:"
	@echo "    make          - Build release (optimized)"
	@echo "    make release  - Build release (optimized)"
	@echo "    make debug    - Build debug"
	@echo "    make freebsd  - Build for FreeBSD (native only)"
	@echo ""
	@echo "  Testing:"
	@echo "    make test           - Run unit tests"
	@echo "    make integration-test - Run integration tests (Docker)"
	@echo "    make docker-test    - Run integration tests (Docker)"
	@echo ""
	@echo "  Docker:"
	@echo "    make docker-build   - Build Docker images"
	@echo "    make docker-clean   - Remove Docker resources"
	@echo ""
	@echo "  Other:"
	@echo "    make clean    - Remove build artifacts"
	@echo "    make install  - Install to /usr/local/bin"
	@echo "    make help     - Show this help"
