# udp-proxy-2020 Makefile
# For convenience on systems with make installed

.PHONY: all build release debug test clean install help

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

# Cross-compile for FreeBSD x86_64
freebsd:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-freebsd

# Show help
help:
	@echo "udp-proxy-2020 build targets:"
	@echo "  make          - Build release (optimized)"
	@echo "  make release  - Build release (optimized)"
	@echo "  make debug    - Build debug"
	@echo "  make test     - Run tests"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Install to /usr/local/bin"
	@echo "  make freebsd  - Cross-compile for FreeBSD x86_64"
	@echo "  make help     - Show this help"
