# udp-proxy-2020 Makefile
# For convenience on systems with make installed

.PHONY: all build release debug test clean install help

# Detect OS
UNAME_S := $(shell uname -s)

# Default target
all: release

# Release build (optimized)
release:
	zig build -Doptimize=ReleaseSmall

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
	set path = ( /root/project/zig-x86_64-freebsd-0.15.2 $path )
	zig build -Doptimize=ReleaseSmall

# Show help
help:
	@echo "udp-proxy-2020 build targets:"
	@echo "  make          - Build release (optimized)"
	@echo "  make release  - Build release (optimized)"
	@echo "  make debug    - Build debug"
	@echo "  make test     - Run tests"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Install to /usr/local/bin"
	@echo "  make freebsd  - Build for FreeBSD (native only)"
	@echo "  make help     - Show this help"
