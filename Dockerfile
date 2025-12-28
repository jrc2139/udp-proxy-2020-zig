# udp-proxy-2020-zig Docker Build
# Multi-stage build: Zig compiler + Runtime with libpcap

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.15.0
ARG ZIG_VERSION=0.15.0
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /usr/local --strip-components=1

# Copy source code
WORKDIR /build
COPY build.zig build.zig.zon* ./
COPY src/ src/

# Build release binary
RUN zig build -Doptimize=ReleaseFast

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM ubuntu:24.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    iproute2 \
    iputils-ping \
    tcpdump \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary from builder
COPY --from=builder /build/zig-out/bin/udp-proxy-2020 /usr/local/bin/

# Add healthcheck
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
    CMD pgrep udp-proxy-2020 || exit 1

# Default command shows help
CMD ["udp-proxy-2020", "--help"]

# =============================================================================
# Stage 3: Test Runner (includes test utilities)
# =============================================================================
FROM ubuntu:24.04 AS test-runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    iproute2 \
    iputils-ping \
    procps \
    bash \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Copy test scripts
COPY tests/integration/ /tests/

WORKDIR /tests
CMD ["bash"]
