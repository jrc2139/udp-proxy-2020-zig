# CLAUDE.md - AI Assistant Guide for udp-proxy-2020-zig

## Project Overview

**udp-proxy-2020** is a high-performance UDP broadcast packet forwarder written in Zig. It forwards UDP broadcast packets between network interfaces using libpcap for packet capture and injection. This enables UDP broadcast services (Sonos, Ubiquiti device discovery, mDNS, etc.) to work across VLANs, VPN tunnels, and different network segments.

This is a Zig port of the original Go-based [udp-proxy-2020](https://github.com/synfinatic/udp-proxy-2020) for improved performance, particularly on FreeBSD/pfSense.

## Quick Reference

### Build Commands
```bash
# Development build (debug)
zig build
# or
make debug

# Release build (optimized)
zig build -Doptimize=ReleaseFast
# or
make release
# or just
make

# Run tests
zig build test
# or
make test

# Clean build artifacts
make clean

# Install to /usr/local/bin (requires root)
make install

# Cross-compile for FreeBSD from Linux
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-freebsd

# Check for compilation errors (used by ZLS)
zig build check
```

### Requirements
- Zig 0.15.x (minimum 0.15.0)
- libpcap (`libpcap-dev` on Debian/Ubuntu, included in FreeBSD base)

## Architecture

```
src/
├── main.zig         # CLI entry point, argument parsing, thread orchestration
├── lib.zig          # Public API exports (for use as a library)
├── pcap.zig         # libpcap C bindings (capture/injection)
├── packet.zig       # Network packet structures (Ethernet, IPv4, UDP)
├── bpf.zig          # BPF filter construction
├── client_cache.zig # TTL-based client IP cache (thread-safe)
├── sender.zig       # Packet forwarding infrastructure (zero-copy ring buffers)
├── listener.zig     # Per-interface packet handler
└── tests.zig        # Test aggregator
```

### Key Components

1. **pcap.zig** - libpcap bindings
   - `Handle`: Wraps `pcap_t` for packet capture/injection
   - `Dumper`: Writes pcap debug files
   - `findAllDevices()`: Enumerates network interfaces
   - `LinkType`: Supported link types (Ethernet, BSD loopback, raw IP)

2. **packet.zig** - Network packet handling
   - `EthernetHeader`, `IPv4Header`, `UdpHeader`: Packed structs matching wire format
   - `ParsedPacket`: Result of parsing raw packet data
   - `PacketBuilder`: Constructs outgoing packets
   - `parsePacket()`: Parses raw bytes into structured packet
   - `calculateIpChecksum()`: Computes IP header checksum

3. **sender.zig** - Zero-copy packet broadcast
   - `PacketRing`: Pre-allocated ring buffer for packet data (256 slots × 9KB)
   - `PacketRef`: Lightweight reference (32 bytes) passed through channels
   - `RefChannel`: Thread-safe channel for packet references
   - `SendPktFeed`: Manages broadcast to all registered interfaces
   - `OutgoingPool`: Pre-allocated buffer pool for outgoing packets

4. **listener.zig** - Per-interface packet handling
   - `Listener`: Captures packets on one interface, forwards via SendPktFeed
   - `UdpSink`: Binds UDP sockets to prevent ICMP Port Unreachable

5. **client_cache.zig** - Client IP tracking
   - Thread-safe TTL-based cache for learned client IPs
   - Zero-allocation iterator for hot path
   - Fixed IPs (never expire) vs learned IPs (TTL-based expiration)

6. **bpf.zig** - BPF filter construction
   - `buildFilter()`: Creates port + network source filter
   - `buildPortFilter()`: Creates port-only filter

### Data Flow

```
[Interface A: pcap capture]
        │
        ▼
[Parse packet] ──→ [Learn client IP if promiscuous]
        │
        ▼
[Store in PacketRing] ──→ [Broadcast PacketRef to all RefChannels]
        │
        ▼
[Interface B: receive PacketRef] ──→ [Get data from ring]
        │
        ▼
[Build outgoing packet] ──→ [pcap inject]
```

### Threading Model
- One thread per interface running `Listener.run()`
- Threads communicate via lock-free channels (`RefChannel`)
- Packet data stored in shared ring buffer to avoid copying
- Mutex held only briefly during sender registration and broadcast iteration

## Code Conventions

### Zig Style
- Use scoped logging: `const log = std.log.scoped(.module_name);`
- Prefer `std.ArrayListUnmanaged` over `ArrayList` for explicit allocator control
- Use `errdefer` for cleanup on error paths
- Network byte order: use `std.mem.bigToNative`/`nativeToBig` for conversions
- Packed/extern structs for wire format compatibility

### Error Handling
- Return errors using Zig's error unions
- Log errors at the appropriate level before returning
- Use `catch |err|` for error propagation with logging

### Memory Management
- General-purpose allocator (GPA) in debug builds for leak detection
- Pre-allocated ring buffers and pools for hot paths
- Zero-copy design: pass references, not data copies
- Always pair allocations with deallocation in `deinit()`

### Testing
- Each module contains its own unit tests
- `tests.zig` aggregates all module tests via `std.testing.refAllDecls`
- Integration tests verify cross-module behavior
- Run unit tests with `zig build test` or `make test`
- Run integration tests with `make integration-test` (requires Docker)

### Integration Tests (Docker)
The project includes Docker-based integration tests that verify packet forwarding:
```bash
# Run all integration tests
make integration-test

# Or manually:
docker compose build
docker compose up -d proxy
docker compose run --rm test-runner
docker compose down -v
```
See `tests/integration/README.md` for details.

## Common Development Tasks

### Adding a New Command-Line Option
1. Add field to `Args` struct in `main.zig`
2. Add parsing logic in `parseArgs()`
3. Update `printHelp()`
4. Use the option in main initialization logic

### Adding a New Packet Type
1. Define packed struct in `packet.zig`
2. Add parsing logic to `parsePacket()`
3. Update `ParsedPacket` struct
4. Add builder method to `PacketBuilder`

### Modifying the BPF Filter
1. Edit `buildFilter()` or `buildPortFilter()` in `bpf.zig`
2. Add tests verifying filter string output
3. Test with actual pcap capture

### Debugging Packet Issues
1. Enable pcap debug: `-P --pcap-path /tmp`
2. Set log level: `-L debug` or `-L trace`
3. Check pcap files with Wireshark: `/tmp/udp-proxy-{in,out}-{iface}.pcap`
4. Use `--log` to write logs to `/tmp/udp-proxy-2020.log`

## Platform-Specific Notes

### FreeBSD/pfSense
- libpcap is part of the base system
- BSD loopback uses 4-byte header with `AF_INET` (2)
- Use native shell (sh) not csh for PATH export

### Linux
- Install `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (Fedora/RHEL)
- Linux loopback uses `AF_INET` value 2 (same as BSD)

### Cross-Compilation
- FreeBSD target: `-Dtarget=x86_64-freebsd`
- Note: Cross-compilation may require sysroot for libpcap

## Performance Considerations

- Zero-copy packet broadcast via ring buffers
- Pre-allocated outgoing buffer pools (32 × 9KB)
- Lock-free channels for inter-thread communication
- Lazy TTL expiration (cleanup every 30s, not per-packet)
- Client cache iterator avoids allocation in hot path

## License

MIT License (same as original udp-proxy-2020)
