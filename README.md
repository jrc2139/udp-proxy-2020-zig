# udp-proxy-2020

A high-performance UDP broadcast packet forwarder written in Zig. This is a port of the original Go-based [udp-proxy-2020](https://github.com/synfinatic/udp-proxy-2020) for improved performance.

## Overview

udp-proxy-2020 forwards UDP broadcast packets between network interfaces using libpcap for packet capture and injection. This enables UDP broadcast services (like Sonos, Ubiquiti device discovery, mDNS, etc.) to work across VLANs, VPN tunnels, and different network segments.

## Requirements

- Zig 0.15.x
- libpcap (included in FreeBSD base system, `libpcap-dev` on Debian/Ubuntu)

## Building

### On FreeBSD/pfSense

libpcap is included in the base system:

```bash
# Install Zig (if not already installed)
fetch https://ziglang.org/download/0.15.2/zig-x86_64-freebsd-0.15.2.tar.xz
tar xf zig-x86_64-freebsd-0.15.2.tar.xz

# Add to PATH (use sh, not csh/tcsh)
sh
export PATH=$PATH:$(pwd)/zig-x86_64-freebsd-0.15.2

# Or if using csh/tcsh (default on pfSense):
# setenv PATH $PATH:$PWD/zig-x86_64-freebsd-0.15.2

# Build (using make or zig directly)
make
# or: zig build -Doptimize=ReleaseFast

# Binary is at zig-out/bin/udp-proxy-2020
```

### On Linux

```bash
# Install libpcap
sudo apt install libpcap-dev  # Debian/Ubuntu
sudo dnf install libpcap-devel  # Fedora/RHEL

# Build
zig build -Doptimize=ReleaseFast
```

### Cross-compile for FreeBSD from Linux

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-freebsd
```

## Usage

```
udp-proxy-2020 [options]

Options:
  -i, --interface <name>    Interface to listen on (required, can specify multiple)
  -p, --port <port>         UDP port to proxy (required, can specify multiple)
  -I, --fixed-ip <ip>       Fixed destination IP (optional, can specify multiple)
  -t, --timeout <ms>        Packet read timeout in ms (default: 250)
  -T, --cache-ttl <min>     Client cache TTL in minutes (default: 180)
  -l, --deliver-local       Deliver packets locally via loopback
  -L, --level <level>       Log level: trace, debug, info, warn, error (default: info)
      --log                 Log to /tmp/udp-proxy-2020.log
      --logfile <path>      Log to custom file path
  -P, --pcap                Write pcap debug files
  -h, --help                Show this help message
```

## Examples

### Forward Sonos discovery between two interfaces

```bash
udp-proxy-2020 -i igb0 -i igb1 -p 1900 -p 1901
```

### Forward mDNS across VLANs with debug logging

```bash
udp-proxy-2020 -i vlan10 -i vlan20 -p 5353 -L debug
```

### Forward to fixed IP addresses (Wireguard peers)

```bash
udp-proxy-2020 -i wg0 -i eth0 -p 9003 -I 10.0.0.2 -I 10.0.0.3
```

### Enable local delivery and pcap debugging

```bash
udp-proxy-2020 -i eth0 -i eth1 -p 9003 -l -P -L trace
```

## Architecture

```
src/
├── main.zig         # CLI entry point and argument parsing
├── lib.zig          # Public API exports
├── pcap.zig         # libpcap C bindings
├── packet.zig       # Network packet structures (Ethernet, IPv4, UDP)
├── bpf.zig          # BPF filter construction
├── client_cache.zig # TTL-based client IP cache
├── sender.zig       # Packet forwarding infrastructure
├── listener.zig     # Per-interface packet handler
└── tests.zig        # Test aggregator
```

## Running Tests

```bash
zig build test
```

## License

Same license as the original udp-proxy-2020 project.
