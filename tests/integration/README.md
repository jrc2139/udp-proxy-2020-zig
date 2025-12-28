# Integration Tests for udp-proxy-2020

This directory contains Docker-based integration tests that verify the UDP proxy correctly forwards packets between network interfaces.

## Architecture

```
net_alpha (172.20.0.0/24)              net_beta (172.21.0.0/24)

┌─────────────────┐                    ┌─────────────────┐
│   test-runner   │                    │   test-runner   │
│   172.20.0.100  │                    │   172.21.0.100  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │         ┌──────────────────┐         │
         │         │    udp-proxy     │         │
         └─────────┤ eth0      eth1   ├─────────┘
                   │ 172.20.0.2       │
                   │          172.21.0.2
                   └──────────────────┘
```

The test-runner container is connected to both networks, allowing it to:
1. Send UDP broadcasts on one network
2. Listen for forwarded packets on the other network
3. Verify the proxy correctly bridges traffic

## Running the Tests

### Quick Start

```bash
# From the project root
make integration-test

# Or manually:
docker compose build
docker compose up -d proxy
docker compose run --rm test-runner
docker compose down -v
```

### Interactive Debugging

```bash
# Start the proxy
docker compose up -d proxy

# Check proxy logs
docker compose logs -f proxy

# Start an interactive shell in test-runner
docker compose run --rm test-runner bash

# Inside the container, you can manually test:
# Listen on beta network:
nc -u -l 9003

# In another terminal, send from alpha:
echo "test" | nc -u -b 172.20.0.255 9003
```

### Cleanup

```bash
make docker-clean
# or
docker compose down -v --rmi local
```

## Test Cases

| Test | Description |
|------|-------------|
| Basic forwarding α→β | Send broadcast on net_alpha, receive on net_beta |
| Basic forwarding β→α | Send broadcast on net_beta, receive on net_alpha |
| Port 1900 (SSDP) | Verify SSDP/UPnP port forwarding |
| Port 5353 (mDNS) | Verify mDNS port forwarding |
| Unconfigured port | Verify packets on unconfigured ports are NOT forwarded |
| Rapid packets | Send multiple packets quickly, verify most arrive |
| Large packet | Test near-MTU packet forwarding |
| Bidirectional | Simultaneous traffic in both directions |

## Files

- `run-tests.sh` - Main test orchestration script
- `lib.sh` - Common test functions and utilities
- `README.md` - This file

## Requirements

- Docker Engine 20.10+
- Docker Compose v2
- ~500MB disk space for images
- Linux host (for network namespace support)

## Troubleshooting

### Tests fail with "Cannot reach proxy"

The proxy container may not have started properly. Check:
```bash
docker compose logs proxy
```

### Tests timeout

Increase the timeout in `lib.sh`:
```bash
TIMEOUT="${TIMEOUT:-10}"  # Increase from 5 to 10
```

### Pcap permission errors

Ensure the proxy container has the required capabilities:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
```

### Debugging packet capture

Start the proxy with pcap debugging enabled:
```bash
docker compose run -d --name proxy-debug proxy \
  udp-proxy-2020 -i eth0 -i eth1 -p 9003 -L debug -P -d /tmp

# After tests, copy pcap files:
docker cp proxy-debug:/tmp/udp-proxy-in-eth0.pcap .
docker cp proxy-debug:/tmp/udp-proxy-out-eth1.pcap .

# Open in Wireshark
wireshark udp-proxy-in-eth0.pcap
```
