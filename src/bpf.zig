//! BPF (Berkeley Packet Filter) filter construction
//!
//! Builds BPF filter strings for pcap to capture only relevant UDP traffic.

const std = @import("std");
const pcap = @import("pcap.zig");
const packet = @import("packet.zig");

const log = std.log.scoped(.bpf);

// ============================================================================
// BPF Filter Builder
// ============================================================================

/// Maximum BPF filter string length
pub const MAX_FILTER_LEN = 4096;

/// Build a BPF filter string for the given ports and interface addresses
/// Format: "(udp port X or udp port Y) and (src net A.B.C.D/N or src net E.F.G.H/M)"
pub fn buildFilter(
    allocator: std.mem.Allocator,
    ports: []const u16,
    addresses: []const pcap.InterfaceAddress,
) ![:0]u8 {
    if (ports.len == 0) {
        return error.NoPortsSpecified;
    }

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    // Build port filter: "udp port X or udp port Y"
    if (ports.len == 1) {
        try writer.print("udp port {d}", .{ports[0]});
    } else {
        try writer.writeByte('(');
        for (ports, 0..) |port, i| {
            if (i > 0) {
                try writer.writeAll(" or ");
            }
            try writer.print("udp port {d}", .{port});
        }
        try writer.writeByte(')');
    }

    // Build source network filter to avoid loops
    // This filters to only accept traffic from the local networks
    var networks = std.ArrayListUnmanaged(NetworkCIDR){};
    defer networks.deinit(allocator);

    for (addresses) |addr| {
        if (addr.addr != null and addr.netmask != null) {
            const ip = addr.addr.?;
            const mask = addr.netmask.?;
            const prefix = packet.netmaskToPrefix(mask);

            // Skip if no prefix (invalid mask)
            if (prefix == 0) continue;

            // Calculate network address
            const net_addr = packet.calculateNetwork(ip, mask);

            try networks.append(allocator, .{
                .addr = net_addr,
                .prefix = prefix,
            });
        }
    }

    // Add network filter if we have valid networks
    if (networks.items.len > 0) {
        try writer.writeAll(" and ");

        if (networks.items.len == 1) {
            const net = networks.items[0];
            try writer.print("src net {d}.{d}.{d}.{d}/{d}", .{
                net.addr[0],
                net.addr[1],
                net.addr[2],
                net.addr[3],
                net.prefix,
            });
        } else {
            try writer.writeByte('(');
            for (networks.items, 0..) |net, i| {
                if (i > 0) {
                    try writer.writeAll(" or ");
                }
                try writer.print("src net {d}.{d}.{d}.{d}/{d}", .{
                    net.addr[0],
                    net.addr[1],
                    net.addr[2],
                    net.addr[3],
                    net.prefix,
                });
            }
            try writer.writeByte(')');
        }
    }

    // Create null-terminated result
    const result = try allocator.allocSentinel(u8, buf.items.len, 0);
    @memcpy(result, buf.items);

    log.debug("BPF filter: {s}", .{result});

    return result;
}

/// Network address with CIDR prefix
const NetworkCIDR = struct {
    addr: [4]u8,
    prefix: u8,
};

/// Build a simple port-only filter (no network restriction)
pub fn buildPortFilter(allocator: std.mem.Allocator, ports: []const u16) ![:0]u8 {
    if (ports.len == 0) {
        return error.NoPortsSpecified;
    }

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    if (ports.len == 1) {
        try writer.print("udp port {d}", .{ports[0]});
    } else {
        try writer.writeByte('(');
        for (ports, 0..) |port, i| {
            if (i > 0) {
                try writer.writeAll(" or ");
            }
            try writer.print("udp port {d}", .{port});
        }
        try writer.writeByte(')');
    }

    const result = try allocator.allocSentinel(u8, buf.items.len, 0);
    @memcpy(result, buf.items);

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "buildPortFilter single port" {
    const allocator = std.testing.allocator;
    const ports = [_]u16{9003};

    const filter = try buildPortFilter(allocator, &ports);
    defer allocator.free(filter);

    try std.testing.expectEqualStrings("udp port 9003", filter);
}

test "buildPortFilter multiple ports" {
    const allocator = std.testing.allocator;
    const ports = [_]u16{ 9003, 9004, 9005 };

    const filter = try buildPortFilter(allocator, &ports);
    defer allocator.free(filter);

    try std.testing.expectEqualStrings("(udp port 9003 or udp port 9004 or udp port 9005)", filter);
}

test "buildFilter with addresses" {
    const allocator = std.testing.allocator;
    const ports = [_]u16{9003};
    const addresses = [_]pcap.InterfaceAddress{
        .{
            .addr = [_]u8{ 192, 168, 1, 100 },
            .netmask = [_]u8{ 255, 255, 255, 0 },
        },
    };

    const filter = try buildFilter(allocator, &ports, &addresses);
    defer allocator.free(filter);

    try std.testing.expectEqualStrings("udp port 9003 and src net 192.168.1.0/24", filter);
}

test "buildFilter with multiple addresses" {
    const allocator = std.testing.allocator;
    const ports = [_]u16{9003};
    const addresses = [_]pcap.InterfaceAddress{
        .{
            .addr = [_]u8{ 192, 168, 1, 100 },
            .netmask = [_]u8{ 255, 255, 255, 0 },
        },
        .{
            .addr = [_]u8{ 10, 0, 0, 1 },
            .netmask = [_]u8{ 255, 255, 0, 0 },
        },
    };

    const filter = try buildFilter(allocator, &ports, &addresses);
    defer allocator.free(filter);

    try std.testing.expectEqualStrings("udp port 9003 and (src net 192.168.1.0/24 or src net 10.0.0.0/16)", filter);
}

test "buildFilter no ports returns error" {
    const allocator = std.testing.allocator;
    const ports = [_]u16{};
    const addresses = [_]pcap.InterfaceAddress{};

    const result = buildFilter(allocator, &ports, &addresses);
    try std.testing.expectError(error.NoPortsSpecified, result);
}
