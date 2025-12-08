//! UDP Proxy 2020 - Test Aggregator
//!
//! Aggregates all tests from the UDP proxy modules.

const std = @import("std");

// Import all modules to run their tests
const pcap = @import("pcap.zig");
const packet = @import("packet.zig");
const bpf = @import("bpf.zig");
const client_cache = @import("client_cache.zig");
const sender = @import("sender.zig");
const listener = @import("listener.zig");

test {
    // Reference all declarations to ensure their tests are run
    std.testing.refAllDecls(pcap);
    std.testing.refAllDecls(packet);
    std.testing.refAllDecls(bpf);
    std.testing.refAllDecls(client_cache);
    std.testing.refAllDecls(sender);
}

// ============================================================================
// Integration Tests
// ============================================================================

test "packet round-trip build and parse" {
    const allocator = std.testing.allocator;

    // Build a packet
    var buffer: [1500]u8 = undefined;
    var builder = packet.PacketBuilder.init(&buffer);

    _ = try builder.addEthernet(
        [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, // src mac
        [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, // dst mac (broadcast)
        .ipv4,
    );

    const ipv4 = try builder.addIPv4(
        [_]u8{ 192, 168, 1, 100 },
        [_]u8{ 192, 168, 1, 255 },
        .udp,
        64,
    );

    const udp = try builder.addUDP(9003, 9003);

    const payload = "Hello, World!";
    try builder.addPayload(payload);

    // Fix up lengths
    const ip_len: u16 = @intCast(packet.IPV4_MIN_HEADER_SIZE + packet.UDP_HEADER_SIZE + payload.len);
    ipv4.setTotalLength(ip_len);

    const udp_len: u16 = @intCast(packet.UDP_HEADER_SIZE + payload.len);
    udp.setLength(udp_len);

    packet.calculateIpChecksum(ipv4);

    const built_data = builder.getData();

    // Parse it back
    const parsed = try packet.parsePacket(built_data, .ethernet);

    try std.testing.expect(parsed.ethernet != null);
    try std.testing.expect(parsed.ipv4 != null);
    try std.testing.expect(parsed.udp != null);

    try std.testing.expectEqual([_]u8{ 192, 168, 1, 100 }, parsed.getSrcIp().?);
    try std.testing.expectEqual([_]u8{ 192, 168, 1, 255 }, parsed.getDstIp().?);
    try std.testing.expectEqual(@as(u16, 9003), parsed.getSrcPort().?);
    try std.testing.expectEqual(@as(u16, 9003), parsed.getDstPort().?);
    try std.testing.expectEqualStrings(payload, parsed.payload);

    _ = allocator; // Not used directly, but kept for consistency
}

test "BPF filter generation" {
    const allocator = std.testing.allocator;

    const ports = [_]u16{ 9003, 9004 };
    const addresses = [_]pcap.InterfaceAddress{
        .{
            .addr = [_]u8{ 192, 168, 1, 100 },
            .netmask = [_]u8{ 255, 255, 255, 0 },
        },
    };

    const filter = try bpf.buildFilter(allocator, &ports, &addresses);
    defer allocator.free(filter);

    // Should contain both ports
    try std.testing.expect(std.mem.indexOf(u8, filter, "udp port 9003") != null);
    try std.testing.expect(std.mem.indexOf(u8, filter, "udp port 9004") != null);

    // Should contain network filter
    try std.testing.expect(std.mem.indexOf(u8, filter, "src net 192.168.1.0/24") != null);
}

test "client cache TTL behavior" {
    const allocator = std.testing.allocator;

    var cache = client_cache.ClientCache.init(allocator, 1); // 1 minute TTL
    defer cache.deinit();

    // Add clients
    try cache.learn([_]u8{ 10, 0, 0, 1 });
    try cache.learn([_]u8{ 10, 0, 0, 2 });
    try cache.addFixed([_]u8{ 10, 0, 0, 100 }); // Fixed, never expires

    // All should be present
    try std.testing.expectEqual(@as(usize, 3), cache.count());

    // Get clients
    const clients = try cache.getClients(allocator);
    defer allocator.free(clients);

    try std.testing.expectEqual(@as(usize, 3), clients.len);
}

test "network calculations" {
    // Broadcast calculation
    const ip = [_]u8{ 192, 168, 1, 100 };
    const mask = [_]u8{ 255, 255, 255, 0 };

    const bcast = packet.calculateBroadcast(ip, mask);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 255 }, &bcast);

    const network = packet.calculateNetwork(ip, mask);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 0 }, &network);

    // Prefix/netmask conversion
    try std.testing.expectEqual(@as(u8, 24), packet.netmaskToPrefix([_]u8{ 255, 255, 255, 0 }));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 0 }, &packet.prefixToNetmask(24));
}
