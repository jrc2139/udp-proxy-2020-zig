//! Network packet structures and utilities
//!
//! Provides packed structs for Ethernet, IPv4, and UDP headers,
//! along with functions for parsing and building packets.

const std = @import("std");
const pcap = @import("pcap.zig");

const log = std.log.scoped(.packet);

// ============================================================================
// Constants
// ============================================================================

pub const ETHERNET_HEADER_SIZE = 14;
pub const IPV4_MIN_HEADER_SIZE = 20;
pub const UDP_HEADER_SIZE = 8;
pub const LOOPBACK_HEADER_SIZE = 4;
pub const MAX_PACKET_SIZE = 9000; // Jumbo frame support

/// Ethernet type values
pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    ipv6 = 0x86DD,
    arp = 0x0806,
    _,
};

/// IP protocol values
pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

/// BSD loopback protocol family (network byte order on big endian systems)
pub const LoopbackFamily = enum(u32) {
    ipv4 = 2, // AF_INET
    ipv6 = if (@import("builtin").os.tag == .freebsd) 28 else 10,
    _,
};

// ============================================================================
// Header Structures
// ============================================================================

/// Ethernet frame header (14 bytes)
pub const EthernetHeader = extern struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16, // Network byte order

    pub fn getEtherType(self: *const EthernetHeader) EtherType {
        return @enumFromInt(std.mem.bigToNative(u16, self.ether_type));
    }

    pub fn setEtherType(self: *EthernetHeader, etype: EtherType) void {
        self.ether_type = std.mem.nativeToBig(u16, @intFromEnum(etype));
    }

    pub fn format(self: *const EthernetHeader, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Eth[{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} -> {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} type=0x{x:0>4}]", .{
            self.src_mac[0], self.src_mac[1], self.src_mac[2],
            self.src_mac[3], self.src_mac[4], self.src_mac[5],
            self.dst_mac[0], self.dst_mac[1], self.dst_mac[2],
            self.dst_mac[3], self.dst_mac[4], self.dst_mac[5],
            std.mem.bigToNative(u16, self.ether_type),
        });
    }
};

/// BSD Loopback/Null header (4 bytes)
pub const LoopbackHeader = extern struct {
    family: u32, // Host byte order on BSD

    pub fn getFamily(self: *const LoopbackHeader) LoopbackFamily {
        // BSD loopback uses host byte order
        return @enumFromInt(self.family);
    }

    pub fn setFamily(self: *LoopbackHeader, family: LoopbackFamily) void {
        self.family = @intFromEnum(family);
    }
};

/// IPv4 header (20+ bytes, without options)
pub const IPv4Header = extern struct {
    version_ihl: u8, // Version (4 bits) + IHL (4 bits)
    tos: u8, // Type of service
    total_length: u16, // Network byte order
    identification: u16, // Network byte order
    flags_fragment: u16, // Flags (3 bits) + Fragment offset (13 bits), network byte order
    ttl: u8,
    protocol: u8,
    checksum: u16, // Network byte order
    src_ip: [4]u8,
    dst_ip: [4]u8,

    pub fn getVersion(self: *const IPv4Header) u4 {
        return @truncate(self.version_ihl >> 4);
    }

    pub fn getIHL(self: *const IPv4Header) u4 {
        return @truncate(self.version_ihl & 0x0F);
    }

    pub fn getHeaderLength(self: *const IPv4Header) usize {
        return @as(usize, self.getIHL()) * 4;
    }

    pub fn getTotalLength(self: *const IPv4Header) u16 {
        return std.mem.bigToNative(u16, self.total_length);
    }

    pub fn setTotalLength(self: *IPv4Header, len: u16) void {
        self.total_length = std.mem.nativeToBig(u16, len);
    }

    pub fn getProtocol(self: *const IPv4Header) IpProtocol {
        return @enumFromInt(self.protocol);
    }

    pub fn setProtocol(self: *IPv4Header, proto: IpProtocol) void {
        self.protocol = @intFromEnum(proto);
    }

    pub fn getChecksum(self: *const IPv4Header) u16 {
        return std.mem.bigToNative(u16, self.checksum);
    }

    pub fn setChecksum(self: *IPv4Header, csum: u16) void {
        self.checksum = std.mem.nativeToBig(u16, csum);
    }

    pub fn format(self: *const IPv4Header, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("IPv4[{d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} proto={d} len={d}]", .{
            self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3],
            self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3],
            self.protocol,
            self.getTotalLength(),
        });
    }
};

/// UDP header (8 bytes)
pub const UdpHeader = extern struct {
    src_port: u16, // Network byte order
    dst_port: u16, // Network byte order
    length: u16, // Network byte order
    checksum: u16, // Network byte order

    pub fn getSrcPort(self: *const UdpHeader) u16 {
        return std.mem.bigToNative(u16, self.src_port);
    }

    pub fn setSrcPort(self: *UdpHeader, port: u16) void {
        self.src_port = std.mem.nativeToBig(u16, port);
    }

    pub fn getDstPort(self: *const UdpHeader) u16 {
        return std.mem.bigToNative(u16, self.dst_port);
    }

    pub fn setDstPort(self: *UdpHeader, port: u16) void {
        self.dst_port = std.mem.nativeToBig(u16, port);
    }

    pub fn getLength(self: *const UdpHeader) u16 {
        return std.mem.bigToNative(u16, self.length);
    }

    pub fn setLength(self: *UdpHeader, len: u16) void {
        self.length = std.mem.nativeToBig(u16, len);
    }

    pub fn format(self: *const UdpHeader, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("UDP[{d} -> {d} len={d}]", .{
            self.getSrcPort(),
            self.getDstPort(),
            self.getLength(),
        });
    }
};

// ============================================================================
// Parsed Packet
// ============================================================================

/// Parsed packet data
pub const ParsedPacket = struct {
    link_type: pcap.LinkType,

    // L2 headers (only one will be valid based on link_type)
    ethernet: ?*const EthernetHeader = null,
    loopback: ?*const LoopbackHeader = null,

    // L3/L4 headers
    ipv4: ?*const IPv4Header = null,
    udp: ?*const UdpHeader = null,

    // Payload
    payload: []const u8 = &[_]u8{},

    // Raw packet data
    raw_data: []const u8,

    pub fn getSrcIp(self: *const ParsedPacket) ?[4]u8 {
        if (self.ipv4) |ip| {
            return ip.src_ip;
        }
        return null;
    }

    pub fn getDstIp(self: *const ParsedPacket) ?[4]u8 {
        if (self.ipv4) |ip| {
            return ip.dst_ip;
        }
        return null;
    }

    pub fn getSrcPort(self: *const ParsedPacket) ?u16 {
        if (self.udp) |u| {
            return u.getSrcPort();
        }
        return null;
    }

    pub fn getDstPort(self: *const ParsedPacket) ?u16 {
        if (self.udp) |u| {
            return u.getDstPort();
        }
        return null;
    }
};

// ============================================================================
// Packet Parsing
// ============================================================================

pub const ParseError = error{
    PacketTooShort,
    UnsupportedLinkType,
    UnsupportedEtherType,
    UnsupportedProtocol,
    InvalidIpVersion,
    InvalidHeaderLength,
};

/// Parse a raw packet based on link type
pub fn parsePacket(data: []const u8, link_type: pcap.LinkType) ParseError!ParsedPacket {
    var result = ParsedPacket{
        .link_type = link_type,
        .raw_data = data,
    };

    var offset: usize = 0;

    // Parse L2 header based on link type
    switch (link_type) {
        .ethernet => {
            if (data.len < ETHERNET_HEADER_SIZE) {
                return ParseError.PacketTooShort;
            }

            const eth: *const EthernetHeader = @ptrCast(@alignCast(data.ptr));
            result.ethernet = eth;
            offset = ETHERNET_HEADER_SIZE;

            // Check ether type
            if (eth.getEtherType() != .ipv4) {
                return ParseError.UnsupportedEtherType;
            }
        },
        .null, .loop => {
            if (data.len < LOOPBACK_HEADER_SIZE) {
                return ParseError.PacketTooShort;
            }

            const loop: *const LoopbackHeader = @ptrCast(@alignCast(data.ptr));
            result.loopback = loop;
            offset = LOOPBACK_HEADER_SIZE;

            // Check family (allow both AF_INET values)
            const family = loop.getFamily();
            if (family != .ipv4) {
                return ParseError.UnsupportedEtherType;
            }
        },
        .raw => {
            // No L2 header, starts with IP
            offset = 0;
        },
        else => {
            return ParseError.UnsupportedLinkType;
        },
    }

    // Parse IPv4 header
    if (data.len < offset + IPV4_MIN_HEADER_SIZE) {
        return ParseError.PacketTooShort;
    }

    const ipv4: *const IPv4Header = @ptrCast(@alignCast(data.ptr + offset));
    result.ipv4 = ipv4;

    // Validate IP version
    if (ipv4.getVersion() != 4) {
        return ParseError.InvalidIpVersion;
    }

    const ip_header_len = ipv4.getHeaderLength();
    if (ip_header_len < IPV4_MIN_HEADER_SIZE) {
        return ParseError.InvalidHeaderLength;
    }

    offset += ip_header_len;

    // Check for UDP
    if (ipv4.getProtocol() != .udp) {
        return ParseError.UnsupportedProtocol;
    }

    // Parse UDP header
    if (data.len < offset + UDP_HEADER_SIZE) {
        return ParseError.PacketTooShort;
    }

    const udp: *const UdpHeader = @ptrCast(@alignCast(data.ptr + offset));
    result.udp = udp;
    offset += UDP_HEADER_SIZE;

    // Remaining is payload
    if (offset < data.len) {
        result.payload = data[offset..];
    }

    return result;
}

// ============================================================================
// Packet Building
// ============================================================================

/// Packet builder for constructing outgoing packets
pub const PacketBuilder = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn init(buffer: []u8) PacketBuilder {
        return PacketBuilder{
            .buffer = buffer,
        };
    }

    /// Add Ethernet header
    pub fn addEthernet(self: *PacketBuilder, src_mac: [6]u8, dst_mac: [6]u8, ether_type: EtherType) !*EthernetHeader {
        if (self.offset + ETHERNET_HEADER_SIZE > self.buffer.len) {
            return error.BufferTooSmall;
        }

        const eth: *EthernetHeader = @ptrCast(@alignCast(self.buffer.ptr + self.offset));
        eth.* = EthernetHeader{
            .dst_mac = dst_mac,
            .src_mac = src_mac,
            .ether_type = undefined,
        };
        eth.setEtherType(ether_type);

        self.offset += ETHERNET_HEADER_SIZE;
        return eth;
    }

    /// Add Loopback header
    pub fn addLoopback(self: *PacketBuilder, family: LoopbackFamily) !*LoopbackHeader {
        if (self.offset + LOOPBACK_HEADER_SIZE > self.buffer.len) {
            return error.BufferTooSmall;
        }

        const loop: *LoopbackHeader = @ptrCast(@alignCast(self.buffer.ptr + self.offset));
        loop.* = LoopbackHeader{
            .family = undefined,
        };
        loop.setFamily(family);

        self.offset += LOOPBACK_HEADER_SIZE;
        return loop;
    }

    /// Add IPv4 header (returns header for later checksum calculation)
    pub fn addIPv4(
        self: *PacketBuilder,
        src_ip: [4]u8,
        dst_ip: [4]u8,
        protocol: IpProtocol,
        ttl: u8,
    ) !*IPv4Header {
        if (self.offset + IPV4_MIN_HEADER_SIZE > self.buffer.len) {
            return error.BufferTooSmall;
        }

        const ipv4: *IPv4Header = @ptrCast(@alignCast(self.buffer.ptr + self.offset));
        ipv4.* = IPv4Header{
            .version_ihl = (4 << 4) | 5, // Version 4, IHL 5 (20 bytes)
            .tos = 0,
            .total_length = 0, // Set later
            .identification = 0,
            .flags_fragment = 0,
            .ttl = ttl,
            .protocol = @intFromEnum(protocol),
            .checksum = 0, // Set later
            .src_ip = src_ip,
            .dst_ip = dst_ip,
        };

        self.offset += IPV4_MIN_HEADER_SIZE;
        return ipv4;
    }

    /// Add UDP header
    pub fn addUDP(self: *PacketBuilder, src_port: u16, dst_port: u16) !*UdpHeader {
        if (self.offset + UDP_HEADER_SIZE > self.buffer.len) {
            return error.BufferTooSmall;
        }

        const udp: *UdpHeader = @ptrCast(@alignCast(self.buffer.ptr + self.offset));
        udp.* = UdpHeader{
            .src_port = undefined,
            .dst_port = undefined,
            .length = 0, // Set later
            .checksum = 0, // 0 is valid for UDP
        };
        udp.setSrcPort(src_port);
        udp.setDstPort(dst_port);

        self.offset += UDP_HEADER_SIZE;
        return udp;
    }

    /// Add payload data
    pub fn addPayload(self: *PacketBuilder, data: []const u8) !void {
        if (self.offset + data.len > self.buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(self.buffer[self.offset..][0..data.len], data);
        self.offset += data.len;
    }

    /// Get the built packet data
    pub fn getData(self: *const PacketBuilder) []u8 {
        return self.buffer[0..self.offset];
    }

    /// Get current offset
    pub fn getOffset(self: *const PacketBuilder) usize {
        return self.offset;
    }
};

// ============================================================================
// Checksum Calculation
// ============================================================================

/// Calculate IPv4 header checksum
/// Optimized to read u16 directly instead of byte-by-byte construction
pub fn calculateIpChecksum(header: *IPv4Header) void {
    // Zero out checksum field
    header.checksum = 0;

    // Cast to u16 array for direct word access (header is aligned)
    const header_u16: [*]const u16 = @ptrCast(@alignCast(header));
    const header_len_u16 = header.getHeaderLength() / 2;

    var sum: u32 = 0;

    // Sum all 16-bit words directly (no byte manipulation)
    for (0..header_len_u16) |i| {
        sum += std.mem.bigToNative(u16, header_u16[i]);
    }

    // Fold 32-bit sum to 16 bits (at most 2 iterations needed)
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    // One's complement
    header.checksum = std.mem.nativeToBig(u16, @as(u16, @truncate(~sum)));
}

/// Calculate network mask from prefix length
pub fn prefixToNetmask(prefix: u8) [4]u8 {
    if (prefix == 0) return [_]u8{ 0, 0, 0, 0 };
    if (prefix >= 32) return [_]u8{ 255, 255, 255, 255 };

    const mask: u32 = ~(@as(u32, 0)) << @intCast(32 - prefix);
    return .{
        @truncate(mask >> 24),
        @truncate(mask >> 16),
        @truncate(mask >> 8),
        @truncate(mask),
    };
}

/// Calculate broadcast address from IP and netmask
pub fn calculateBroadcast(ip: [4]u8, netmask: [4]u8) [4]u8 {
    return .{
        ip[0] | ~netmask[0],
        ip[1] | ~netmask[1],
        ip[2] | ~netmask[2],
        ip[3] | ~netmask[3],
    };
}

/// Calculate network address from IP and netmask
pub fn calculateNetwork(ip: [4]u8, netmask: [4]u8) [4]u8 {
    return .{
        ip[0] & netmask[0],
        ip[1] & netmask[1],
        ip[2] & netmask[2],
        ip[3] & netmask[3],
    };
}

/// Get the prefix length from a netmask
pub fn netmaskToPrefix(netmask: [4]u8) u8 {
    const mask: u32 = (@as(u32, netmask[0]) << 24) |
        (@as(u32, netmask[1]) << 16) |
        (@as(u32, netmask[2]) << 8) |
        netmask[3];

    if (mask == 0) return 0;

    var count: u8 = 0;
    var m = mask;
    while ((m & 0x80000000) != 0) {
        count += 1;
        m <<= 1;
    }
    return count;
}

/// Broadcast MAC address
pub const BROADCAST_MAC: [6]u8 = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// ============================================================================
// Tests
// ============================================================================

test "EthernetHeader size" {
    try std.testing.expectEqual(@as(usize, 14), @sizeOf(EthernetHeader));
}

test "IPv4Header size" {
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(IPv4Header));
}

test "UdpHeader size" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(UdpHeader));
}

test "LoopbackHeader size" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(LoopbackHeader));
}

test "calculateBroadcast" {
    const ip = [_]u8{ 192, 168, 1, 100 };
    const mask = [_]u8{ 255, 255, 255, 0 };
    const bcast = calculateBroadcast(ip, mask);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 255 }, &bcast);
}

test "prefixToNetmask" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 0 }, &prefixToNetmask(24));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 0, 0 }, &prefixToNetmask(16));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 0, 0, 0 }, &prefixToNetmask(8));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 255 }, &prefixToNetmask(32));
}

test "netmaskToPrefix" {
    try std.testing.expectEqual(@as(u8, 24), netmaskToPrefix([_]u8{ 255, 255, 255, 0 }));
    try std.testing.expectEqual(@as(u8, 16), netmaskToPrefix([_]u8{ 255, 255, 0, 0 }));
    try std.testing.expectEqual(@as(u8, 8), netmaskToPrefix([_]u8{ 255, 0, 0, 0 }));
}

test "IPv4 checksum calculation" {
    // Create a minimal valid IPv4 header
    var header = IPv4Header{
        .version_ihl = (4 << 4) | 5,
        .tos = 0,
        .total_length = std.mem.nativeToBig(u16, 40),
        .identification = 0,
        .flags_fragment = 0,
        .ttl = 64,
        .protocol = 17, // UDP
        .checksum = 0,
        .src_ip = .{ 192, 168, 1, 1 },
        .dst_ip = .{ 192, 168, 1, 2 },
    };

    calculateIpChecksum(&header);

    // Checksum should be non-zero for this header
    try std.testing.expect(header.checksum != 0);
}
