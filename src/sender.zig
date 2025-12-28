//! Packet sender infrastructure
//!
//! Manages the broadcast of packets between interfaces.
//! Each interface registers a send channel, and packets are
//! forwarded to all interfaces except the source.
//!
//! Design: Zero-copy packet broadcast using ring buffers and references.
//! Packets are stored once in a shared ring buffer, and lightweight refs
//! are passed through channels. This eliminates per-packet allocation and
//! minimizes lock hold time.

const std = @import("std");
const pcap = @import("pcap.zig");
const packet = @import("packet.zig");

const log = std.log.scoped(.sender);

// ============================================================================
// Types
// ============================================================================

/// Maximum packet data size
pub const MAX_PACKET_SIZE = 9000;

/// Ring buffer size - must be power of 2 for fast modulo
pub const RING_SIZE = 256;

// ============================================================================
// Zero-Copy Infrastructure
// ============================================================================

/// Pre-allocated ring buffer for packet data.
/// Stores packets in fixed slots, eliminating per-packet allocation.
pub const PacketRing = struct {
    buffers: [RING_SIZE][MAX_PACKET_SIZE]u8,
    lengths: [RING_SIZE]u16,
    write_idx: std.atomic.Value(u32),

    pub fn init() PacketRing {
        return PacketRing{
            .buffers = undefined,
            .lengths = [_]u16{0} ** RING_SIZE,
            .write_idx = std.atomic.Value(u32).init(0),
        };
    }

    /// Store packet data and return the slot index.
    /// Thread-safe via atomic increment.
    pub fn store(self: *PacketRing, data: []const u8) u8 {
        const idx = self.write_idx.fetchAdd(1, .monotonic) % RING_SIZE;
        const len: u16 = @intCast(@min(data.len, MAX_PACKET_SIZE));
        @memcpy(self.buffers[idx][0..len], data[0..len]);
        self.lengths[idx] = len;
        return @intCast(idx);
    }

    /// Get packet data from a slot.
    pub fn get(self: *const PacketRing, idx: u8) []const u8 {
        return self.buffers[idx][0..self.lengths[idx]];
    }
};

/// Lightweight packet reference - passed through channels instead of full packet data.
/// Only 32 bytes vs 9KB for SendPacket.
pub const PacketRef = struct {
    /// Index into the shared ring buffer
    ring_idx: u8,
    /// Link type of source interface
    link_type: pcap.LinkType,
    /// Source interface name (pointer to static string in listener config)
    src_interface: []const u8,
    /// Capture timestamp
    timestamp_sec: i64,
    timestamp_usec: i64,
};

/// Packet to be sent to another interface
pub const SendPacket = struct {
    /// Raw packet data (copied)
    data: [MAX_PACKET_SIZE]u8,
    /// Actual length of packet data
    len: usize,
    /// Source interface name
    src_interface: []const u8,
    /// Link type of source interface
    link_type: pcap.LinkType,
    /// Capture timestamp
    timestamp_sec: i64,
    timestamp_usec: i64,

    /// Get the packet data slice
    pub fn getData(self: *const SendPacket) []const u8 {
        return self.data[0..self.len];
    }
};

/// Simple ring buffer for packet references (32 bytes each vs 9KB)
const RefQueue = struct {
    const QUEUE_SIZE = 256;

    items: [QUEUE_SIZE]PacketRef,
    read_pos: usize,
    write_pos: usize,
    count: usize,

    fn init() RefQueue {
        return RefQueue{
            .items = undefined,
            .read_pos = 0,
            .write_pos = 0,
            .count = 0,
        };
    }

    fn push(self: *RefQueue, item: PacketRef) bool {
        if (self.count >= QUEUE_SIZE) {
            return false; // Queue full
        }
        self.items[self.write_pos] = item;
        self.write_pos = (self.write_pos + 1) % QUEUE_SIZE;
        self.count += 1;
        return true;
    }

    fn pop(self: *RefQueue) ?PacketRef {
        if (self.count == 0) {
            return null;
        }
        const item = self.items[self.read_pos];
        self.read_pos = (self.read_pos + 1) % QUEUE_SIZE;
        self.count -= 1;
        return item;
    }
};

/// Legacy ring buffer for full packets (kept for compatibility during transition)
const PacketQueue = struct {
    const QUEUE_SIZE = 256;

    items: [QUEUE_SIZE]SendPacket,
    read_pos: usize,
    write_pos: usize,
    count: usize,

    fn init() PacketQueue {
        return PacketQueue{
            .items = undefined,
            .read_pos = 0,
            .write_pos = 0,
            .count = 0,
        };
    }

    fn push(self: *PacketQueue, item: SendPacket) bool {
        if (self.count >= QUEUE_SIZE) {
            return false; // Queue full
        }
        self.items[self.write_pos] = item;
        self.write_pos = (self.write_pos + 1) % QUEUE_SIZE;
        self.count += 1;
        return true;
    }

    fn pop(self: *PacketQueue) ?SendPacket {
        if (self.count == 0) {
            return null;
        }
        const item = self.items[self.read_pos];
        self.read_pos = (self.read_pos + 1) % QUEUE_SIZE;
        self.count -= 1;
        return item;
    }
};

/// Channel for receiving packet references (zero-copy)
pub const RefChannel = struct {
    queue: RefQueue,
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    closed: bool,

    pub fn init() RefChannel {
        return RefChannel{
            .queue = RefQueue.init(),
            .mutex = .{},
            .cond = .{},
            .closed = false,
        };
    }

    pub fn deinit(_: *RefChannel) void {
        // Nothing to free
    }

    /// Send a packet ref to this channel
    pub fn send(self: *RefChannel, ref: PacketRef) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return error.ChannelClosed;

        if (!self.queue.push(ref)) {
            return error.QueueFull;
        }
        self.cond.signal();
    }

    /// Receive a packet ref from this channel (blocking)
    pub fn receive(self: *RefChannel) ?PacketRef {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.queue.count == 0 and !self.closed) {
            self.cond.wait(&self.mutex);
        }

        if (self.closed and self.queue.count == 0) {
            return null;
        }

        return self.queue.pop();
    }

    /// Try to receive without blocking
    pub fn tryReceive(self: *RefChannel) ?PacketRef {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.queue.pop();
    }

    /// Close the channel
    pub fn close(self: *RefChannel) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.cond.broadcast();
    }
};

/// Legacy channel for full packets (kept for compatibility)
pub const SendChannel = struct {
    queue: PacketQueue,
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    closed: bool,

    pub fn init() SendChannel {
        return SendChannel{
            .queue = PacketQueue.init(),
            .mutex = .{},
            .cond = .{},
            .closed = false,
        };
    }

    pub fn deinit(_: *SendChannel) void {
        // Nothing to free
    }

    /// Send a packet to this channel
    pub fn send(self: *SendChannel, pkt: SendPacket) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return error.ChannelClosed;

        if (!self.queue.push(pkt)) {
            return error.QueueFull;
        }
        self.cond.signal();
    }

    /// Receive a packet from this channel (blocking)
    pub fn receive(self: *SendChannel) ?SendPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.queue.count == 0 and !self.closed) {
            self.cond.wait(&self.mutex);
        }

        if (self.closed and self.queue.count == 0) {
            return null;
        }

        return self.queue.pop();
    }

    /// Try to receive without blocking
    pub fn tryReceive(self: *SendChannel) ?SendPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.queue.pop();
    }

    /// Close the channel
    pub fn close(self: *SendChannel) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.cond.broadcast();
    }
};

/// Packet feed that manages all send channels (zero-copy version)
/// Uses RwLock: multiple broadcasts can happen concurrently (read),
/// while registration is exclusive (write).
pub const SendPktFeed = struct {
    /// Map of interface name to ref channel
    senders: std.StringHashMap(*RefChannel),
    /// Shared packet ring buffer - stores actual packet data
    ring: *PacketRing,
    /// Allocator
    allocator: std.mem.Allocator,
    /// RwLock for concurrent broadcast (read) vs exclusive registration (write)
    rwlock: std.Thread.RwLock,

    pub fn init(allocator: std.mem.Allocator) !SendPktFeed {
        const ring = try allocator.create(PacketRing);
        ring.* = PacketRing.init();

        return SendPktFeed{
            .senders = std.StringHashMap(*RefChannel).init(allocator),
            .ring = ring,
            .allocator = allocator,
            .rwlock = .{},
        };
    }

    pub fn deinit(self: *SendPktFeed) void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        var key_iter = self.senders.keyIterator();
        while (key_iter.next()) |key| {
            self.allocator.free(key.*);
        }

        var value_iter = self.senders.valueIterator();
        while (value_iter.next()) |channel| {
            channel.*.close();
            channel.*.deinit();
            self.allocator.destroy(channel.*);
        }
        self.senders.deinit();
        self.allocator.destroy(self.ring);
    }

    /// Register a ref channel for an interface (exclusive write lock)
    pub fn registerSender(self: *SendPktFeed, iface_name: []const u8) !*RefChannel {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        // Create new channel
        const channel = try self.allocator.create(RefChannel);
        channel.* = RefChannel.init();

        // Copy interface name for the key
        const name_copy = try self.allocator.dupe(u8, iface_name);

        try self.senders.put(name_copy, channel);

        log.debug("Registered sender for interface: {s}", .{iface_name});

        return channel;
    }

    /// Get packet data from the shared ring buffer
    pub fn getPacketData(self: *const SendPktFeed, ring_idx: u8) []const u8 {
        return self.ring.get(ring_idx);
    }

    /// Broadcast a packet to all interfaces except the source (zero-copy)
    /// Stores packet data once in ring buffer, sends lightweight refs to all channels.
    /// Uses shared read lock - multiple broadcasts can happen concurrently.
    pub fn broadcast(
        self: *SendPktFeed,
        data: []const u8,
        src_interface: []const u8,
        link_type: pcap.LinkType,
        timestamp_sec: i64,
        timestamp_usec: i64,
    ) void {
        if (data.len > MAX_PACKET_SIZE) {
            log.warn("Packet too large to broadcast: {d} bytes", .{data.len});
            return;
        }

        // Store packet data in ring buffer (one copy, outside lock)
        const ring_idx = self.ring.store(data);

        // Create lightweight ref (32 bytes vs 9KB)
        const ref = PacketRef{
            .ring_idx = ring_idx,
            .link_type = link_type,
            .src_interface = src_interface,
            .timestamp_sec = timestamp_sec,
            .timestamp_usec = timestamp_usec,
        };

        // Shared read lock - allows concurrent broadcasts from multiple interfaces
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        var iter = self.senders.iterator();
        while (iter.next()) |entry| {
            // Skip the source interface
            if (std.mem.eql(u8, entry.key_ptr.*, src_interface)) {
                continue;
            }

            entry.value_ptr.*.send(ref) catch |err| {
                log.warn("Failed to send ref to {s}: {}", .{ entry.key_ptr.*, err });
            };
        }
    }

    /// Get the number of registered senders
    pub fn count(self: *SendPktFeed) usize {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.senders.count();
    }
};

// ============================================================================
// Pre-allocated Outgoing Buffers
// ============================================================================

/// Pre-allocated buffer pool for outgoing packets.
/// Eliminates per-destination allocation in hot path.
pub const OutgoingPool = struct {
    const POOL_SIZE = 32; // Enough for burst to 32 clients

    buffers: [POOL_SIZE][MAX_PACKET_SIZE]u8,
    idx: u8,

    pub fn init() OutgoingPool {
        return OutgoingPool{
            .buffers = undefined,
            .idx = 0,
        };
    }

    /// Acquire a buffer from the pool (round-robin)
    pub fn acquire(self: *OutgoingPool) *[MAX_PACKET_SIZE]u8 {
        const buf = &self.buffers[self.idx];
        self.idx = (self.idx + 1) % POOL_SIZE;
        return buf;
    }
};

// ============================================================================
// Packet Modification
// ============================================================================

/// Build an outgoing packet with modified destination IP into a pre-allocated buffer.
/// Returns the slice of the buffer that was used.
pub fn buildOutgoingPacketInto(
    buffer: []u8,
    parsed: packet.ParsedPacket,
    dst_ip: [4]u8,
    dst_link_type: pcap.LinkType,
    src_mac: [6]u8,
) ![]u8 {
    const original_ipv4 = parsed.ipv4 orelse return error.NoIpv4Header;
    const original_udp = parsed.udp orelse return error.NoUdpHeader;

    // Calculate sizes
    const l2_size: usize = switch (dst_link_type) {
        .ethernet => packet.ETHERNET_HEADER_SIZE,
        .null, .loop => packet.LOOPBACK_HEADER_SIZE,
        .raw => 0,
        else => return error.UnsupportedLinkType,
    };
    const ip_header_size = original_ipv4.getHeaderLength();
    const udp_size = packet.UDP_HEADER_SIZE;
    const payload_size = parsed.payload.len;
    const total_size = l2_size + ip_header_size + udp_size + payload_size;

    if (total_size > buffer.len) {
        return error.BufferTooSmall;
    }

    var builder = packet.PacketBuilder.init(buffer[0..total_size]);

    // Add L2 header based on destination link type
    switch (dst_link_type) {
        .ethernet => {
            _ = try builder.addEthernet(src_mac, packet.BROADCAST_MAC, .ipv4);
        },
        .null, .loop => {
            _ = try builder.addLoopback(.ipv4);
        },
        .raw => {
            // No L2 header
        },
        else => return error.UnsupportedLinkType,
    }

    // Add IPv4 header (copy from original but change dst IP)
    const ipv4 = try builder.addIPv4(
        original_ipv4.src_ip,
        dst_ip,
        original_ipv4.getProtocol(),
        original_ipv4.ttl,
    );

    // Copy additional IPv4 fields
    ipv4.tos = original_ipv4.tos;
    ipv4.identification = original_ipv4.identification;
    ipv4.flags_fragment = original_ipv4.flags_fragment;

    // Add UDP header
    const udp = try builder.addUDP(
        original_udp.getSrcPort(),
        original_udp.getDstPort(),
    );

    // Add payload
    try builder.addPayload(parsed.payload);

    // Fix up lengths
    const ip_total_len: u16 = @intCast(ip_header_size + udp_size + payload_size);
    ipv4.setTotalLength(ip_total_len);

    const udp_len: u16 = @intCast(udp_size + payload_size);
    udp.setLength(udp_len);

    // Calculate checksums
    packet.calculateIpChecksum(ipv4);
    // UDP checksum is left as 0 (valid for UDP)

    return builder.getData();
}

/// Build an outgoing packet with modified destination IP (legacy allocating version)
pub fn buildOutgoingPacket(
    allocator: std.mem.Allocator,
    parsed: packet.ParsedPacket,
    dst_ip: [4]u8,
    dst_link_type: pcap.LinkType,
    src_mac: [6]u8,
) ![]u8 {
    const original_ipv4 = parsed.ipv4 orelse return error.NoIpv4Header;
    const original_udp = parsed.udp orelse return error.NoUdpHeader;

    // Calculate sizes
    const l2_size: usize = switch (dst_link_type) {
        .ethernet => packet.ETHERNET_HEADER_SIZE,
        .null, .loop => packet.LOOPBACK_HEADER_SIZE,
        .raw => 0,
        else => return error.UnsupportedLinkType,
    };
    const ip_header_size = original_ipv4.getHeaderLength();
    const udp_size = packet.UDP_HEADER_SIZE;
    const payload_size = parsed.payload.len;
    const total_size = l2_size + ip_header_size + udp_size + payload_size;

    // Allocate buffer
    const buffer = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buffer);

    var builder = packet.PacketBuilder.init(buffer);

    // Add L2 header based on destination link type
    switch (dst_link_type) {
        .ethernet => {
            _ = try builder.addEthernet(src_mac, packet.BROADCAST_MAC, .ipv4);
        },
        .null, .loop => {
            _ = try builder.addLoopback(.ipv4);
        },
        .raw => {
            // No L2 header
        },
        else => return error.UnsupportedLinkType,
    }

    // Add IPv4 header (copy from original but change dst IP)
    const ipv4 = try builder.addIPv4(
        original_ipv4.src_ip,
        dst_ip,
        original_ipv4.getProtocol(),
        original_ipv4.ttl,
    );

    // Copy additional IPv4 fields
    ipv4.tos = original_ipv4.tos;
    ipv4.identification = original_ipv4.identification;
    ipv4.flags_fragment = original_ipv4.flags_fragment;

    // Add UDP header
    const udp = try builder.addUDP(
        original_udp.getSrcPort(),
        original_udp.getDstPort(),
    );

    // Add payload
    try builder.addPayload(parsed.payload);

    // Fix up lengths
    const ip_total_len: u16 = @intCast(ip_header_size + udp_size + payload_size);
    ipv4.setTotalLength(ip_total_len);

    const udp_len: u16 = @intCast(udp_size + payload_size);
    udp.setLength(udp_len);

    // Calculate checksums
    packet.calculateIpChecksum(ipv4);
    // UDP checksum is left as 0 (valid for UDP)

    return builder.getData();
}

// ============================================================================
// Tests
// ============================================================================

test "SendPktFeed registration" {
    const allocator = std.testing.allocator;

    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    _ = try feed.registerSender("eth0");
    _ = try feed.registerSender("eth1");

    try std.testing.expectEqual(@as(usize, 2), feed.count());
}

test "PacketRing store and retrieve" {
    var ring = PacketRing.init();
    const data = "Hello, World!";

    const idx = ring.store(data);
    const retrieved = ring.get(idx);

    try std.testing.expectEqualStrings(data, retrieved);
}

test "OutgoingPool round-robin" {
    var pool = OutgoingPool.init();

    const buf1 = pool.acquire();
    const buf2 = pool.acquire();

    // Should be different buffers
    try std.testing.expect(buf1 != buf2);
}

test "SendPacket data copy" {
    const data = "Hello, World!";
    var pkt = SendPacket{
        .data = undefined,
        .len = data.len,
        .src_interface = "eth0",
        .link_type = .ethernet,
        .timestamp_sec = 0,
        .timestamp_usec = 0,
    };
    @memcpy(pkt.data[0..data.len], data);

    try std.testing.expectEqualStrings(data, pkt.getData());
}

test "PacketQueue basic operations" {
    var queue = PacketQueue.init();

    // Queue should be empty initially
    try std.testing.expect(queue.pop() == null);

    // Push a packet
    var pkt = SendPacket{
        .data = undefined,
        .len = 5,
        .src_interface = "eth0",
        .link_type = .ethernet,
        .timestamp_sec = 0,
        .timestamp_usec = 0,
    };
    @memcpy(pkt.data[0..5], "hello");

    try std.testing.expect(queue.push(pkt));
    try std.testing.expectEqual(@as(usize, 1), queue.count);

    // Pop the packet
    const popped = queue.pop();
    try std.testing.expect(popped != null);
    try std.testing.expectEqualStrings("hello", popped.?.getData());
    try std.testing.expectEqual(@as(usize, 0), queue.count);
}
