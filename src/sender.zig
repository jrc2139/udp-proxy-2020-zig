//! Packet sender infrastructure
//!
//! Manages the broadcast of packets between interfaces.
//! Each interface registers a send channel, and packets are
//! forwarded to all interfaces except the source.
//!
//! Design: Zero-copy packet broadcast using ring buffers and references.
//! Packets are stored once in a shared ring buffer, and lightweight refs
//! are passed through lock-free MPSC channels. This eliminates per-packet
//! allocation and avoids mutex overhead in the hot path.
//!
//! The RefChannel uses a Vyukov bounded MPSC queue with per-slot sequence
//! numbers. Multiple producer threads (broadcasting interfaces) can push
//! concurrently without locks. The single consumer thread (the listener)
//! pops without contention.

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
    /// Thread-safe via atomic increment. The non-atomic memcpy/length writes
    /// are ordered by the sequence store (release) in MpscRefQueue.push(),
    /// which the consumer observes via sequence load (acquire) in pop().
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

/// Lock-free bounded MPSC queue for packet references.
/// Based on Dmitry Vyukov's bounded MPSC queue with per-slot sequence numbers.
/// Multiple producers can push concurrently via CAS on write_pos.
/// Single consumer pops sequentially without contention.
pub const MpscRefQueue = struct {
    pub const QUEUE_SIZE = 256;
    const MASK = QUEUE_SIZE - 1;

    items: [QUEUE_SIZE]PacketRef,
    sequence: [QUEUE_SIZE]std.atomic.Value(u32),
    write_pos: std.atomic.Value(u32),
    read_pos: u32, // only consumer touches this

    pub fn init() MpscRefQueue {
        var self: MpscRefQueue = undefined;
        self.write_pos = std.atomic.Value(u32).init(0);
        self.read_pos = 0;
        for (0..QUEUE_SIZE) |i| {
            self.sequence[i] = std.atomic.Value(u32).init(@intCast(i));
        }
        return self;
    }

    /// Push a ref into the queue. Lock-free, safe from multiple producers.
    /// Returns false if the queue is full.
    pub fn push(self: *MpscRefQueue, item: PacketRef) bool {
        var pos = self.write_pos.load(.monotonic);
        while (true) {
            const slot = pos & MASK;
            const seq = self.sequence[slot].load(.acquire);
            const diff = @as(i64, seq) - @as(i64, pos);
            if (diff == 0) {
                // Slot available -- try to claim it
                if (self.write_pos.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |updated| {
                    pos = updated; // Lost race, retry with new pos
                } else {
                    // Claimed. Write data, then mark slot as filled.
                    self.items[slot] = item;
                    self.sequence[slot].store(pos +% 1, .release);
                    return true;
                }
            } else if (diff < 0) {
                return false; // Queue full
            } else {
                // Slot was reclaimed by consumer while we were looking.
                pos = self.write_pos.load(.monotonic);
            }
        }
    }

    /// Pop a ref from the queue. Only safe from a single consumer.
    /// Returns null if empty.
    pub fn pop(self: *MpscRefQueue) ?PacketRef {
        const slot = self.read_pos & MASK;
        const seq = self.sequence[slot].load(.acquire);
        const expected = self.read_pos +% 1;
        if (seq != expected) return null; // Empty or not yet committed
        const item = self.items[slot];
        self.sequence[slot].store(self.read_pos +% QUEUE_SIZE, .release);
        self.read_pos +%= 1;
        return item;
    }

    /// Check if queue appears empty (non-authoritative, for spin loops).
    pub fn isEmpty(self: *const MpscRefQueue) bool {
        const slot = self.read_pos & MASK;
        const seq = self.sequence[slot].load(.monotonic);
        return seq != self.read_pos +% 1;
    }
};

/// Lock-free channel for receiving packet references.
/// Uses MpscRefQueue internally -- no mutexes in the hot path.
/// Blocking receive uses spin + nanosleep hybrid for the send-only case.
pub const RefChannel = struct {
    queue: MpscRefQueue,
    closed: std.atomic.Value(bool),

    pub fn init() RefChannel {
        return RefChannel{
            .queue = MpscRefQueue.init(),
            .closed = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(_: *RefChannel) void {}

    /// Send a packet ref. Lock-free, safe from multiple producer threads.
    pub fn send(self: *RefChannel, ref: PacketRef) !void {
        if (self.closed.load(.acquire)) return error.ChannelClosed;
        if (!self.queue.push(ref)) return error.QueueFull;
    }

    /// Receive a packet ref (blocking). Spins briefly, then falls back to
    /// 100us nanosleep polling. Used only by send-only/loopback listeners.
    pub fn receive(self: *RefChannel) ?PacketRef {
        var spin: u32 = 0;
        while (true) {
            if (self.queue.pop()) |item| return item;
            if (self.closed.load(.acquire)) return self.queue.pop(); // drain
            if (spin < 128) {
                std.atomic.spinLoopHint();
                spin += 1;
            } else {
                const req = std.c.timespec{ .sec = 0, .nsec = 100_000 }; // 100us
                _ = std.c.nanosleep(&req, null);
                spin = 0;
            }
        }
    }

    /// Try to receive without blocking. Lock-free.
    pub fn tryReceive(self: *RefChannel) ?PacketRef {
        return self.queue.pop();
    }

    /// Close the channel. The consumer will drain remaining items.
    pub fn close(self: *RefChannel) void {
        self.closed.store(true, .release);
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
    rwlock: std.Io.RwLock,

    pub fn init(allocator: std.mem.Allocator) !SendPktFeed {
        const ring = try allocator.create(PacketRing);
        ring.* = PacketRing.init();

        return SendPktFeed{
            .senders = std.StringHashMap(*RefChannel).init(allocator),
            .ring = ring,
            .allocator = allocator,
            .rwlock = std.Io.RwLock.init,
        };
    }

    pub fn deinit(self: *SendPktFeed) void {
        self.rwlock.lockUncancelable(undefined);
        defer self.rwlock.unlock(undefined);

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
        self.rwlock.lockUncancelable(undefined);
        defer self.rwlock.unlock(undefined);

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
        self.rwlock.lockSharedUncancelable(undefined);
        defer self.rwlock.unlockShared(undefined);

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
        self.rwlock.lockSharedUncancelable(undefined);
        defer self.rwlock.unlockShared(undefined);
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

// ============================================================================
// MpscRefQueue Tests
// ============================================================================

fn makeRef(idx: u8) PacketRef {
    return PacketRef{
        .ring_idx = idx,
        .link_type = .ethernet,
        .src_interface = "test",
        .timestamp_sec = 0,
        .timestamp_usec = 0,
    };
}

test "MpscRefQueue: single-threaded push and pop" {
    var q = MpscRefQueue.init();

    try std.testing.expect(q.pop() == null); // empty

    try std.testing.expect(q.push(makeRef(1)));
    try std.testing.expect(q.push(makeRef(2)));
    try std.testing.expect(q.push(makeRef(3)));

    try std.testing.expectEqual(@as(u8, 1), q.pop().?.ring_idx);
    try std.testing.expectEqual(@as(u8, 2), q.pop().?.ring_idx);
    try std.testing.expectEqual(@as(u8, 3), q.pop().?.ring_idx);
    try std.testing.expect(q.pop() == null); // drained
}

test "MpscRefQueue: fill to capacity" {
    var q = MpscRefQueue.init();

    // Fill all slots
    for (0..MpscRefQueue.QUEUE_SIZE) |i| {
        try std.testing.expect(q.push(makeRef(@intCast(i & 0xFF))));
    }

    // Next push should fail (queue full)
    try std.testing.expect(!q.push(makeRef(0)));

    // Pop one, then push should succeed again
    _ = q.pop();
    try std.testing.expect(q.push(makeRef(42)));
}

test "MpscRefQueue: wrap-around correctness" {
    var q = MpscRefQueue.init();

    // Push and pop past the wrap boundary
    for (0..MpscRefQueue.QUEUE_SIZE * 3) |i| {
        try std.testing.expect(q.push(makeRef(@intCast(i & 0xFF))));
        const ref = q.pop().?;
        try std.testing.expectEqual(@as(u8, @intCast(i & 0xFF)), ref.ring_idx);
    }

    try std.testing.expect(q.isEmpty());
}

test "MpscRefQueue: isEmpty reflects state" {
    var q = MpscRefQueue.init();
    try std.testing.expect(q.isEmpty());

    try std.testing.expect(q.push(makeRef(1)));
    try std.testing.expect(!q.isEmpty());

    _ = q.pop();
    try std.testing.expect(q.isEmpty());
}

test "MpscRefQueue: MPSC stress test" {
    // 4 producer threads, 1 consumer (this thread)
    const NUM_PRODUCERS = 4;
    const ITEMS_PER_PRODUCER = 10_000;

    var q = MpscRefQueue.init();
    var produced = [_]std.atomic.Value(u32){std.atomic.Value(u32).init(0)} ** NUM_PRODUCERS;

    const ProducerCtx = struct {
        queue: *MpscRefQueue,
        id: u8,
        produced: *std.atomic.Value(u32),

        fn run(ctx: @This()) void {
            var i: u32 = 0;
            while (i < ITEMS_PER_PRODUCER) {
                if (ctx.queue.push(makeRef(ctx.id))) {
                    i += 1;
                } else {
                    // Queue full, spin
                    std.atomic.spinLoopHint();
                }
            }
            ctx.produced.store(i, .release);
        }
    };

    // Spawn producers
    var threads: [NUM_PRODUCERS]std.Thread = undefined;
    for (0..NUM_PRODUCERS) |i| {
        threads[i] = try std.Thread.spawn(.{}, ProducerCtx.run, .{ProducerCtx{
            .queue = &q,
            .id = @intCast(i),
            .produced = &produced[i],
        }});
    }

    // Consumer: count items per producer
    var counts = [_]u32{0} ** NUM_PRODUCERS;
    var total: u32 = 0;
    const expected_total = NUM_PRODUCERS * ITEMS_PER_PRODUCER;

    while (total < expected_total) {
        if (q.pop()) |ref| {
            counts[ref.ring_idx] += 1;
            total += 1;
        } else {
            std.atomic.spinLoopHint();
        }
    }

    // Join producers
    for (&threads) |*t| t.join();

    // Verify: each producer sent exactly ITEMS_PER_PRODUCER
    for (counts) |c| {
        try std.testing.expectEqual(@as(u32, ITEMS_PER_PRODUCER), c);
    }
    try std.testing.expect(q.isEmpty());
}

// ============================================================================
// RefChannel Tests
// ============================================================================

test "RefChannel: send and tryReceive" {
    var ch = RefChannel.init();
    defer ch.deinit();

    try ch.send(makeRef(10));
    try ch.send(makeRef(20));

    try std.testing.expectEqual(@as(u8, 10), ch.tryReceive().?.ring_idx);
    try std.testing.expectEqual(@as(u8, 20), ch.tryReceive().?.ring_idx);
    try std.testing.expect(ch.tryReceive() == null);
}

test "RefChannel: send after close returns error" {
    var ch = RefChannel.init();
    defer ch.deinit();

    ch.close();
    try std.testing.expectError(error.ChannelClosed, ch.send(makeRef(1)));
}

test "RefChannel: receive drains on close" {
    var ch = RefChannel.init();
    defer ch.deinit();

    try ch.send(makeRef(42));
    ch.close();

    // Should still get the queued item
    const ref = ch.receive();
    try std.testing.expect(ref != null);
    try std.testing.expectEqual(@as(u8, 42), ref.?.ring_idx);

    // Now should get null (closed + empty)
    try std.testing.expect(ch.receive() == null);
}

test "RefChannel: MPSC concurrent send + tryReceive" {
    const NUM_SENDERS = 4;
    const ITEMS_PER_SENDER = 5_000;

    var ch = RefChannel.init();
    defer ch.deinit();

    const SenderCtx = struct {
        channel: *RefChannel,
        id: u8,

        fn run(ctx: @This()) void {
            var i: u32 = 0;
            while (i < ITEMS_PER_SENDER) {
                ctx.channel.send(makeRef(ctx.id)) catch {
                    std.atomic.spinLoopHint();
                    continue;
                };
                i += 1;
            }
        }
    };

    var threads: [NUM_SENDERS]std.Thread = undefined;
    for (0..NUM_SENDERS) |i| {
        threads[i] = try std.Thread.spawn(.{}, SenderCtx.run, .{SenderCtx{
            .channel = &ch,
            .id = @intCast(i),
        }});
    }

    var counts = [_]u32{0} ** NUM_SENDERS;
    var total: u32 = 0;
    const expected = NUM_SENDERS * ITEMS_PER_SENDER;

    while (total < expected) {
        if (ch.tryReceive()) |ref| {
            counts[ref.ring_idx] += 1;
            total += 1;
        } else {
            std.atomic.spinLoopHint();
        }
    }

    for (&threads) |*t| t.join();

    for (counts) |c| {
        try std.testing.expectEqual(@as(u32, ITEMS_PER_SENDER), c);
    }
}

// ============================================================================
// SendPktFeed Tripwire Tests
// ============================================================================

test "SendPktFeed: init and deinit with leak detection" {
    const allocator = std.testing.allocator;
    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    try std.testing.expectEqual(@as(usize, 0), feed.count());
}

test "SendPktFeed: register multiple senders" {
    const allocator = std.testing.allocator;
    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    _ = try feed.registerSender("eth0");
    _ = try feed.registerSender("eth1");
    _ = try feed.registerSender("wg0");

    try std.testing.expectEqual(@as(usize, 3), feed.count());
}

test "SendPktFeed: broadcast skips source interface" {
    const allocator = std.testing.allocator;
    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    const ch_a = try feed.registerSender("eth0");
    const ch_b = try feed.registerSender("eth1");

    // Broadcast from eth0 -- should only go to eth1
    feed.broadcast("hello", "eth0", .ethernet, 0, 0);

    try std.testing.expect(ch_a.tryReceive() == null); // skipped
    try std.testing.expect(ch_b.tryReceive() != null); // received
}

test "SendPktFeed: allocation failure on init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const result = SendPktFeed.init(failing.allocator());
    try std.testing.expectError(error.OutOfMemory, result);
}

test "SendPktFeed: allocation failure on registerSender" {
    // Use a FailingAllocator as the feed's allocator so registerSender hits OOM
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });

    // init uses 1 allocation (the PacketRing), so fail_index=1 lets init succeed
    // but the next allocation (in registerSender) will fail
    var feed = try SendPktFeed.init(failing.allocator());
    defer feed.deinit();

    const result = feed.registerSender("eth0");
    try std.testing.expectError(error.OutOfMemory, result);
}
