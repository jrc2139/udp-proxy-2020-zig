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
const tripwire = @import("tripwire");

const log = std.log.scoped(.sender);

/// Valid `Io` backing the contended (futex) path of `reg_mutex`. The Threaded
/// futex ops ignore userdata, so the process-wide instance is a correct
/// source; passing `undefined` would crash on lock contention.
inline fn syncIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Tripwire points for SendPktFeed.init. Test-only; inlined to no-ops in
/// release builds via tripwire.enabled = builtin.is_test.
pub const feed_init_tw = tripwire.module(enum {
    after_ring_alloc,
}, error{OutOfMemory});

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
///
/// Slot lifetime safety: the ring is shared by all producers, and a captured
/// packet's slot can be recycled (overwritten) while a lagging consumer still
/// holds a reference to it. Each slot therefore carries a generation stamp
/// (`seqs`). A consumer copies the bytes out and verifies (seqlock) that the
/// slot still held its packet before and after the copy; a mismatch means the
/// slot was recycled, so the consumer drops the packet instead of forwarding
/// corrupt data.
pub const PacketRing = struct {
    /// Top bit of a stamp marks "write in progress"; the low 31 bits are the
    /// store sequence number. A consumer's seq never has the top bit set, so a
    /// slot that is mid-write never compares equal to a held seq.
    const WRITING_BIT: u32 = 0x8000_0000;
    const SEQ_MASK: u32 = 0x7FFF_FFFF;

    buffers: [RING_SIZE][MAX_PACKET_SIZE]u8,
    lengths: [RING_SIZE]u16,
    /// Per-slot generation stamp (see WRITING_BIT / SEQ_MASK).
    seqs: [RING_SIZE]std.atomic.Value(u32),
    write_idx: std.atomic.Value(u32),

    pub fn init() PacketRing {
        var self = PacketRing{
            .buffers = undefined,
            .lengths = [_]u16{0} ** RING_SIZE,
            .seqs = undefined,
            .write_idx = std.atomic.Value(u32).init(0),
        };
        for (0..RING_SIZE) |i| self.seqs[i] = std.atomic.Value(u32).init(0);
        return self;
    }

    /// Store packet data and return its unique sequence number, which also
    /// encodes the slot (`seq % RING_SIZE`). The slot's stamp is set to WRITING
    /// before the copy and to `seq` after, so a consumer holding a previous seq
    /// for the same slot detects the overwrite in `copyOut`.
    pub fn store(self: *PacketRing, data: []const u8) u32 {
        const raw = self.write_idx.fetchAdd(1, .monotonic);
        const seq = raw & SEQ_MASK;
        const idx = raw % RING_SIZE;
        const len: u16 = @intCast(@min(data.len, MAX_PACKET_SIZE));
        self.seqs[idx].store(seq | WRITING_BIT, .release);
        @memcpy(self.buffers[idx][0..len], data[0..len]);
        self.lengths[idx] = len;
        self.seqs[idx].store(seq, .release);
        return seq;
    }

    /// Copy the packet identified by `seq` into `dst`, validating (seqlock)
    /// that the slot still holds that store before and after the copy. Returns
    /// the copied slice, or null if the slot was recycled/overwritten -- the
    /// caller must then drop the packet. `dst` should be at least
    /// MAX_PACKET_SIZE; the copy is clamped to `dst.len` regardless.
    pub fn copyOut(self: *const PacketRing, seq: u32, dst: []u8) ?[]const u8 {
        const idx = seq % RING_SIZE;
        if (self.seqs[idx].load(.acquire) != seq) return null;
        const len = @min(@as(usize, self.lengths[idx]), @min(dst.len, MAX_PACKET_SIZE));
        @memcpy(dst[0..len], self.buffers[idx][0..len]);
        // Re-validate: an overwrite concurrent with the copy may have torn the
        // bytes, so discard them if the slot no longer holds our seq.
        if (self.seqs[idx].load(.acquire) != seq) return null;
        return dst[0..len];
    }
};

/// Lightweight packet reference - passed through channels instead of full packet data.
/// 16 bytes: fits in half a cache line. MpscRefQueue items fit in L1 cache (4KB).
pub const PacketRef = struct {
    /// Ring store sequence number; also encodes the slot (`seq % RING_SIZE`).
    /// The consumer validates the slot still holds this seq before forwarding.
    seq: u32,
    /// Compact link type index (0=ethernet, 1=null, 2=loop, 3=enc, 4=raw)
    link_type_idx: u8,
    /// Source interface index (into SendPktFeed.iface_channels)
    src_iface_idx: u8,
    /// L2 header size in bytes (offset to IPv4 header)
    l2_size: u8,
    /// IPv4 header length in bytes (usually 20)
    ip_header_len: u8,
    /// Capture timestamp in microseconds since epoch
    timestamp_us: i64,
};

/// Convert LinkType to compact index for PacketRef
pub fn linkTypeToIdx(lt: pcap.LinkType) u8 {
    return switch (lt) {
        .ethernet => 0,
        .null => 1,
        .loop => 2,
        .enc => 3,
        .raw => 4,
        else => 255,
    };
}

/// Convert compact index back to LinkType
pub fn idxToLinkType(idx: u8) pcap.LinkType {
    return switch (idx) {
        0 => .ethernet,
        1 => .null,
        2 => .loop,
        3 => .enc,
        4 => .raw,
        else => .ethernet,
    };
}

/// Get L2 header size for a link type
pub fn linkTypeL2Size(lt: pcap.LinkType) u8 {
    return switch (lt) {
        .ethernet => packet.ETHERNET_HEADER_SIZE,
        .null, .loop => packet.LOOPBACK_HEADER_SIZE,
        .enc => packet.ENC_HEADER_SIZE,
        .raw => 0,
        else => 0,
    };
}

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
    // Cache-line padding: prevent false sharing between producer (write_pos)
    // and consumer (read_pos) which would cause cache-line bouncing.
    _cache_pad: [60]u8 = undefined,
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

/// Maximum number of interfaces supported
pub const MAX_IFACES = 16;

/// Packet feed that manages all send channels (zero-copy version).
/// After registration, broadcast uses a frozen array of channels with no locks.
pub const SendPktFeed = struct {
    /// Indexed array of channels (populated during registration, immutable after)
    iface_channels: [MAX_IFACES]*RefChannel = undefined,
    /// Number of registered interfaces
    iface_count: u8 = 0,
    /// Map of interface name to ref channel (for cleanup and name lookup)
    senders: std.StringHashMap(*RefChannel),
    /// Shared packet ring buffer - stores actual packet data
    ring: *PacketRing,
    /// Allocator
    allocator: std.mem.Allocator,
    /// Mutex for registration (not used in hot path)
    reg_mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator) !SendPktFeed {
        const ring = try allocator.create(PacketRing);
        errdefer allocator.destroy(ring);
        ring.* = PacketRing.init();

        try feed_init_tw.check(.after_ring_alloc);

        return SendPktFeed{
            .senders = std.StringHashMap(*RefChannel).init(allocator),
            .ring = ring,
            .allocator = allocator,
            .reg_mutex = std.Io.Mutex.init,
        };
    }

    pub fn deinit(self: *SendPktFeed) void {
        var key_iter = self.senders.keyIterator();
        while (key_iter.next()) |key| {
            self.allocator.free(key.*);
        }

        for (0..self.iface_count) |i| {
            self.iface_channels[i].close();
            self.iface_channels[i].deinit();
            self.allocator.destroy(self.iface_channels[i]);
        }
        self.senders.deinit();
        self.allocator.destroy(self.ring);
    }

    /// Register a ref channel for an interface. Returns the interface index.
    pub fn registerSender(self: *SendPktFeed, iface_name: []const u8) !struct { channel: *RefChannel, idx: u8 } {
        self.reg_mutex.lockUncancelable(syncIo());
        defer self.reg_mutex.unlock(syncIo());

        if (self.iface_count >= MAX_IFACES) {
            log.err("Too many interfaces (max {d})", .{MAX_IFACES});
            return error.TooManyInterfaces;
        }

        // Create new channel
        const channel = try self.allocator.create(RefChannel);
        channel.* = RefChannel.init();

        // Copy interface name for the map key
        const name_copy = try self.allocator.dupe(u8, iface_name);
        try self.senders.put(name_copy, channel);

        // Add to indexed array
        const idx = self.iface_count;
        self.iface_channels[idx] = channel;
        self.iface_count += 1;

        log.debug("Registered sender for interface: {s} (idx={d})", .{ iface_name, idx });

        return .{ .channel = channel, .idx = idx };
    }

    /// Copy the packet for `seq` out of the shared ring into `dst`, validating
    /// the slot was not recycled. Returns null if the consumer must drop it.
    pub fn copyPacket(self: *const SendPktFeed, seq: u32, dst: []u8) ?[]const u8 {
        return self.ring.copyOut(seq, dst);
    }

    /// Broadcast a packet to all interfaces except the source (zero-copy).
    /// Uses frozen array -- no locks, no hash map iteration in the hot path.
    pub fn broadcast(
        self: *SendPktFeed,
        data: []const u8,
        src_iface_idx: u8,
        link_type: pcap.LinkType,
        l2_size: u8,
        ip_header_len: u8,
        timestamp_us: i64,
    ) void {
        if (data.len > MAX_PACKET_SIZE) {
            log.warn("Packet too large to broadcast: {d} bytes", .{data.len});
            return;
        }

        // Store packet data in ring buffer (one copy)
        const seq = self.ring.store(data);

        // Create compact ref (16 bytes)
        const ref = PacketRef{
            .seq = seq,
            .link_type_idx = linkTypeToIdx(link_type),
            .src_iface_idx = src_iface_idx,
            .l2_size = l2_size,
            .ip_header_len = ip_header_len,
            .timestamp_us = timestamp_us,
        };

        // Iterate frozen array -- no lock needed, array is immutable after startup
        for (0..self.iface_count) |i| {
            if (i == src_iface_idx) continue;
            self.iface_channels[i].send(ref) catch |err| {
                log.warn("Failed to send ref to iface {d}: {}", .{ i, err });
            };
        }
    }

    /// Get the number of registered senders
    pub fn count(self: *SendPktFeed) usize {
        return self.iface_count;
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
        .enc => packet.ENC_HEADER_SIZE,
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
        .enc => {
            // ENC header: AF_INET (2), SPI (0), flags (0)
            try builder.addEnc();
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

/// Fast-path for Ethernet-to-Ethernet forwarding with standard IPv4 header (IHL=5).
/// Instead of rebuilding the packet header-by-header via PacketBuilder, this does
/// a single memcpy of the entire packet then patches only the bytes that change:
/// dst MAC (6B), src MAC (6B), dst IP (4B), and IP checksum (2B).
pub fn fastPatchEthernetPacket(
    buffer: []u8,
    original: []const u8,
    dst_ip: [4]u8,
    src_mac: [6]u8,
) ![]u8 {
    if (original.len > buffer.len) return error.BufferTooSmall;
    if (original.len < packet.ETHERNET_HEADER_SIZE + packet.IPV4_MIN_HEADER_SIZE)
        return error.PacketTooShort;

    // Single memcpy of entire packet
    @memcpy(buffer[0..original.len], original);

    // Patch destination MAC to broadcast (bytes 0-5)
    @memcpy(buffer[0..6], &packet.BROADCAST_MAC);

    // Patch source MAC (bytes 6-11)
    @memcpy(buffer[6..12], &src_mac);

    // Patch destination IP (ETH=14 + version_ihl=1 + tos=1 + total_length=2 +
    // identification=2 + flags_fragment=2 + ttl=1 + protocol=1 + checksum=2 + src_ip=4 = offset 30)
    @memcpy(buffer[30..34], &dst_ip);

    // Recalculate IP checksum
    const ipv4: *packet.IPv4Header = @ptrCast(@alignCast(buffer.ptr + packet.ETHERNET_HEADER_SIZE));
    packet.calculateIpChecksum(ipv4);

    // The destination IP changed, and it is covered by the UDP pseudo-header, so
    // the original UDP checksum is now invalid -- a receiver that validates it
    // would drop the packet. Zero it (0 disables the optional IPv4 UDP checksum),
    // matching buildOutgoingPacketInto. Guarded by length since this helper does
    // not otherwise require a UDP header to be present.
    const udp_csum_off = packet.ETHERNET_HEADER_SIZE + packet.IPV4_MIN_HEADER_SIZE + 6;
    if (original.len >= udp_csum_off + 2) {
        buffer[udp_csum_off] = 0;
        buffer[udp_csum_off + 1] = 0;
    }

    return buffer[0..original.len];
}

// ============================================================================
// Tests
// ============================================================================

test "SendPktFeed registration" {
    const allocator = std.testing.allocator;

    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    const r0 = try feed.registerSender("eth0");
    const r1 = try feed.registerSender("eth1");

    try std.testing.expectEqual(@as(u8, 0), r0.idx);
    try std.testing.expectEqual(@as(u8, 1), r1.idx);
    try std.testing.expectEqual(@as(usize, 2), feed.count());
}

test "PacketRing store and retrieve" {
    var ring = PacketRing.init();
    const data = "Hello, World!";

    const seq = ring.store(data);
    var buf: [MAX_PACKET_SIZE]u8 = undefined;
    const retrieved = ring.copyOut(seq, &buf).?;

    try std.testing.expectEqualStrings(data, retrieved);
}

test "PacketRing.copyOut detects slot recycling" {
    var ring = PacketRing.init();
    var buf: [MAX_PACKET_SIZE]u8 = undefined;

    const seq_a = ring.store("packet A");
    // Valid immediately after store.
    try std.testing.expectEqualStrings("packet A", ring.copyOut(seq_a, &buf).?);

    // Overwrite the same slot RING_SIZE times so seq_a's slot is recycled.
    for (0..RING_SIZE) |_| {
        _ = ring.store("newer packet");
    }

    // seq_a's slot now holds a newer store -> copyOut must drop (null).
    try std.testing.expect(ring.copyOut(seq_a, &buf) == null);
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
        .seq = idx,
        .link_type_idx = 0, // ethernet
        .src_iface_idx = 0,
        .l2_size = 14,
        .ip_header_len = 20,
        .timestamp_us = 0,
    };
}

test "MpscRefQueue: single-threaded push and pop" {
    var q = MpscRefQueue.init();

    try std.testing.expect(q.pop() == null); // empty

    try std.testing.expect(q.push(makeRef(1)));
    try std.testing.expect(q.push(makeRef(2)));
    try std.testing.expect(q.push(makeRef(3)));

    try std.testing.expectEqual(@as(u32, 1), q.pop().?.seq);
    try std.testing.expectEqual(@as(u32, 2), q.pop().?.seq);
    try std.testing.expectEqual(@as(u32, 3), q.pop().?.seq);
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
        try std.testing.expectEqual(@as(u32, @intCast(i & 0xFF)), ref.seq);
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
            counts[ref.seq] += 1;
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

    try std.testing.expectEqual(@as(u32, 10), ch.tryReceive().?.seq);
    try std.testing.expectEqual(@as(u32, 20), ch.tryReceive().?.seq);
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
    try std.testing.expectEqual(@as(u32, 42), ref.?.seq);

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
            counts[ref.seq] += 1;
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

    const r0 = try feed.registerSender("eth0");
    const r1 = try feed.registerSender("eth1");
    const r2 = try feed.registerSender("wg0");

    try std.testing.expectEqual(@as(u8, 0), r0.idx);
    try std.testing.expectEqual(@as(u8, 1), r1.idx);
    try std.testing.expectEqual(@as(u8, 2), r2.idx);
    try std.testing.expectEqual(@as(usize, 3), feed.count());
}

test "SendPktFeed: broadcast skips source interface" {
    const allocator = std.testing.allocator;
    var feed = try SendPktFeed.init(allocator);
    defer feed.deinit();

    const r_a = try feed.registerSender("eth0");
    const r_b = try feed.registerSender("eth1");

    // Broadcast from eth0 (idx=0) -- should only go to eth1
    feed.broadcast("hello", r_a.idx, .ethernet, 14, 20, 0);

    try std.testing.expect(r_a.channel.tryReceive() == null); // skipped
    try std.testing.expect(r_b.channel.tryReceive() != null); // received
}

test "fastPatchEthernetPacket matches buildOutgoingPacketInto" {
    // Buffers need 4-byte alignment because PacketBuilder casts the backing
    // storage to *IPv4Header (u32 fields); stack u8 arrays default to align 1.
    // Production uses heap-allocated pools which already meet the alignment.
    var original: [100]u8 align(4) = undefined;
    var builder = packet.PacketBuilder.init(&original);

    const src_mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const dst_mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    _ = try builder.addEthernet(src_mac, dst_mac, .ipv4);
    const ipv4 = try builder.addIPv4(.{ 192, 168, 1, 1 }, .{ 192, 168, 1, 255 }, .udp, 64);
    const udp_hdr = try builder.addUDP(9003, 9003);
    try builder.addPayload("hello world");

    const ip_total: u16 = @intCast(packet.IPV4_MIN_HEADER_SIZE + packet.UDP_HEADER_SIZE + 11);
    ipv4.setTotalLength(ip_total);
    const udp_total: u16 = @intCast(packet.UDP_HEADER_SIZE + 11);
    udp_hdr.setLength(udp_total);
    packet.calculateIpChecksum(ipv4);

    const pkt_data = builder.getData();

    // Parse for buildOutgoingPacketInto
    const parsed = try packet.parsePacket(pkt_data, .ethernet);

    const new_dst_ip = [_]u8{ 10, 0, 0, 1 };
    const new_src_mac = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

    // Build via full path
    var buf_full: [MAX_PACKET_SIZE]u8 align(4) = undefined;
    const full_result = try buildOutgoingPacketInto(&buf_full, parsed, new_dst_ip, .ethernet, new_src_mac);

    // Build via fast path
    var buf_fast: [MAX_PACKET_SIZE]u8 align(4) = undefined;
    const fast_result = try fastPatchEthernetPacket(&buf_fast, pkt_data, new_dst_ip, new_src_mac);

    // Both should produce identical output
    try std.testing.expectEqual(full_result.len, fast_result.len);
    try std.testing.expectEqualSlices(u8, full_result, fast_result);
}

test "fastPatchEthernetPacket zeroes stale UDP checksum after dst-IP rewrite" {
    // Real mDNS/SSDP/Sonos packets carry a non-zero UDP checksum. The fast path
    // rewrites the destination IP, which is covered by the UDP pseudo-header, so
    // the original checksum becomes invalid and receivers would drop the packet.
    var original: [100]u8 align(4) = undefined;
    var builder = packet.PacketBuilder.init(&original);

    const src_mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const dst_mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    _ = try builder.addEthernet(src_mac, dst_mac, .ipv4);
    const ipv4 = try builder.addIPv4(.{ 192, 168, 1, 1 }, .{ 192, 168, 1, 255 }, .udp, 64);
    const udp_hdr = try builder.addUDP(9003, 9003);
    try builder.addPayload("hello world");

    ipv4.setTotalLength(@intCast(packet.IPV4_MIN_HEADER_SIZE + packet.UDP_HEADER_SIZE + 11));
    udp_hdr.setLength(@intCast(packet.UDP_HEADER_SIZE + 11));
    // Stamp a non-zero UDP checksum, as a real captured packet would have.
    udp_hdr.checksum = std.mem.nativeToBig(u16, 0xABCD);
    packet.calculateIpChecksum(ipv4);

    const pkt_data = builder.getData();

    var buf_fast: [MAX_PACKET_SIZE]u8 align(4) = undefined;
    const new_src_mac = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    const fast = try fastPatchEthernetPacket(&buf_fast, pkt_data, .{ 10, 0, 0, 1 }, new_src_mac);

    // The fast path must zero the now-invalid UDP checksum (0 disables it, which
    // is valid for IPv4 UDP and matches buildOutgoingPacketInto).
    const out_udp: *const packet.UdpHeader = @ptrCast(@alignCast(fast.ptr + packet.ETHERNET_HEADER_SIZE + packet.IPV4_MIN_HEADER_SIZE));
    try std.testing.expectEqual(@as(u16, 0), out_udp.checksum);
}

test "compact PacketRef is 16 bytes" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PacketRef));
}

test "linkType round-trip conversion" {
    const types = [_]pcap.LinkType{ .ethernet, .null, .loop, .enc, .raw };
    for (types) |lt| {
        try std.testing.expectEqual(lt, idxToLinkType(linkTypeToIdx(lt)));
    }
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

    if (feed.registerSender("eth0")) |_| {
        try std.testing.expect(false); // should not succeed
    } else |err| {
        try std.testing.expectEqual(error.OutOfMemory, err);
    }
}

test "SendPktFeed.init tripwires clean up on failure at every point" {
    inline for (std.meta.tags(feed_init_tw.FailPoint)) |pt| {
        feed_init_tw.reset();
        feed_init_tw.errorAlways(pt, error.OutOfMemory);

        try std.testing.expectError(
            error.OutOfMemory,
            SendPktFeed.init(std.testing.allocator),
        );
    }
    feed_init_tw.reset();
}
