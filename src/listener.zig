//! Per-interface packet listener
//!
//! Handles packet capture, learning, and forwarding for a single interface.
//! Supports both thread-based (run) and coroutine-based (runCoro) operation.

const std = @import("std");
const pcap = @import("pcap.zig");
const packet = @import("packet.zig");
const bpf = @import("bpf.zig");
const sender = @import("sender.zig");
const ClientCache = @import("client_cache.zig").ClientCache;
const tripwire = @import("tripwire");

const log = std.log.scoped(.listener);

/// Tripwire points for Listener.init. Used only in tests to exercise the
/// errdefer chain; inlined to no-ops in release builds.
pub const init_tw = tripwire.module(enum {
    /// Before any allocation (client_cache HashMap is lazy; nothing to free).
    after_client_cache_init,
    /// After the fixed_ips loop — HashMap backing is populated, so the
    /// errdefer must fire or the buckets leak.
    after_fixed_ips,
}, error{OutOfMemory});

/// Return milliseconds since Unix epoch using POSIX clock_gettime.
fn milliTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

/// Stop a listener after this many consecutive pcap capture errors (~5s at the
/// 1ms idle poll). A persistent error (e.g. the interface went down) is fatal
/// for that handle, so escalate to a visible err log + stop rather than spin.
const MAX_CONSECUTIVE_CAPTURE_ERRORS = 5000;

// ============================================================================
// Types
// ============================================================================

pub const ListenerConfig = struct {
    /// Interface name
    iface_name: [:0]const u8,
    /// UDP ports to monitor
    ports: []const u16,
    /// Pcap timeout in milliseconds
    timeout_ms: i32,
    /// Client cache TTL in minutes
    cache_ttl_minutes: u32,
    /// Fixed IPs for this interface
    fixed_ips: []const [4]u8,
    /// Enable promiscuous mode
    promisc: bool,
    /// Send-only mode (don't capture, only forward)
    send_only: bool,
    /// Enable pcap debugging
    pcap_debug: bool,
    /// Path for pcap debug files
    pcap_path: []const u8,
};

/// Network interface listener
pub const Listener = struct {
    /// Configuration
    config: ListenerConfig,
    /// Allocator
    allocator: std.mem.Allocator,
    /// Pcap handle
    handle: ?pcap.Handle,
    /// Link type
    link_type: pcap.LinkType,
    /// Interface hardware address (MAC)
    hw_addr: [6]u8,
    /// Broadcast IP address (for non-promisc interfaces)
    broadcast_ip: ?[4]u8,
    /// Client cache (for promisc interfaces)
    client_cache: ClientCache,
    /// Ref channel for receiving packet refs to forward (zero-copy, thread mode)
    ref_channel: ?*sender.RefChannel,
    /// Interface index in the SendPktFeed (for compact PacketRef)
    iface_idx: u8,
    /// Reference to the SendPktFeed for accessing packet data (thread mode)
    feed: ?*sender.SendPktFeed,
    /// Pre-allocated buffer pool for outgoing packets
    outgoing_pool: sender.OutgoingPool,
    /// Pcap dumper for incoming packets
    in_dumper: ?pcap.Dumper,
    /// Pcap dumper for outgoing packets
    out_dumper: ?pcap.Dumper,
    /// Running flag (atomic: set false by stop()/deinit from another thread,
    /// read by the listener thread's run loop).
    running: std.atomic.Value(bool),

    /// Initialize a new listener
    pub fn init(allocator: std.mem.Allocator, config: ListenerConfig) !Listener {
        var self = Listener{
            .config = config,
            .allocator = allocator,
            .handle = null,
            .link_type = .ethernet,
            .hw_addr = [_]u8{0} ** 6,
            .broadcast_ip = null,
            .client_cache = ClientCache.init(allocator, config.cache_ttl_minutes),
            .ref_channel = null,
            .iface_idx = 0,
            .feed = null,
            .outgoing_pool = sender.OutgoingPool.init(),
            .in_dumper = null,
            .out_dumper = null,
            .running = std.atomic.Value(bool).init(false),
        };
        // If any fallible step below fails, the HashMap backing storage
        // allocated by addFixed must be released, else we leak it.
        errdefer self.client_cache.deinit();

        try init_tw.check(.after_client_cache_init);

        // Add fixed IPs to cache
        for (config.fixed_ips) |ip| {
            try self.client_cache.addFixed(ip);
        }

        try init_tw.check(.after_fixed_ips);

        return self;
    }

    /// Deinitialize the listener
    pub fn deinit(self: *Listener) void {
        self.running.store(false, .release);

        if (self.in_dumper) |*d| {
            d.close();
        }
        if (self.out_dumper) |*d| {
            d.close();
        }
        if (self.handle) |*h| {
            h.close();
        }

        self.client_cache.deinit();
    }

    /// Open and configure pcap handle
    pub fn open(self: *Listener, interfaces: []const pcap.Interface) !void {
        // Find our interface
        var found_iface: ?pcap.Interface = null;
        for (interfaces) |iface| {
            if (std.mem.eql(u8, iface.name, self.config.iface_name[0..self.config.iface_name.len])) {
                found_iface = iface;
                break;
            }
        }

        if (found_iface == null) {
            log.err("Interface not found: {s}", .{self.config.iface_name});
            return error.InterfaceNotFound;
        }

        const iface = found_iface.?;

        // Calculate broadcast address for non-p2p interfaces
        if (!self.config.promisc) {
            for (iface.addresses) |addr| {
                if (addr.addr != null and addr.netmask != null) {
                    self.broadcast_ip = packet.calculateBroadcast(addr.addr.?, addr.netmask.?);
                    break;
                }
            }
        }

        // Create pcap handle
        var handle = try pcap.Handle.create(self.allocator, self.config.iface_name);
        errdefer handle.close();

        // Configure -- always enable promiscuous mode so pcap captures
        // multicast packets (mDNS, SSDP) in addition to broadcast
        try handle.setSnaplen(9000);
        try handle.setPromisc(true);
        try handle.setTimeout(self.config.timeout_ms);
        try handle.setImmediateMode(true); // deliver packets without BPF buffering delay
        try handle.setBufferSize(4 * 1024 * 1024); // 4MB kernel buffer (default is 512KB-2MB)

        // Activate
        try handle.activate();

        self.link_type = handle.getLinkType();

        if (!self.link_type.isSupported()) {
            log.err("{s}: unsupported link type: {s}", .{ self.config.iface_name, self.link_type.name() });
            return error.UnsupportedLinkType;
        }

        // Resolve the interface MAC to use as the source MAC of forwarded
        // Ethernet frames; an all-zero source MAC can be dropped by switches.
        if (pcap.getInterfaceMac(self.config.iface_name)) |mac| {
            self.hw_addr = mac;
            log.debug("{s}: source MAC {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                self.config.iface_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            });
        } else if (self.link_type == .ethernet) {
            log.warn("{s}: could not resolve interface MAC; forwarded frames will use a zero source MAC", .{self.config.iface_name});
        }

        // Set BPF filter -- use port-only filter for interfaces without addresses (e.g., enc0)
        const filter = if (iface.addresses.len > 0)
            try bpf.buildFilter(self.allocator, self.config.ports, iface.addresses)
        else
            try bpf.buildPortFilter(self.allocator, self.config.ports);
        defer self.allocator.free(filter);

        try handle.setFilter(filter);

        // Set direction to inbound only
        handle.setDirection(.in) catch |err| {
            log.warn("{s}: failed to set direction (continuing anyway): {}", .{ self.config.iface_name, err });
        };

        self.handle = handle;

        // Open pcap debug files if enabled
        if (self.config.pcap_debug) {
            try self.openDebugFiles();
        }

        log.info("{s}: opened (link_type={s}, promisc={}, ports={any})", .{
            self.config.iface_name,
            self.link_type.name(),
            self.config.promisc,
            self.config.ports,
        });
    }

    /// Open debug pcap files
    fn openDebugFiles(self: *Listener) !void {
        // Create filenames
        var in_path_buf: [256]u8 = undefined;
        var out_path_buf: [256]u8 = undefined;

        const in_path = std.fmt.bufPrintZ(&in_path_buf, "{s}/udp-proxy-in-{s}.pcap", .{
            self.config.pcap_path,
            self.config.iface_name,
        }) catch return error.PathTooLong;

        const out_path = std.fmt.bufPrintZ(&out_path_buf, "{s}/udp-proxy-out-{s}.pcap", .{
            self.config.pcap_path,
            self.config.iface_name,
        }) catch return error.PathTooLong;

        if (self.handle) |*h| {
            self.in_dumper = pcap.Dumper.open(h, in_path) catch |err| {
                log.warn("Failed to open {s}: {}", .{ in_path, err });
                return;
            };

            self.out_dumper = pcap.Dumper.open(h, out_path) catch |err| {
                log.warn("Failed to open {s}: {}", .{ out_path, err });
                return;
            };
        }
    }

    /// Register with the send feed (thread mode)
    pub fn registerSender(self: *Listener, feed: *sender.SendPktFeed) !void {
        const result = try feed.registerSender(self.config.iface_name);
        self.ref_channel = result.channel;
        self.iface_idx = result.idx;
        self.feed = feed;
    }

    /// Main packet handling loop (zero-copy version, thread mode)
    pub fn run(self: *Listener, feed: *sender.SendPktFeed) void {
        self.running.store(true, .release);

        // Set non-blocking mode for normal (non-send-only) listeners
        // so we can interleave pcap capture with ref channel draining
        if (!self.config.send_only) {
            if (self.handle) |*h| {
                h.setNonBlock(true) catch |err| {
                    log.warn("{s}: failed to set non-blocking mode: {}", .{ self.config.iface_name, err });
                };
            }
        }

        // Cache the selectable fd for poll() (null on platforms that don't support it)
        const pcap_fd: ?std.posix.fd_t = if (self.handle) |*h| h.getSelectableFd() else null;

        // Cleanup timer (every 30 seconds - less aggressive than before)
        var last_cleanup = milliTimestamp();
        const cleanup_interval: i64 = 30000;

        log.debug("{s}: starting packet handler (send_only={})", .{ self.config.iface_name, self.config.send_only });

        // Consecutive pcap capture errors; reset on any healthy read.
        var capture_errors: u32 = 0;

        while (self.running.load(.acquire)) {
            if (self.config.send_only) {
                // Send-only mode: block on channel, no pcap capture
                if (self.ref_channel) |channel| {
                    // Use blocking receive to avoid CPU spin
                    if (channel.receive()) |ref| {
                        self.sendPacketsFromRef(ref) catch |err| {
                            log.warn("{s}: failed to send packet: {}", .{ self.config.iface_name, err });
                        };
                    }
                    // Drain any additional queued packets
                    while (channel.tryReceive()) |ref| {
                        self.sendPacketsFromRef(ref) catch |err| {
                            log.warn("{s}: failed to send packet: {}", .{ self.config.iface_name, err });
                        };
                    }
                }
            } else {
                // Non-blocking event loop: service both pcap capture and
                // ref channel every iteration, sleep only when idle.
                var did_work = false;

                // 1. Drain ref channel (forward queued packets from other interfaces)
                if (self.ref_channel) |channel| {
                    while (channel.tryReceive()) |ref| {
                        self.sendPacketsFromRef(ref) catch |err| {
                            log.warn("{s}: failed to send packet: {}", .{ self.config.iface_name, err });
                        };
                        did_work = true;
                    }
                }

                // 2. Drain pcap (capture all available packets, non-blocking)
                if (self.handle) |*handle| {
                    while (true) {
                        if (handle.nextPacket()) |result| {
                            capture_errors = 0; // healthy read (a packet, or empty)
                            if (result) |pkt_data| {
                                self.handleIncomingPacket(pkt_data.data, pkt_data.info, feed);
                                did_work = true;
                            } else break; // no more packets available
                        } else |err| {
                            if (err == pcap.Error.NoMorePackets) break;
                            capture_errors += 1;
                            // Log sparsely to avoid flooding on a broken interface.
                            if (capture_errors == 1 or capture_errors % 1000 == 0) {
                                log.warn("{s}: capture error ({d} in a row): {}", .{ self.config.iface_name, capture_errors, err });
                            }
                            if (capture_errors >= MAX_CONSECUTIVE_CAPTURE_ERRORS) {
                                log.err("{s}: capture failing persistently after {d} consecutive errors; stopping this interface's listener", .{ self.config.iface_name, capture_errors });
                                self.running.store(false, .release);
                            }
                            break;
                        }
                    }
                }

                // 3. Sleep if idle (poll pcap fd for 1ms to avoid CPU spin)
                if (!did_work) {
                    if (pcap_fd) |fd| {
                        var pfds = [_]std.posix.pollfd{
                            .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 },
                        };
                        _ = std.posix.poll(&pfds, 1) catch {};
                    } else {
                        const req = std.c.timespec{ .sec = 0, .nsec = 1_000_000 }; // 1ms
                        _ = std.c.nanosleep(&req, null);
                    }
                }
            }

            // Periodic cleanup (less frequent, lazy expiration handles most cases)
            const now = milliTimestamp();
            if (now - last_cleanup > cleanup_interval) {
                self.client_cache.cleanup();
                last_cleanup = now;
            }
        }

        log.debug("{s}: packet handler stopped", .{self.config.iface_name});
    }

    /// Handle an incoming packet
    fn handleIncomingPacket(
        self: *Listener,
        data: []const u8,
        info: pcap.CaptureInfo,
        feed: *sender.SendPktFeed,
    ) void {
        // Parse the packet
        const parsed = packet.parsePacket(data, self.link_type) catch |err| {
            log.debug("{s}: failed to parse packet: {}", .{ self.config.iface_name, err });
            return;
        };

        // Learn client IP for promiscuous interfaces
        if (self.config.promisc) {
            if (parsed.getSrcIp()) |src_ip| {
                self.client_cache.learn(src_ip) catch {};
            }
        }

        // Write to debug pcap
        if (self.in_dumper) |*d| {
            d.writePacket(info, data);
        }

        // Broadcast to other interfaces with pre-computed offsets (avoids re-parsing)
        log.debug("{s}: forwarding packet ({d} bytes)", .{ self.config.iface_name, data.len });

        const l2_size = sender.linkTypeL2Size(self.link_type);
        const ip_hl: u8 = @intCast(parsed.ipv4.?.getHeaderLength());

        feed.broadcast(
            data,
            self.iface_idx,
            self.link_type,
            l2_size,
            ip_hl,
            info.timestamp_sec * 1_000_000 + info.timestamp_usec,
        );
    }

    /// Send packets from a packet reference (zero-copy version).
    /// Uses pre-computed header offsets from PacketRef to skip re-parsing.
    fn sendPacketsFromRef(self: *Listener, ref: sender.PacketRef) !void {
        // Copy the packet out of the shared ring ONCE into a private buffer,
        // validating the slot was not recycled by a faster producer. After this
        // point all work is on the private copy, so the ring is never re-read.
        // align(4): the header pointer casts below require >=2-byte alignment;
        // a stack [N]u8 would otherwise default to align 1.
        var scratch: [sender.MAX_PACKET_SIZE]u8 align(4) = undefined;
        const pkt_data = if (self.feed) |feed|
            (feed.copyPacket(ref.seq, &scratch) orelse {
                log.debug("{s}: dropped packet: ring slot recycled before forward (seq={d})", .{ self.config.iface_name, ref.seq });
                return;
            })
        else
            return error.NoFeed;

        // Reconstruct parsed packet from pre-computed offsets (NO parsePacket call)
        const min_len = @as(usize, ref.l2_size) + ref.ip_header_len + packet.UDP_HEADER_SIZE;
        if (pkt_data.len < min_len) {
            log.warn("{s}: packet too short from iface {d}: {d} < {d}", .{
                self.config.iface_name, ref.src_iface_idx, pkt_data.len, min_len,
            });
            return;
        }

        const ipv4: *const packet.IPv4Header = @ptrCast(@alignCast(pkt_data.ptr + ref.l2_size));
        const udp: *const packet.UdpHeader = @ptrCast(@alignCast(pkt_data.ptr + ref.l2_size + ref.ip_header_len));
        const payload_start = @as(usize, ref.l2_size) + ref.ip_header_len + packet.UDP_HEADER_SIZE;
        // Trim to the UDP length field so Ethernet padding is not forwarded as
        // payload (the rebuild path recomputes lengths from this slice). The
        // min_len check above guarantees payload_start <= pkt_data.len.
        const payload_len = packet.udpPayloadLen(udp.getLength(), pkt_data.len - payload_start);
        const payload = pkt_data[payload_start .. payload_start + payload_len];

        const parsed = packet.ParsedPacket{
            .link_type = sender.idxToLinkType(ref.link_type_idx),
            .ipv4 = ipv4,
            .udp = udp,
            .payload = payload,
            .raw_data = pkt_data,
        };

        // Determine destination IPs
        if (!self.config.promisc) {
            // Non-promiscuous: send to broadcast address
            if (self.broadcast_ip) |bcast_ip| {
                try self.sendToDestinationZeroCopy(parsed, bcast_ip, ref);
            }
        } else {
            // Promiscuous: iterate clients without allocation
            var client_iter = self.client_cache.iterator();
            var sent_count: usize = 0;

            while (client_iter.next()) |client_ip| {
                self.sendToDestinationZeroCopy(parsed, client_ip, ref) catch |err| {
                    const reason: []const u8 = if (err == error.WriteError and self.handle != null)
                        self.handle.?.lastError()
                    else
                        @errorName(err);
                    log.warn("{s}: failed to send to {d}.{d}.{d}.{d}: {s}", .{
                        self.config.iface_name,
                        client_ip[0],
                        client_ip[1],
                        client_ip[2],
                        client_ip[3],
                        reason,
                    });
                    continue;
                };
                sent_count += 1;
            }

            if (sent_count == 0) {
                log.debug("{s}: no clients to forward to", .{self.config.iface_name});
            }
        }
    }

    /// Send a packet to a specific destination using pre-allocated buffer (zero-copy)
    fn sendToDestinationZeroCopy(
        self: *Listener,
        parsed: packet.ParsedPacket,
        dst_ip: [4]u8,
        ref: sender.PacketRef,
    ) !void {
        // Acquire buffer from pre-allocated pool (no allocation!)
        const buffer = self.outgoing_pool.acquire();

        // Fast path: Ethernet-to-Ethernet with standard IPv4 (no options)
        // Just memcpy + patch dst_mac/src_mac/dst_ip/checksum
        const out_data = if (ref.link_type_idx == 0 and // source is Ethernet
            self.link_type == .ethernet and // dest is Ethernet
            ref.ip_header_len == packet.IPV4_MIN_HEADER_SIZE) // standard IPv4, no options
            try sender.fastPatchEthernetPacket(
                buffer,
                parsed.raw_data,
                dst_ip,
                self.hw_addr,
            )
        else
            // Full rebuild for cross-link-type or IPv4-with-options cases
            try sender.buildOutgoingPacketInto(
                buffer,
                parsed,
                dst_ip,
                self.link_type,
                self.hw_addr,
            );

        // Write to debug pcap
        if (self.out_dumper) |*d| {
            const info = pcap.CaptureInfo{
                .timestamp_sec = @divTrunc(ref.timestamp_us, 1_000_000),
                .timestamp_usec = @mod(ref.timestamp_us, 1_000_000),
                .capture_len = @intCast(out_data.len),
                .wire_len = @intCast(out_data.len),
            };
            d.writePacket(info, out_data);
        }

        // Send the packet
        if (self.handle) |*handle| {
            try handle.sendPacket(out_data);

            log.debug("{s} => {d}.{d}.{d}.{d}: sent {d} bytes", .{
                self.config.iface_name,
                dst_ip[0],
                dst_ip[1],
                dst_ip[2],
                dst_ip[3],
                out_data.len,
            });
        }
    }

    /// Stop the listener
    pub fn stop(self: *Listener) void {
        self.running.store(false, .release);
        if (self.ref_channel) |channel| {
            channel.close();
        }
    }

    /// Get interface name
    pub fn getName(self: *const Listener) []const u8 {
        return self.config.iface_name;
    }
};

/// UDP sink - binds UDP ports to absorb traffic and prevent ICMP Port Unreachable.
/// Uses a single poll thread for all sockets instead of thread-per-socket.
pub const UdpSink = struct {
    sockets: std.ArrayListUnmanaged(c_int),
    allocator: std.mem.Allocator,
    thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator) UdpSink {
        return UdpSink{
            .sockets = .empty,
            .allocator = allocator,
            .thread = null,
        };
    }

    pub fn deinit(self: *UdpSink) void {
        // Close all sockets -- causes poll() to return in the sink thread
        for (self.sockets.items) |sock| {
            _ = std.c.close(sock);
        }
        if (self.thread) |thread| {
            thread.join();
        }
        self.sockets.deinit(self.allocator);
    }

    /// Bind to the specified port on the given interface address
    pub fn bind(self: *UdpSink, ip: [4]u8, port: u16) !void {
        const sock = std.c.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        if (sock < 0) return error.SocketCreationFailed;
        errdefer _ = std.c.close(sock);

        // Allow quick restart without EADDRINUSE
        const enable: c_int = 1;
        _ = std.c.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, @ptrCast(&enable), @sizeOf(c_int));

        var addr: std.posix.sockaddr.in = std.mem.zeroes(std.posix.sockaddr.in);
        addr.family = std.posix.AF.INET;
        addr.port = std.mem.nativeToBig(u16, port);
        addr.addr = @bitCast(ip);

        if (std.c.bind(sock, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in)) < 0) {
            log.warn("Failed to bind to {d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], port });
            return error.BindFailed;
        }

        try self.sockets.append(self.allocator, sock);
        log.debug("UDP sink bound to {d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], port });
    }

    /// Start the single poll thread after all sockets are bound
    pub fn start(self: *UdpSink) !void {
        if (self.sockets.items.len == 0) return;
        self.thread = try std.Thread.spawn(.{}, sinkPollThread, .{self.sockets.items});
    }

    fn sinkPollThread(sockets: []const c_int) void {
        var pfds: [64]std.posix.pollfd = undefined;
        const n = @min(sockets.len, pfds.len);
        for (sockets[0..n], 0..n) |sock, i| {
            pfds[i] = .{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 };
        }

        var buf: [8192]u8 = undefined;
        while (true) {
            _ = std.posix.poll(pfds[0..n], -1) catch break; // sockets closed, exit
            for (pfds[0..n]) |*pfd| {
                if (pfd.revents & std.posix.POLL.IN != 0) {
                    _ = std.c.recvfrom(pfd.fd, &buf, buf.len, 0, null, null);
                }
                if (pfd.revents & std.posix.POLL.NVAL != 0) return; // fd closed
            }
        }
    }
};

test "Listener.init tripwires clean up on failure at every point" {
    const config = ListenerConfig{
        .iface_name = "lo",
        .ports = &[_]u16{9003},
        .timeout_ms = 100,
        .cache_ttl_minutes = 5,
        .fixed_ips = &[_][4]u8{.{ 10, 0, 0, 1 }},
        .promisc = false,
        .send_only = false,
        .pcap_debug = false,
        .pcap_path = "",
    };

    inline for (std.meta.tags(init_tw.FailPoint)) |pt| {
        init_tw.reset();
        init_tw.errorAlways(pt, error.OutOfMemory);

        // std.testing.allocator panics the test on leak, so if errdefer
        // cleanup is missing for this failure point, this test fails.
        try std.testing.expectError(
            error.OutOfMemory,
            Listener.init(std.testing.allocator, config),
        );
    }
    init_tw.reset();
}

test "Listener.run exits promptly when stopped" {
    const allocator = std.testing.allocator;
    var feed = try sender.SendPktFeed.init(allocator);
    defer feed.deinit();

    const config = ListenerConfig{
        .iface_name = "lo",
        .ports = &[_]u16{9003},
        .timeout_ms = 100,
        .cache_ttl_minutes = 5,
        .fixed_ips = &[_][4]u8{},
        .promisc = false,
        .send_only = false,
        .pcap_debug = false,
        .pcap_path = "",
    };
    var listener = try Listener.init(allocator, config);
    defer listener.deinit();
    // No open() -> the pcap handle stays null, so run() just idles checking the
    // `running` flag each iteration.

    const Runner = struct {
        fn go(l: *Listener, f: *sender.SendPktFeed) void {
            l.run(f);
        }
    };
    var thread = try std.Thread.spawn(.{}, Runner.go, .{ &listener, &feed });

    // Let the loop start, then request shutdown. join() returns only if run()
    // observed the stop and exited -- otherwise this test hangs, which is the
    // failure signal.
    const ns = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
    _ = std.c.nanosleep(&ns, null);
    listener.stop();
    thread.join();
}
