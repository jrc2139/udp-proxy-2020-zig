//! Per-interface packet listener
//!
//! Handles packet capture, learning, and forwarding for a single interface.

const std = @import("std");
const pcap = @import("pcap.zig");
const packet = @import("packet.zig");
const bpf = @import("bpf.zig");
const sender = @import("sender.zig");
const ClientCache = @import("client_cache.zig").ClientCache;

const log = std.log.scoped(.listener);

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
    /// Ref channel for receiving packet refs to forward (zero-copy)
    ref_channel: ?*sender.RefChannel,
    /// Reference to the SendPktFeed for accessing packet data
    feed: ?*sender.SendPktFeed,
    /// Pre-allocated buffer pool for outgoing packets
    outgoing_pool: sender.OutgoingPool,
    /// Pcap dumper for incoming packets
    in_dumper: ?pcap.Dumper,
    /// Pcap dumper for outgoing packets
    out_dumper: ?pcap.Dumper,
    /// Running flag
    running: bool,

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
            .feed = null,
            .outgoing_pool = sender.OutgoingPool.init(),
            .in_dumper = null,
            .out_dumper = null,
            .running = false,
        };

        // Add fixed IPs to cache
        for (config.fixed_ips) |ip| {
            try self.client_cache.addFixed(ip);
        }

        return self;
    }

    /// Deinitialize the listener
    pub fn deinit(self: *Listener) void {
        self.running = false;

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

        if (iface.addresses.len == 0) {
            log.err("Interface {s} has no configured addresses", .{self.config.iface_name});
            return error.InterfaceNotConfigured;
        }

        // Calculate broadcast address for non-promisc interfaces
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

        // Configure
        try handle.setSnaplen(9000);
        try handle.setPromisc(self.config.promisc);
        try handle.setTimeout(self.config.timeout_ms);

        // Activate
        try handle.activate();

        self.link_type = handle.getLinkType();

        if (!self.link_type.isSupported()) {
            log.err("{s}: unsupported link type: {s}", .{ self.config.iface_name, self.link_type.name() });
            return error.UnsupportedLinkType;
        }

        // Set BPF filter
        const filter = try bpf.buildFilter(self.allocator, self.config.ports, iface.addresses);
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

    /// Register with the send feed
    pub fn registerSender(self: *Listener, feed: *sender.SendPktFeed) !void {
        self.ref_channel = try feed.registerSender(self.config.iface_name);
        self.feed = feed;
    }

    /// Main packet handling loop (zero-copy version)
    pub fn run(self: *Listener, feed: *sender.SendPktFeed) void {
        self.running = true;

        // Cleanup timer (every 30 seconds - less aggressive than before)
        var last_cleanup = std.time.milliTimestamp();
        const cleanup_interval: i64 = 30000;

        log.debug("{s}: starting packet handler (send_only={})", .{ self.config.iface_name, self.config.send_only });

        while (self.running) {
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
                // Normal mode: capture packets and check ref channel
                // Check for packets to send from other interfaces (non-blocking)
                if (self.ref_channel) |channel| {
                    while (channel.tryReceive()) |ref| {
                        self.sendPacketsFromRef(ref) catch |err| {
                            log.warn("{s}: failed to send packet: {}", .{ self.config.iface_name, err });
                        };
                    }
                }

                // Capture incoming packets (blocks for up to timeout_ms)
                if (self.handle) |*handle| {
                    if (handle.nextPacket()) |result| {
                        if (result) |pkt_data| {
                            self.handleIncomingPacket(pkt_data.data, pkt_data.info, feed);
                        }
                    } else |err| {
                        if (err != pcap.Error.NoMorePackets) {
                            log.warn("{s}: capture error: {}", .{ self.config.iface_name, err });
                        }
                    }
                }
            }

            // Periodic cleanup (less frequent, lazy expiration handles most cases)
            const now = std.time.milliTimestamp();
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

        // Broadcast to other interfaces
        log.debug("{s}: forwarding packet ({d} bytes)", .{ self.config.iface_name, data.len });

        feed.broadcast(
            data,
            self.config.iface_name,
            self.link_type,
            info.timestamp_sec,
            info.timestamp_usec,
        );
    }

    /// Send packets from a packet reference (zero-copy version)
    fn sendPacketsFromRef(self: *Listener, ref: sender.PacketRef) !void {
        // Get packet data from the shared ring buffer
        const pkt_data = if (self.feed) |feed|
            feed.getPacketData(ref.ring_idx)
        else
            return error.NoFeed;

        // Parse the incoming packet
        const parsed = packet.parsePacket(pkt_data, ref.link_type) catch |err| {
            log.warn("{s}: failed to parse packet from {s}: {}", .{
                self.config.iface_name,
                ref.src_interface,
                err,
            });
            return;
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
                    log.warn("{s}: failed to send to {d}.{d}.{d}.{d}: {}", .{
                        self.config.iface_name,
                        client_ip[0],
                        client_ip[1],
                        client_ip[2],
                        client_ip[3],
                        err,
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

        // Build the outgoing packet into pre-allocated buffer
        const out_data = try sender.buildOutgoingPacketInto(
            buffer,
            parsed,
            dst_ip,
            self.link_type,
            self.hw_addr,
        );

        // Write to debug pcap
        if (self.out_dumper) |*d| {
            const info = pcap.CaptureInfo{
                .timestamp_sec = ref.timestamp_sec,
                .timestamp_usec = ref.timestamp_usec,
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
        self.running = false;
        if (self.ref_channel) |channel| {
            channel.close();
        }
    }

    /// Get interface name
    pub fn getName(self: *const Listener) []const u8 {
        return self.config.iface_name;
    }
};

/// UDP sink - listens on UDP ports to prevent ICMP Port Unreachable
pub const UdpSink = struct {
    sockets: std.ArrayListUnmanaged(std.posix.socket_t),
    allocator: std.mem.Allocator,
    threads: std.ArrayListUnmanaged(std.Thread),

    pub fn init(allocator: std.mem.Allocator) UdpSink {
        return UdpSink{
            .sockets = .{},
            .allocator = allocator,
            .threads = .{},
        };
    }

    pub fn deinit(self: *UdpSink) void {
        // Close all sockets
        for (self.sockets.items) |sock| {
            std.posix.close(sock);
        }
        self.sockets.deinit(self.allocator);

        // Wait for threads
        for (self.threads.items) |thread| {
            thread.join();
        }
        self.threads.deinit(self.allocator);
    }

    /// Bind to the specified port on the given interface address
    pub fn bind(self: *UdpSink, ip: [4]u8, port: u16) !void {
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        const addr = std.net.Address.initIp4(ip, port);

        std.posix.bind(sock, &addr.any, addr.getOsSockLen()) catch |err| {
            log.warn("Failed to bind to {d}.{d}.{d}.{d}:{d}: {}", .{
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                port,
                err,
            });
            return err;
        };

        try self.sockets.append(self.allocator, sock);

        // Start sink thread
        const thread = try std.Thread.spawn(.{}, sinkThread, .{sock});
        try self.threads.append(self.allocator, thread);

        log.debug("UDP sink bound to {d}.{d}.{d}.{d}:{d}", .{
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            port,
        });
    }

    fn sinkThread(sock: std.posix.socket_t) void {
        var buf: [8192]u8 = undefined;

        while (true) {
            _ = std.posix.recvfrom(sock, &buf, 0, null, null) catch |err| {
                if (err == error.ConnectionResetByPeer or
                    err == error.SocketNotConnected)
                {
                    // Expected errors, continue
                    continue;
                }
                // Socket likely closed, exit
                break;
            };
            // Discard the data
        }
    }
};
