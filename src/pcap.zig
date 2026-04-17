//! libpcap bindings for Zig
//!
//! Provides a safe Zig wrapper around libpcap for packet capture and injection.
//! Supports FreeBSD, Linux, and macOS via the native libpcap installation.

const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.pcap);

// ============================================================================
// Manual libpcap bindings (replaces @cImport to avoid FreeBSD translate-c bugs)
// ============================================================================

const PCAP_ERRBUF_SIZE = 256;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffffffff;
const PCAP_IF_LOOPBACK: u32 = 0x00000001;
const PCAP_IF_UP: u32 = 0x00000002;
const PCAP_IF_RUNNING: u32 = 0x00000004;

const pcap_t = opaque {};
const pcap_dumper_t = opaque {};

const bpf_insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const bpf_program = extern struct {
    bf_len: c_uint,
    bf_insns: ?[*]bpf_insn,
};

const pcap_pkthdr = extern struct {
    ts: std.posix.timeval,
    caplen: u32,
    len: u32,
};

const pcap_addr = extern struct {
    next: ?*pcap_addr,
    addr: ?*std.posix.sockaddr,
    netmask: ?*std.posix.sockaddr,
    broadaddr: ?*std.posix.sockaddr,
    dstaddr: ?*std.posix.sockaddr,
};

const pcap_if_t = extern struct {
    next: ?*pcap_if_t,
    name: [*:0]const u8,
    description: ?[*:0]const u8,
    addresses: ?*pcap_addr,
    flags: u32,
};

extern "c" fn pcap_create(source: [*:0]const u8, errbuf: [*]u8) ?*pcap_t;
extern "c" fn pcap_set_snaplen(p: *pcap_t, snaplen: c_int) c_int;
extern "c" fn pcap_set_promisc(p: *pcap_t, promisc: c_int) c_int;
extern "c" fn pcap_set_timeout(p: *pcap_t, to_ms: c_int) c_int;
extern "c" fn pcap_activate(p: *pcap_t) c_int;
extern "c" fn pcap_geterr(p: *pcap_t) [*:0]const u8;
extern "c" fn pcap_datalink(p: *pcap_t) c_int;
extern "c" fn pcap_compile(p: *pcap_t, fp: *bpf_program, str: [*:0]const u8, optimize: c_int, netmask: u32) c_int;
extern "c" fn pcap_freecode(fp: *bpf_program) void;
extern "c" fn pcap_setfilter(p: *pcap_t, fp: *bpf_program) c_int;
extern "c" fn pcap_setdirection(p: *pcap_t, d: c_int) c_int;
extern "c" fn pcap_next_ex(p: *pcap_t, pkt_header: *?*pcap_pkthdr, pkt_data: *?[*]const u8) c_int;
extern "c" fn pcap_inject(p: *pcap_t, buf: [*]const u8, size: usize) c_int;
extern "c" fn pcap_get_selectable_fd(p: *pcap_t) c_int;
extern "c" fn pcap_set_immediate_mode(p: *pcap_t, immediate_mode: c_int) c_int;
extern "c" fn pcap_set_buffer_size(p: *pcap_t, buffer_size: c_int) c_int;
extern "c" fn pcap_setnonblock(p: *pcap_t, nonblock: c_int, errbuf: [*]u8) c_int;
extern "c" fn pcap_close(p: *pcap_t) void;
extern "c" fn pcap_dump_open(p: *pcap_t, fname: [*:0]const u8) ?*pcap_dumper_t;
extern "c" fn pcap_dump(user: ?*anyopaque, h: *const pcap_pkthdr, sp: [*]const u8) void;
extern "c" fn pcap_dump_flush(p: *pcap_dumper_t) c_int;
extern "c" fn pcap_dump_close(p: *pcap_dumper_t) void;
extern "c" fn pcap_findalldevs(alldevsp: *?*pcap_if_t, errbuf: [*]u8) c_int;
extern "c" fn pcap_freealldevs(alldevs: ?*pcap_if_t) void;

// ============================================================================
// Types
// ============================================================================

/// Link layer types supported for packet capture
pub const LinkType = enum(c_int) {
    null = 0, // BSD loopback
    ethernet = 1, // Ethernet
    raw = 101, // Raw IP (Linux cooked capture uses 113)
    loop = 108, // OpenBSD loopback
    enc = 109, // IPsec encapsulation (FreeBSD/OpenBSD enc0)
    linux_sll = 113, // Linux cooked capture
    _,

    pub fn fromRaw(value: c_int) LinkType {
        return @enumFromInt(value);
    }

    pub fn isSupported(self: LinkType) bool {
        return switch (self) {
            .null, .ethernet, .loop, .raw, .enc => true,
            else => false,
        };
    }

    pub fn name(self: LinkType) []const u8 {
        return switch (self) {
            .null => "NULL/Loopback",
            .ethernet => "Ethernet",
            .loop => "OpenBSD Loopback",
            .raw => "Raw IP",
            .enc => "IPsec ENC",
            .linux_sll => "Linux SLL",
            _ => "Unknown",
        };
    }
};

/// Capture direction
pub const Direction = enum(c_uint) {
    in_out = 0,
    in = 1,
    out = 2,
};

/// Pcap errors
pub const Error = error{
    ActivationFailed,
    AlreadyActivated,
    BufferOverflow,
    CaptureError,
    DeviceNotFound,
    FilterCompileFailed,
    FilterSetFailed,
    HandleCreationFailed,
    InterfaceNotFound,
    InvalidHandle,
    NoMorePackets,
    NotActivated,
    PermissionDenied,
    PromiscFailed,
    ReadError,
    SetDirectionFailed,
    SnaplenFailed,
    TimeoutFailed,
    WriteError,
    DumpOpenFailed,
};

/// Interface address information
pub const InterfaceAddress = struct {
    addr: ?[4]u8 = null, // IPv4 address
    netmask: ?[4]u8 = null, // Network mask
    broadcast: ?[4]u8 = null, // Broadcast address (if available)
    p2p: ?[4]u8 = null, // Point-to-point destination (if available)
};

/// Network interface information
pub const Interface = struct {
    name: []const u8,
    description: ?[]const u8 = null,
    addresses: []InterfaceAddress,
    flags: u32 = 0,

    pub fn isLoopback(self: Interface) bool {
        return (self.flags & PCAP_IF_LOOPBACK) != 0;
    }

    pub fn isUp(self: Interface) bool {
        return (self.flags & PCAP_IF_UP) != 0;
    }

    pub fn isRunning(self: Interface) bool {
        return (self.flags & PCAP_IF_RUNNING) != 0;
    }
};

/// Packet capture info from pcap_pkthdr
pub const CaptureInfo = struct {
    timestamp_sec: i64,
    timestamp_usec: i64,
    capture_len: u32,
    wire_len: u32,
};

// ============================================================================
// Pcap Handle
// ============================================================================

/// Wrapper around a pcap_t handle
pub const Handle = struct {
    handle: *pcap_t,
    link_type: LinkType = .ethernet,
    activated: bool = false,
    allocator: std.mem.Allocator,

    /// Create a new pcap handle for the specified interface
    pub fn create(allocator: std.mem.Allocator, device: [:0]const u8) Error!Handle {
        var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;

        const handle = pcap_create(device.ptr, &errbuf);
        if (handle == null) {
            log.err("pcap_create failed: {s}", .{std.mem.sliceTo(&errbuf, 0)});
            return Error.HandleCreationFailed;
        }

        return Handle{
            .handle = handle.?,
            .allocator = allocator,
        };
    }

    /// Set the snapshot length
    pub fn setSnaplen(self: *Handle, snaplen: c_int) Error!void {
        if (self.activated) return Error.AlreadyActivated;
        if (pcap_set_snaplen(self.handle, snaplen) != 0) {
            log.err("pcap_set_snaplen failed", .{});
            return Error.SnaplenFailed;
        }
    }

    /// Set promiscuous mode
    pub fn setPromisc(self: *Handle, promisc: bool) Error!void {
        if (self.activated) return Error.AlreadyActivated;
        if (pcap_set_promisc(self.handle, if (promisc) 1 else 0) != 0) {
            log.err("pcap_set_promisc failed", .{});
            return Error.PromiscFailed;
        }
    }

    /// Set the read timeout in milliseconds
    pub fn setTimeout(self: *Handle, timeout_ms: c_int) Error!void {
        if (self.activated) return Error.AlreadyActivated;
        if (pcap_set_timeout(self.handle, timeout_ms) != 0) {
            log.err("pcap_set_timeout failed", .{});
            return Error.TimeoutFailed;
        }
    }

    /// Set immediate mode (deliver packets without buffering)
    pub fn setImmediateMode(self: *Handle, immediate: bool) Error!void {
        if (self.activated) return Error.AlreadyActivated;
        if (pcap_set_immediate_mode(self.handle, if (immediate) 1 else 0) != 0) {
            log.err("pcap_set_immediate_mode failed", .{});
            return Error.ActivationFailed;
        }
    }

    /// Set the kernel capture buffer size in bytes
    pub fn setBufferSize(self: *Handle, size: c_int) Error!void {
        if (self.activated) return Error.AlreadyActivated;
        if (pcap_set_buffer_size(self.handle, size) != 0) {
            log.err("pcap_set_buffer_size failed", .{});
            return Error.ActivationFailed;
        }
    }

    /// Activate the pcap handle
    pub fn activate(self: *Handle) Error!void {
        if (self.activated) return Error.AlreadyActivated;

        const ret = pcap_activate(self.handle);
        if (ret < 0) {
            const err_str = pcap_geterr(self.handle);
            log.err("pcap_activate failed: {s}", .{std.mem.span(err_str)});
            return Error.ActivationFailed;
        }
        if (ret > 0) {
            // Warning, but activation succeeded
            const warn_str = pcap_geterr(self.handle);
            log.warn("pcap_activate warning: {s}", .{std.mem.span(warn_str)});
        }

        self.activated = true;
        self.link_type = LinkType.fromRaw(pcap_datalink(self.handle));

        if (!self.link_type.isSupported()) {
            log.warn("unsupported link type: {s} ({d})", .{ self.link_type.name(), @intFromEnum(self.link_type) });
        }
    }

    /// Set BPF filter
    pub fn setFilter(self: *Handle, filter_str: [:0]const u8) Error!void {
        if (!self.activated) return Error.NotActivated;

        var fp: bpf_program = undefined;

        if (pcap_compile(self.handle, &fp, filter_str.ptr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            const err_str = pcap_geterr(self.handle);
            log.err("pcap_compile failed: {s}", .{std.mem.span(err_str)});
            return Error.FilterCompileFailed;
        }
        defer pcap_freecode(&fp);

        if (pcap_setfilter(self.handle, &fp) < 0) {
            const err_str = pcap_geterr(self.handle);
            log.err("pcap_setfilter failed: {s}", .{std.mem.span(err_str)});
            return Error.FilterSetFailed;
        }

        log.debug("BPF filter set: {s}", .{filter_str});
    }

    /// Set capture direction
    pub fn setDirection(self: *Handle, direction: Direction) Error!void {
        if (!self.activated) return Error.NotActivated;

        if (pcap_setdirection(self.handle, @intCast(@intFromEnum(direction))) < 0) {
            const err_str = pcap_geterr(self.handle);
            log.err("pcap_setdirection failed: {s}", .{std.mem.span(err_str)});
            return Error.SetDirectionFailed;
        }
    }

    /// Read the next packet (blocking)
    /// Returns null if timeout with no packet, or error
    pub fn nextPacket(self: *Handle) Error!?struct { info: CaptureInfo, data: []const u8 } {
        if (!self.activated) return Error.NotActivated;

        var header: ?*pcap_pkthdr = null;
        var data: ?[*]const u8 = null;

        const ret = pcap_next_ex(self.handle, &header, &data);

        switch (ret) {
            1 => {
                const hdr = header.?;
                // Success
                const info = CaptureInfo{
                    .timestamp_sec = hdr.ts.sec,
                    .timestamp_usec = hdr.ts.usec,
                    .capture_len = @intCast(hdr.caplen),
                    .wire_len = @intCast(hdr.len),
                };
                return .{
                    .info = info,
                    .data = data.?[0..info.capture_len],
                };
            },
            0 => {
                // Timeout - no packet
                return null;
            },
            -1 => {
                const err_str = pcap_geterr(self.handle);
                log.err("pcap_next_ex error: {s}", .{std.mem.span(err_str)});
                return Error.ReadError;
            },
            -2 => {
                // EOF (reading from savefile)
                return Error.NoMorePackets;
            },
            else => {
                return Error.ReadError;
            },
        }
    }

    /// Inject/send a packet
    pub fn sendPacket(self: *Handle, data: []const u8) Error!void {
        if (!self.activated) return Error.NotActivated;

        const ret = pcap_inject(self.handle, data.ptr, data.len);
        if (ret < 0) {
            const err_str = pcap_geterr(self.handle);
            log.err("pcap_inject failed: {s}", .{std.mem.span(err_str)});
            return Error.WriteError;
        }

        if (@as(usize, @intCast(ret)) != data.len) {
            log.warn("pcap_inject: only sent {d} of {d} bytes", .{ ret, data.len });
        }
    }

    /// Get the link type
    pub fn getLinkType(self: *Handle) LinkType {
        return self.link_type;
    }

    /// Get the selectable file descriptor for async I/O polling.
    /// Returns null if the platform doesn't support selectable fds (Windows).
    /// This fd can be used with poll/select/epoll to wait for packets.
    pub fn getSelectableFd(self: *Handle) ?std.posix.fd_t {
        if (!self.activated) return null;

        const fd = pcap_get_selectable_fd(self.handle);
        if (fd == -1) {
            return null;
        }
        return fd;
    }

    /// Set non-blocking mode on the pcap handle.
    /// When enabled, nextPacket() returns immediately if no packet is available.
    pub fn setNonBlock(self: *Handle, nonblock: bool) Error!void {
        if (!self.activated) return Error.NotActivated;

        var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
        if (pcap_setnonblock(self.handle, if (nonblock) 1 else 0, &errbuf) < 0) {
            log.err("pcap_setnonblock failed: {s}", .{std.mem.sliceTo(&errbuf, 0)});
            return Error.CaptureError;
        }
    }

    /// Close the handle
    pub fn close(self: *Handle) void {
        pcap_close(self.handle);
    }
};

/// Pcap dump file writer
pub const Dumper = struct {
    dumper: *pcap_dumper_t,
    handle: *Handle,

    pub fn open(handle: *Handle, path: [:0]const u8) Error!Dumper {
        const dumper = pcap_dump_open(handle.handle, path.ptr);
        if (dumper == null) {
            const err_str = pcap_geterr(handle.handle);
            log.err("pcap_dump_open failed: {s}", .{std.mem.span(err_str)});
            return Error.DumpOpenFailed;
        }

        return Dumper{
            .dumper = dumper.?,
            .handle = handle,
        };
    }

    pub fn writePacket(self: *Dumper, info: CaptureInfo, data: []const u8) void {
        var header: pcap_pkthdr = .{
            .ts = .{
                .sec = @intCast(info.timestamp_sec),
                .usec = @intCast(info.timestamp_usec),
            },
            .caplen = info.capture_len,
            .len = info.wire_len,
        };

        pcap_dump(@ptrCast(self.dumper), &header, data.ptr);
    }

    pub fn flush(self: *Dumper) void {
        _ = pcap_dump_flush(self.dumper);
    }

    pub fn close(self: *Dumper) void {
        pcap_dump_close(self.dumper);
    }
};

// ============================================================================
// Interface Discovery
// ============================================================================

/// Find all network interfaces
pub fn findAllDevices(allocator: std.mem.Allocator) ![]Interface {
    var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: ?*pcap_if_t = null;

    if (pcap_findalldevs(&alldevs, &errbuf) < 0) {
        log.err("pcap_findalldevs failed: {s}", .{std.mem.sliceTo(&errbuf, 0)});
        return error.DeviceEnumerationFailed;
    }
    defer pcap_freealldevs(alldevs);

    // Count devices
    var count: usize = 0;
    var dev = alldevs;
    while (dev) |d| : (dev = d.next) {
        count += 1;
    }

    var interfaces = try allocator.alloc(Interface, count);
    errdefer allocator.free(interfaces);

    var idx: usize = 0;
    dev = alldevs;
    while (dev) |d| : (dev = d.next) {
        // Copy name
        const name = std.mem.span(d.name);
        const name_copy = try allocator.dupe(u8, name);

        // Copy description if present
        var desc_copy: ?[]const u8 = null;
        if (d.description) |desc| {
            desc_copy = try allocator.dupe(u8, std.mem.span(desc));
        }

        // Count and copy addresses
        var addr_count: usize = 0;
        var addr_ptr = d.addresses;
        while (addr_ptr) |a| : (addr_ptr = a.*.next) {
            // Only count IPv4 addresses
            if (a.*.addr) |addr_sockaddr| {
                if (addr_sockaddr.*.family == std.posix.AF.INET) {
                    addr_count += 1;
                }
            }
        }

        var addresses = try allocator.alloc(InterfaceAddress, addr_count);

        var addr_idx: usize = 0;
        addr_ptr = d.addresses;
        while (addr_ptr) |a| : (addr_ptr = a.*.next) {
            if (a.*.addr) |addr_sockaddr| {
                if (addr_sockaddr.*.family == std.posix.AF.INET) {
                    var iface_addr = InterfaceAddress{};

                    // Extract IPv4 address
                    const sockaddr_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr_sockaddr));
                    iface_addr.addr = @bitCast(sockaddr_in.addr);

                    // Extract netmask if present
                    if (a.*.netmask) |nm| {
                        const nm_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(nm));
                        iface_addr.netmask = @bitCast(nm_in.addr);
                    }

                    // Extract broadcast if present
                    if (a.*.broadaddr) |ba| {
                        const ba_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(ba));
                        iface_addr.broadcast = @bitCast(ba_in.addr);
                    }

                    // Extract p2p destination if present
                    if (a.*.dstaddr) |da| {
                        const da_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(da));
                        iface_addr.p2p = @bitCast(da_in.addr);
                    }

                    addresses[addr_idx] = iface_addr;
                    addr_idx += 1;
                }
            }
        }

        interfaces[idx] = Interface{
            .name = name_copy,
            .description = desc_copy,
            .addresses = addresses,
            .flags = d.flags,
        };
        idx += 1;
    }

    return interfaces;
}

/// Free interfaces allocated by findAllDevices
pub fn freeDevices(allocator: std.mem.Allocator, interfaces: []Interface) void {
    for (interfaces) |iface| {
        allocator.free(iface.name);
        if (iface.description) |desc| {
            allocator.free(desc);
        }
        allocator.free(iface.addresses);
    }
    allocator.free(interfaces);
}

/// Find loopback interface name
pub fn findLoopback(allocator: std.mem.Allocator) !?[]const u8 {
    const interfaces = try findAllDevices(allocator);
    defer freeDevices(allocator, interfaces);

    for (interfaces) |iface| {
        for (iface.addresses) |addr| {
            if (addr.addr) |a| {
                // Check for 127.0.0.1
                if (a[0] == 127 and a[1] == 0 and a[2] == 0 and a[3] == 1) {
                    return try allocator.dupe(u8, iface.name);
                }
            }
        }
    }

    return null;
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Format an IPv4 address as a string
pub fn formatIpv4(addr: [4]u8) [15:0]u8 {
    var buf: [15:0]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch unreachable;
    return buf;
}

/// Parse an IPv4 address string
pub fn parseIpv4(str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var idx: usize = 0;
    var iter = std.mem.splitScalar(u8, str, '.');

    while (iter.next()) |part| {
        if (idx >= 4) return null;
        result[idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        idx += 1;
    }

    if (idx != 4) return null;
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "LinkType.isSupported" {
    try std.testing.expect(LinkType.ethernet.isSupported());
    try std.testing.expect(LinkType.null.isSupported());
    try std.testing.expect(LinkType.loop.isSupported());
    try std.testing.expect(LinkType.raw.isSupported());
    try std.testing.expect(!LinkType.linux_sll.isSupported());
}

test "parseIpv4 valid" {
    const addr = parseIpv4("192.168.1.1");
    try std.testing.expect(addr != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &addr.?);
}

test "parseIpv4 invalid" {
    try std.testing.expect(parseIpv4("256.1.1.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("not.an.ip.addr") == null);
}
