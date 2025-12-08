//! UDP Proxy 2020 - Zig Edition
//!
//! A UDP broadcast packet forwarder for routing UDP traffic across
//! network interfaces, including VPN tunnels and VLANs.
//!
//! Ported from the Go implementation for improved performance on FreeBSD.

const std = @import("std");
const builtin = @import("builtin");

const pcap = @import("pcap.zig");
const packet = @import("packet.zig");
const sender = @import("sender.zig");
const Listener = @import("listener.zig").Listener;
const ListenerConfig = @import("listener.zig").ListenerConfig;
const UdpSink = @import("listener.zig").UdpSink;

const log = std.log.scoped(.@"udp-proxy");

// ============================================================================
// Version Info
// ============================================================================

pub const version = "0.1.0";
pub const build_info = "zig-port";

// ============================================================================
// CLI Arguments
// ============================================================================

const Args = struct {
    interfaces: std.ArrayListUnmanaged([:0]const u8),
    fixed_ips: std.ArrayListUnmanaged(FixedIp),
    ports: std.ArrayListUnmanaged(u16),
    timeout_ms: i32 = 250,
    cache_ttl: u32 = 180,
    deliver_local: bool = false,
    log_level: std.log.Level = .info,
    log_file: ?[]const u8 = null,
    use_default_log: bool = false,
    pcap_debug: bool = false,
    pcap_path: []const u8 = "/tmp",
    list_interfaces: bool = false,
    show_version: bool = false,
    no_listen: bool = false,

    const FixedIp = struct {
        interface: [:0]const u8,
        ip: [4]u8,
    };

    fn init() Args {
        return Args{
            .interfaces = .{},
            .fixed_ips = .{},
            .ports = .{},
        };
    }

    fn deinit(self: *Args, allocator: std.mem.Allocator) void {
        for (self.interfaces.items) |iface| {
            allocator.free(iface);
        }
        self.interfaces.deinit(allocator);

        for (self.fixed_ips.items) |fip| {
            allocator.free(fip.interface);
        }
        self.fixed_ips.deinit(allocator);

        self.ports.deinit(allocator);
    }
};

// ============================================================================
// Logging Configuration
// ============================================================================

pub const std_options: std.Options = .{
    .log_level = .debug, // Allow all levels, filter at runtime
    .logFn = customLog,
};

var runtime_log_level: std.log.Level = .info;
var log_file: ?std.fs.File = null;
var log_mutex: std.Thread.Mutex = .{};
const default_log_path = "/tmp/udp-proxy-2020.log";

fn customLog(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(runtime_log_level)) {
        return;
    }

    const level_txt = comptime switch (level) {
        .err => "ERROR",
        .warn => "WARN ",
        .info => "INFO ",
        .debug => "DEBUG",
    };

    const scope_prefix = if (scope == .default) "" else "[" ++ @tagName(scope) ++ "] ";

    // Get current timestamp
    const timestamp = std.time.timestamp();
    const epoch_secs: u64 = @intCast(timestamp);
    const epoch_day = std.time.epoch.EpochDay{ .day = @intCast(@divFloor(epoch_secs, std.time.s_per_day)) };
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs: u64 = @intCast(@mod(epoch_secs, std.time.s_per_day));
    const hours: u64 = day_secs / 3600;
    const minutes: u64 = (day_secs % 3600) / 60;
    const seconds: u64 = day_secs % 60;

    // Format the message into a buffer
    var buf: [8192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s} {s}" ++ format ++ "\n", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u6, month_day.day_index) + 1, // day_index is 0-based, display 1-based
        hours,
        minutes,
        seconds,
        level_txt,
        scope_prefix,
    } ++ args) catch return;

    // Lock for thread safety and write atomically
    log_mutex.lock();
    defer log_mutex.unlock();

    const output_file = log_file orelse std.fs.File.stderr();
    _ = output_file.write(msg) catch {};
}

fn initLogFile(path: ?[]const u8) !void {
    const log_path = path orelse default_log_path;
    // Open with append mode
    log_file = try std.fs.cwd().openFile(log_path, .{ .mode = .write_only });
    log_file.?.seekFromEnd(0) catch {};
}

fn initLogFileCreate(path: ?[]const u8) !void {
    const log_path = path orelse default_log_path;
    // Create if doesn't exist, open for append
    log_file = std.fs.cwd().openFile(log_path, .{ .mode = .write_only }) catch |err| {
        if (err == error.FileNotFound) {
            return try createLogFile(log_path);
        }
        return err;
    };
    log_file.?.seekFromEnd(0) catch {};
}

fn createLogFile(path: []const u8) !void {
    log_file = try std.fs.cwd().createFile(path, .{});
}

fn deinitLogFile() void {
    if (log_file) |f| {
        f.close();
        log_file = null;
    }
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    // Use GPA for leak detection in debug builds
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            log.err("Memory leak detected!", .{});
        }
    }
    const allocator = gpa.allocator();

    // Parse arguments
    var args = Args.init();
    defer args.deinit(allocator);

    parseArgs(allocator, &args) catch |err| {
        log.err("Failed to parse arguments: {}", .{err});
        std.process.exit(1);
    };

    // Set runtime log level
    runtime_log_level = args.log_level;

    // Initialize log file if requested
    if (args.log_file != null or args.use_default_log) {
        initLogFileCreate(args.log_file) catch |err| {
            // Fall back to stderr if we can't open log file
            var err_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&err_buf, "Warning: Could not open log file: {}\n", .{err}) catch "Warning: Could not open log file\n";
            _ = std.fs.File.stderr().write(msg) catch {};
        };
    }
    defer deinitLogFile();

    // Handle --version
    if (args.show_version) {
        var buf: [4096]u8 = undefined;
        const stdout = std.fs.File.stdout();
        var writer = stdout.writer(&buf);
        try writer.interface.print("udp-proxy-2020 (Zig) Version {s}\n", .{version});
        try writer.interface.print("{s} built with Zig {s}\n", .{ build_info, builtin.zig_version_string });
        try writer.interface.flush();
        return;
    }

    // Handle --list-interfaces
    if (args.list_interfaces) {
        try listInterfaces(allocator);
        return;
    }

    // Validate arguments
    if (args.interfaces.items.len < 2) {
        log.err("Please specify two or more --interface", .{});
        std.process.exit(1);
    }

    if (args.ports.items.len < 1) {
        log.err("Please specify one or more --port", .{});
        std.process.exit(1);
    }

    // Check fixed IPs are for specified interfaces
    for (args.fixed_ips.items) |fip| {
        var found = false;
        for (args.interfaces.items) |iface| {
            if (std.mem.eql(u8, fip.interface, iface)) {
                found = true;
                break;
            }
        }
        if (!found) {
            log.err("--fixed-ip interface '{s}' must be specified via --interface", .{fip.interface});
            std.process.exit(1);
        }
    }

    // Get available interfaces
    const interfaces = pcap.findAllDevices(allocator) catch |err| {
        log.err("Failed to enumerate interfaces: {}", .{err});
        std.process.exit(1);
    };
    defer pcap.freeDevices(allocator, interfaces);

    // Create packet feed
    var feed = sender.SendPktFeed.init(allocator);
    defer feed.deinit();

    // Create listeners
    var listeners = std.ArrayListUnmanaged(Listener){};
    defer {
        for (listeners.items) |*l| {
            l.deinit();
        }
        listeners.deinit(allocator);
    }

    for (args.interfaces.items) |iface_name| {
        // Check for duplicates
        for (listeners.items) |existing| {
            if (std.mem.eql(u8, existing.getName(), iface_name)) {
                log.err("Can't specify the same interface ({s}) multiple times", .{iface_name});
                std.process.exit(1);
            }
        }

        // Determine if this interface needs promiscuous mode
        // (interfaces without broadcast support, like tun/wireguard)
        var promisc = false;
        for (interfaces) |iface| {
            if (std.mem.eql(u8, iface.name, iface_name[0..iface_name.len])) {
                // If no broadcast address in any address, use promisc
                var has_broadcast = false;
                for (iface.addresses) |addr| {
                    if (addr.broadcast != null) {
                        has_broadcast = true;
                        break;
                    }
                }
                promisc = !has_broadcast;
                break;
            }
        }

        // Collect fixed IPs for this interface
        var fixed_ips = std.ArrayListUnmanaged([4]u8){};
        defer fixed_ips.deinit(allocator);

        for (args.fixed_ips.items) |fip| {
            if (std.mem.eql(u8, fip.interface, iface_name)) {
                try fixed_ips.append(allocator, fip.ip);
            }
        }

        const config = ListenerConfig{
            .iface_name = iface_name,
            .ports = args.ports.items,
            .timeout_ms = args.timeout_ms,
            .cache_ttl_minutes = args.cache_ttl,
            .fixed_ips = try allocator.dupe([4]u8, fixed_ips.items),
            .promisc = promisc,
            .send_only = false,
            .pcap_debug = args.pcap_debug,
            .pcap_path = args.pcap_path,
        };

        var listener = try Listener.init(allocator, config);
        errdefer listener.deinit();

        try listener.open(interfaces);
        try listener.registerSender(&feed);

        try listeners.append(allocator, listener);
    }

    // Add loopback listener if deliver-local is enabled
    if (args.deliver_local) {
        if (try pcap.findLoopback(allocator)) |loopback_name| {
            defer allocator.free(loopback_name);

            const lb_name = try allocator.allocSentinel(u8, loopback_name.len, 0);
            @memcpy(lb_name, loopback_name);

            const config = ListenerConfig{
                .iface_name = lb_name,
                .ports = args.ports.items,
                .timeout_ms = args.timeout_ms,
                .cache_ttl_minutes = args.cache_ttl,
                .fixed_ips = &[_][4]u8{.{ 127, 0, 0, 1 }},
                .promisc = false,
                .send_only = true,
                .pcap_debug = args.pcap_debug,
                .pcap_path = args.pcap_path,
            };

            var listener = try Listener.init(allocator, config);
            errdefer listener.deinit();

            try listener.open(interfaces);
            try listener.registerSender(&feed);

            try listeners.append(allocator, listener);
        } else {
            log.warn("Could not find loopback interface for --deliver-local", .{});
        }
    }

    // Start UDP sinks (unless --no-listen)
    var sink: ?UdpSink = null;
    if (!args.no_listen) {
        sink = UdpSink.init(allocator);

        for (interfaces) |iface| {
            for (args.interfaces.items) |wanted| {
                if (std.mem.eql(u8, iface.name, wanted[0..wanted.len])) {
                    for (iface.addresses) |addr| {
                        if (addr.addr) |ip| {
                            for (args.ports.items) |port| {
                                sink.?.bind(ip, port) catch {};
                            }
                        }
                    }
                }
            }
        }
    }
    defer if (sink) |*s| s.deinit();

    log.info("Initialization complete! Starting packet handlers...", .{});

    // Start listener threads
    var threads = std.ArrayListUnmanaged(std.Thread){};
    defer {
        for (threads.items) |thread| {
            thread.join();
        }
        threads.deinit(allocator);
    }

    for (listeners.items) |*listener| {
        const thread = try std.Thread.spawn(.{}, runListener, .{ listener, &feed });
        try threads.append(allocator, thread);
    }

    // Wait for all threads (they run forever unless stopped)
    for (threads.items) |thread| {
        thread.join();
    }
}

fn runListener(listener: *Listener, feed: *sender.SendPktFeed) void {
    listener.run(feed);
}

// ============================================================================
// Argument Parsing
// ============================================================================

fn parseArgs(allocator: std.mem.Allocator, args: *Args) !void {
    var arg_iter = std.process.args();
    _ = arg_iter.skip(); // Skip program name

    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interface")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            // Handle comma-separated interfaces
            var iface_iter = std.mem.splitScalar(u8, value, ',');
            while (iface_iter.next()) |iface| {
                const iface_z = try allocator.allocSentinel(u8, iface.len, 0);
                @memcpy(iface_z, iface);
                try args.interfaces.append(allocator, iface_z);
            }
        } else if (std.mem.eql(u8, arg, "-I") or std.mem.eql(u8, arg, "--fixed-ip")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            // Parse interface@ip format
            if (std.mem.indexOf(u8, value, "@")) |at_pos| {
                const iface = value[0..at_pos];
                const ip_str = value[at_pos + 1 ..];

                const ip = pcap.parseIpv4(ip_str) orelse {
                    log.err("Invalid IP address in --fixed-ip: {s}", .{ip_str});
                    return error.InvalidIpAddress;
                };

                const iface_z = try allocator.allocSentinel(u8, iface.len, 0);
                @memcpy(iface_z, iface);

                try args.fixed_ips.append(allocator, .{
                    .interface = iface_z,
                    .ip = ip,
                });
            } else {
                log.err("--fixed-ip must be in format interface@ip", .{});
                return error.InvalidFormat;
            }
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            const port = std.fmt.parseInt(u16, value, 10) catch {
                log.err("Invalid port number: {s}", .{value});
                return error.InvalidPort;
            };
            try args.ports.append(allocator, port);
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--timeout")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            args.timeout_ms = std.fmt.parseInt(i32, value, 10) catch {
                log.err("Invalid timeout: {s}", .{value});
                return error.InvalidTimeout;
            };
        } else if (std.mem.eql(u8, arg, "-T") or std.mem.eql(u8, arg, "--cache-ttl")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            args.cache_ttl = std.fmt.parseInt(u32, value, 10) catch {
                log.err("Invalid cache-ttl: {s}", .{value});
                return error.InvalidCacheTtl;
            };
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--deliver-local")) {
            args.deliver_local = true;
        } else if (std.mem.eql(u8, arg, "-L") or std.mem.eql(u8, arg, "--level")) {
            const value = arg_iter.next() orelse return error.MissingValue;
            if (std.mem.eql(u8, value, "trace") or std.mem.eql(u8, value, "debug")) {
                args.log_level = .debug;
            } else if (std.mem.eql(u8, value, "info")) {
                args.log_level = .info;
            } else if (std.mem.eql(u8, value, "warn")) {
                args.log_level = .warn;
            } else if (std.mem.eql(u8, value, "error")) {
                args.log_level = .err;
            } else {
                log.err("Invalid log level: {s}", .{value});
                return error.InvalidLogLevel;
            }
        } else if (std.mem.eql(u8, arg, "--log")) {
            args.use_default_log = true;
        } else if (std.mem.eql(u8, arg, "--logfile")) {
            args.log_file = arg_iter.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "-P") or std.mem.eql(u8, arg, "--pcap")) {
            args.pcap_debug = true;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--pcap-path")) {
            args.pcap_path = arg_iter.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--list-interfaces")) {
            args.list_interfaces = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            args.show_version = true;
        } else if (std.mem.eql(u8, arg, "--no-listen")) {
            args.no_listen = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else {
            log.err("Unknown argument: {s}", .{arg});
            printHelp();
            std.process.exit(1);
        }
    }
}

fn printHelp() void {
    var buf: [4096]u8 = undefined;
    const stdout = std.fs.File.stdout();
    var writer = stdout.writer(&buf);
    writer.interface.print(
        \\udp-proxy-2020 (Zig) - A UDP broadcast packet forwarder
        \\
        \\Usage: udp-proxy-2020 [OPTIONS]
        \\
        \\Options:
        \\  -i, --interface <IFACE>     Network interface (can be comma-separated or repeated)
        \\  -I, --fixed-ip <IFACE@IP>   Fixed IP to always forward to (interface@ip format)
        \\  -p, --port <PORT>           UDP port to monitor (can be repeated)
        \\  -t, --timeout <MS>          Pcap timeout in milliseconds (default: 250)
        \\  -T, --cache-ttl <MIN>       Client cache TTL in minutes (default: 180)
        \\  -l, --deliver-local         Deliver packets locally via loopback
        \\  -L, --level <LEVEL>         Log level: trace|debug|info|warn|error (default: info)
        \\      --log                   Log to /tmp/udp-proxy-2020.log
        \\      --logfile <PATH>        Log to custom file path
        \\  -P, --pcap                  Enable pcap debugging (write packet captures)
        \\  -d, --pcap-path <DIR>       Directory for pcap debug files (default: /tmp)
        \\      --list-interfaces       List available interfaces and exit
        \\      --no-listen             Don't bind UDP sockets (use if another app needs the port)
        \\  -v, --version               Show version and exit
        \\  -h, --help                  Show this help
        \\
        \\Example:
        \\  udp-proxy-2020 -i eth0,eth1,tun0 -p 9003 -T 300
        \\
        \\
    , .{}) catch {};
    writer.interface.flush() catch {};
}

// ============================================================================
// List Interfaces
// ============================================================================

fn listInterfaces(allocator: std.mem.Allocator) !void {
    const interfaces = try pcap.findAllDevices(allocator);
    defer pcap.freeDevices(allocator, interfaces);

    var buf: [4096]u8 = undefined;
    const stdout = std.fs.File.stdout();
    var writer = stdout.writer(&buf);
    const w = &writer.interface;

    for (interfaces) |iface| {
        try w.print("Interface: {s}\n", .{iface.name});

        for (iface.addresses) |addr| {
            if (addr.addr) |ip| {
                const prefix = if (addr.netmask) |mask| packet.netmaskToPrefix(mask) else 0;

                if (addr.broadcast) |bcast| {
                    try w.print("\t- IP: {d}.{d}.{d}.{d}/{d}  Broadcast: {d}.{d}.{d}.{d}\n", .{
                        ip[0],    ip[1],    ip[2],    ip[3],    prefix,
                        bcast[0], bcast[1], bcast[2], bcast[3],
                    });
                } else if (addr.p2p) |p2p| {
                    try w.print("\t- IP: {d}.{d}.{d}.{d}/{d}  PointToPoint: {d}.{d}.{d}.{d}\n", .{
                        ip[0],  ip[1],  ip[2],  ip[3],  prefix,
                        p2p[0], p2p[1], p2p[2], p2p[3],
                    });
                } else {
                    try w.print("\t- IP: {d}.{d}.{d}.{d}/{d}\n", .{
                        ip[0], ip[1], ip[2], ip[3], prefix,
                    });
                }
            }
        }

        try w.print("\n", .{});
    }
    try w.flush();
}
