//! Client IP cache with TTL support
//!
//! Tracks learned client IP addresses for promiscuous interfaces.
//! Used to forward packets to discovered clients on point-to-point
//! interfaces like VPN tunnels.

const std = @import("std");

const log = std.log.scoped(.client_cache);

// ============================================================================
// Types
// ============================================================================

/// Client IP address as a string key
pub const IpKey = [15]u8; // "xxx.xxx.xxx.xxx"

/// Client entry with expiration time
pub const ClientEntry = struct {
    /// Expiration timestamp (milliseconds since epoch)
    expires_at: i64,
    /// Whether this is a fixed IP (never expires)
    is_fixed: bool,
};

/// Thread-safe client cache with TTL support
pub const ClientCache = struct {
    /// Map of IP addresses to client entries
    clients: std.StringHashMap(ClientEntry),
    /// Allocator for the cache
    allocator: std.mem.Allocator,
    /// TTL in milliseconds
    ttl_ms: i64,
    /// Mutex for thread safety
    mutex: std.Thread.Mutex,

    /// Initialize a new client cache
    pub fn init(allocator: std.mem.Allocator, ttl_minutes: u32) ClientCache {
        const ttl_ms: i64 = @as(i64, ttl_minutes) * 60 * 1000;

        return ClientCache{
            .clients = std.StringHashMap(ClientEntry).init(allocator),
            .allocator = allocator,
            .ttl_ms = ttl_ms,
            .mutex = .{},
        };
    }

    /// Deinitialize the cache
    pub fn deinit(self: *ClientCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Free all allocated keys
        var iter = self.clients.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.clients.deinit();
    }

    /// Add a fixed IP that never expires
    pub fn addFixed(self: *ClientCache, ip: [4]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = try self.makeKey(ip);

        // Check if already exists
        if (self.clients.get(key)) |existing| {
            if (existing.is_fixed) {
                self.allocator.free(key);
                return; // Already exists as fixed
            }
        }

        try self.clients.put(key, ClientEntry{
            .expires_at = std.math.maxInt(i64), // Never expires
            .is_fixed = true,
        });

        log.debug("Added fixed IP: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    /// Learn a client IP (update TTL if exists)
    pub fn learn(self: *ClientCache, ip: [4]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        const expires_at: i64 = now + self.ttl_ms;

        const key_str = formatIp(ip);

        // Check if already exists
        if (self.clients.getPtr(key_str[0..ipLen(key_str)])) |entry| {
            if (!entry.is_fixed) {
                // Update expiration
                entry.expires_at = expires_at;
            }
            return;
        }

        // New entry - allocate key
        const key = try self.makeKey(ip);
        try self.clients.put(key, ClientEntry{
            .expires_at = expires_at,
            .is_fixed = false,
        });

        log.debug("Learned client IP: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    /// Get all valid (non-expired) client IPs
    /// Caller must free the returned slice
    pub fn getClients(self: *ClientCache, allocator: std.mem.Allocator) ![][4]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Count valid clients first
        var valid_count: usize = 0;
        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.is_fixed or entry.value_ptr.expires_at > now) {
                valid_count += 1;
            }
        }

        var result = try allocator.alloc([4]u8, valid_count);
        var idx: usize = 0;

        iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.is_fixed or entry.value_ptr.expires_at > now) {
                if (parseIpKey(entry.key_ptr.*)) |ip| {
                    result[idx] = ip;
                    idx += 1;
                }
            }
        }

        return result[0..idx];
    }

    /// Remove expired entries
    pub fn cleanup(self: *ClientCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        var to_remove = std.ArrayListUnmanaged([]const u8){};
        defer to_remove.deinit(self.allocator);

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.is_fixed and entry.value_ptr.expires_at <= now) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            log.debug("Removing expired client: {s}", .{key});
            _ = self.clients.remove(key);
            self.allocator.free(key);
        }
    }

    /// Get the number of clients (including expired)
    pub fn count(self: *ClientCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.clients.count();
    }

    /// Check if a client exists
    pub fn contains(self: *ClientCache, ip: [4]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_str = formatIp(ip);
        const key = key_str[0..ipLen(key_str)];

        if (self.clients.get(key)) |entry| {
            if (entry.is_fixed) return true;

            const now = std.time.milliTimestamp();
            return entry.expires_at > now;
        }
        return false;
    }

    // Internal helpers

    fn makeKey(self: *ClientCache, ip: [4]u8) ![]u8 {
        const key_str = formatIp(ip);
        const len = ipLen(key_str);
        const key = try self.allocator.alloc(u8, len);
        @memcpy(key, key_str[0..len]);
        return key;
    }
};

/// Format an IP address to string
fn formatIp(ip: [4]u8) [15]u8 {
    var buf: [15]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch {};
    return buf;
}

/// Get the actual length of a formatted IP string
fn ipLen(buf: [15]u8) usize {
    for (buf, 0..) |c, i| {
        if (c == 0 or (c < '0' or c > '9') and c != '.') {
            return i;
        }
    }
    return 15;
}

/// Parse an IP key back to bytes
fn parseIpKey(key: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var idx: usize = 0;
    var iter = std.mem.splitScalar(u8, key, '.');

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

test "ClientCache basic operations" {
    const allocator = std.testing.allocator;

    var cache = ClientCache.init(allocator, 5); // 5 minute TTL
    defer cache.deinit();

    // Add a fixed IP
    try cache.addFixed([_]u8{ 192, 168, 1, 1 });
    try std.testing.expect(cache.contains([_]u8{ 192, 168, 1, 1 }));

    // Learn a dynamic IP
    try cache.learn([_]u8{ 10, 0, 0, 1 });
    try std.testing.expect(cache.contains([_]u8{ 10, 0, 0, 1 }));

    // Get all clients
    const clients = try cache.getClients(allocator);
    defer allocator.free(clients);
    try std.testing.expectEqual(@as(usize, 2), clients.len);
}

test "ClientCache fixed IP never expires" {
    const allocator = std.testing.allocator;

    var cache = ClientCache.init(allocator, 0); // 0 minute TTL = immediate expiration
    defer cache.deinit();

    // Add a fixed IP - should not expire even with 0 TTL
    try cache.addFixed([_]u8{ 192, 168, 1, 1 });

    cache.cleanup();
    try std.testing.expect(cache.contains([_]u8{ 192, 168, 1, 1 }));
}

test "formatIp" {
    const ip = [_]u8{ 192, 168, 1, 1 };
    const formatted = formatIp(ip);
    const len = ipLen(formatted);
    try std.testing.expectEqualStrings("192.168.1.1", formatted[0..len]);
}

test "parseIpKey" {
    const key = "10.0.0.1";
    const ip = parseIpKey(key);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &ip.?);
}

test "parseIpKey invalid" {
    try std.testing.expect(parseIpKey("256.0.0.1") == null);
    try std.testing.expect(parseIpKey("1.2.3") == null);
    try std.testing.expect(parseIpKey("not.an.ip") == null);
}
