//! Client IP cache with TTL support
//!
//! Tracks learned client IP addresses for promiscuous interfaces.
//! Used to forward packets to discovered clients on point-to-point
//! interfaces like VPN tunnels.
//!
//! Design: Uses [4]u8 as direct keys (no string conversion overhead).
//!
//! Ownership: each cache is owned by exactly one listener thread -- learn(),
//! iterator(), cleanup() and friends are all called from that thread's run
//! loop -- so it is intentionally not synchronized. Do not share a cache across
//! threads without adding synchronization.

const std = @import("std");

const log = std.log.scoped(.client_cache);

/// Return milliseconds since Unix epoch using POSIX clock_gettime.
fn milliTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

// ============================================================================
// Types
// ============================================================================

/// Client entry with expiration time
pub const ClientEntry = struct {
    /// Expiration timestamp (milliseconds since epoch)
    expires_at: i64,
    /// Whether this is a fixed IP (never expires)
    is_fixed: bool,
};

/// Per-listener client cache with TTL support (single-thread-owned; see the
/// module doc). Uses [4]u8 directly as keys -- no string allocation or parsing.
pub const ClientCache = struct {
    /// Map of IP addresses to client entries
    /// Using [4]u8 directly: hash is fast (4 bytes), no allocation needed
    clients: std.AutoHashMap([4]u8, ClientEntry),
    /// Allocator for the cache
    allocator: std.mem.Allocator,
    /// TTL in milliseconds
    ttl_ms: i64,

    /// Initialize a new client cache
    pub fn init(allocator: std.mem.Allocator, ttl_minutes: u32) ClientCache {
        const ttl_ms: i64 = @as(i64, ttl_minutes) * 60 * 1000;

        return ClientCache{
            .clients = std.AutoHashMap([4]u8, ClientEntry).init(allocator),
            .allocator = allocator,
            .ttl_ms = ttl_ms,
        };
    }

    /// Deinitialize the cache
    pub fn deinit(self: *ClientCache) void {
        self.clients.deinit();
    }

    /// Add a fixed IP that never expires
    pub fn addFixed(self: *ClientCache, ip: [4]u8) !void {
        // Check if already exists as fixed
        if (self.clients.get(ip)) |existing| {
            if (existing.is_fixed) {
                return; // Already exists as fixed
            }
        }

        try self.clients.put(ip, ClientEntry{
            .expires_at = std.math.maxInt(i64), // Never expires
            .is_fixed = true,
        });

        log.debug("Added fixed IP: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    /// Learn a client IP (update TTL if exists)
    pub fn learn(self: *ClientCache, ip: [4]u8) !void {
        const now = milliTimestamp();
        const expires_at: i64 = now + self.ttl_ms;

        // Check if already exists
        if (self.clients.getPtr(ip)) |entry| {
            if (!entry.is_fixed) {
                // Update expiration
                entry.expires_at = expires_at;
            }
            return;
        }

        // New entry - no allocation needed, [4]u8 is stored by value
        try self.clients.put(ip, ClientEntry{
            .expires_at = expires_at,
            .is_fixed = false,
        });

        log.debug("Learned client IP: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    /// Zero-allocation iterator over valid (non-expired) clients. Must be used
    /// only by the owning thread (it walks the live HashMap directly).
    pub const ClientIterator = struct {
        inner: std.AutoHashMap([4]u8, ClientEntry).Iterator,
        now: i64,

        pub fn next(self: *ClientIterator) ?[4]u8 {
            while (self.inner.next()) |entry| {
                if (entry.value_ptr.is_fixed or entry.value_ptr.expires_at > self.now) {
                    return entry.key_ptr.*;
                }
            }
            return null;
        }
    };

    /// Get an iterator over valid clients (zero allocation, lazy expiration).
    pub fn iterator(self: *ClientCache) ClientIterator {
        return ClientIterator{
            .inner = self.clients.iterator(),
            .now = milliTimestamp(),
        };
    }

    /// Remove expired entries using stack-allocated collection (no heap allocation).
    pub fn cleanup(self: *ClientCache) void {
        const now = milliTimestamp();

        // Stack-allocated buffer for expired keys (64 clients is plenty for VPN peers)
        var to_remove: [64][4]u8 = undefined;
        var remove_count: usize = 0;

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.is_fixed and entry.value_ptr.expires_at <= now) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |ip| {
            log.debug("Removing expired client: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
            _ = self.clients.remove(ip);
        }
    }

    /// Get the number of clients (including expired)
    pub fn count(self: *ClientCache) usize {
        return self.clients.count();
    }

    /// Check if a client exists
    pub fn contains(self: *ClientCache, ip: [4]u8) bool {
        if (self.clients.get(ip)) |entry| {
            if (entry.is_fixed) return true;

            const now = milliTimestamp();
            return entry.expires_at > now;
        }
        return false;
    }
};

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

    // Iterate clients
    var count_val: usize = 0;
    var iter = cache.iterator();
    while (iter.next()) |_| count_val += 1;
    try std.testing.expectEqual(@as(usize, 2), count_val);
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

test "ClientIterator zero allocation" {
    const allocator = std.testing.allocator;

    var cache = ClientCache.init(allocator, 5);
    defer cache.deinit();

    // Add some clients
    try cache.addFixed([_]u8{ 192, 168, 1, 1 });
    try cache.learn([_]u8{ 10, 0, 0, 1 });
    try cache.learn([_]u8{ 10, 0, 0, 2 });

    // Iterate without allocation
    var count_val: usize = 0;
    var iter = cache.iterator();
    while (iter.next()) |_| {
        count_val += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), count_val);
}

test "ClientCache direct IP key lookup" {
    const allocator = std.testing.allocator;

    var cache = ClientCache.init(allocator, 5);
    defer cache.deinit();

    const ip = [_]u8{ 192, 168, 1, 100 };
    try cache.learn(ip);

    // Direct lookup - no string conversion
    try std.testing.expect(cache.contains(ip));
    try std.testing.expect(!cache.contains([_]u8{ 192, 168, 1, 101 }));
}

test "ClientCache update existing entry" {
    const allocator = std.testing.allocator;

    var cache = ClientCache.init(allocator, 5);
    defer cache.deinit();

    const ip = [_]u8{ 10, 0, 0, 1 };

    // Learn same IP twice - should update, not duplicate
    try cache.learn(ip);
    try cache.learn(ip);

    try std.testing.expectEqual(@as(usize, 1), cache.count());
}
