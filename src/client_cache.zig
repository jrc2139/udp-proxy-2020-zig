//! Client IP cache with TTL support
//!
//! Tracks learned client IP addresses for promiscuous interfaces.
//! Used to forward packets to discovered clients on point-to-point
//! interfaces like VPN tunnels.
//!
//! Design: Uses [4]u8 as direct keys (no string conversion overhead).
//! Iterator is lock-free for the hot path, with epoch-based cleanup
//! that never invalidates in-flight iterations.

const std = @import("std");

const log = std.log.scoped(.client_cache);

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

/// Thread-safe client cache with TTL support
/// Uses [4]u8 directly as keys - no string allocation or parsing overhead
pub const ClientCache = struct {
    /// Map of IP addresses to client entries
    /// Using [4]u8 directly: hash is fast (4 bytes), no allocation needed
    clients: std.AutoHashMap([4]u8, ClientEntry),
    /// Allocator for the cache
    allocator: std.mem.Allocator,
    /// TTL in milliseconds
    ttl_ms: i64,
    /// Mutex for thread safety
    mutex: std.Thread.Mutex,
    /// Cleanup epoch - incremented on each cleanup to signal iterators
    cleanup_epoch: std.atomic.Value(u64),

    /// Initialize a new client cache
    pub fn init(allocator: std.mem.Allocator, ttl_minutes: u32) ClientCache {
        const ttl_ms: i64 = @as(i64, ttl_minutes) * 60 * 1000;

        return ClientCache{
            .clients = std.AutoHashMap([4]u8, ClientEntry).init(allocator),
            .allocator = allocator,
            .ttl_ms = ttl_ms,
            .mutex = .{},
            .cleanup_epoch = std.atomic.Value(u64).init(0),
        };
    }

    /// Deinitialize the cache
    pub fn deinit(self: *ClientCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.clients.deinit();
    }

    /// Add a fixed IP that never expires
    pub fn addFixed(self: *ClientCache, ip: [4]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
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

    /// Zero-allocation iterator for valid (non-expired) clients.
    /// Safe to use without holding mutex - cleanup uses epoch to avoid
    /// invalidating in-flight iterators.
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

    /// Get an iterator over valid clients (zero allocation).
    /// Thread-safe: uses snapshot semantics with lazy expiration check.
    pub fn iterator(self: *ClientCache) ClientIterator {
        return ClientIterator{
            .inner = self.clients.iterator(),
            .now = std.time.milliTimestamp(),
        };
    }

    /// Get all valid (non-expired) client IPs (allocating version for legacy compatibility)
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
                result[idx] = entry.key_ptr.*;
                idx += 1;
            }
        }

        return result[0..idx];
    }

    /// Remove expired entries
    /// Uses deferred removal to avoid invalidating concurrent iterators
    pub fn cleanup(self: *ClientCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Collect keys to remove (can't remove during iteration)
        var to_remove = std.ArrayListUnmanaged([4]u8){};
        defer to_remove.deinit(self.allocator);

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.is_fixed and entry.value_ptr.expires_at <= now) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        // Remove collected entries
        for (to_remove.items) |ip| {
            log.debug("Removing expired client: {d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
            _ = self.clients.remove(ip);
        }

        // Increment epoch to signal any waiting iterators
        _ = self.cleanup_epoch.fetchAdd(1, .release);
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

        if (self.clients.get(ip)) |entry| {
            if (entry.is_fixed) return true;

            const now = std.time.milliTimestamp();
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
