// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const types = @import("types.zig");
const provider_mod = @import("provider.zig");
const aead = @import("../crypto/aead.zig");
const hkdf = @import("../crypto/hkdf.zig");
const observability = @import("observability");

pub const Error = error{
    KeyNotFound,
    InvalidKeyVersion,
    InvalidIdentifier,
    RotationInProgress,
    OutOfMemory,
    MasterKeyRequired,
};

/// Key cache entry
const CacheEntry = struct {
    key: [32]u8,
    version: u16,
};

/// Key cache for performance
const KeyCache = struct {
    map: std.StringHashMap(CacheEntry),
    hits: u64 = 0,
    misses: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) KeyCache {
        return .{
            .map = std.StringHashMap(CacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *KeyCache) void {
        const allocator = self.map.allocator;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            std.crypto.secureZero(u8, &entry.value_ptr.key);
            allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
    }

    pub fn get(self: *KeyCache, key: []const u8) ?CacheEntry {
        if (self.map.get(key)) |entry| {
            self.hits += 1;
            return entry;
        }
        self.misses += 1;
        return null;
    }

    pub fn put(self: *KeyCache, key: []const u8, entry: CacheEntry) !void {
        try self.map.put(key, entry);
    }

    /// Securely zero all cached keys and free owned key strings, then clear.
    pub fn secureClear(self: *KeyCache) void {
        const allocator = self.map.allocator;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            std.crypto.secureZero(u8, &entry.value_ptr.key);
            allocator.free(entry.key_ptr.*);
        }
        self.map.clearRetainingCapacity();
    }
};

/// Hierarchical Key Manager
/// TRK (Tenant Root Key) -> SK (Schema Key) -> FEK (Field Encryption Key) / BIK (Blind Index Key)
///
/// The master key is injected at initialization rather than read from environment
/// variables, allowing callers to source it from any key management system.
///
/// Identifiers (`tenant`, `schema`, `field`) must be non-empty and must not
/// contain `:` or `/` — these are reserved as derivation-context delimiters;
/// violations return `Error.InvalidIdentifier`.
pub const KeyManager = struct {
    allocator: std.mem.Allocator,
    master_key: [32]u8,
    fek_cache: KeyCache,
    bik_cache: KeyCache,
    key_versions: std.StringHashMap(u16),

    /// Initialize the key manager with an explicitly provided master key.
    /// The caller is responsible for sourcing the master key securely
    /// (e.g., from a KMS, HSM, or environment variable).
    pub fn init(allocator: std.mem.Allocator, master_key: [32]u8) !*KeyManager {
        const manager = try allocator.create(KeyManager);

        manager.* = .{
            .allocator = allocator,
            .master_key = master_key,
            .fek_cache = KeyCache.init(allocator),
            .bik_cache = KeyCache.init(allocator),
            .key_versions = std.StringHashMap(u16).init(allocator),
        };

        return manager;
    }

    /// Initialize the key manager using a pluggable key provider.
    /// The provider's `getMasterKey` is called once; the provider is
    /// not retained after init returns.
    pub fn initWithProvider(allocator: std.mem.Allocator, prov: provider_mod.MasterKeyProvider) !*KeyManager {
        const master_key = prov.getMasterKey() catch return Error.MasterKeyRequired;
        return init(allocator, master_key);
    }

    pub fn deinit(self: *KeyManager) void {
        std.crypto.secureZero(u8, &self.master_key);
        self.fek_cache.deinit();
        self.bik_cache.deinit();
        // Free owned key strings in key_versions map
        var it = self.key_versions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.key_versions.deinit();
        self.allocator.destroy(self);
    }

    /// Get current key version for a field (default 1)
    fn getKeyVersion(self: *KeyManager, key_path: []const u8) u16 {
        return self.key_versions.get(key_path) orelse 1;
    }

    /// Reserved characters in identifiers: ':' and '/' are delimiters in
    /// HKDF derivation contexts and rotation key-paths. Rejecting them at
    /// the API boundary keeps every downstream encoding injective without
    /// changing the (compatibility-locked) HKDF context format.
    fn validateIdentifier(s: []const u8) Error!void {
        if (s.len == 0) return Error.InvalidIdentifier;
        for (s) |c| {
            if (c == ':' or c == '/') return Error.InvalidIdentifier;
        }
    }

    fn validateIds(ids: types.KeyIds) Error!void {
        try validateIdentifier(ids.tenant);
        try validateIdentifier(ids.schema);
        try validateIdentifier(ids.field);
    }

    /// Build an injective (length-prefixed) cache key for FEK/BIK lookup.
    /// Layout: [len:u32 LE][tenant][len:u32 LE][schema][len:u32 LE][field][version:u16 LE]
    fn buildCacheKey(allocator: std.mem.Allocator, ids: types.KeyIds) ![]u8 {
        const total = 4 + ids.tenant.len + 4 + ids.schema.len + 4 + ids.field.len + 2;
        const key = try allocator.alloc(u8, total);
        var pos: usize = 0;
        inline for (.{ ids.tenant, ids.schema, ids.field }) |s| {
            std.mem.writeInt(u32, key[pos..][0..4], @intCast(s.len), .little);
            pos += 4;
            @memcpy(key[pos .. pos + s.len], s);
            pos += s.len;
        }
        std.mem.writeInt(u16, key[pos..][0..2], ids.version, .little);
        return key;
    }

    /// Stack-buffer variant for the hot cache-hit path: writes the same
    /// injective encoding into `buf` and returns the used slice, or null
    /// if the identifiers exceed the buffer (caller falls back to heap).
    fn buildCacheKeyBuf(buf: []u8, ids: types.KeyIds) ?[]const u8 {
        const total = 4 + ids.tenant.len + 4 + ids.schema.len + 4 + ids.field.len + 2;
        if (total > buf.len) return null;
        var pos: usize = 0;
        inline for (.{ ids.tenant, ids.schema, ids.field }) |s| {
            std.mem.writeInt(u32, buf[pos..][0..4], @intCast(s.len), .little);
            pos += 4;
            @memcpy(buf[pos .. pos + s.len], s);
            pos += s.len;
        }
        std.mem.writeInt(u16, buf[pos..][0..2], ids.version, .little);
        return buf[0..total];
    }

    /// Get Field Encryption Key (FEK).
    /// Derives TRK -> SK -> FEK using HKDF.
    pub fn getFEK(self: *KeyManager, ids: types.KeyIds) ![32]u8 {
        try validateIds(ids);

        var key_buf: [256]u8 = undefined;
        const stack_key = buildCacheKeyBuf(&key_buf, ids);
        if (stack_key) |sk_key| {
            if (self.fek_cache.get(sk_key)) |entry| return entry.key;
        }

        var trk = try hkdf.deriveTRK(&self.master_key, ids.tenant);
        defer std.crypto.secureZero(u8, &trk);
        var sk = try hkdf.deriveSK(&trk, ids.schema);
        defer std.crypto.secureZero(u8, &sk);
        const fek = try hkdf.deriveFEKVersioned(&sk, ids.field, ids.version);

        const cache_key = try buildCacheKey(self.allocator, ids);
        errdefer self.allocator.free(cache_key);
        if (stack_key == null) {
            // Identifiers too long for the stack buffer — check the heap key
            // before inserting to avoid duplicate-key leaks.
            if (self.fek_cache.get(cache_key)) |entry| {
                self.allocator.free(cache_key);
                return entry.key;
            }
        }
        try self.fek_cache.put(cache_key, .{ .key = fek, .version = ids.version });
        return fek;
    }

    /// Get Blind Index Key (BIK)
    pub fn getBIK(self: *KeyManager, ids: types.KeyIds) ![32]u8 {
        try validateIds(ids);

        var key_buf: [256]u8 = undefined;
        const stack_key = buildCacheKeyBuf(&key_buf, ids);
        if (stack_key) |sk_key| {
            if (self.bik_cache.get(sk_key)) |entry| return entry.key;
        }

        var trk = try hkdf.deriveTRK(&self.master_key, ids.tenant);
        defer std.crypto.secureZero(u8, &trk);
        var sk = try hkdf.deriveSK(&trk, ids.schema);
        defer std.crypto.secureZero(u8, &sk);
        const bik = try hkdf.deriveBIKVersioned(&sk, ids.field, ids.version);

        const cache_key = try buildCacheKey(self.allocator, ids);
        errdefer self.allocator.free(cache_key);
        if (stack_key == null) {
            // Identifiers too long for the stack buffer — check the heap key
            // before inserting to avoid duplicate-key leaks.
            if (self.bik_cache.get(cache_key)) |entry| {
                self.allocator.free(cache_key);
                return entry.key;
            }
        }
        try self.bik_cache.put(cache_key, .{ .key = bik, .version = ids.version });
        return bik;
    }

    /// Rotate FEK to new version.
    /// Creates vN+1; new writes use new version.
    /// Old version remains available for reading during migration.
    /// Note: version state is in-memory only and resets when the KeyManager
    /// is destroyed. Callers must persist version state externally if needed.
    pub fn rotateFEK(
        self: *KeyManager,
        tenant: []const u8,
        schema: []const u8,
        field: []const u8,
    ) !u16 {
        // Span attrs: only the schema-level field name. SECURITY: the
        // 32-byte master key, derived FEKs/BIKs, and key version
        // integers are NEVER attached. Rotation involves no AEAD
        // primitive, so `fle.algorithm` is empty.
        var __obs_span = observability.startFleSpan("rotate_key", field, "");
        defer __obs_span.end(null);
        errdefer observability.endFleSpan(__obs_span, false);

        try validateIdentifier(tenant);
        try validateIdentifier(schema);
        try validateIdentifier(field);

        const total = 4 + tenant.len + 4 + schema.len + 4 + field.len;
        const key_path = try self.allocator.alloc(u8, total);
        {
            var pos: usize = 0;
            inline for (.{ tenant, schema, field }) |s| {
                std.mem.writeInt(u32, key_path[pos..][0..4], @intCast(s.len), .little);
                pos += 4;
                @memcpy(key_path[pos .. pos + s.len], s);
                pos += s.len;
            }
        }
        errdefer self.allocator.free(key_path);

        const current_version = self.getKeyVersion(key_path);
        if (current_version == std.math.maxInt(u16)) {
            observability.endFleSpan(__obs_span, false);
            return Error.InvalidKeyVersion;
        }
        const new_version = current_version + 1;

        // Use getOrPut to atomically insert/update without a window where
        // the version state is absent (avoids fetchRemove + put race on OOM)
        const gop = try self.key_versions.getOrPut(key_path);
        if (gop.found_existing) {
            // Map already owns a key string — free the new duplicate
            self.allocator.free(key_path);
        }
        // else: map now owns key_path via getOrPut
        gop.value_ptr.* = new_version;

        observability.endFleSpan(__obs_span, true);
        return new_version;
    }

    /// Wrap a key (encrypt it) using a wrapping key
    pub fn wrapKey(self: *KeyManager, key_to_wrap: []const u8, wrapping_key: []const u8) !aead.EnvelopeV1 {
        const aad_data = try aead.makeAAD(self.allocator, "system", "sys", "key_wrap", "0", 1);
        defer self.allocator.free(aad_data);

        return aead.encryptField(self.allocator, .aes256_gcm, wrapping_key, aad_data, key_to_wrap, 1);
    }

    /// Unwrap a key (decrypt it) using a wrapping key
    pub fn unwrapKey(self: *KeyManager, envelope: aead.EnvelopeV1, wrapping_key: []const u8) ![]u8 {
        const aad_data = try aead.makeAAD(self.allocator, "system", "sys", "key_wrap", "0", 1);
        defer self.allocator.free(aad_data);

        return aead.decryptField(self.allocator, wrapping_key, aad_data, envelope);
    }

    /// Securely clear all cached keys. Call after key rotation events
    /// to force re-derivation on next access.
    pub fn clearCache(self: *KeyManager) void {
        self.fek_cache.secureClear();
        self.bik_cache.secureClear();
    }

    /// Get cache statistics
    pub fn cacheStats(self: *KeyManager) struct { hits: u64, misses: u64 } {
        return .{
            .hits = self.fek_cache.hits + self.bik_cache.hits,
            .misses = self.fek_cache.misses + self.bik_cache.misses,
        };
    }
};

test "KeyManager FEK derivation and caching" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    const ids = types.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "ssn",
        .version = 1,
    };

    const fek1 = try manager.getFEK(ids);
    const fek2 = try manager.getFEK(ids);

    try testing.expectEqualSlices(u8, &fek1, &fek2);

    const stats = manager.cacheStats();
    try testing.expectEqual(@as(u64, 1), stats.hits);
    try testing.expectEqual(@as(u64, 1), stats.misses);
}

test "KeyManager FEK rotation" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    const tenant = "tenant1";
    const schema = "Person";
    const field = "ssn";

    const ids_v1 = types.KeyIds{
        .tenant = tenant,
        .schema = schema,
        .field = field,
        .version = 1,
    };
    const fek_v1 = try manager.getFEK(ids_v1);

    const new_version = try manager.rotateFEK(tenant, schema, field);
    try testing.expectEqual(@as(u16, 2), new_version);

    const ids_v2 = types.KeyIds{
        .tenant = tenant,
        .schema = schema,
        .field = field,
        .version = 2,
    };
    const fek_v2 = try manager.getFEK(ids_v2);

    try testing.expect(!std.mem.eql(u8, &fek_v1, &fek_v2));

    const fek_v1_again = try manager.getFEK(ids_v1);
    try testing.expectEqualSlices(u8, &fek_v1, &fek_v1_again);
}

test "KeyManager BIK derivation" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    const ids = types.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "email",
        .version = 1,
    };

    const bik = try manager.getBIK(ids);
    const fek = try manager.getFEK(ids);

    try testing.expect(!std.mem.eql(u8, &bik, &fek));
}

test "KeyManager initWithProvider using StaticKeyProvider" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var static_prov = provider_mod.StaticKeyProvider.init(master_key);
    const prov = static_prov.provider();

    var manager = try KeyManager.initWithProvider(allocator, prov);
    defer manager.deinit();

    // Verify it works the same as direct init
    var manager2 = try KeyManager.init(allocator, master_key);
    defer manager2.deinit();

    const ids = types.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "ssn",
        .version = 1,
    };

    const fek1 = try manager.getFEK(ids);
    const fek2 = try manager2.getFEK(ids);
    try testing.expectEqualSlices(u8, &fek1, &fek2);
}

test "rotateFEK version persists across multiple rotations" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    const v2 = try manager.rotateFEK("t1", "Person", "ssn");
    try testing.expectEqual(@as(u16, 2), v2);

    const v3 = try manager.rotateFEK("t1", "Person", "ssn");
    try testing.expectEqual(@as(u16, 3), v3);

    const v4 = try manager.rotateFEK("t1", "Person", "ssn");
    try testing.expectEqual(@as(u16, 4), v4);
}

test "getFEK rejects identifiers containing reserved delimiters" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);
    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    // ':' and '/' are reserved (HKDF context + cache delimiters); empty is invalid.
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a:b", .schema = "s", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a", .schema = "s/x", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a", .schema = "s", .field = "", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getBIK(.{ .tenant = "a:b", .schema = "s", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.rotateFEK("a:b", "s", "f"));
}

test "cache keys are injective — no cross-identifier collision" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);
    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    // Same concatenation under the old ':' scheme, different identities.
    // "ab"+"c" vs "a"+"bc" — distinct tenants MUST get distinct FEKs even
    // when one primes the cache first.
    const fek1 = try manager.getFEK(.{ .tenant = "ab", .schema = "c", .field = "f", .version = 1 });
    const fek2 = try manager.getFEK(.{ .tenant = "a", .schema = "bc", .field = "f", .version = 1 });
    try testing.expect(!std.mem.eql(u8, &fek1, &fek2));
}

test "clearCache forces re-derivation" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    const ids = types.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "ssn",
        .version = 1,
    };

    // Prime the cache
    const fek1 = try manager.getFEK(ids);
    const stats1 = manager.cacheStats();
    try testing.expectEqual(@as(u64, 1), stats1.misses);

    // Clear cache
    manager.clearCache();

    // Next call should re-derive (cache miss) but produce same key
    const fek2 = try manager.getFEK(ids);
    const stats2 = manager.cacheStats();
    try testing.expectEqual(@as(u64, 2), stats2.misses);
    try testing.expectEqualSlices(u8, &fek1, &fek2);
}
