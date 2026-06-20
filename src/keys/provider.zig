// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

/// Pluggable master key source.
///
/// Implementations can load the master key from any backend:
/// environment variable, KMS, HSM, file, or a static value.
///
/// Use with `KeyManager.initWithProvider` to decouple key sourcing
/// from key management.
pub const MasterKeyProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Retrieve the 32-byte master key.
        getMasterKey: *const fn (ptr: *anyopaque) GetKeyError![32]u8,
        /// Release any resources held by the provider.
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub const GetKeyError = error{
        MasterKeyRequired,
        MasterKeyUnavailable,
        OutOfMemory,
    };

    pub fn getMasterKey(self: MasterKeyProvider) GetKeyError![32]u8 {
        return self.vtable.getMasterKey(self.ptr);
    }

    pub fn deinit(self: MasterKeyProvider) void {
        self.vtable.deinit(self.ptr);
    }
};

/// A provider that holds a static master key value.
/// Useful for testing and for callers that have already sourced the key.
pub const StaticKeyProvider = struct {
    key: [32]u8,

    pub fn init(key: [32]u8) StaticKeyProvider {
        return .{ .key = key };
    }

    pub fn provider(self: *StaticKeyProvider) MasterKeyProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn getMasterKey(ptr: *anyopaque) MasterKeyProvider.GetKeyError![32]u8 {
        const self: *StaticKeyProvider = @ptrCast(@alignCast(ptr));
        return self.key;
    }

    fn deinitFn(ptr: *anyopaque) void {
        const self: *StaticKeyProvider = @ptrCast(@alignCast(ptr));
        std.crypto.secureZero(u8, &self.key);
    }

    const vtable = MasterKeyProvider.VTable{
        .getMasterKey = &getMasterKey,
        .deinit = &deinitFn,
    };
};

/// Parse master-key material. Accepted formats (exact, no truncation):
///   - exactly 32 raw bytes, or
///   - exactly 64 hex characters (decoded to 32 bytes).
/// Anything else is rejected — silent truncation of longer values would
/// quietly reduce effective key entropy.
pub fn parseKeyMaterial(value: []const u8) MasterKeyProvider.GetKeyError![32]u8 {
    var key: [32]u8 = undefined;
    if (value.len == 64) {
        for (0..32) |i| {
            const hi = std.fmt.charToDigit(value[i * 2], 16) catch {
                std.crypto.secureZero(u8, &key);
                return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
            };
            const lo = std.fmt.charToDigit(value[i * 2 + 1], 16) catch {
                std.crypto.secureZero(u8, &key);
                return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
            };
            key[i] = @as(u8, hi) * 16 + @as(u8, lo);
        }
        return key;
    }
    if (value.len == 32) {
        @memcpy(&key, value);
        return key;
    }
    return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
}

/// A provider that reads the master key from an environment variable.
/// The env var value must be EXACTLY 32 raw bytes or EXACTLY 64 hex
/// characters (decoded to 32 bytes). Any other length — including longer
/// values that older versions silently truncated — is rejected with
/// `MasterKeyUnavailable` to prevent weak or entropy-reduced key material.
pub const EnvKeyProvider = struct {
    allocator: std.mem.Allocator,
    env_var: []const u8,

    pub fn init(allocator: std.mem.Allocator, env_var: []const u8) EnvKeyProvider {
        return .{ .allocator = allocator, .env_var = env_var };
    }

    pub fn provider(self: *EnvKeyProvider) MasterKeyProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn getMasterKey(ptr: *anyopaque) MasterKeyProvider.GetKeyError![32]u8 {
        const self: *EnvKeyProvider = @ptrCast(@alignCast(ptr));
        const env_val = std.process.getEnvVarOwned(self.allocator, self.env_var) catch {
            return MasterKeyProvider.GetKeyError.MasterKeyRequired;
        };
        defer {
            // Securely zero the env var copy before freeing
            @memset(@as([]volatile u8, @volatileCast(env_val)), 0);
            self.allocator.free(env_val);
        }

        return parseKeyMaterial(env_val);
    }

    fn deinitFn(_: *anyopaque) void {}

    const vtable = MasterKeyProvider.VTable{
        .getMasterKey = &getMasterKey,
        .deinit = &deinitFn,
    };
};

test "parseKeyMaterial accepts exactly 32 raw bytes" {
    const raw = [_]u8{0xAB} ** 32;
    const key = try parseKeyMaterial(&raw);
    try std.testing.expectEqualSlices(u8, &raw, &key);
}

test "parseKeyMaterial accepts exactly 64 hex chars" {
    const hex = "00112233445566778899aabbccddeeff" ++ "00112233445566778899aabbccddeeff";
    const key = try parseKeyMaterial(hex);
    try std.testing.expectEqual(@as(u8, 0x00), key[0]);
    try std.testing.expectEqual(@as(u8, 0xff), key[15]);
}

test "parseKeyMaterial rejects truncatable / short / bad-hex values" {
    const testing = std.testing;
    const E = MasterKeyProvider.GetKeyError;
    // 33 raw bytes: previously silently truncated — now rejected.
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 33));
    // 48 bytes: rejected (neither 32 raw nor 64 hex).
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 48));
    // 31 bytes: too short.
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 31));
    // 64 chars with an invalid nibble.
    const bad_hex = "zz112233445566778899aabbccddeeff" ++ "00112233445566778899aabbccddeeff";
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(bad_hex));
    // >64 bytes: also rejected (not a valid 64-hex string, no truncation).
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 65));
}

test "StaticKeyProvider round-trip" {
    var key: [32]u8 = undefined;
    // fips-exempt: non-security — test/example fixture key generation
    std.Io.Threaded.global_single_threaded.io().random(&key);

    var static_prov = StaticKeyProvider.init(key);
    const prov = static_prov.provider();

    const retrieved = try prov.getMasterKey();
    try std.testing.expectEqualSlices(u8, &key, &retrieved);
}
