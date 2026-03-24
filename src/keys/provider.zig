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

/// A provider that reads the master key from an environment variable.
/// The env var value must be exactly 32 raw bytes or 64 hex-encoded bytes.
/// Values shorter than 32 bytes are rejected to prevent weak key material.
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

        var key: [32]u8 = undefined;

        if (env_val.len == 64) {
            // Try hex decoding: 64 hex chars = 32 bytes.
            // All-or-nothing: if any nibble is invalid, reject entirely.
            for (0..32) |i| {
                const hi = std.fmt.charToDigit(env_val[i * 2], 16) catch {
                    return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
                };
                const lo = std.fmt.charToDigit(env_val[i * 2 + 1], 16) catch {
                    return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
                };
                key[i] = @as(u8, hi) * 16 + @as(u8, lo);
            }
            return key;
        }

        if (env_val.len >= 32) {
            @memcpy(&key, env_val[0..32]);
            return key;
        }

        // Reject values shorter than 32 bytes — no SHA-256 fallback
        return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
    }

    fn deinitFn(_: *anyopaque) void {}

    const vtable = MasterKeyProvider.VTable{
        .getMasterKey = &getMasterKey,
        .deinit = &deinitFn,
    };
};

test "StaticKeyProvider round-trip" {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var static_prov = StaticKeyProvider.init(key);
    const prov = static_prov.provider();

    const retrieved = try prov.getMasterKey();
    try std.testing.expectEqualSlices(u8, &key, &retrieved);
}
