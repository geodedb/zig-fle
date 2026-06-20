// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const backend = @import("crypto_backend");
const observability = @import("observability");

/// Supported AEAD algorithms.
/// Wire values are stable for serialized envelopes and cross-project use.
pub const Alg = enum(u8) {
    aes256_gcm = 1,
    chacha20_poly1305 = 2,
    xchacha20_poly1305 = 3,

    /// Nonce size in bytes for this algorithm's AEAD primitive.
    /// NOTE: this describes the primitive itself, not EnvelopeV1 — the
    /// envelope carries a fixed 12-byte nonce, so the 24-byte value
    /// reported for `xchacha20_poly1305` never applies to envelopes.
    pub fn nonceSz(self: Alg) usize {
        return switch (self) {
            .aes256_gcm, .chacha20_poly1305 => 12,
            .xchacha20_poly1305 => 24,
        };
    }

    /// Human-readable algorithm name.
    pub fn name(self: Alg) []const u8 {
        return switch (self) {
            .aes256_gcm => "aes-256-gcm",
            .chacha20_poly1305 => "chacha20-poly1305",
            .xchacha20_poly1305 => "xchacha20-poly1305",
        };
    }
};

/// AEAD-related errors
pub const Error = error{
    InvalidAlg,
    InvalidKey,
    AEADAuthFailed,
    InvalidEnvelope,
    InvalidInput,
    OutOfMemory,
};

/// Envelope V1 format for encrypted fields
/// Format: [alg_id:u8][key_version:u16 LE][nonce:12][tag:16][ciphertext_len:u32 LE][ciphertext]
///
/// EnvelopeV1 is inherently a 12-byte-nonce format: it supports only
/// `aes256_gcm` and `chacha20_poly1305`. `xchacha20_poly1305` requires
/// 24-byte nonces and is rejected by `encryptField`/`decryptField` —
/// use `wrapKey32`/`unwrapKey32` for XChaCha20-Poly1305 key wrapping.
pub const EnvelopeV1 = struct {
    alg_id: u8,
    key_version: u16,
    nonce: [12]u8,
    tag: [16]u8,
    ciphertext: []u8,

    pub fn deinit(self: *EnvelopeV1, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
    }

    /// Serialize envelope to binary format
    pub fn serialize(self: EnvelopeV1, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 1 + 2 + 12 + 16 + 4 + self.ciphertext.len;
        var buffer = try allocator.alloc(u8, total_len);

        buffer[0] = self.alg_id;
        std.mem.writeInt(u16, buffer[1..3], self.key_version, .little);
        @memcpy(buffer[3..15], &self.nonce);
        @memcpy(buffer[15..31], &self.tag);
        std.mem.writeInt(u32, buffer[31..35], @intCast(self.ciphertext.len), .little);
        @memcpy(buffer[35..], self.ciphertext);

        return buffer;
    }

    /// Deserialize envelope from binary format
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !EnvelopeV1 {
        if (data.len < 35) return Error.InvalidEnvelope;

        const alg_id = data[0];
        const key_version = std.mem.readInt(u16, data[1..3], .little);
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, data[3..15]);
        var tag: [16]u8 = undefined;
        @memcpy(&tag, data[15..31]);
        const ciphertext_len = std.mem.readInt(u32, data[31..35], .little);

        if (ciphertext_len > data.len - 35) return Error.InvalidEnvelope;

        const ciphertext = try allocator.alloc(u8, ciphertext_len);
        @memcpy(ciphertext, data[35 .. 35 + ciphertext_len]);

        return EnvelopeV1{
            .alg_id = alg_id,
            .key_version = key_version,
            .nonce = nonce,
            .tag = tag,
            .ciphertext = ciphertext,
        };
    }
};

/// Construct Additional Authenticated Data (AAD) binding ciphertext to context.
/// Uses length-prefixed encoding to prevent injection: each field is preceded
/// by its length as a 4-byte little-endian u32. This is canonically unambiguous
/// regardless of field content.
/// Format: [len:u32 LE][tenant_id][len:u32 LE][schema][len:u32 LE][field][len:u32 LE][record_id][key_version:u16 LE]
pub fn makeAAD(
    allocator: std.mem.Allocator,
    tenant_id: []const u8,
    schema: []const u8,
    field: []const u8,
    record_id: []const u8,
    key_version: u16,
) ![]u8 {
    const total_len = 4 + tenant_id.len + 4 + schema.len + 4 + field.len + 4 + record_id.len + 2;
    var aad = try allocator.alloc(u8, total_len);

    var pos: usize = 0;
    inline for (.{ tenant_id, schema, field, record_id }) |s| {
        std.mem.writeInt(u32, aad[pos..][0..4], @intCast(s.len), .little);
        pos += 4;
        @memcpy(aad[pos .. pos + s.len], s);
        pos += s.len;
    }
    std.mem.writeInt(u16, aad[pos..][0..2], key_version, .little);

    return aad;
}

/// Maximum plaintext size for field encryption (64 KiB).
pub const max_plaintext_size: usize = 64 * 1024;

/// Encrypt field data with AEAD.
/// Nonces are always generated from the CSPRNG seam
/// (`backend.Csprng.bytes`; fallible — a draw failure is surfaced as
/// `Error.InvalidInput`, handled below at the nonce-draw site).
/// Only AES-256-GCM and ChaCha20-Poly1305 are supported through this API;
/// use `wrapKey32` for XChaCha20-Poly1305 key wrapping.
pub fn encryptField(
    allocator: std.mem.Allocator,
    alg: Alg,
    fek: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    key_version: u16,
) !EnvelopeV1 {
    // Span attrs: fle.algorithm only. The schema-level field name is
    // buried inside the opaque AAD byte slice at this layer and is
    // intentionally NOT propagated as `fle.field` here — the bulk path
    // populates it from `BulkField.field`. SECURITY: `fek`, `aad`,
    // `plaintext`, and `ciphertext` are NEVER included as attributes.
    var __obs_span = observability.startFleSpan("encrypt", "", alg.name());
    defer __obs_span.end(null);
    errdefer observability.endFleSpan(__obs_span, false);

    if (fek.len != 32) return Error.InvalidKey;
    if (plaintext.len > max_plaintext_size) return Error.InvalidInput;
    if (alg == .xchacha20_poly1305) {
        // XChaCha20 requires 24-byte nonces; not compatible with EnvelopeV1.
        // Use wrapKey32 or the raw XChaCha20Poly1305 primitive directly.
        // Validated BEFORE allocating so rejection costs no alloc/free
        // round-trip (mirrors decryptField).
        return Error.InvalidAlg;
    }

    // FIPS-approved selection: AES-256-GCM only under -Dfips=true.
    // ChaCha20-Poly1305 is not FIPS-approved (spec §5 ChaCha->AES-GCM);
    // reject it before allocating so rejection costs no alloc round-trip.
    if (backend.fips_enabled and alg == .chacha20_poly1305) {
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidAlg;
    }

    var nonce: [12]u8 = undefined;
    backend.Csprng.bytes(&nonce) catch {
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidInput;
    };

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    var tag: [16]u8 = undefined;

    switch (alg) {
        .aes256_gcm => {
            backend.Aead.seal(.aes_256_gcm, fek[0..32], &nonce, aad, plaintext, ciphertext, &tag) catch {
                observability.endFleSpan(__obs_span, false);
                return Error.InvalidInput;
            };
        },
        .chacha20_poly1305 => {
            if (backend.fips_enabled) unreachable; // rejected above under fips
            const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            ChaCha.encrypt(ciphertext, &tag, plaintext, aad, nonce, fek[0..32].*);
        },
        .xchacha20_poly1305 => unreachable, // rejected before allocation above
    }

    observability.endFleSpan(__obs_span, true);
    return EnvelopeV1{
        .alg_id = @intFromEnum(alg),
        .key_version = key_version,
        .nonce = nonce,
        .tag = tag,
        .ciphertext = ciphertext,
    };
}

/// Decrypt field data from envelope
pub fn decryptField(
    allocator: std.mem.Allocator,
    fek: []const u8,
    aad: []const u8,
    envelope: EnvelopeV1,
) ![]u8 {
    // Span attrs: only algorithm (resolved from envelope.alg_id below
    // when valid). Schema-level field name lives in opaque AAD; bulk
    // path overrides. SECURITY: `fek`, `aad`, `envelope.ciphertext`,
    // and resulting plaintext are NEVER attributes.
    const alg_name: []const u8 = if (envelope.alg_id >= 1 and envelope.alg_id <= 3)
        (@as(Alg, @enumFromInt(envelope.alg_id))).name()
    else
        "";
    var __obs_span = observability.startFleSpan("decrypt", "", alg_name);
    defer __obs_span.end(null);
    errdefer observability.endFleSpan(__obs_span, false);

    if (fek.len != 32) return Error.InvalidKey;

    // Resolve and validate the algorithm BEFORE allocating: rejecting a
    // corrupted alg_id must not cost an alloc/free round-trip.
    const alg: Alg = inline for (@typeInfo(Alg).@"enum".fields) |f| {
        if (envelope.alg_id == f.value) break @enumFromInt(f.value);
    } else {
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidAlg;
    };
    if (alg == .xchacha20_poly1305) {
        // XChaCha20 uses 24-byte nonces; not compatible with EnvelopeV1 (12-byte nonce).
        // Use unwrapKey32 for key unwrapping or the raw primitive directly.
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidAlg;
    }

    const plaintext = try allocator.alloc(u8, envelope.ciphertext.len);
    // Single point of cleanup: ANY error return past this allocation —
    // including the AEAD auth failures below and any future fallible
    // step — scrubs and frees the buffer exactly once. Failure paths
    // below return errors and rely on this; they must NOT free directly.
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    switch (alg) {
        .aes256_gcm => {
            backend.Aead.open(.aes_256_gcm, fek[0..32], &envelope.nonce, aad, envelope.ciphertext, &envelope.tag, plaintext) catch |err| switch (err) {
                // AuthFailed -> generic AEADAuthFailed (no decryption oracle).
                // Unsupported/OpensslFailure also collapse to AEADAuthFailed
                // so callers learn nothing beyond "decryption failed".
                error.AuthFailed, error.Unsupported, error.OpensslFailure => {
                    observability.endFleSpan(__obs_span, false);
                    return Error.AEADAuthFailed;
                },
            };
        },
        .chacha20_poly1305 => {
            if (backend.fips_enabled) {
                observability.endFleSpan(__obs_span, false);
                return Error.InvalidAlg;
            }
            const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            ChaCha.decrypt(plaintext, envelope.ciphertext, envelope.tag, aad, envelope.nonce, fek[0..32].*) catch |err| switch (err) {
                error.AuthenticationFailed => {
                    observability.endFleSpan(__obs_span, false);
                    return Error.AEADAuthFailed;
                },
            };
        },
        .xchacha20_poly1305 => unreachable, // rejected above
    }

    observability.endFleSpan(__obs_span, true);
    return plaintext;
}

// ============================================================================
// Standalone key wrapping (stack-only, no allocator)
//
// XChaCha20-Poly1305 is NOT FIPS-approved. Under -Dfips=true the
// `wrapKey32`/`unwrapKey32` helpers are compiled out (the `key_wrap`
// namespace becomes empty and the file-scope re-exports are absent);
// callers needing FIPS key wrapping use KeyManager.wrapKey/unwrapKey
// (AES-256-GCM via encryptField/decryptField).
//
// NOTE (deviation from plan's `usingnamespace`): Zig 0.16 REMOVED
// `pub usingnamespace`, so the FIPS-gating is implemented via a
// comptime-selected namespace struct (`key_wrap`) whose members are
// genuinely absent under fips. `@hasDecl(@This(), "wrapKey32")` cannot
// be made false for a top-level `pub const` (a void-bound decl still
// reports present), so presence is asserted on the `key_wrap` namespace
// instead — the functions are still fully compiled out under fips.
// ============================================================================

/// Size of a wrapped 32-byte key: nonce(24) + tag(16) + ciphertext(32) = 72 bytes.
pub const wrapped_key_size: usize = 24 + 16 + 32;

/// XChaCha20-Poly1305 key-wrap namespace. Empty under -Dfips=true
/// (XChaCha is non-FIPS); under -Dfips=false it exposes
/// `wrapKey32`/`unwrapKey32`.
pub const key_wrap = if (backend.fips_enabled) struct {} else struct {
    /// Wrap a 32-byte key using XChaCha20-Poly1305. (non-FIPS only)
    /// Returns a fixed 72-byte array: nonce(24) || tag(16) || ciphertext(32).
    /// Stack-only operation — no allocator required.
    pub fn wrapKey32(key: [32]u8, wrapping_key: [32]u8) [wrapped_key_size]u8 {
        const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
        var result: [wrapped_key_size]u8 = undefined;

        var nonce: [24]u8 = undefined;
        backend.Csprng.bytes(&nonce) catch @panic("CSPRNG failure");
        @memcpy(result[0..24], &nonce);

        var tag: [16]u8 = undefined;
        XChaCha.encrypt(result[40..72], &tag, &key, "", nonce, wrapping_key);
        @memcpy(result[24..40], &tag);

        return result;
    }

    /// Unwrap a 32-byte key from a 72-byte wrapped blob. (non-FIPS only)
    /// Input format: nonce(24) || tag(16) || ciphertext(32).
    /// Stack-only operation — no allocator required.
    pub fn unwrapKey32(wrapped: *const [wrapped_key_size]u8, wrapping_key: [32]u8) ![32]u8 {
        const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

        const nonce = wrapped[0..24].*;
        const tag = wrapped[24..40].*;
        const ciphertext = wrapped[40..72];

        var plaintext: [32]u8 = undefined;
        XChaCha.decrypt(&plaintext, ciphertext, tag, "", nonce, wrapping_key) catch {
            std.crypto.secureZero(u8, &plaintext);
            return Error.AEADAuthFailed;
        };

        return plaintext;
    }
};

test "AEAD round-trip with AES-256-GCM" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);

    const plaintext = "sensitive data";
    const aad = try makeAAD(allocator, "tenant1", "Person", "ssn", "node123", 1);
    defer allocator.free(aad);

    var envelope = try encryptField(allocator, .aes256_gcm, &fek, aad, plaintext, 1);
    defer envelope.deinit(allocator);

    const decrypted = try decryptField(allocator, &fek, aad, envelope);
    defer {
        std.crypto.secureZero(u8, decrypted);
        allocator.free(decrypted);
    }

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "AES-256-GCM round-trip works in both fips modes" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);

    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    var env = try encryptField(allocator, .aes256_gcm, &fek, aad, "payload", 1);
    defer env.deinit(allocator);
    const pt = try decryptField(allocator, &fek, aad, env);
    defer {
        std.crypto.secureZero(u8, pt);
        allocator.free(pt);
    }
    try testing.expectEqualStrings("payload", pt);
}

test "ChaCha20-Poly1305 is rejected under -Dfips=true, allowed otherwise" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);
    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    if (backend.fips_enabled) {
        // Under FIPS, ChaCha is not approved: encryptField must reject it.
        try testing.expectError(Error.InvalidAlg, encryptField(allocator, .chacha20_poly1305, &fek, aad, "x", 1));
    } else {
        var env = try encryptField(allocator, .chacha20_poly1305, &fek, aad, "x", 1);
        defer env.deinit(allocator);
        const pt = try decryptField(allocator, &fek, aad, env);
        defer {
            std.crypto.secureZero(u8, pt);
            allocator.free(pt);
        }
        try testing.expectEqualStrings("x", pt);
    }
}

test "AEAD auth fails with wrong AAD" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);

    const plaintext = "sensitive data";
    const aad1 = try makeAAD(allocator, "tenant1", "Person", "ssn", "node123", 1);
    defer allocator.free(aad1);
    const aad2 = try makeAAD(allocator, "tenant2", "Person", "ssn", "node123", 1);
    defer allocator.free(aad2);

    var envelope = try encryptField(allocator, .aes256_gcm, &fek, aad1, plaintext, 1);
    defer envelope.deinit(allocator);

    const result = decryptField(allocator, &fek, aad2, envelope);
    try testing.expectError(Error.AEADAuthFailed, result);
}

test "Envelope serialization round-trip" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var envelope = EnvelopeV1{
        .alg_id = 1,
        .key_version = 2,
        .nonce = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        .tag = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .ciphertext = try allocator.dupe(u8, "abcd"),
    };
    defer envelope.deinit(allocator);

    const serialized = try envelope.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try EnvelopeV1.deserialize(allocator, serialized);
    defer deserialized.deinit(allocator);

    try testing.expectEqual(envelope.alg_id, deserialized.alg_id);
    try testing.expectEqual(envelope.key_version, deserialized.key_version);
    try testing.expectEqualSlices(u8, &envelope.nonce, &deserialized.nonce);
    try testing.expectEqualSlices(u8, &envelope.tag, &deserialized.tag);
    try testing.expectEqualSlices(u8, envelope.ciphertext, deserialized.ciphertext);
}

test "key-wrap surface is FIPS-aware" {
    if (backend.fips_enabled) {
        // XChaCha20-Poly1305 wrapKey32 is compiled out under FIPS.
        try std.testing.expect(!@hasDecl(key_wrap, "wrapKey32"));
        try std.testing.expect(!@hasDecl(key_wrap, "unwrapKey32"));
    } else {
        var key: [32]u8 = undefined;
        var wk: [32]u8 = undefined;
        try backend.Csprng.bytes(&key);
        try backend.Csprng.bytes(&wk);
        const wrapped = key_wrap.wrapKey32(key, wk);
        const unwrapped = try key_wrap.unwrapKey32(&wrapped, wk);
        try std.testing.expectEqualSlices(u8, &key, &unwrapped);
    }
}

test "wrapKey32/unwrapKey32 round-trip" {
    if (backend.fips_enabled) return error.SkipZigTest;
    var key: [32]u8 = undefined;
    try backend.Csprng.bytes(&key);
    var wrapping_key: [32]u8 = undefined;
    try backend.Csprng.bytes(&wrapping_key);

    const wrapped = key_wrap.wrapKey32(key, wrapping_key);
    const unwrapped = try key_wrap.unwrapKey32(&wrapped, wrapping_key);

    try std.testing.expectEqualSlices(u8, &key, &unwrapped);
}

test "unwrapKey32 rejects wrong wrapping key" {
    if (backend.fips_enabled) return error.SkipZigTest;
    var key: [32]u8 = undefined;
    try backend.Csprng.bytes(&key);
    var wrapping_key: [32]u8 = undefined;
    try backend.Csprng.bytes(&wrapping_key);

    const wrapped = key_wrap.wrapKey32(key, wrapping_key);

    var wrong_key: [32]u8 = undefined;
    try backend.Csprng.bytes(&wrong_key);

    const result = key_wrap.unwrapKey32(&wrapped, wrong_key);
    try std.testing.expectError(Error.AEADAuthFailed, result);
}

test "Alg nonceSz and name" {
    try std.testing.expectEqual(@as(usize, 12), Alg.aes256_gcm.nonceSz());
    try std.testing.expectEqual(@as(usize, 12), Alg.chacha20_poly1305.nonceSz());
    try std.testing.expectEqual(@as(usize, 24), Alg.xchacha20_poly1305.nonceSz());
    try std.testing.expectEqualStrings("aes-256-gcm", Alg.aes256_gcm.name());
    try std.testing.expectEqualStrings("xchacha20-poly1305", Alg.xchacha20_poly1305.name());
}

test "encryptField rejects xchacha20_poly1305" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);

    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    const result = encryptField(allocator, .xchacha20_poly1305, &fek, aad, "data", 1);
    try testing.expectError(Error.InvalidAlg, result);
}

test "makeAAD length-prefixed format" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const aad = try makeAAD(allocator, "t1", "Person", "ssn", "r1", 42);
    defer allocator.free(aad);

    // Verify length-prefixed format: [len:u32 LE][data] per field + [version:u16 LE]
    var pos: usize = 0;

    // tenant: "t1" (len=2)
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("t1", aad[pos .. pos + 2]);
    pos += 2;

    // schema: "Person" (len=6)
    try testing.expectEqual(@as(u32, 6), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("Person", aad[pos .. pos + 6]);
    pos += 6;

    // field: "ssn" (len=3)
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("ssn", aad[pos .. pos + 3]);
    pos += 3;

    // record_id: "r1" (len=2)
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("r1", aad[pos .. pos + 2]);
    pos += 2;

    // key_version: 42 as u16 LE
    try testing.expectEqual(@as(u16, 42), std.mem.readInt(u16, aad[pos..][0..2], .little));
    pos += 2;

    try testing.expectEqual(aad.len, pos);
}

test "deserialize rejects overflow-length envelope without panicking" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Valid 35-byte header, ciphertext_len = 0xFFFFFFFF (overflows 35 + len in u32)
    var data: [40]u8 = @splat(0);
    data[0] = 1; // alg_id
    std.mem.writeInt(u32, data[31..35], 0xFFFF_FFFF, .little);
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &data));
}

test "deserialize rejects truncated and boundary-length envelopes" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Shorter than header
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &[_]u8{0} ** 34));

    // Header claims 5 ciphertext bytes but only 4 present
    var data: [39]u8 = @splat(0);
    std.mem.writeInt(u32, data[31..35], 5, .little);
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &data));

    // Exact boundary: claims 4, has 4 — must succeed
    var ok_data: [39]u8 = @splat(0);
    ok_data[0] = 1;
    std.mem.writeInt(u32, ok_data[31..35], 4, .little);
    var env = try EnvelopeV1.deserialize(allocator, &ok_data);
    defer env.deinit(allocator);
    try testing.expectEqual(@as(usize, 4), env.ciphertext.len);
}

test "fuzz EnvelopeV1.deserialize never crashes on arbitrary input" {
    // Adapted to the installed Zig 0.16 fuzz API: testOne receives a
    // *std.testing.Smith input generator rather than a raw byte slice.
    const Ctx = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var gpa: std.heap.DebugAllocator(.{}) = .init;
            defer _ = gpa.deinit();
            const allocator = gpa.allocator();

            // Arbitrary length (0..256) and arbitrary content; covers
            // sub-header, boundary, and over-claimed-length inputs.
            var buf: [256]u8 = undefined;
            const len = smith.slice(&buf);
            var env = EnvelopeV1.deserialize(allocator, buf[0..len]) catch return;
            env.deinit(allocator);
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}

test "encryptField produces unique nonces across calls" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);

    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    // 64 encryptions of the same plaintext under the same key must
    // yield 64 distinct nonces (random-nonce contract).
    var seen = std.AutoHashMap([12]u8, void).init(allocator);
    defer seen.deinit();
    for (0..64) |_| {
        var env = try encryptField(allocator, .aes256_gcm, &fek, aad, "x", 1);
        defer env.deinit(allocator);
        const gop = try seen.getOrPut(env.nonce);
        try testing.expect(!gop.found_existing);
    }
}
