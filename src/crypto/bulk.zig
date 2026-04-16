// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Bulk field encryption API.
//!
//! Amortizes per-field dispatch overhead by chunking fields across a
//! caller-provided `thread_pool.ThreadPool`. Partial-success error
//! semantics: per-field errors are reported in the results slice; the
//! function itself returns `error.OutOfMemory` only for setup-allocation
//! failures.
//!
//! Callers that do not want a pool may pass `pool = null`; the batch
//! then runs serially in the caller thread.

const std = @import("std");
const tp = @import("thread_pool");

const aead = @import("aead.zig");

pub const Alg = aead.Alg;
pub const EnvelopeV1 = aead.EnvelopeV1;
pub const Error = aead.Error;

/// Default number of fields per worker task. See plan Background §3:
/// AES-NI AES-GCM at GB/s means sub-microsecond per-field submit overhead
/// dominates unless we chunk.
pub const default_chunk_size: usize = 1024;

/// One field's worth of input for a bulk encrypt call.
///
/// All slice inputs are borrowed — the caller must keep them alive until
/// `encryptFieldsBulk` returns.
pub const BulkField = struct {
    fek: []const u8, // 32 bytes; InvalidKey if != 32
    alg: Alg,
    tenant_id: []const u8,
    schema: []const u8,
    field: []const u8,
    record_id: []const u8,
    key_version: u16,
    plaintext: []const u8, // must be <= aead.max_plaintext_size
};

/// One field's worth of input for a bulk decrypt call.
pub const BulkDecryptField = struct {
    fek: []const u8, // 32 bytes
    tenant_id: []const u8,
    schema: []const u8,
    field: []const u8,
    record_id: []const u8,
    key_version: u16,
    envelope: EnvelopeV1, // by value; ciphertext slice is borrowed
};

/// Per-field result. `ok` carries an owned `EnvelopeV1` (caller frees via
/// `EnvelopeV1.deinit(allocator)` — the same allocator passed to
/// `encryptFieldsBulk`). `err` carries the error that terminated this
/// field's processing; no allocation is associated with the error arm.
pub const BulkResult = union(enum) {
    ok: EnvelopeV1,
    err: Error,
};

/// Per-field decrypt result. `ok.plaintext` is owned by the caller (same
/// allocator). Callers should `std.crypto.secureZero` before `free`.
pub const BulkDecryptResult = union(enum) {
    ok: struct { plaintext: []u8 },
    err: Error,
};

/// Tunables for a bulk call.
pub const BulkOptions = struct {
    /// Fields per submitted task. 0 → use `default_chunk_size`.
    chunk_size: usize = 0,
    /// Task lane for submitted chunks. Default `.default` is correct
    /// for CPU-bound crypto work.
    lane: tp.TaskLane = .default,
};

// ============================================================================
// Stubs — Task 3 fills in
// ============================================================================

/// Encrypt `fields.len` fields in bulk. `out_results` MUST be the same
/// length as `fields`. Returns the count of `BulkResult.ok` entries.
///
/// Partial-success semantics: an error encrypting one field never fails
/// the call. Only setup-level allocation failures (e.g. task-context
/// scratch allocation) bubble up as `error.OutOfMemory`.
pub fn encryptFieldsBulk(
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const BulkField,
    out_results: []BulkResult,
    options: BulkOptions,
) !usize {
    std.debug.assert(out_results.len == fields.len);
    _ = options; // serial path ignores chunk_size/lane
    _ = pool; // Task 4 wires pool; serial ignores it

    var ok_count: usize = 0;
    for (fields, 0..) |f, idx| {
        out_results[idx] = encryptOne(allocator, f);
        if (out_results[idx] == .ok) ok_count += 1;
    }
    return ok_count;
}

/// Encrypt a single field. Returns a `BulkResult` so the caller can
/// write it directly into the output slice without an intermediate
/// error-union dance.
fn encryptOne(allocator: std.mem.Allocator, f: BulkField) BulkResult {
    const aad = aead.makeAAD(
        allocator,
        f.tenant_id,
        f.schema,
        f.field,
        f.record_id,
        f.key_version,
    ) catch |e| return .{ .err = toFleError(e) };
    defer allocator.free(aad);

    const env = aead.encryptField(
        allocator,
        f.alg,
        f.fek,
        aad,
        f.plaintext,
        f.key_version,
    ) catch |e| return .{ .err = toFleError(e) };

    return .{ .ok = env };
}

fn toFleError(e: anyerror) Error {
    return switch (e) {
        error.InvalidKey => Error.InvalidKey,
        error.InvalidAlg => Error.InvalidAlg,
        error.InvalidInput => Error.InvalidInput,
        error.InvalidEnvelope => Error.InvalidEnvelope,
        error.AEADAuthFailed => Error.AEADAuthFailed,
        error.NonceReuse => Error.NonceReuse,
        error.OutOfMemory => Error.OutOfMemory,
        error.SearchNotPermitted => Error.SearchNotPermitted,
        else => Error.InvalidInput, // defensive catch-all
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

test "encryptFieldsBulk serial: round-trip across 3 fields" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    _ = std.os.linux.getrandom(@ptrCast(&fek), @sizeOf(@TypeOf(fek)), 0);

    const fields = [_]BulkField{
        .{ .fek = &fek, .alg = .aes256_gcm, .tenant_id = "t1", .schema = "Person", .field = "ssn", .record_id = "r1", .key_version = 1, .plaintext = "111-11-1111" },
        .{ .fek = &fek, .alg = .aes256_gcm, .tenant_id = "t1", .schema = "Person", .field = "email", .record_id = "r1", .key_version = 1, .plaintext = "a@b.com" },
        .{ .fek = &fek, .alg = .chacha20_poly1305, .tenant_id = "t1", .schema = "Person", .field = "phone", .record_id = "r1", .key_version = 1, .plaintext = "555-0100" },
    };

    var results = [_]BulkResult{.{ .err = Error.InvalidAlg }} ** 3;
    const ok_count = try encryptFieldsBulk(allocator, null, &fields, &results, .{});
    defer for (&results) |*r| switch (r.*) {
        .ok => |*env| env.deinit(allocator),
        .err => {},
    };

    try testing.expectEqual(@as(usize, 3), ok_count);
    for (results) |r| try testing.expect(r == .ok);
    try testing.expectEqual(@as(u8, @intFromEnum(Alg.aes256_gcm)), results[0].ok.alg_id);
    try testing.expectEqual(@as(u8, @intFromEnum(Alg.chacha20_poly1305)), results[2].ok.alg_id);
}

test "encryptFieldsBulk serial: partial success — oversized plaintext errors one slot" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    _ = std.os.linux.getrandom(@ptrCast(&fek), @sizeOf(@TypeOf(fek)), 0);

    // Build an intentionally oversized plaintext (> max_plaintext_size).
    const oversized = try allocator.alloc(u8, aead.max_plaintext_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');

    const fields = [_]BulkField{
        .{ .fek = &fek, .alg = .aes256_gcm, .tenant_id = "t", .schema = "S", .field = "good", .record_id = "r", .key_version = 1, .plaintext = "ok" },
        .{ .fek = &fek, .alg = .aes256_gcm, .tenant_id = "t", .schema = "S", .field = "bad", .record_id = "r", .key_version = 1, .plaintext = oversized },
        .{ .fek = &fek, .alg = .aes256_gcm, .tenant_id = "t", .schema = "S", .field = "good2", .record_id = "r", .key_version = 1, .plaintext = "ok2" },
    };

    var results = [_]BulkResult{.{ .err = Error.InvalidAlg }} ** 3;
    const ok_count = try encryptFieldsBulk(allocator, null, &fields, &results, .{});
    defer for (&results) |*r| switch (r.*) {
        .ok => |*env| env.deinit(allocator),
        .err => {},
    };

    try testing.expectEqual(@as(usize, 2), ok_count);
    try testing.expect(results[0] == .ok);
    try testing.expect(results[1] == .err);
    try testing.expectEqual(Error.InvalidInput, results[1].err);
    try testing.expect(results[2] == .ok);
}

/// Decrypt `fields.len` envelopes in bulk. `out_results` MUST be the
/// same length as `fields`. Returns the count of `BulkDecryptResult.ok`.
pub fn decryptFieldsBulk(
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const BulkDecryptField,
    out_results: []BulkDecryptResult,
    options: BulkOptions,
) !usize {
    _ = allocator;
    _ = pool;
    _ = fields;
    _ = out_results;
    _ = options;
    @panic("decryptFieldsBulk: not implemented");
}
