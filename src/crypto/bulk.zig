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
const observability = @import("observability");

pub const Alg = aead.Alg;
pub const EnvelopeV1 = aead.EnvelopeV1;
pub const Error = aead.Error;

/// Default number of fields per worker task. See plan Background §3:
/// AES-NI AES-GCM at GB/s means sub-microsecond per-field submit overhead
/// dominates unless we chunk.
pub const default_chunk_size: usize = 4096;

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
    // ONE span per bulk call (not per field) per the otel rollout
    // spec. Per-field schema names + algorithms live on each
    // BulkField and are intentionally NOT aggregated as attributes
    // here to avoid cardinality blow-up. SECURITY: per-field `fek`,
    // `plaintext`, `aad`, `record_id`, `tenant_id`, `schema`, and
    // `field` are NEVER attached.
    var __obs_span = observability.startFleSpan("bulk_encrypt", "", "");
    defer __obs_span.end(null);
    errdefer observability.endFleSpan(__obs_span, false);

    std.debug.assert(out_results.len == fields.len);
    if (fields.len == 0) {
        observability.endFleSpan(__obs_span, true);
        return 0;
    }

    // Serial fallback.
    if (pool == null or fields.len == 1) {
        var ok_count: usize = 0;
        for (fields, 0..) |f, idx| {
            out_results[idx] = encryptOne(allocator, f);
            if (out_results[idx] == .ok) ok_count += 1;
        }
        observability.endFleSpan(__obs_span, true);
        return ok_count;
    }

    const chunk_size = if (options.chunk_size == 0) default_chunk_size else options.chunk_size;
    const p = pool.?;

    const n_chunks = (fields.len + chunk_size - 1) / chunk_size;
    const ctxs = try allocator.alloc(ChunkCtx, n_chunks);
    defer allocator.free(ctxs);

    var wg = p.waitGroup();

    // Pre-populate chunk contexts before submission.
    var i: usize = 0;
    var ci: usize = 0;
    while (i < fields.len) : (ci += 1) {
        const end = @min(i + chunk_size, fields.len);
        ctxs[ci] = .{
            .allocator = allocator,
            .fields = fields[i..end],
            .out_slice = out_results[i..end],
            .wg = &wg,
        };
        i = end;
    }

    // WaitGroup.add(n_chunks) BEFORE any submission — prevents a fast-finishing
    // task from calling done() before add() runs (underflow / premature unblock).
    wg.add(@intCast(n_chunks));

    // Submit each chunk. On submit failure, run remaining chunks inline so that
    // partial-success semantics are preserved and wg.done() is always called.
    for (ctxs, 0..) |*c, k| {
        _ = p.submit(encryptChunk, c, .{
            .lane = options.lane,
        }) catch {
            // Run this chunk and all remaining chunks inline.
            for (ctxs[k..]) |*rest| {
                encryptChunkInline(rest);
                rest.wg.done();
            }
            break;
        };
    }

    wg.wait();

    var ok_count: usize = 0;
    for (out_results) |r| if (r == .ok) {
        ok_count += 1;
    };
    observability.endFleSpan(__obs_span, true);
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

const ChunkCtx = struct {
    allocator: std.mem.Allocator,
    fields: []const BulkField,
    out_slice: []BulkResult,
    wg: *tp.WaitGroup,
};

fn encryptChunk(ctx_: *anyopaque, _: *tp.TaskContext) void {
    const c: *ChunkCtx = @ptrCast(@alignCast(ctx_));
    encryptChunkInline(c);
    c.wg.done();
}

fn encryptChunkInline(c: *ChunkCtx) void {
    // Arena scoped to this chunk — keeps per-field AAD allocations out of
    // the global allocator hot path. AAD lifetime: single encrypt call.
    var arena = std.heap.ArenaAllocator.init(c.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    for (c.fields, 0..) |f, idx| {
        const aad_bytes = aead.makeAAD(
            arena_alloc,
            f.tenant_id,
            f.schema,
            f.field,
            f.record_id,
            f.key_version,
        ) catch |e| {
            c.out_slice[idx] = .{ .err = toFleError(e) };
            continue;
        };

        const env = aead.encryptField(
            c.allocator, // envelope ciphertext outlives the chunk → global allocator
            f.alg,
            f.fek,
            aad_bytes,
            f.plaintext,
            f.key_version,
        ) catch |e| {
            c.out_slice[idx] = .{ .err = toFleError(e) };
            continue;
        };

        c.out_slice[idx] = .{ .ok = env };
    }
}

fn decryptOne(allocator: std.mem.Allocator, f: BulkDecryptField) BulkDecryptResult {
    const aad = aead.makeAAD(
        allocator,
        f.tenant_id,
        f.schema,
        f.field,
        f.record_id,
        f.key_version,
    ) catch |e| return .{ .err = toFleError(e) };
    defer allocator.free(aad);

    const pt = aead.decryptField(allocator, f.fek, aad, f.envelope) catch |e| {
        return .{ .err = toFleError(e) };
    };
    return .{ .ok = .{ .plaintext = pt } };
}

const DecryptChunkCtx = struct {
    allocator: std.mem.Allocator,
    fields: []const BulkDecryptField,
    out_slice: []BulkDecryptResult,
    wg: *tp.WaitGroup,
};

fn decryptChunk(ctx_: *anyopaque, _: *tp.TaskContext) void {
    const c: *DecryptChunkCtx = @ptrCast(@alignCast(ctx_));
    decryptChunkInline(c);
    c.wg.done();
}

fn decryptChunkInline(c: *DecryptChunkCtx) void {
    var arena = std.heap.ArenaAllocator.init(c.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    for (c.fields, 0..) |f, idx| {
        const aad = aead.makeAAD(
            arena_alloc,
            f.tenant_id,
            f.schema,
            f.field,
            f.record_id,
            f.key_version,
        ) catch |e| {
            c.out_slice[idx] = .{ .err = toFleError(e) };
            continue;
        };

        const pt = aead.decryptField(c.allocator, f.fek, aad, f.envelope) catch |e| {
            c.out_slice[idx] = .{ .err = toFleError(e) };
            continue;
        };
        c.out_slice[idx] = .{ .ok = .{ .plaintext = pt } };
    }
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
    std.Io.Threaded.global_single_threaded.io().random(&fek);

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
    std.Io.Threaded.global_single_threaded.io().random(&fek);

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

test "encryptFieldsBulk parallel: 10k fields across 4 workers" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 4 });
    defer {
        _ = pool.shutdown(.drain, 5 * std.time.ns_per_s) catch {};
        pool.deinit();
    }

    var fek: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&fek);

    const N = 10_000;
    const fields = try allocator.alloc(BulkField, N);
    defer allocator.free(fields);
    const pt_bufs = try allocator.alloc([]u8, N);
    defer {
        for (pt_bufs) |b| allocator.free(b);
        allocator.free(pt_bufs);
    }
    for (0..N) |i| {
        pt_bufs[i] = try std.fmt.allocPrint(allocator, "pt-{d}", .{i});
        fields[i] = .{
            .fek = &fek,
            .alg = .aes256_gcm,
            .tenant_id = "t",
            .schema = "S",
            .field = "f",
            .record_id = "r",
            .key_version = 1,
            .plaintext = pt_bufs[i],
        };
    }

    const results = try allocator.alloc(BulkResult, N);
    defer {
        for (results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(results);
    }

    const stats_before = pool.statsSnapshot();
    const ok_count = try encryptFieldsBulk(allocator, &pool, fields, results, .{ .chunk_size = 512 });
    const stats_after = pool.statsSnapshot();
    // N=10k / chunk_size=512 = ~20 chunks; expect at least that many submissions.
    try testing.expect(stats_after.submitted - stats_before.submitted >= 19);
    try testing.expectEqual(N, ok_count);

    // Spot-check: decrypt field 42 and 7777 round-trips.
    for ([_]usize{ 42, 7777 }) |idx| {
        const aad = try aead.makeAAD(allocator, "t", "S", "f", "r", 1);
        defer allocator.free(aad);
        const pt = try aead.decryptField(allocator, &fek, aad, results[idx].ok);
        defer {
            std.crypto.secureZero(u8, pt);
            allocator.free(pt);
        }
        try testing.expectEqualStrings(pt_bufs[idx], pt);
    }
}

test "decryptFieldsBulk: round-trip 10k envelopes through parallel encrypt + parallel decrypt" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 4 });
    defer {
        _ = pool.shutdown(.drain, 5 * std.time.ns_per_s) catch {};
        pool.deinit();
    }

    var fek: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&fek);

    const N = 10_000;
    const enc_fields = try allocator.alloc(BulkField, N);
    defer allocator.free(enc_fields);
    const pts = try allocator.alloc([]u8, N);
    defer {
        for (pts) |p| allocator.free(p);
        allocator.free(pts);
    }
    for (0..N) |i| {
        pts[i] = try std.fmt.allocPrint(allocator, "plaintext-{d}", .{i});
        enc_fields[i] = .{
            .fek = &fek,
            .alg = .aes256_gcm,
            .tenant_id = "t",
            .schema = "S",
            .field = "f",
            .record_id = "r",
            .key_version = 1,
            .plaintext = pts[i],
        };
    }

    const enc_results = try allocator.alloc(BulkResult, N);
    defer {
        for (enc_results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(enc_results);
    }
    _ = try encryptFieldsBulk(allocator, &pool, enc_fields, enc_results, .{ .chunk_size = 1024 });

    const dec_fields = try allocator.alloc(BulkDecryptField, N);
    defer allocator.free(dec_fields);
    for (0..N) |i| {
        dec_fields[i] = .{
            .fek = &fek,
            .tenant_id = "t",
            .schema = "S",
            .field = "f",
            .record_id = "r",
            .key_version = 1,
            .envelope = enc_results[i].ok,
        };
    }

    const dec_results = try allocator.alloc(BulkDecryptResult, N);
    defer {
        for (dec_results) |*r| switch (r.*) {
            .ok => |ok| {
                std.crypto.secureZero(u8, ok.plaintext);
                allocator.free(ok.plaintext);
            },
            .err => {},
        };
        allocator.free(dec_results);
    }
    const ok_dec = try decryptFieldsBulk(allocator, &pool, dec_fields, dec_results, .{ .chunk_size = 1024 });
    try testing.expectEqual(N, ok_dec);
    try testing.expectEqualStrings(pts[42], dec_results[42].ok.plaintext);
    try testing.expectEqualStrings(pts[9876], dec_results[9876].ok.plaintext);
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
    // ONE span per bulk call (not per field). Same security
    // invariants as encryptFieldsBulk: per-field `fek`, ciphertext,
    // tag, nonce, AAD, record_id, tenant_id, schema, and field are
    // NEVER attached.
    var __obs_span = observability.startFleSpan("bulk_decrypt", "", "");
    defer __obs_span.end(null);
    errdefer observability.endFleSpan(__obs_span, false);

    std.debug.assert(out_results.len == fields.len);
    if (fields.len == 0) {
        observability.endFleSpan(__obs_span, true);
        return 0;
    }

    if (pool == null or fields.len == 1) {
        var ok_count: usize = 0;
        for (fields, 0..) |f, idx| {
            out_results[idx] = decryptOne(allocator, f);
            if (out_results[idx] == .ok) ok_count += 1;
        }
        observability.endFleSpan(__obs_span, true);
        return ok_count;
    }

    const chunk_size = if (options.chunk_size == 0) default_chunk_size else options.chunk_size;
    const p = pool.?;
    const n_chunks = (fields.len + chunk_size - 1) / chunk_size;

    const ctxs = try allocator.alloc(DecryptChunkCtx, n_chunks);
    defer allocator.free(ctxs);

    var wg = p.waitGroup();

    var i: usize = 0;
    var ci: usize = 0;
    while (i < fields.len) : (ci += 1) {
        const end = @min(i + chunk_size, fields.len);
        ctxs[ci] = .{
            .allocator = allocator,
            .fields = fields[i..end],
            .out_slice = out_results[i..end],
            .wg = &wg,
        };
        i = end;
    }
    wg.add(@intCast(n_chunks));

    for (ctxs, 0..) |*c, k| {
        _ = p.submit(decryptChunk, c, .{ .lane = options.lane }) catch {
            // Partial-success: run remaining chunks inline, each manually
            // decrementing the WaitGroup.
            for (ctxs[k..]) |*rest| {
                decryptChunkInline(rest);
                rest.wg.done();
            }
            break;
        };
    }
    wg.wait();

    var ok_count: usize = 0;
    for (out_results) |r| if (r == .ok) {
        ok_count += 1;
    };
    observability.endFleSpan(__obs_span, true);
    return ok_count;
}
