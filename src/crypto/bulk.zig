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
    _ = allocator;
    _ = pool;
    _ = fields;
    _ = out_results;
    _ = options;
    @panic("encryptFieldsBulk: not implemented");
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
