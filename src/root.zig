// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # fle - Field-Level Encryption
//!
//! A portable Zig library for field-level encryption with searchable
//! blind indices and hierarchical key management.
//!
//! ## Features
//!
//! - AEAD envelope encryption (AES-256-GCM; ChaCha20-Poly1305 is
//!   non-FIPS and rejected/compiled out under `-Dfips=true`)
//! - HKDF-SHA256 hierarchical key derivation (TRK -> SK -> FEK/BIK)
//! - Blind-index HMAC for searchable encrypted fields
//! - Schema annotation parsing for encryption/search metadata
//! - Key rotation support with version tracking
//!
//! ## Thread Safety
//!
//! `KeyManager` and `BlindIndex` are **NOT** thread-safe. They use
//! `std.StringHashMap` internally which does not support concurrent access.
//! Callers must serialize access externally (e.g., with a mutex) if sharing
//! across threads. Stateless functions (`encryptField`, `decryptField`,
//! `hkdfSha256`, `wrapKey32`, `unwrapKey32`) are safe to call concurrently.
//!
//! For high-throughput workloads, see the `bulk` submodule
//! (`encryptFieldsBulk`, `decryptFieldsBulk`) which dispatches per-field
//! AEAD work across a caller-provided `thread_pool.ThreadPool` with
//! partial-success error semantics.
//!
//! The allocator passed to `encryptFieldsBulk`/`decryptFieldsBulk` MUST be
//! thread-safe when a pool is supplied — worker chunks allocate from it
//! concurrently. (`std.heap.smp_allocator`, `std.heap.page_allocator`, and
//! the default-config DebugAllocator are thread-safe; a bare
//! `ArenaAllocator` is not.)
//!
//! ## Key Lifetime & Rotation
//!
//! - FEKs use random 96-bit AEAD nonces. Per NIST SP 800-38D, rotate a FEK
//!   (via `KeyManager.rotateFEK`) well before 2^32 encryptions under the
//!   same key; plan rotation at or below ~2^28 encryptions per field-version
//!   for margin.
//! - The KeyManager FEK/BIK caches are unbounded and hold derived keys in
//!   process memory for the manager's lifetime. Call `clearCache()` after
//!   rotation events or on a residency schedule; `deinit` zeroizes all
//!   cached key material.
//!
//! ## Quick Start
//!
//! ```zig
//! const fle = @import("fle");
//!
//! // Create a key manager with an explicit master key
//! var master_key: [32]u8 = undefined;
//! std.Io.Threaded.global_single_threaded.io().random(&master_key);
//! var km = try fle.KeyManager.init(allocator, master_key);
//! defer km.deinit();
//!
//! // Derive a field encryption key
//! const fek = try km.getFEK(.{
//!     .tenant = "tenant1",
//!     .schema = "Person",
//!     .field = "ssn",
//!     .version = 1,
//! });
//!
//! // Encrypt a field value
//! const aad = try fle.aead.makeAAD(allocator, "tenant1", "Person", "ssn", "record1", 1);
//! defer allocator.free(aad);
//! var envelope = try fle.aead.encryptField(allocator, .aes256_gcm, &fek, aad, "123-45-6789", 1);
//! defer envelope.deinit(allocator);
//! ```

const std = @import("std");
const crypto_backend = @import("crypto_backend");

/// Library version
pub const version = "0.1.6";

// ============================================================================
// Submodule re-exports
// ============================================================================

/// AEAD envelope encryption (AES-256-GCM; ChaCha20-Poly1305 non-FIPS,
/// rejected under `-Dfips=true` — see docs/FIPS.md).
pub const aead = @import("crypto/aead.zig");

/// HKDF-SHA256 key derivation — general-purpose RFC 5869 implementation
/// and FLE-specific key hierarchy helpers (TRK/SK/FEK/BIK).
pub const hkdf = @import("crypto/hkdf.zig");

/// Blind-index HMAC helpers and normalization
pub const hmac = @import("crypto/hmac.zig");

/// Portable key metadata and value types
pub const key_types = @import("keys/types.zig");

/// Hierarchical key manager with caching and rotation
pub const key_manager = @import("keys/manager.zig");

/// Pluggable master key provider interface
pub const key_provider = @import("keys/provider.zig");

/// Searchable blind-index implementation
pub const blind_index = @import("index/blind_index.zig");

/// Schema annotation parsing and metadata
pub const annotations = @import("schema/annotations.zig");

/// Bulk encrypt/decrypt entry points (requires `thread_pool`).
pub const bulk = @import("crypto/bulk.zig");

/// otel observability seam. Surfaces `startFleSpan` / `endFleSpan` plus
/// the `enabled` flag. When `-Dwith_otel=false` (the default), every
/// helper collapses to a comptime no-op and the otel dependency is
/// never resolved. The public API is reachable as `fle.observability`.
pub const observability = @import("observability");

/// Bootstrap helper for the enabled build. Only registered as a build
/// import when `-Dwith_otel=true`; under the disabled build the
/// reference resolves to a placeholder empty struct so the public root
/// stays uniform.
pub const observability_init = if (observability.enabled)
    @import("observability_init")
else
    struct {};

// ============================================================================
// Convenience aliases for the most common public types
// ============================================================================

/// AEAD algorithm selector. AES-256-GCM is the only FIPS-approved envelope
/// algorithm; ChaCha20-Poly1305 and XChaCha20-Poly1305 (key wrap) are
/// non-FIPS and rejected/compiled out under `-Dfips=true` (see docs/FIPS.md).
pub const Alg = aead.Alg;
/// Serialized encrypted-field envelope (alg, key version, nonce, tag, ciphertext).
pub const EnvelopeV1 = aead.EnvelopeV1;

/// XChaCha20-Poly1305 key-wrap namespace (stack-only, no allocator).
/// XChaCha is NOT FIPS-approved: under -Dfips=true this namespace is
/// EMPTY (`wrapKey32`/`unwrapKey32` absent — use `KeyManager.wrapKey`/
/// `unwrapKey`, which are AES-256-GCM); under -Dfips=false it exposes
/// `key_wrap.wrapKey32`/`key_wrap.unwrapKey32`.
///
/// Zig 0.16 removed `pub usingnamespace`, so FIPS-absence is asserted on
/// this namespace (genuinely empty under fips) rather than via
/// `@hasDecl(fle, "wrapKey32")` — a top-level `pub const` always reports
/// present. The flat `wrapKey32`/`unwrapKey32` aliases below resolve to
/// `void` under fips (so they pull no XChaCha code) and to the real
/// functions under non-fips for backward-compatible call sites.
pub const key_wrap = aead.key_wrap;
/// Wrap a 32-byte key with XChaCha20-Poly1305 (stack-only). Non-FIPS only;
/// `void` under -Dfips=true (use `KeyManager.wrapKey`).
pub const wrapKey32 = if (crypto_backend.fips_enabled) {} else aead.key_wrap.wrapKey32;
/// Unwrap a 32-byte key previously wrapped with `wrapKey32`. Non-FIPS only;
/// `void` under -Dfips=true (use `KeyManager.unwrapKey`).
pub const unwrapKey32 = if (crypto_backend.fips_enabled) {} else aead.key_wrap.unwrapKey32;
/// RFC 5869 HKDF-SHA256 (arbitrary output length).
pub const hkdfSha256 = hkdf.hkdfSha256;
/// Derive a single 32-byte key via HKDF-SHA256.
pub const deriveKey32 = hkdf.deriveKey32;
/// Hierarchical key manager: master -> TRK -> SK -> FEK/BIK, with caching and rotation.
pub const KeyManager = key_manager.KeyManager;
/// Identifier tuple (tenant/schema/field/version) for key derivation. Identifiers must not contain ':' or '/'.
pub const KeyIds = key_types.KeyIds;
/// In-memory searchable blind index: HMAC(BIK, normalize(value)) -> record IDs.
pub const BlindIndex = blind_index.BlindIndex;
/// 32-byte blind-index token (full-width HMAC-SHA256 output).
pub const BlindIndexToken = blind_index.BlindIndexToken;
/// Pluggable master-key source vtable interface.
pub const MasterKeyProvider = key_provider.MasterKeyProvider;
/// MasterKeyProvider backed by a static in-memory key (tests, pre-sourced keys).
pub const StaticKeyProvider = key_provider.StaticKeyProvider;
/// MasterKeyProvider reading exactly 32 raw bytes or 64 hex chars from an env var.
pub const EnvKeyProvider = key_provider.EnvKeyProvider;
/// Parser for `@encrypted`/`@searchable`/`@visible`/`@classify` schema annotations.
pub const AnnotationParser = annotations.AnnotationParser;
/// Per-field encryption/search/visibility/classification metadata produced by annotation parsing.
pub const FieldMetadata = annotations.FieldMetadata;
/// Per-type field-name -> `FieldMetadata` map produced by annotation parsing.
pub const TypeMetadata = annotations.TypeMetadata;
/// One field's input for `encryptFieldsBulk`.
pub const BulkField = bulk.BulkField;
/// One field's input for `decryptFieldsBulk`.
pub const BulkDecryptField = bulk.BulkDecryptField;
/// Per-field bulk encrypt result (owned envelope or error).
pub const BulkResult = bulk.BulkResult;
/// Per-field bulk decrypt result (owned plaintext or error).
pub const BulkDecryptResult = bulk.BulkDecryptResult;
/// Tunables (chunk size, task lane) for bulk calls.
pub const BulkOptions = bulk.BulkOptions;
/// Encrypt many fields, optionally fanned out across a thread pool. Requires a thread-safe allocator when pooled.
pub const encryptFieldsBulk = bulk.encryptFieldsBulk;
/// Decrypt many envelopes, optionally fanned out across a thread pool. Requires a thread-safe allocator when pooled.
pub const decryptFieldsBulk = bulk.decryptFieldsBulk;

// ============================================================================
// Unit Tests
// ============================================================================

test {
    // Ensure all submodule tests are run
    std.testing.refAllDecls(@This());
}
