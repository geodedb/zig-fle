// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # fle - Field-Level Encryption
//!
//! A portable, zero-dependency Zig library for field-level encryption with
//! searchable blind indices and hierarchical key management.
//!
//! ## Features
//!
//! - AEAD envelope encryption (AES-256-GCM, ChaCha20-Poly1305)
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
//! ## Quick Start
//!
//! ```zig
//! const fle = @import("fle");
//!
//! // Create a key manager with an explicit master key
//! var master_key: [32]u8 = undefined;
//! std.crypto.random.bytes(&master_key);
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

/// Library version
pub const version = "0.1.0";

// ============================================================================
// Submodule re-exports
// ============================================================================

/// AEAD envelope encryption (AES-256-GCM, ChaCha20-Poly1305)
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

// ============================================================================
// Convenience aliases for the most common public types
// ============================================================================

pub const Alg = aead.Alg;
pub const EnvelopeV1 = aead.EnvelopeV1;
pub const wrapKey32 = aead.wrapKey32;
pub const unwrapKey32 = aead.unwrapKey32;
pub const hkdfSha256 = hkdf.hkdfSha256;
pub const deriveKey32 = hkdf.deriveKey32;
pub const KeyManager = key_manager.KeyManager;
pub const KeyIds = key_types.KeyIds;
pub const BlindIndex = blind_index.BlindIndex;
pub const MasterKeyProvider = key_provider.MasterKeyProvider;
pub const StaticKeyProvider = key_provider.StaticKeyProvider;
pub const EnvKeyProvider = key_provider.EnvKeyProvider;
pub const AnnotationParser = annotations.AnnotationParser;
pub const FieldMetadata = annotations.FieldMetadata;
pub const TypeMetadata = annotations.TypeMetadata;

// ============================================================================
// Unit Tests
// ============================================================================

test {
    // Ensure all submodule tests are run
    std.testing.refAllDecls(@This());
}
