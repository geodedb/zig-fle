// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! FIPS enforcement proof (spec §5/§7). Under -Dfips=true the seam must
//! reject non-FIPS AEAD (ChaCha20-Poly1305) and compile out the XChaCha
//! key-wrap helpers; under -Dfips=false both remain available.
//!
//! NOTE: Zig 0.16 removed `pub usingnamespace`, so the key-wrap helpers
//! are gated via the `fle.key_wrap` namespace (genuinely EMPTY under
//! fips) rather than top-level `fle.wrapKey32`. The presence assertions
//! below target that namespace, which is the load-bearing enforcement
//! surface: under fips the XChaCha functions are absent and uncallable.
const std = @import("std");
const fle = @import("fle");
const backend = @import("crypto_backend");

test "fips build rejects ChaCha20-Poly1305 at the AEAD boundary" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    try backend.Csprng.bytes(&fek);
    const aad = try fle.aead.makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    if (backend.fips_enabled) {
        try std.testing.expectError(
            fle.aead.Error.InvalidAlg,
            fle.aead.encryptField(allocator, .chacha20_poly1305, &fek, aad, "x", 1),
        );
    } else {
        var env = try fle.aead.encryptField(allocator, .chacha20_poly1305, &fek, aad, "x", 1);
        env.deinit(allocator);
    }
}

test "fips build compiles out XChaCha key-wrap helpers" {
    if (backend.fips_enabled) {
        try std.testing.expect(!@hasDecl(fle.key_wrap, "wrapKey32"));
        try std.testing.expect(!@hasDecl(fle.key_wrap, "unwrapKey32"));
    } else {
        try std.testing.expect(@hasDecl(fle.key_wrap, "wrapKey32"));
        try std.testing.expect(@hasDecl(fle.key_wrap, "unwrapKey32"));
    }
}
