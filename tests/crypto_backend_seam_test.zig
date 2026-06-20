// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Seam smoke test. Proves fle resolves the canonical crypto_backend
//! seam and the backend's API is callable in whichever mode is built.
const std = @import("std");
const backend = @import("crypto_backend");

test "crypto_backend seam exposes the FIPS-approved API surface" {
    backend.assertActive(); // no-op under -Dfips=false; self-test under -Dfips=true

    // AES-256-GCM seal/open round-trip through the seam.
    var key: [32]u8 = @splat(7);
    var nonce: [12]u8 = @splat(0);
    const pt = "seam check";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try backend.Aead.seal(.aes_256_gcm, &key, &nonce, "", pt, &ct, &tag);
    var rt: [pt.len]u8 = undefined;
    try backend.Aead.open(.aes_256_gcm, &key, &nonce, "", &ct, &tag, &rt);
    try std.testing.expectEqualSlices(u8, pt, &rt);

    // HMAC-SHA256 and HKDF-SHA256 reachable through the seam.
    var mac: [32]u8 = undefined;
    _ = try backend.Mac.hmac(.sha256, "k", "m", &mac);
    var okm: [32]u8 = undefined;
    try backend.Kdf.hkdf(.sha256, "ikm", "salt", "info", &okm);

    // CSPRNG draws distinct bytes.
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    try backend.Csprng.bytes(&a);
    try backend.Csprng.bytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
