// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for fle
//!
//! End-to-end tests verifying the extracted FLE core works independently
//! of Geode-specific env vars or singleton state.

const std = @import("std");
const fle = @import("fle");

// ============================================================================
// Lifecycle: encrypt -> serialize -> deserialize -> decrypt
// ============================================================================

test "integration: full encrypt/decrypt lifecycle" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a master key (caller-provided, not from env)
    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    const ids = fle.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "ssn",
        .version = 1,
    };

    // Derive FEK through the hierarchy
    const fek = try km.getFEK(ids);

    // Build AAD
    const aad = try fle.aead.makeAAD(allocator, ids.tenant, ids.schema, ids.field, "record-42", ids.version);
    defer allocator.free(aad);

    const plaintext = "123-45-6789";

    // Encrypt
    var envelope = try fle.aead.encryptField(allocator, .aes256_gcm, &fek, aad, plaintext, ids.version);
    defer envelope.deinit(allocator);

    // Serialize -> Deserialize (simulates storage round-trip)
    const serialized = try envelope.serialize(allocator);
    defer allocator.free(serialized);

    var restored = try fle.EnvelopeV1.deserialize(allocator, serialized);
    defer restored.deinit(allocator);

    // Decrypt
    const decrypted = try fle.aead.decryptField(allocator, &fek, aad, restored);
    defer {
        std.crypto.secureZero(u8, decrypted);
        allocator.free(decrypted);
    }

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

// ============================================================================
// Key hierarchy: TRK -> SK -> FEK/BIK are distinct
// ============================================================================

test "integration: key hierarchy produces distinct keys" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    const ids = fle.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "email",
        .version = 1,
    };

    const fek = try km.getFEK(ids);
    const bik = try km.getBIK(ids);

    // FEK and BIK for the same field must differ
    try std.testing.expect(!std.mem.eql(u8, &fek, &bik));
}

// ============================================================================
// Key rotation: v1 and v2 produce different FEKs, both remain accessible
// ============================================================================

test "integration: key rotation produces new FEK" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    const tenant = "tenant1";
    const schema = "Person";
    const field = "ssn";

    const fek_v1 = try km.getFEK(.{ .tenant = tenant, .schema = schema, .field = field, .version = 1 });

    const new_ver = try km.rotateFEK(tenant, schema, field);
    try std.testing.expectEqual(@as(u16, 2), new_ver);

    const fek_v2 = try km.getFEK(.{ .tenant = tenant, .schema = schema, .field = field, .version = 2 });

    // Keys must differ
    try std.testing.expect(!std.mem.eql(u8, &fek_v1, &fek_v2));

    // Old key still available for migration reads
    const fek_v1_again = try km.getFEK(.{ .tenant = tenant, .schema = schema, .field = field, .version = 1 });
    try std.testing.expectEqualSlices(u8, &fek_v1, &fek_v1_again);
}

// ============================================================================
// Blind index: index, lookup, remove
// ============================================================================

test "integration: blind index search on encrypted field" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    const ids = fle.KeyIds{
        .tenant = "tenant1",
        .schema = "Person",
        .field = "email",
        .version = 1,
    };

    const bik = try km.getBIK(ids);

    var index = fle.BlindIndex.init(allocator);
    defer index.deinit();

    // Index two records with same email
    try index.put("Person", "email", bik, "alice@example.com", "p1");
    try index.put("Person", "email", bik, "alice@example.com", "p2");
    try index.put("Person", "email", bik, "bob@example.com", "p3");

    // Lookup matches
    const results = try index.lookup("Person", "email", bik, "alice@example.com");
    try std.testing.expect(results != null);
    try std.testing.expectEqual(@as(usize, 2), results.?.len);

    // Remove one record
    try index.remove("Person", "email", "p1");
    const after = try index.lookup("Person", "email", bik, "alice@example.com");
    try std.testing.expect(after != null);
    try std.testing.expectEqual(@as(usize, 1), after.?.len);
}

// ============================================================================
// Annotation parsing
// ============================================================================

test "integration: annotation-driven encryption metadata" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var type_meta = fle.TypeMetadata.init(allocator, "Person");
    defer type_meta.deinit();

    try fle.annotations.applyAnnotations(
        allocator,
        &type_meta,
        "ssn",
        "@encrypted(alg:\"AES-256-GCM\", rotate:\"90d\") @searchable(index:\"blind-hmac-sha256\")",
    );

    try std.testing.expect(type_meta.isFieldEncrypted("ssn"));
    try std.testing.expect(type_meta.isFieldSearchable("ssn"));
    try std.testing.expect(!type_meta.isFieldEncrypted("name"));

    const meta = type_meta.getField("ssn").?;
    try std.testing.expectEqual(@as(?u32, 90), meta.encryption.rotation_interval_days);
}

// ============================================================================
// ChaCha20-Poly1305 round-trip
// ============================================================================

test "integration: ChaCha20-Poly1305 encrypt/decrypt" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.crypto.random.bytes(&fek);

    const aad = try fle.aead.makeAAD(allocator, "t1", "X", "f", "r1", 1);
    defer allocator.free(aad);

    var envelope = try fle.aead.encryptField(allocator, .chacha20_poly1305, &fek, aad, "secret", 1);
    defer envelope.deinit(allocator);

    const decrypted = try fle.aead.decryptField(allocator, &fek, aad, envelope);
    defer {
        std.crypto.secureZero(u8, decrypted);
        allocator.free(decrypted);
    }

    try std.testing.expectEqualStrings("secret", decrypted);
}

// ============================================================================
// Version string
// ============================================================================

test "integration: version is defined" {
    try std.testing.expectEqualStrings("0.1.0", fle.version);
}
