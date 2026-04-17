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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a master key (caller-provided, not from env)
    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&fek);

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

// ============================================================================
// Bulk parallel == serial correctness property
// ============================================================================

test "bulk parallel matches serial for identical inputs" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const tp = @import("thread_pool");

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 4 });
    defer {
        _ = pool.shutdown(.drain, 5 * std.time.ns_per_s) catch {};
        pool.deinit();
    }

    var fek: [32]u8 = undefined;
    _ = std.os.linux.getrandom(@ptrCast(&fek), @sizeOf(@TypeOf(fek)), 0);

    const N = 2048;
    const fields = try allocator.alloc(fle.BulkField, N);
    defer allocator.free(fields);
    for (0..N) |i| {
        const pt = try std.fmt.allocPrint(allocator, "v-{d}", .{i});
        fields[i] = .{
            .fek = &fek,
            .alg = .aes256_gcm,
            .tenant_id = "t",
            .schema = "S",
            .field = "f",
            .record_id = "r",
            .key_version = 1,
            .plaintext = pt,
        };
    }
    defer for (fields) |f| allocator.free(@constCast(f.plaintext));

    // Serial encrypt — source of truth.
    const serial_results = try allocator.alloc(fle.BulkResult, N);
    defer {
        for (serial_results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(serial_results);
    }
    _ = try fle.encryptFieldsBulk(allocator, null, fields, serial_results, .{});

    // Parallel encrypt.
    const parallel_results = try allocator.alloc(fle.BulkResult, N);
    defer {
        for (parallel_results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(parallel_results);
    }
    _ = try fle.encryptFieldsBulk(allocator, &pool, fields, parallel_results, .{ .chunk_size = 256 });

    // Both must decrypt to the same plaintext using serial decrypt.
    for (0..N) |i| {
        const aad = try fle.aead.makeAAD(allocator, "t", "S", "f", "r", 1);
        defer allocator.free(aad);
        const pt_serial = try fle.aead.decryptField(allocator, &fek, aad, serial_results[i].ok);
        defer {
            std.crypto.secureZero(u8, pt_serial);
            allocator.free(pt_serial);
        }
        const pt_parallel = try fle.aead.decryptField(allocator, &fek, aad, parallel_results[i].ok);
        defer {
            std.crypto.secureZero(u8, pt_parallel);
            allocator.free(pt_parallel);
        }
        try testing.expectEqualStrings(pt_serial, pt_parallel);
        try testing.expectEqualStrings(fields[i].plaintext, pt_parallel);
    }
}
