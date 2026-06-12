// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic field-level encryption example: derive a key, encrypt a field,
//! serialize the envelope, deserialize, and decrypt.

const std = @import("std");
const fle = @import("fle");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Master key — source from your KMS/HSM in production.
    var master_key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&master_key);

    const km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    // 2. Derive the field encryption key for (tenant, schema, field, version).
    const ids: fle.KeyIds = .{ .tenant = "tenant1", .schema = "Person", .field = "ssn", .version = 1 };
    const fek = try km.getFEK(ids);

    // 3. Bind the ciphertext to its context via AAD, then encrypt.
    const aad = try fle.aead.makeAAD(allocator, ids.tenant, ids.schema, ids.field, "record-42", ids.version);
    defer allocator.free(aad);

    var envelope = try fle.aead.encryptField(allocator, .aes256_gcm, &fek, aad, "123-45-6789", ids.version);
    defer envelope.deinit(allocator);

    // 4. Serialize for storage; deserialize on read.
    const stored = try envelope.serialize(allocator);
    defer allocator.free(stored);

    var loaded = try fle.EnvelopeV1.deserialize(allocator, stored);
    defer loaded.deinit(allocator);

    // 5. Decrypt (fails with AEADAuthFailed if AAD or ciphertext was tampered).
    const plaintext = try fle.aead.decryptField(allocator, &fek, aad, loaded);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    std.debug.print("decrypted: {s}\n", .{plaintext});
}
