// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Schema annotation example: parse `@encrypted`/`@searchable` annotations
//! for a field and inspect the resulting `FieldMetadata`.

const std = @import("std");
const fle = @import("fle");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Per-type metadata catalog keyed by field name.
    var type_meta = fle.TypeMetadata.init(allocator, "Person");
    defer type_meta.deinit();

    // Parse the annotation string and record metadata for Person.ssn.
    const annotation_text =
        "@encrypted(alg:\"AES-256-GCM\", key_scope:\"field\", rotate:\"90d\") " ++
        "@searchable(index:\"blind-hmac-sha256\")";
    try fle.annotations.applyAnnotations(allocator, &type_meta, "ssn", annotation_text);

    // Unannotated fields stay plaintext.
    try fle.annotations.applyAnnotations(allocator, &type_meta, "name", "");

    const meta = type_meta.getField("ssn").?;
    std.debug.print("field: {s}.{s}\n", .{ type_meta.type_name, meta.field_name });
    std.debug.print("  encrypted:  {}\n", .{meta.isEncrypted()});
    std.debug.print("  algorithm:  {s}\n", .{@tagName(meta.algorithm().?)});
    std.debug.print("  key scope:  {s}\n", .{@tagName(meta.encryption.key_scope)});
    std.debug.print("  rotate:     every {?d} days\n", .{meta.encryption.rotation_interval_days});
    std.debug.print("  searchable: {} ({s})\n", .{ meta.isSearchable(), @tagName(meta.search.index_type) });

    std.debug.print("Person.name encrypted: {}\n", .{type_meta.isFieldEncrypted("name")});
}
