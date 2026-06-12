// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Minimal example: bulk-encrypt 1024 fields on a 4-worker thread-pool.

const std = @import("std");
const fle = @import("fle");
const tp = @import("thread_pool");

pub fn main() !void {
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

    const N: usize = 1024;
    const fields = try allocator.alloc(fle.BulkField, N);
    defer allocator.free(fields);
    for (0..N) |i| {
        const pt = try std.fmt.allocPrint(allocator, "secret-{d}", .{i});
        fields[i] = .{
            .fek = &fek,
            .alg = .aes256_gcm,
            .tenant_id = "demo",
            .schema = "Person",
            .field = "ssn",
            .record_id = "r1",
            .key_version = 1,
            .plaintext = pt,
        };
    }
    defer for (fields) |f| allocator.free(@constCast(f.plaintext));

    const results = try allocator.alloc(fle.BulkResult, N);
    defer {
        for (results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(results);
    }

    const ok = try fle.encryptFieldsBulk(allocator, &pool, fields, results, .{});
    std.debug.print("encrypted {d} / {d} fields\n", .{ ok, N });
}
