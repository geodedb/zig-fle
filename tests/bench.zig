// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const fle = @import("fle");
const tp = @import("thread_pool");

fn genFields(allocator: std.mem.Allocator, fek: *const [32]u8, n: usize, pt_len: usize) ![]fle.BulkField {
    const fields = try allocator.alloc(fle.BulkField, n);
    const pt_pool = try allocator.alloc(u8, pt_len);
    @memset(pt_pool, 'x');
    for (0..n) |i| {
        fields[i] = .{
            .fek = fek,
            .alg = .aes256_gcm,
            .tenant_id = "t",
            .schema = "S",
            .field = "f",
            .record_id = "r",
            .key_version = 1,
            .plaintext = pt_pool, // same buffer — bench measures crypto, not alloc
        };
    }
    return fields;
}

fn monoNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s +
        @as(u64, @intCast(ts.nsec));
}

fn runOnce(
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const fle.BulkField,
    chunk_size: usize,
) !u64 {
    const results = try allocator.alloc(fle.BulkResult, fields.len);
    defer {
        for (results) |*r| switch (r.*) {
            .ok => |*env| env.deinit(allocator),
            .err => {},
        };
        allocator.free(results);
    }
    const t0 = monoNs();
    _ = try fle.encryptFieldsBulk(allocator, pool, fields, results, .{ .chunk_size = chunk_size });
    return monoNs() - t0;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&fek);

    const N: usize = 100_000;
    const pt_len: usize = 64; // realistic encrypted-field size
    const fields = try genFields(allocator, &fek, N, pt_len);
    defer allocator.free(fields);
    defer allocator.free(@constCast(fields[0].plaintext));

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 8 });
    defer {
        _ = pool.shutdown(.drain, 5 * std.time.ns_per_s) catch {};
        pool.deinit();
    }

    // Warmup.
    _ = try runOnce(allocator, null, fields, 0);

    const serial_ns = try runOnce(allocator, null, fields, 0);
    std.debug.print("serial:           {d:>10} ns  ({d:.2} M fields/s)\n", .{
        serial_ns, @as(f64, @floatFromInt(N)) / (@as(f64, @floatFromInt(serial_ns)) / 1e9) / 1e6,
    });

    for ([_]usize{ 64, 256, 1024, 4096 }) |cs| {
        const ns = try runOnce(allocator, &pool, fields, cs);
        std.debug.print("parallel cs={d:>5}: {d:>10} ns  ({d:.2} M fields/s)\n", .{
            cs, ns, @as(f64, @floatFromInt(N)) / (@as(f64, @floatFromInt(ns)) / 1e9) / 1e6,
        });
    }
}
