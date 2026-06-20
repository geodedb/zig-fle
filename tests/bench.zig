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
    const allocator = std.heap.smp_allocator;

    var fek: [32]u8 = undefined;
    try @import("crypto_backend").Csprng.bytes(&fek);

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 8 });
    defer {
        _ = pool.shutdown(.drain, 5 * std.time.ns_per_s) catch {};
        pool.deinit();
    }

    // ------------------------------------------------------------------
    // Chunk-size sweep at the small-field workload (100k × 64B).
    // ------------------------------------------------------------------
    {
        const N: usize = 100_000;
        const pt_len: usize = 64; // realistic encrypted-field size
        const fields = try genFields(allocator, &fek, N, pt_len);
        defer allocator.free(fields);
        defer allocator.free(@constCast(fields[0].plaintext));

        // Warmup.
        _ = try runOnce(allocator, null, fields, 0);
        _ = try runOnce(allocator, &pool, fields, 1024); // parallel warmup

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

    // ------------------------------------------------------------------
    // Payload-size sweep: serial vs parallel (cs=1024) so the
    // serial/parallel break-even (PERF-FU-001) stays visible. N shrinks
    // as payload grows to keep total runtime bounded.
    // ------------------------------------------------------------------
    std.debug.print("\npayload sweep (serial vs parallel cs=1024, best of 3):\n", .{});
    const cases = [_]struct { n: usize, pt: usize }{
        .{ .n = 100_000, .pt = 64 },
        .{ .n = 20_000, .pt = 1024 },
        .{ .n = 4_000, .pt = 16384 },
    };
    for (cases) |c| {
        const fields = try genFields(allocator, &fek, c.n, c.pt);
        defer allocator.free(fields);
        defer allocator.free(@constCast(fields[0].plaintext));

        // Warmup.
        _ = try runOnce(allocator, null, fields, 0);
        _ = try runOnce(allocator, &pool, fields, 1024);

        var serial_best: u64 = std.math.maxInt(u64);
        var par_best: u64 = std.math.maxInt(u64);
        for (0..3) |_| {
            serial_best = @min(serial_best, try runOnce(allocator, null, fields, 0));
            par_best = @min(par_best, try runOnce(allocator, &pool, fields, 1024));
        }

        const nf = @as(f64, @floatFromInt(c.n));
        std.debug.print(
            "pt={d:>6}B N={d:>7}: serial {d:>8.1} ns/field | parallel {d:>8.1} ns/field\n",
            .{
                c.pt,                                      c.n,
                @as(f64, @floatFromInt(serial_best)) / nf, @as(f64, @floatFromInt(par_best)) / nf,
            },
        );
    }
}
