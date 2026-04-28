// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = b.option(
        bool,
        "with_otel",
        "Compile in otel instrumentation (off by default; zero overhead when off)",
    ) orelse false;

    // Materialize ONE shared `build_options` module. Each consumer
    // module imports the SAME instance via `addImport` to avoid Zig's
    // "file exists in modules X and X0" error when two independent
    // `addOptions` modules end up sharing a transitive file path.
    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    const build_options_mod = build_options.createModule();

    const thread_pool_dep = b.dependency("thread_pool", .{
        .target = target,
        .optimize = optimize,
    });
    const thread_pool_module = thread_pool_dep.module("thread_pool");

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (lib, tests, bench, plus the seam tests) resolves
    // to the same source file via `@import("observability")`. Using
    // relative `@import("observability.zig")` from each module would
    // trip Zig's "file exists in modules X and Y" error because the
    // file would be pulled into multiple module trees. The seam's
    // `enabled` flag tracks `build_options.with_otel`; when off, every
    // helper compiles to a comptime-known no-op and the otel dependency
    // is never resolved. The optional `otel` import is wired below
    // inside the `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // Gated otel dependency. The `lazy = true` entry in build.zig.zon
    // means Zig only fetches the package when this branch executes;
    // with the flag off the dependency is never resolved and the
    // produced artifacts contain zero otel symbols (verified by
    // otel/scripts/verify-consumer-noop.sh).
    var otel_mod: ?*std.Build.Module = null;
    var observability_init_mod: ?*std.Build.Module = null;
    if (with_otel) {
        if (b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        })) |otel_dep| {
            const m = otel_dep.module("otel");
            otel_mod = m;
            // The seam itself imports `otel` when enabled.
            observability_mod.addImport("otel", m);

            // Bootstrap helper. Only registered when `-Dwith_otel=true`
            // so the disabled build never compiles otel-touching code.
            // Gated from root.zig via
            // `if (observability.enabled) @import("observability_init")`.
            observability_init_mod = b.addModule("observability_init", .{
                .root_source_file = b.path("src/observability_init.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "otel", .module = m },
                    .{ .name = "observability", .module = observability_mod },
                },
            });
        }
    }

    // Main library module
    const module = b.addModule("fle", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "thread_pool", .module = thread_pool_module },
            .{ .name = "observability", .module = observability_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });
    if (observability_init_mod) |m| module.addImport("observability_init", m);
    if (otel_mod) |m| module.addImport("otel", m);

    // Unit tests
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "thread_pool", .module = thread_pool_module },
                .{ .name = "observability", .module = observability_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (observability_init_mod) |m| unit_tests.root_module.addImport("observability_init", m);
    if (otel_mod) |m| unit_tests.root_module.addImport("otel", m);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Observability seam tests. See addObservabilityTests for the
    // disabled/enabled split.
    addObservabilityTests(b, target, optimize, module, build_options_mod, otel_mod, test_step);

    // Integration tests
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fle", .module = module },
                .{ .name = "thread_pool", .module = thread_pool_module },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    integration_step.dependOn(&run_integration_tests.step);

    // Bench step
    const bench_step = b.step("bench", "Run micro-benchmarks");
    const bench_exe = b.addExecutable(.{
        .name = "fle_bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "fle", .module = module },
                .{ .name = "thread_pool", .module = thread_pool_module },
            },
        }),
    });
    const run_bench = b.addRunArtifact(bench_exe);
    bench_step.dependOn(&run_bench.step);

    // Check step
    const check_step = b.step("check", "Check for compilation errors");
    const check = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "thread_pool", .module = thread_pool_module },
                .{ .name = "observability", .module = observability_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (observability_init_mod) |m| check.root_module.addImport("observability_init", m);
    if (otel_mod) |m| check.root_module.addImport("otel", m);
    check_step.dependOn(&check.step);
}

// ============================================================================
// Observability seam tests
// ============================================================================
//
// Two test targets:
//
//   - `observability_disabled_test.zig` runs under BOTH flag values.
//     Each test inside it is skip-guarded via
//     `if (fle.observability.enabled) return error.SkipZigTest;` so the
//     disabled-mode invariants only fire when the flag is off.
//
//   - `observability_enabled_test.zig` is registered under both flag
//     values too, but every test inside it skips when the flag is off.
//     The `otel` import is wired only when `with_otel = true`; the stub
//     branch in the test file
//     (`const otel = if (build_options.with_otel) ...`) ensures the
//     file still compiles cleanly under the disabled build. This file
//     is created in Chunk C; until then the call below detects its
//     absence and skips registration.
fn addObservabilityTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    fle_mod: *std.Build.Module,
    build_options_mod: *std.Build.Module,
    otel_mod: ?*std.Build.Module,
    test_step: *std.Build.Step,
) void {
    // Disabled-mode no-op tests.
    const disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fle", .module = fle_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    const run_disabled_tests = b.addRunArtifact(disabled_tests);
    test_step.dependOn(&run_disabled_tests.step);

    // Enabled-mode smoke test. Skipped at runtime under
    // -Dwith_otel=false; under -Dwith_otel=true it installs an
    // in-memory recorder, drives one fle span through the seam, and
    // asserts the recorder captured it.
    const enabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_enabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fle", .module = fle_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (otel_mod) |m| enabled_tests.root_module.addImport("otel", m);
    const run_enabled_tests = b.addRunArtifact(enabled_tests);
    test_step.dependOn(&run_enabled_tests.step);
}
