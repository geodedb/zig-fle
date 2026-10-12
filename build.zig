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

    // -Dfips: route security crypto through the linked FIPS-140-3 provider.
    // Off by default; zero overhead when off (the seam collapses to the
    // std shim and the fips dependency is never resolved).
    const fips = b.option(
        bool,
        "fips",
        "Route security crypto through the linked FIPS-140-3 provider (off by default; zero overhead when off)",
    ) orelse false;
    const openssl_path = b.option([]const u8, "openssl_path", "OpenSSL install prefix for non-standard installs (e.g. /usr/local/ssl)");

    // Materialize ONE shared `build_options` module. BOTH `with_otel`
    // and `fips` live on this single instance; it is threaded into every
    // compile unit and into the lazy `fips` dependency's consumers. A
    // second `addOptions()` reachable from the same file graph triggers
    // Zig 0.16 GAP-0020 ("file exists in modules build_options and
    // build_options0").
    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    build_options.addOption(bool, "fips", fips);
    build_options.addOption([]const u8, "package_name", "fle");
    const build_options_mod = build_options.createModule();

    const link = @import("src/link.zig");

    // std_shim backend (always available; std.crypto-backed; no OpenSSL
    // link). policy.zig is imported by std_shim via a relative import in
    // the same module, so it needs no separate module registration here.
    const std_shim_mod = b.addModule("std_shim", .{
        .root_source_file = b.path("src/std_shim.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The crypto seam is a SHARED NAMED MODULE so every consumer resolves
    // the same crypto_backend.zig source via one module identity.
    const crypto_backend_mod = b.addModule("crypto_backend", .{
        .root_source_file = b.path("src/crypto_backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
            .{ .name = "std_shim", .module = std_shim_mod },
        },
    });

    // fips backend: resolved LAZILY only when -Dfips=true so the disabled
    // build never fetches OpenSSL-linked code. build.zig.zon pins the
    // published fips release as a lazy git+https dependency.
    if (fips) {
        if (b.lazyDependency("fips", .{ .target = target, .optimize = optimize })) |fips_dep| {
            const fips_mod = fips_dep.module("fips");
            crypto_backend_mod.addImport("fips", fips_mod);
            link.linkOpenssl(b, fips_mod, openssl_path);
            // The seam re-exports fips types; the artifact roots that pull
            // crypto_backend must also link OpenSSL. Done per-artifact below.
        }
    }

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
            .{ .name = "crypto_backend", .module = crypto_backend_mod },
        },
    });
    if (observability_init_mod) |m| module.addImport("observability_init", m);
    if (otel_mod) |m| module.addImport("otel", m);
    if (fips) link.linkOpenssl(b, module, openssl_path);

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
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (observability_init_mod) |m| unit_tests.root_module.addImport("observability_init", m);
    if (otel_mod) |m| unit_tests.root_module.addImport("otel", m);
    if (fips) link.linkOpenssl(b, unit_tests.root_module, openssl_path);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // crypto_backend seam smoke test (runs under both -Dfips values).
    const seam_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/crypto_backend_seam_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, seam_tests.root_module, openssl_path);
    const run_seam_tests = b.addRunArtifact(seam_tests);
    test_step.dependOn(&run_seam_tests.step);

    // FIPS enforcement proof (spec §5/§7): ChaCha rejected + key-wrap
    // compiled out under fips; both available otherwise. Dual-mode.
    const enforcement_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fips_enforcement_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fle", .module = module },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, enforcement_tests.root_module, openssl_path);
    const run_enforcement_tests = b.addRunArtifact(enforcement_tests);
    test_step.dependOn(&run_enforcement_tests.step);

    // Observability seam tests. See addObservabilityTests for the
    // disabled/enabled split.
    addObservabilityTests(b, target, optimize, module, build_options_mod, otel_mod, crypto_backend_mod, fips, openssl_path, test_step);

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
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, integration_tests.root_module, openssl_path);
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
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, bench_exe.root_module, openssl_path);
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
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (observability_init_mod) |m| check.root_module.addImport("observability_init", m);
    if (otel_mod) |m| check.root_module.addImport("otel", m);
    if (fips) link.linkOpenssl(b, check.root_module, openssl_path);
    check_step.dependOn(&check.step);

    // Examples — compiled in `check`, runnable via `zig build examples`.
    const examples_step = b.step("examples", "Build and run examples");
    inline for (.{ "basic", "annotations", "bulk" }) |ex_name| {
        const ex = b.addExecutable(.{
            .name = "example_" ++ ex_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ ex_name ++ ".zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "fle", .module = module },
                    .{ .name = "thread_pool", .module = thread_pool_module },
                    .{ .name = "crypto_backend", .module = crypto_backend_mod },
                },
            }),
        });
        if (fips) link.linkOpenssl(b, ex.root_module, openssl_path);
        const run_ex = b.addRunArtifact(ex);
        examples_step.dependOn(&run_ex.step);
        check_step.dependOn(&ex.step); // examples can't rot: compile in check
    }
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
    crypto_backend_mod: *std.Build.Module,
    fips: bool,
    openssl_path: ?[]const u8,
    test_step: *std.Build.Step,
) void {
    const link = @import("src/link.zig");

    // Disabled-mode no-op tests.
    const disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "fle", .module = fle_mod },
                .{ .name = "build_options", .module = build_options_mod },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, disabled_tests.root_module, openssl_path);
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
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (otel_mod) |m| enabled_tests.root_module.addImport("otel", m);
    if (fips) link.linkOpenssl(b, enabled_tests.root_module, openssl_path);
    const run_enabled_tests = b.addRunArtifact(enabled_tests);
    test_step.dependOn(&run_enabled_tests.step);
}
