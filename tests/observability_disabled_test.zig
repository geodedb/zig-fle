//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! fle publishes its public surface as the "fle" module rooted at
//! src/root.zig. The seam is exposed as `fle.observability` so this test
//! can drive the disabled-mode invariants through the public root.

const std = @import("std");
const fle = @import("fle");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, fle.observability.enabled);
}

test "fle span helper is a no-op when otel disabled" {
    if (fle.observability.enabled) return error.SkipZigTest;
    var span = fle.observability.startFleSpan("encrypt", "ssn", "aes-256-gcm");
    fle.observability.endFleSpan(span, true);
    // Belt-and-suspenders: the seam's `endFleSpan` already covers the
    // lifecycle; this line just verifies the no-op fallback's signature
    // matches the real API's `Span.end(?u64) void`.
    span.end(null);
}
