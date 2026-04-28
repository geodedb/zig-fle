//! Verifies one fle span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from the recipe template — we exercise the seam
//! directly via the in-memory recorder rather than driving a real
//! `aead.encryptField` call. The seam's behaviour is identical:
//! `startFleSpan` -> `endFleSpan` enters and leaves one tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const fle = @import("fle");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one fle.* operation span recorded when otel enabled" {
    if (!fle.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "fle-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "fle-test" });
    fle.observability.global.tracer = &tracer;
    defer fle.observability.global.tracer = null;

    const span = fle.observability.startFleSpan("encrypt", "email", "AES-256-GCM");
    fle.observability.endFleSpan(span, true);

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "fle.{operation}".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("fle.encrypt", recorded.name);

    // Verify the fle.field + fle.algorithm attributes landed on the
    // span. The in-memory recorder stores attributes as `[]KV`
    // (string-stringified key/value pairs) — see
    // otel/src/exporters/in_memory.zig:30.
    var found_field: ?[]const u8 = null;
    var found_alg: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "fle.field")) {
            found_field = kv.value;
        } else if (std.mem.eql(u8, kv.key, "fle.algorithm")) {
            found_alg = kv.value;
        }
    }
    const field_value = found_field orelse return error.MissingFleFieldAttribute;
    try std.testing.expectEqualStrings("email", field_value);
    const alg_value = found_alg orelse return error.MissingFleAlgorithmAttribute;
    try std.testing.expectEqualStrings("AES-256-GCM", alg_value);
}
