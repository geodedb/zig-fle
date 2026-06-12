//! observability.zig — single-file otel seam for fle.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break field-level
//! encryption operations.
//!
//! NOTE: deviation from the recipe template — fle's public entry points
//! (`encryptField`, `decryptField`, `rotateFEK`, the bulk variants) are
//! crypto operations, not HTTP requests. Wrapping them through the
//! template's `instrumentation.http.startClientSpan` shape would force
//! synthetic method/url strings that misrepresent the operation. We
//! expose the generic `startClientSpan` / `startServerSpan` helpers for
//! template symmetry with grpc-zig (and to keep the seam recipe-shaped),
//! AND a domain-specific `startFleSpan(operation, field, algorithm)`
//! helper that constructs a span via `otel.api.trace.Tracer.startSpan`
//! with an fle-shaped span name (`"fle.{operation}"`) and the
//! `fle.field` / `fle.algorithm` attributes.
//!
//! SECURITY: span attributes carry only the SCHEMA-LEVEL field name
//! (e.g. "ssn", "email") and the algorithm name. Plaintext, ciphertext,
//! and key material MUST NEVER be passed in.

const std = @import("std");
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import + the conditional otel import. The previous pattern surfaced
// a Zig 0.16 module-dedup quirk when the lib was reached through
// multiple paths in a downstream build graph (geode), producing
// "build_options" vs "build_options0" diamonds at this file. The
// seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is
// resolved.
pub const enabled: bool = false;

const otel = struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes — the closure
/// shape the recipe template ships AND the plain-string-field shape used
/// at hot-path call sites.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; fle hot paths use `startFleSpan` instead.
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry; fle has no authoritative-server entry point.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

/// Start a span for an fle field-encryption operation.
///
/// Span shape:
///   - name: `"fle.{operation}"` (e.g. `"fle.encrypt"`, `"fle.decrypt"`,
///     `"fle.rotate_key"`, `"fle.bulk_encrypt"`).
///   - kind: `.client` (the fle library acts as a client to the
///     underlying AEAD primitive; mirrors the `db.*` semantic-conventions
///     guidance other crypto-adjacent consumers in this repo group use).
///   - attributes:
///       * `fle.field = field` — the SCHEMA-LEVEL field name (e.g. "ssn",
///         "email"). NEVER the field VALUE.
///       * `fle.algorithm = algorithm` — the AEAD algorithm name
///         (e.g. "aes-256-gcm").
///
/// SECURITY:
///   - NEVER pass plaintext, ciphertext, or key material as `field` or
///     `algorithm`.
///   - `field` should be the schema-level identifier the application
///     uses (the same string passed as `field` to `aead.makeAAD`).
///   - If the schema-level field names are themselves sensitive in the
///     consuming application, hash them BEFORE calling this helper —
///     the seam does no hashing, by design, so the recorded value is
///     deterministic and aggregatable across operations.
///
/// `operation`, `field`, and `algorithm` MUST be string literals or
/// slices whose lifetimes outlive the span. The SDK dupes the span name
/// into the span arena, but attribute values are stored by reference at
/// the stringified value layer; using stable strings keeps the recorder
/// safe from dangling slices.
pub fn startFleSpan(operation: []const u8, field: []const u8, algorithm: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    // Compose the span name on the stack; the SDK dupes the name into
    // the span arena, so a pointer to a stack buffer is safe here.
    var name_buf: [128]u8 = undefined;
    const span_name = std.fmt.bufPrint(
        name_buf[0..],
        "fle.{s}",
        .{operation},
    ) catch "fle";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .client }) catch return Span{};
    // Best-effort attribute attachment. Failures (OOM in the attribute
    // set) cannot block the crypto operation — telemetry is non-fatal.
    span.setStringAttribute("fle.field", field) catch {};
    span.setStringAttribute("fle.algorithm", algorithm) catch {};
    return span;
}

/// Close an fle span, recording success/failure.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` with an empty description — fle errors carry no
/// caller-confidential context, but we deliberately omit the error
/// name/message from the span description anyway to avoid leaking AEAD
/// failure modes that could aid an attacker timing authentication
/// failures. Then end the span. Callers typically pair this with
/// `defer span.end(null)` at the call site so the span is always ended
/// regardless of which path is taken. `setStatus` + `end` are
/// idempotent for status reporting (only the first status write wins;
/// the deferred `end(null)` is a redundant no-op).
pub fn endFleSpan(span: Span, ok: bool) void {
    if (!enabled) return;
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", "");
    }
    // Idempotent close: otel Span.end is `ended`-flag-guarded (otel src/api/trace.zig:212-215), so call sites may safely overlap explicit endFleSpan with defer/errdefer closes.
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
