# fle

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.15.1+-orange.svg)](https://ziglang.org/)

A Zig library for fle

## Features

- **Zero Dependencies**: Pure Zig standard library only
- **Memory Safe**: Proper allocation patterns with no leaks
- **Cross-Platform**: Linux, macOS, Windows support
- **Well Tested**: Comprehensive unit and integration tests

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .fle = .{
        .url = "https://gitlab.com/devnw/zig/fle/-/archive/v0.1.0/fle-v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const fle = b.dependency("fle", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("fle", fle.module("fle"));
```

## Quick Start

```zig
const std = @import("std");
const fle = @import("fle");

pub fn main() !void {
    try fle.init(.{
        .debug = true,
    });
}
```

## Requirements

- Zig 0.15.1 or later

## Building

```bash
# Build the library
make build

# Run tests
make test

# Quick development iteration
make dev

# Full CI pipeline
make ci
```

## Observability

`fle` ships an opt-in OpenTelemetry seam. Build with `-Dwith_otel=true`
to compile in instrumentation; the default (`-Dwith_otel=false`)
leaves every span site as a comptime no-op so the optimizer
eliminates the entry/exit calls and the `otel` dependency is never
fetched.

Each public FLE crypto entry point emits exactly one span per call,
named `fle.{operation}`:

| Entry point                  | Span name          |
|------------------------------|--------------------|
| `aead.encryptField`          | `fle.encrypt`      |
| `aead.decryptField`          | `fle.decrypt`      |
| `KeyManager.rotateFEK`       | `fle.rotate_key`   |
| `bulk.encryptFieldsBulk`     | `fle.bulk_encrypt` |
| `bulk.decryptFieldsBulk`     | `fle.bulk_decrypt` |

The bulk entry points emit ONE span per call (not per field).

Span attributes are limited to:

- `fle.field` — schema-level field name (e.g. `"ssn"`, `"email"`).
  NEVER the field VALUE.
- `fle.algorithm` — AEAD algorithm name (e.g. `"aes-256-gcm"`).

**Security**: plaintext, ciphertext, AAD bytes, the master key,
derived FEKs/BIKs, key versions, tenant ids, record ids, and
schema names are NEVER attached as span attributes. If your
application's schema-level field names are themselves sensitive,
hash them BEFORE calling the FLE API — the seam does no hashing.

```bash
zig build test                  # default: -Dwith_otel=false (no-op)
zig build test -Dwith_otel=true # otel compiled in, spans emitted
```

When enabled, the consumer's process bootstrap calls
`fle.observability_init.Otel.init(allocator, "service-name")` and
parks the returned value at a stable address (a `var` in `main` or
a heap allocation), then calls `installGlobals(&that_value)` so the
seam can publish its tracer pointer. Span emission is non-fatal:
every emit is `catch {}`-discarded so a failed exporter cannot
propagate into FLE crypto operations.

For the full integration recipe and template files, see
`otel/docs/integration/RECIPE.md` in the otel repo.

## Documentation

See the [docs](docs/) directory for detailed documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
