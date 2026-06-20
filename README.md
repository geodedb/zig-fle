# fle

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0+-orange.svg)](https://ziglang.org/)

A portable Zig library for field-level encryption (FLE) with searchable
blind indices and hierarchical key management.

## Features

- **AEAD envelope encryption**: AES-256-GCM and ChaCha20-Poly1305, with
  context-binding AAD and XChaCha20-Poly1305 key wrapping
- **Hierarchical key derivation**: HKDF-SHA256 master → TRK → SK → FEK/BIK
  (see [docs/KEY_HIERARCHY.md](docs/KEY_HIERARCHY.md))
- **Searchable blind indices**: HMAC-SHA256 equality search over encrypted fields
- **Minimal dependencies**: thread-pool (bulk API); optional otel (observability)
- **Memory Safe**: Proper allocation patterns with no leaks
- **Cross-Platform**: Linux, macOS, Windows support
- **Well Tested**: Comprehensive unit, integration, and fuzz tests

## Out of Scope

`fle` is the portable crypto core extracted from Geode. By design it does
**not** include:

- **Catalog persistence** — durable storage of schema/field encryption
  metadata stays in Geode (`fle_catalog.zig`)
- **Policy and enforcement** — RBAC evaluation and visibility enforcement
  stay in Geode; this library only parses `@visible`/`@classify` metadata
- **KMS integration** — no cloud KMS/HSM clients; bring your own master-key
  source by implementing the `MasterKeyProvider` interface
- **Key-version persistence** — rotation state is in-memory; persist
  current versions externally if they must survive restarts

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
const fle = @import("fle");

// Create a key manager with an explicit master key
var master_key: [32]u8 = undefined;
std.Io.Threaded.global_single_threaded.io().random(&master_key);
var km = try fle.KeyManager.init(allocator, master_key);
defer km.deinit();

// Derive a field encryption key
const fek = try km.getFEK(.{
    .tenant = "tenant1",
    .schema = "Person",
    .field = "ssn",
    .version = 1,
});

// Encrypt a field value
const aad = try fle.aead.makeAAD(allocator, "tenant1", "Person", "ssn", "record1", 1);
defer allocator.free(aad);
var envelope = try fle.aead.encryptField(allocator, .aes256_gcm, &fek, aad, "123-45-6789", 1);
defer envelope.deinit(allocator);
```

Complete runnable programs live in [examples/](examples/) — run them with
`zig build examples`.

## Requirements

- Zig 0.16.0 or later

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

## FIPS-140-3 mode

`fle` supports a build-flag-gated FIPS-140-3 mode. Build with `-Dfips=true` to
route all security crypto (AES-256-GCM, HKDF-SHA256, HMAC-SHA256, CSPRNG)
through a linked OpenSSL 3.x FIPS provider via the `src/crypto_backend.zig`
seam. The default (`-Dfips=false`) uses a `std.crypto`-backed shim with **zero
overhead, no `fips` dependency, and no OpenSSL link**.

Behavior changes under `-Dfips=true`:

- `aead.encryptField`/`decryptField` reject `ChaCha20-Poly1305` (not
  FIPS-approved) with `Error.InvalidAlg` — use **AES-256-GCM**, the only
  approved envelope algorithm.
- `wrapKey32`/`unwrapKey32` (XChaCha20-Poly1305 key wrap) are **compiled out**
  (`fle.key_wrap` is empty); use `KeyManager.wrapKey`/`unwrapKey` (AES-256-GCM).

The `EnvelopeV1` wire format, AAD construction, key hierarchy, blind index, and
bulk API are unchanged across modes.

```bash
zig build test                      # default: -Dfips=false (std shim, no OpenSSL)
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf \
  zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl --summary all
make test-dual                      # both modes
```

See [docs/FIPS.md](docs/FIPS.md) for the full algorithm policy, the seam
contract, and the dual-mode test gate.

## Documentation

- [docs/KEY_HIERARCHY.md](docs/KEY_HIERARCHY.md) — key derivation, envelope
  format, blind-index flow, rotation, and zeroization guarantees
- [docs/FIPS.md](docs/FIPS.md) — FIPS-140-3 mode, the crypto seam, approved
  algorithms, and behavior changes under `-Dfips=true`
- See the [docs](docs/) directory for the rest of the documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
