# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.21] - 2026-11-17

### Changed

- otel v0.1.28 -> v0.1.30, whose tree (slog, json, config, yaml, metrics, tls, grpc-zig v0.1.16) is on thread-pool v0.2.11, so this library and its consumers resolve a single otel and thread-pool (SONNY-6630).

## [0.1.18] - 2026-10-12

- Verify OpenSSL release signatures against exact primary-key fingerprints, including certified signing subkeys (SONNY-4865).
- Require authenticated OpenSSL 3.6.5 provisioning and real-signature regression checks in CI.
- Pin the formatter component to Zig 0.16.0 so release checks use the project compiler.

## [Unreleased]

## [0.1.13] - 2026-09-15

### Changed

- Converge grpc_zig v0.1.10 (GAP-0838 diamond sync).

## [0.1.12] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.11] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).

## [0.1.6] - 2026-06-12

2026-06-11 security audit remediation.

### Security

- Nonces and key material are generated from the process CSPRNG — the
  library never silently uses uninitialized memory for randomness
  (FLE-001, FLE-012)
- Overflow-safe envelope length validation with malformed-input and fuzz
  test coverage (FLE-002)
- Identifier validation plus injective (length-prefixed) cache and index
  keys — derivation contexts can no longer collide (FLE-003)
- Blind index zeroizes normalized plaintext buffers; `lookup` lifetime
  documented; `BlindIndexToken` re-exported (FLE-006, FLE-008)
- `decryptField` validates the algorithm before allocating and scrubs the
  plaintext buffer on every failure path (CX-004)
- `EnvKeyProvider` zeroizes partial key material on error (FLE-013)
- HKDF-SHA256 verified against RFC 5869 test cases 1-3 (FLE-011)

### Changed

- **BREAKING**: `EnvKeyProvider`/`parseKeyMaterial` accept only exactly
  32 raw bytes or exactly 64 hex characters; values of 33-63 bytes or more
  than 64 bytes — previously silently truncated — are now rejected with
  `MasterKeyUnavailable` (FLE-013)
- **BREAKING**: key-derivation identifiers (`tenant`, `schema`, `field`)
  containing `:` or `/`, or empty, are now rejected with
  `Error.InvalidIdentifier` (FLE-003)
- **BREAKING**: never-raised error variants `NonceReuse`,
  `SearchNotPermitted`, and `RotationInProgress` were removed — exhaustive
  `switch`es over the error sets must drop those arms (DC-001..003)
- Bulk default chunk size is now 1024 (was 4096); the serial bulk path
  uses an internal arena; per-chunk `ok_count` aggregation (perf#1, perf#7)
- Bulk encrypt/decrypt drivers and `getFEK`/`getBIK` deduplicated via
  comptime generics (DUP-001..003); FEK/BIK cache hits use a stack-buffer
  key (no allocation) (perf#2)
- `KeyManager.wrapKey`/`unwrapKey` use a comptime AAD constant and gained
  direct test coverage
- Bench methodology: ReleaseFast module graph, SMP allocator, parallel
  warmup (B1-B3)
- `minimum_zig_version` raised from 0.15.1 to 0.16.0 — the library depends
  on 0.16-era APIs (`std.Io.Threaded`, `std.Io.Mutex`) and does not compile
  on 0.15.1 (CI-001)

### Added

- Runnable `examples/basic.zig` (encrypt → serialize → decrypt) and
  `examples/annotations.zig`, wired into `zig build examples` and compiled
  by `zig build check` (#24, #25)
- `docs/KEY_HIERARCHY.md`: key derivation, envelope format, blind-index
  flow, rotation, and zeroization guarantees (#23)
- Doc comments on all public root aliases; thread-safety, key-lifetime,
  and cache-residency guidance in the module docs (DOC-001..003)

### Fixed

- README quick start now shows the real API (`fle.init` never existed);
  false "Zero Dependencies" claim corrected; Out of Scope section added (#26)

## [0.1.5] - 2026-06-02

### Changed

- Converged transitive `tls` dependency onto v0.1.9 (diamond sync);
  added `sync_diamond_deps` auto-resolver script

## [0.1.4] - 2026-05-31

### Changed

- Converged dependency-graph pins across the zig-devnw siblings;
  aligned thread-pool pin

## [0.1.3] - 2026-05-02

### Changed

- Converged sibling dependency pins; release with tagged sibling deps

## [0.1.2] - 2026-05-02

### Fixed

- Observability seam: hardcode `enabled = false` default to avoid the
  Zig 0.16 `build_options` module-dedup error

## [0.1.1] - 2026-05-02

### Changed

- Release bump onto tagged sibling dependencies

## [0.1.0] - 2026-05-02

### Added

- FLE core extracted from Geode: AEAD envelope encryption (AES-256-GCM,
  ChaCha20-Poly1305), HKDF-SHA256 key hierarchy (master → TRK → SK →
  FEK/BIK), searchable blind indices, schema annotation parsing, key
  rotation
- Bulk encrypt/decrypt API (`encryptFieldsBulk`/`decryptFieldsBulk`) with
  serial and thread-pool parallel paths, partial-success semantics, and a
  bench suite
- Opt-in OpenTelemetry observability seam (`-Dwith_otel`, no-op and
  dependency-free by default)
- Diamond-dependency detector pre-commit hook; CI pipeline (gitleaks,
  zig fmt, test matrix)

### Changed

- Migrated to Zig 0.16.0 (enum casts, `crypto.random` replacement, build
  API updates)

[Unreleased]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.6...HEAD
[0.1.6]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.5...v0.1.6
[0.1.5]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.4...v0.1.5
[0.1.4]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.3...v0.1.4
[0.1.3]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.2...v0.1.3
[0.1.2]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.1...v0.1.2
[0.1.1]: https://gitlab.com/devnw/zig/fle/-/compare/v0.1.0...v0.1.1
[0.1.0]: https://gitlab.com/devnw/zig/fle/-/releases/v0.1.0
