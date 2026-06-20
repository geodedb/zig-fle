<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 mode (`-Dfips`)

`fle` supports a build-flag-gated FIPS-140-3 mode. When `-Dfips=true`, all
security-relevant cryptography routes through a **linked FIPS-140-3 validated
module** (the OpenSSL 3.x FIPS provider) and non-FIPS-approved algorithms are
compiled out or rejected at runtime. The flag mirrors the existing `with_otel`
flag: **off by default, zero overhead when off**.

## The seam

`src/crypto_backend.zig` is the canonical crypto seam (copied verbatim from the
`fips` package). Every security primitive in `fle` imports it; no security path
calls `std.crypto` directly.

```zig
const backend = @import("crypto_backend");
pub const fips_enabled = build_options.fips;          // comptime
const impl = if (fips_enabled) @import("fips") else @import("std_shim");
```

- `-Dfips=false` (default): the seam re-exports the local `std_shim` backend
  (std.crypto-backed). **No `fips` dependency is resolved, no lazy fetch
  happens, and no OpenSSL is linked.** The non-FIPS path depends only on `std`
  plus the local `src/policy.zig`.
- `-Dfips=true`: the seam re-exports `@import("fips")` — the only branch that
  pulls the lazy `fips` dependency and links libcrypto/libssl.

The three canonical files (`crypto_backend.zig`, `std_shim.zig`, `policy.zig`)
are kept byte-identical to their `fips/` sources; fix the `fips/` canonical
source and re-copy rather than hand-editing them here.

## Approved algorithms used by `fle`

| Use | Algorithm | Seam call |
|-----|-----------|-----------|
| Field AEAD | AES-256-GCM | `crypto_backend.Aead.seal/open(.aes_256_gcm, …)` |
| Key derivation (TRK→SK→FEK/BIK) | HKDF-SHA256 | `crypto_backend.Kdf.hkdf(.sha256, …)` |
| Blind index | HMAC-SHA256 | `crypto_backend.Mac.hmac(.sha256, …)` |
| Nonces / random keys | SP 800-90A CSPRNG | `crypto_backend.Csprng.bytes(…)` |

Under `-Dfips=true` these are OpenSSL's FIPS implementations; under
`-Dfips=false` they are the byte-compatible `std.crypto` equivalents.

## Behavior changes under `-Dfips=true`

| Surface | `-Dfips=false` | `-Dfips=true` |
|---------|----------------|---------------|
| `aead.encryptField`/`decryptField` with `.chacha20_poly1305` | ChaCha20-Poly1305 round-trips | returns `Error.InvalidAlg` (ChaCha is not FIPS-approved) |
| `aead.encryptField`/`decryptField` with `.aes256_gcm` | AES-256-GCM | AES-256-GCM (unchanged; the only approved envelope alg) |
| `wrapKey32` / `unwrapKey32` (XChaCha20-Poly1305 key wrap) | available via `fle.key_wrap` | **compiled out** — `fle.key_wrap` is empty. Use `KeyManager.wrapKey`/`unwrapKey` (AES-256-GCM) instead |

The `EnvelopeV1` wire format, `makeAAD` construction, the key hierarchy, the
blind index, and the bulk API are unchanged across modes. `Alg` keeps all three
wire-stable variants; the ChaCha paths are simply unreachable/rejected under
fips.

> **Note on `key_wrap` (Zig 0.16):** Zig 0.16 removed `pub usingnamespace`, so
> the XChaCha key-wrap helpers are gated via the `fle.key_wrap` namespace, which
> is genuinely **empty** under `-Dfips=true` (`@hasDecl(fle.key_wrap,
> "wrapKey32")` is false). The flat `fle.wrapKey32`/`fle.unwrapKey32` aliases
> resolve to `void` under fips (so they pull no XChaCha code) and to the real
> functions under non-fips.

## Building & testing

```sh
# Default (std shim, no OpenSSL, zero overhead) — must be green:
zig build test --summary all

# FIPS backend (OpenSSL FIPS provider at /usr/local/ssl):
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf \
  zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl --summary all

# Both at once:
make test-dual
```

`-Dopenssl_path=` points at a non-standard OpenSSL install prefix
(`<prefix>/include`, `<prefix>/lib`, `<prefix>/lib64`). The FIPS-built OpenSSL
is provisioned by the `fips` package's `make deps` (default prefix
`/usr/local/ssl`).

## Enforcement proof

`tests/fips_enforcement_test.zig` is a dual-mode runtime proof:

- ChaCha20-Poly1305 is rejected at the AEAD boundary under fips (`InvalidAlg`).
- The XChaCha key-wrap helpers are absent from `fle.key_wrap` under fips.

Both hold under `-Dfips=true`; both surfaces remain available under
`-Dfips=false`.

## Out of scope

The pre-existing `tests/integration.zig` `integration: version is defined` test
asserts `fle.version == "0.1.0"` while `src/root.zig` declares `"0.1.6"`; it
fails on `main` independent of this work and is intentionally left untouched.
