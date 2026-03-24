# GAP Analysis - Resolved Items

Last updated: 2026-03-23

## Closed Gaps

### GAP-001: Key manager hard-wired to GEODE_MASTER_KEY

- **Evidence**: Geode `src/keys/manager.zig:73-94` called `std.process.getEnvVarOwned(allocator, "GEODE_MASTER_KEY")`
- **Resolution**: `KeyManager.init` now accepts `master_key: [32]u8` as an explicit parameter. Callers source the key from their own KMS, HSM, or env var.
- **Files changed**: `src/keys/manager.zig`
- **Verification**: All 3 KeyManager tests pass without any env var set.

### GAP-002: Cross-module aliases prevent standalone builds

- **Evidence**: Geode `src/keys/manager.zig:2-4` imported `fle_key_types`, `fle_aead`, `fle_hkdf`; `src/index/blind_index.zig:2` imported `fle_hmac`
- **Resolution**: All imports use relative paths within this repo (`@import("types.zig")`, `@import("../crypto/aead.zig")`, etc.)
- **Files changed**: `src/keys/manager.zig`, `src/index/blind_index.zig`
- **Verification**: `zig build test` and `zig build test-integration` pass without module aliases.

### GAP-003: Catalog persistence is product-specific (Won't Do)

- **Evidence**: Geode `src/schema/fle_catalog.zig` contains global file-backed catalog
- **Resolution**: Intentionally kept in Geode. This library only owns the crypto/key/annotation core.
- **Reason**: Catalog is tightly coupled to Geode runtime; extraction would require an adapter layer that is out of scope for the initial extraction.

### GAP-004: Enforcement tests blur library boundary (Won't Do)

- **Evidence**: Geode `src/security/test_fle_enforcement.zig` contains Geode-specific policy tests
- **Resolution**: Intentionally kept in Geode. Enforcement and policy logic are product-specific.
- **Reason**: Including enforcement would drag Geode policy semantics into a general-purpose crypto library.

## Ported Tests

| Source | Target | Tests |
|---|---|---|
| Geode `src/crypto/aead.zig` tests | `src/crypto/aead.zig` | 3 tests (round-trip, auth fail, serialization) |
| Geode `src/crypto/hkdf.zig` tests | `src/crypto/hkdf.zig` | 2 tests (derivation, hierarchy) |
| Geode `src/crypto/hmac.zig` tests | `src/crypto/hmac.zig` | 3 tests (RFC vector, normalization, hex round-trip) |
| Geode `src/keys/manager.zig` tests | `src/keys/manager.zig` | 3 tests (FEK caching, rotation, BIK derivation) |
| Geode `src/index/blind_index.zig` tests | `src/index/blind_index.zig` | 3 tests (put/lookup, normalization, remove) |
| Geode `src/schema/annotations.zig` tests | `src/schema/annotations.zig` | 4 tests (encrypted, searchable, visible, apply) |
| Geode lifecycle test | `tests/integration.zig` | 7 tests (lifecycle, hierarchy, rotation, blind index, annotations, ChaCha, version) |

**Total (Geode extraction): 19 unit + 7 integration = 26 tests**

---

## Cross-Project Gaps (encrypted-fs / spyder)

### GAP-EFS-001: Standalone key wrap/unwrap (Closed)

- **Evidence**: encrypted-fs `src/encryption.zig:270-292` has stack-only `wrapKey`/`unwrapKey` using XChaCha20. FLE's `KeyManager.wrapKey` requires a manager instance and heap-allocates.
- **Resolution**: Added `wrapKey32` and `unwrapKey32` to `src/crypto/aead.zig`. Stack-only, no allocator. Returns fixed 72-byte array (nonce:24 + tag:16 + ciphertext:32). Re-exported from `root.zig`.
- **Files changed**: `src/crypto/aead.zig`, `src/root.zig`
- **Verification**: 2 new tests (round-trip, wrong-key rejection).

### GAP-EFS-002: XChaCha20-Poly1305 in algorithm enum (Closed)

- **Evidence**: encrypted-fs `src/encryption.zig:26` defines `xchacha20_poly1305` (24-byte nonce). FLE only had `chacha20_poly1305` (12-byte nonce).
- **Resolution**: Added `xchacha20_poly1305 = 3` to `Alg` enum with `nonceSz()` and `name()` helpers. `encryptField`/`decryptField` reject XChaCha20 since `EnvelopeV1` uses 12-byte nonces; XChaCha20 encryption is available via `wrapKey32`/`unwrapKey32`.
- **Files changed**: `src/crypto/aead.zig`
- **Verification**: 1 new test (nonceSz/name helpers).

### GAP-EFS-003: HKDF as first-class public primitive (Closed)

- **Evidence**: encrypted-fs `src/hsm_protector.zig:11-17` reimplements HKDF-SHA256. FLE had the same primitive but documented as an internal helper.
- **Resolution**: Updated doc comments on `hkdfSha256` and `deriveKey32` to position as general-purpose RFC 5869 primitives. Added top-level re-exports in `root.zig`: `fle.hkdfSha256` and `fle.deriveKey32`.
- **Files changed**: `src/crypto/hkdf.zig`, `src/root.zig`
- **Verification**: No new tests needed (existing HKDF tests already cover the primitives).

### GAP-SPY-001: MasterKeyProvider vtable interface (Closed)

- **Evidence**: spyder `src/update/verification/interface.zig:50-60` demonstrates vtable pattern. FLE's `KeyManager.init` only accepted raw `[32]u8`.
- **Resolution**: Created `src/keys/provider.zig` with:
  - `MasterKeyProvider` vtable (`ptr: *anyopaque` + `VTable` with `getMasterKey`/`deinit`)
  - `StaticKeyProvider` (wraps a static `[32]u8`)
  - `EnvKeyProvider` (reads from environment variable, SHA-256 hashes if < 32 bytes)
  - Added `KeyManager.initWithProvider(allocator, provider)` alongside existing `init`
  - All types re-exported from `root.zig`
- **Files changed**: `src/keys/provider.zig` (new), `src/keys/manager.zig`, `src/root.zig`
- **Verification**: 2 new tests (StaticKeyProvider round-trip, initWithProvider parity with init).

---

## Audit Findings (2026-03-23)

### AUDIT-001: encryptField hardcoded key_version=1 (Closed - Critical)

- **Evidence**: `src/crypto/aead.zig:180` returned `.key_version = 1` regardless of actual version
- **Resolution**: Added `key_version: u16` parameter to `encryptField`. Callers pass the version explicitly.
- **Files changed**: `src/crypto/aead.zig`, `src/keys/manager.zig`, `tests/integration.zig`, `src/root.zig`

### AUDIT-002: nonce_opt allows nonce reuse (Closed - Critical)

- **Evidence**: `encryptField` accepted `nonce_opt: ?[12]u8` enabling caller-injected nonces
- **Resolution**: Removed `nonce_opt` parameter entirely. Nonces are always generated randomly from OS CSPRNG.
- **Files changed**: `src/crypto/aead.zig`, all callers updated

### AUDIT-003: rewrapSK/rewrapTRK are no-ops (Closed - Critical)

- **Evidence**: Both functions generated random keys, wrapped/unwrapped, then discarded results via `defer`
- **Resolution**: Removed both functions. Added `KeyManager.clearCache()` for cache invalidation after rotation events.
- **Files changed**: `src/keys/manager.zig`

### AUDIT-004: EnvKeyProvider SHA-256 fallback (Closed - Critical)

- **Evidence**: Values < 32 bytes were SHA-256 hashed (no stretching). 64-char hex keys were truncated to 32 ASCII bytes.
- **Resolution**: Values < 32 bytes now rejected with `MasterKeyUnavailable`. 64-char hex values are decoded to 32 bytes. Env var copy is securely zeroed before free.
- **Files changed**: `src/keys/provider.zig`

### AUDIT-005: AAD injection via 0x1F separator (Closed - High)

- **Evidence**: `makeAAD` used 0x1F as field delimiter; inputs containing 0x1F could produce cross-tenant AAD collisions
- **Resolution**: AAD now uses length-prefixed encoding: `[len:u32 LE][data]` per field. Canonically unambiguous regardless of content.
- **Files changed**: `src/crypto/aead.zig`
- **Note**: This is a wire-format breaking change. Existing encrypted data using the old AAD format will fail AEAD auth verification.

### AUDIT-006: Cache clearing without zeroing (Closed - High)

- **Evidence**: `clearRetainingCapacity()` at `manager.zig:249-250` left key material in retained memory; also leaked owned key strings
- **Resolution**: Added `KeyCache.secureClear()` that iterates entries, `secureZero`s keys, frees owned strings, then clears. Used by `KeyManager.clearCache()`.
- **Files changed**: `src/keys/manager.zig`

### AUDIT-007: HKDF lacks RFC 5869 test vectors (Closed - High)

- **Evidence**: HKDF tests only checked "non-zero" and "deterministic" properties
- **Resolution**: Added RFC 5869 Appendix A Test Case 1 with full known-answer verification (42-byte OKM).
- **Files changed**: `src/crypto/hkdf.zig`

### AUDIT-008: HKDF intermediates not zeroed; dead code (Closed - Medium)

- **Evidence**: `t_prev` and `t` buffers in HKDF expand loop were not securely zeroed. `CacheEntry.last_accessed` was written but never read.
- **Resolution**: Added `secureZero` for `t` (per iteration) and `t_prev` (after loop). Removed `last_accessed` field and timestamp calls from `CacheEntry`.
- **Files changed**: `src/crypto/hkdf.zig`, `src/keys/manager.zig`

### AUDIT-009: Thread safety not documented (Closed - High)

- **Evidence**: `KeyManager` and `BlindIndex` use unsynchronized `StringHashMap` with no documentation about thread safety constraints
- **Resolution**: Added Thread Safety section to `root.zig` module doc comment. States that `KeyManager` and `BlindIndex` are NOT thread-safe and require external synchronization. Stateless functions are safe for concurrent use.
- **Files changed**: `src/root.zig`

## Updated Test Totals

| Category | Count |
|---|---|
| Geode-ported unit tests | 18 |
| Cross-project gap tests | 5 |
| Provider tests | 1 |
| Audit RFC 5869 test | 1 |
| **Total unit tests** | **25** |
| Integration tests | 7 |
| **Grand total** | **32** |
