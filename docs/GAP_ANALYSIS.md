# GAP Analysis

Last updated: 2026-03-23

Repository status: FLE core extracted from Geode. All crypto, key management, blind index, and annotation modules are in place with passing tests. Cross-project overlap with `encrypted-fs` and `spyder/agent` has been analyzed.

## Goal

Extract the reusable field-level-encryption core from Geode while leaving product-specific persistence, configuration, and enforcement adapters in Geode. Consolidate overlapping crypto patterns from `encrypted-fs` and `spyder/agent` where the FLE library is the natural owner.

## Intended Boundary

Move into this library:

| Geode source | Why it belongs here | Status |
|---|---|---|
| `src/crypto/aead.zig:26`, `:81`, `:119`, `:163` | Core AEAD envelope, AAD construction, encrypt/decrypt logic | **Closed** |
| `src/crypto/hkdf.zig:8`, `:59`, `:70`, `:77`, `:84`, `:98` | Portable key-derivation hierarchy | **Closed** |
| `src/crypto/hmac.zig:7`, `:16`, `:41`, `:54` | Blind-index normalization and token helpers | **Closed** |
| `src/keys/types.zig:7`, `:15`, `:33`, `:45`, `:52` | Portable key metadata/value types | **Closed** |
| `src/keys/manager.zig:65`, `:139`, `:170`, `:203`, `:226`, `:235`, `:244`, `:295` | Reusable key management logic once env/config assumptions are removed | **Closed** |
| `src/index/blind_index.zig:2`, `:24`, `:29`, `:61`, `:106`, `:135` | Searchable blind-index implementation | **Closed** |
| `src/schema/annotations.zig:7`, `:37`, `:62`, `:87`, `:129`, `:220`, `:269` | Schema annotation parsing and metadata application | **Closed** |

Keep in Geode:

| Geode source | Why it stays | Status |
|---|---|---|
| `src/schema/fle_catalog.zig:17`, `:216`, `:339`, `:344`, `:378`, `:463` | Current catalog is global, file-backed, and Geode-runtime specific | **Won't Do** - stays in Geode by design |
| `src/security/test_fle_enforcement.zig` | Product enforcement behavior should remain Geode integration coverage | **Won't Do** - stays in Geode by design |

## Concrete Gaps (Geode extraction - closed)

| Gap | Evidence | Impact | Required fix | Status |
|---|---|---|---|---|
| Key manager is hard-wired to a Geode env var | `src/keys/manager.zig:73` through `:94` require `GEODE_MASTER_KEY` | Prevents generic reuse | Replace with an injected key provider / master-key source | **Closed** - `KeyManager.init` now takes explicit `master_key: [32]u8` parameter |
| Standalone packaging currently relies on cross-module aliases | `src/keys/manager.zig:2`, `:3`, `:4`, `src/index/blind_index.zig:2` | Direct standalone tests fail without those aliases | Make this repo the canonical owner of those modules and wire them internally | **Closed** - all imports use relative paths within the repo |
| Catalog persistence is product-specific | `src/schema/fle_catalog.zig:339`, `:344`, `:378`, `:463` | Should not be part of a reusable crypto core | Keep as Geode adapter or move to a separate storage package later | **Won't Do** - remains in Geode as planned |
| Library/code boundary is blurred by enforcement tests and runtime rules | `src/security/test_fle_enforcement.zig:27`, `:40`, `:64`, `:82`, `:104`, `:119`, `:133`, `:151`, `:172`, `:204`, `:219`, `:232`, `:250`, `:271`, `:289`, `:304`, `:323` | Risk of dragging Geode policy semantics into the library | Keep enforcement and policy logic in Geode | **Won't Do** - remains in Geode as planned |

---

## Cross-Project Overlap: `encrypted-fs`

Source: `../encrypted-fs` (`/home/benji/src/gl/devnw/zig/encrypted-fs`)

### Overlapping areas

#### Key wrapping (should move to FLE)

| encrypted-fs source | What it does | FLE equivalent | Gap |
|---|---|---|---|
| `src/encryption.zig:270-292` `wrapKey` / `unwrapKey` | Wraps a 32-byte key with XChaCha20-Poly1305, returns fixed 72-byte `nonce\|\|tag\|\|ciphertext` | `src/keys/manager.zig` `wrapKey` / `unwrapKey` | FLE already has key wrapping via `KeyManager.wrapKey`/`unwrapKey` but ties it to the manager instance. encrypted-fs has a standalone, stack-only version (no heap allocation, fixed-size output). FLE should expose a standalone `wrapKey`/`unwrapKey` that both projects can share. |

#### HKDF for wrapping-key derivation (should move to FLE)

| encrypted-fs source | What it does | FLE equivalent | Gap |
|---|---|---|---|
| `src/hsm_protector.zig:11-17` `deriveWrappingKey` | HKDF-SHA256 extract+expand with domain-separation string `"encrypted-fs-hsm-wrapping-key-v1"` | `src/crypto/hkdf.zig` `hkdfSha256` | Both projects implement HKDF-SHA256. FLE's implementation is a manual extract+expand loop. encrypted-fs uses `std.crypto.kdf.hkdf.Hkdf`. FLE should also offer a `deriveKey32` variant that accepts arbitrary salt+info, usable by encrypted-fs for its HSM wrapping derivation. This is already present (`hkdf.deriveKey32`) but not exported as a first-class standalone primitive. |

#### Algorithm enum (should consolidate)

| encrypted-fs source | What it does | FLE equivalent | Gap |
|---|---|---|---|
| `src/encryption.zig:26-43` `EncryptionAlgorithm` | Enum: `xchacha20_poly1305 = 0`, `aes_256_gcm = 1` with `nonceSz()` and `name()` helpers | `src/crypto/aead.zig:7-10` `Alg` | Both projects define algorithm enums. FLE uses `aes256_gcm = 1`, `chacha20_poly1305 = 2`. encrypted-fs uses `xchacha20_poly1305 = 0`, `aes_256_gcm = 1`. The wire values differ and XChaCha20 (24-byte nonce) is not the same as ChaCha20 (12-byte nonce). Consolidation requires a unified enum that covers all three variants. |

### Areas that stay in encrypted-fs

| encrypted-fs source | What it does | Why it stays |
|---|---|---|
| `src/encryption.zig:100-144` `deriveKeyWith` | PBKDF2 (SHA-256/SHA-512) and Argon2id password-to-key derivation with minimum-iteration enforcement | Password-based KDF is drive-encryption-specific. FLE's key hierarchy starts from an already-derived master key. |
| `src/encryption.zig:146-197` `hashKey*`, `verifyKeyHash` | SHA-256/BLAKE3 key hashing with salted variants and timing-safe comparison | Drive container integrity verification, not field-level concern. |
| `src/encryption.zig:199-233` `encryptDataWith` | Monotonic nonce counter for AES-GCM (SEC-014), hybrid nonce construction | Session-scoped nonce management for drive I/O. FLE uses per-field random nonces. |
| `src/protector.zig:1-71+` `PasswordProtectorData`, `HsmProtectorData` | Serializable protector data structures with KDF params, wrapped keys | Protector serialization format is specific to the encrypted-fs container format. |
| `src/hsm_protector.zig:26-60+` `createProtector` | PKCS#11 token interaction, PIN verification, certificate fingerprinting | HSM hardware interaction is specific to encrypted-fs. |
| `src/tpm2_protector.zig` | TPM2 sealed blob wrapping | Hardware-specific. |
| `src/vfs.zig`, `src/storage.zig`, `src/container_format.zig` | Virtual filesystem, container serialization | Drive-level concerns. |
| `src/signing.zig` | ECDSA/TPM2 signature verification for container integrity | Drive-level concern. |

### New gaps identified from encrypted-fs overlap

| Gap ID | Gap | Evidence | Impact | Required fix | Status |
|---|---|---|---|---|---|
| GAP-EFS-001 | FLE lacks standalone key wrap/unwrap | encrypted-fs `src/encryption.zig:270-292` has a zero-alloc `wrapKey`/`unwrapKey` that operates on fixed-size arrays. FLE's `KeyManager.wrapKey` requires a `*KeyManager` instance and heap-allocates the envelope. | encrypted-fs cannot depend on FLE for key wrapping without pulling in the full `KeyManager`. Other consumers (e.g., a future key-escrow tool) would face the same issue. | Add `pub fn wrapKey32(key: [32]u8, wrapping_key: [32]u8) [72]u8` and `pub fn unwrapKey32(wrapped: *const [72]u8, wrapping_key: [32]u8) ![32]u8` as standalone functions in `src/crypto/aead.zig` (stack-only, no allocator). | **Closed** - `wrapKey32`/`unwrapKey32` added to `src/crypto/aead.zig` using XChaCha20-Poly1305, stack-only, re-exported from `root.zig` |
| GAP-EFS-002 | Algorithm enum does not cover XChaCha20-Poly1305 | encrypted-fs `src/encryption.zig:26` defines `xchacha20_poly1305` (24-byte nonce). FLE `src/crypto/aead.zig:8` defines `chacha20_poly1305` (12-byte nonce). These are distinct algorithms. | Any consumer needing both 12-byte and 24-byte nonce ChaCha variants must maintain its own enum. | Extend `Alg` in `src/crypto/aead.zig` to include `xchacha20_poly1305 = 3` and support 24-byte nonces in `encryptField`/`decryptField`. Update `EnvelopeV1` nonce field to handle variable-length nonces or add an `EnvelopeV2`. | **Closed** - `Alg` extended with `xchacha20_poly1305 = 3`, `nonceSz()` and `name()` helpers added. XChaCha20 encryption available via `wrapKey32`/`unwrapKey32`; `encryptField`/`decryptField` reject XChaCha20 since `EnvelopeV1` uses 12-byte nonces. |
| GAP-EFS-003 | `hkdf.deriveKey32` not positioned as a shared primitive | encrypted-fs `src/hsm_protector.zig:11-17` reimplements HKDF-SHA256 extract+expand using `std.crypto.kdf.hkdf.Hkdf`. FLE has `hkdf.deriveKey32` but its doc and export framing present it as an internal helper for the key hierarchy, not a general-purpose HKDF primitive. | encrypted-fs cannot obviously depend on FLE's HKDF without reading into its internals. | Promote `hkdfSha256` and `deriveKey32` as first-class public API in root.zig with doc comments positioning them as general-purpose HKDF primitives usable outside the FLE key hierarchy. They are already exported; the gap is documentation and positioning. | **Closed** - doc comments updated to position as general-purpose RFC 5869 primitives; `hkdfSha256` and `deriveKey32` re-exported as top-level aliases in `root.zig` |

---

## Cross-Project Overlap: `spyder/agent`

Source: `~/src/gl/devnw/spyder/agent` (`/home/benji/src/gl/devnw/spyder/agent`)

### Overlapping areas

#### HKDF extract+expand (conceptual overlap only)

| spyder source | What it does | FLE equivalent | Assessment |
|---|---|---|---|
| `src/quic/crypto.zig:9-31` vendor stubs | HKDF extract/expand for QUIC Initial secrets with vendor dispatch. Stubs return zero arrays when vendor is unavailable. | `src/crypto/hkdf.zig` `hkdfSha256` | **No action needed.** Spyder's HKDF is protocol-specific (QUIC v2 labels, TLS 1.3 key schedule) and dispatches to a vendor TLS library. FLE's HKDF is a generic RFC 5869 implementation with field-encryption context strings. The primitives solve different problems at different layers. |
| `src/quic/crypto.zig:47-49` `deriveInitialSecret` | Derives QUIC v2 initial secret from connection ID using a fixed 20-byte salt (RFC 9369). | `src/crypto/hkdf.zig:70` `deriveTRK` | **No action needed.** QUIC uses a protocol-mandated salt and label structure that cannot be changed. FLE uses a domain-specific context hierarchy. Sharing an implementation would couple unrelated protocol layers. |

#### AEAD seal/open (conceptual overlap only)

| spyder source | What it does | FLE equivalent | Assessment |
|---|---|---|---|
| `src/quic/aead.zig:14-18` `InitialKeys` | 16-byte key, 12-byte IV, 16-byte HP key for QUIC AES-128-GCM. | `src/crypto/aead.zig:27` `EnvelopeV1` | **No action needed.** Spyder uses AES-128-GCM for QUIC packets (16-byte key). FLE uses AES-256-GCM for field encryption (32-byte key). Different algorithm parameters, different envelope formats, different security requirements. |
| `src/quic/aead.zig:33-50+` `seal` | Encrypts QUIC packet payload with nonce XOR for packet number masking. Dispatches to vendor crypto. | `src/crypto/aead.zig:119` `encryptField` | **No action needed.** QUIC AEAD requires packet-number-based nonce construction and header protection. FLE uses random nonces with AAD context binding. The operations are structurally different. |

#### Vtable-based interface pattern (design pattern to adopt)

| spyder source | What it does | FLE relevance |
|---|---|---|
| `src/update/verification/interface.zig:50-60` `Verifier` | Defines a vtable-based interface: `ptr: *anyopaque` + `vtable: *const VTable` with `verify`, `verifyWithStats`, `deinit` methods. Allows pluggable verification backends (TUF, custom). | FLE's `KeyManager` currently takes a raw `[32]u8` master key. A future `MasterKeyProvider` vtable interface would allow pluggable key sources (env var, KMS, HSM, file) without changing `KeyManager` internals. This is a design pattern gap, not a code-sharing gap. |

### Areas that stay in spyder

| spyder source | What it does | Why it stays |
|---|---|---|
| `src/quic/crypto.zig` (all) | QUIC v2 key schedule with vendor TLS dispatch | Protocol-specific, mandated by RFC 9001/9369. |
| `src/quic/aead.zig` (all) | QUIC packet encryption with header protection | Packet-level concern with nonce XOR semantics. |
| `src/update/verification/` (all) | TUF signature verification, M-of-N threshold | Software update verification, unrelated to field encryption. |
| `src/update/minituf.zig` | Canonical signing message framing `"TUF-SIG\x00"` | TUF-specific domain separation. |
| `src/tls/skeleton.zig` | TLS 1.3 handshake key schedule | Protocol-specific. |

### New gaps identified from spyder overlap

| Gap ID | Gap | Evidence | Impact | Required fix | Status |
|---|---|---|---|---|---|
| GAP-SPY-001 | FLE lacks a `MasterKeyProvider` interface | spyder `src/update/verification/interface.zig:50-60` demonstrates a vtable pattern for pluggable backends. FLE's `KeyManager.init` takes a raw `[32]u8`, forcing every caller to source the key before calling init. | Callers that need KMS, HSM, env-var, or file-based key loading must implement that logic themselves and cannot swap providers at runtime. Testing requires generating random keys inline. | Add a `MasterKeyProvider` vtable interface in `src/keys/provider.zig`: `ptr: *anyopaque` + `vtable: *const VTable` with `fn getMasterKey(self) ![32]u8` and `fn deinit(self) void`. Add `KeyManager.initWithProvider(allocator, provider)` alongside the existing `init(allocator, master_key)`. Provide a `StaticKeyProvider` for the current direct-injection path. | **Closed** - `MasterKeyProvider` vtable, `StaticKeyProvider`, and `EnvKeyProvider` added in `src/keys/provider.zig`. `KeyManager.initWithProvider` added. All re-exported from `root.zig`. |

---

## Tests And Benchmarks Ported

| Geode test | Coverage provided | Status |
|---|---|---|
| `src/crypto/aead.zig:215`, `:240`, `:262` | Envelope round-trip and AAD integrity | **Ported** - inline tests in `src/crypto/aead.zig` |
| `src/crypto/hkdf.zig:111`, `:142` | Key-derivation hierarchy behavior | **Ported** - inline tests in `src/crypto/hkdf.zig` |
| `src/crypto/hmac.zig:67`, `:87`, `:99` | Blind-index HMAC normalization and token encoding | **Ported** - inline tests in `src/crypto/hmac.zig` |
| `src/keys/manager.zig:338`, `:369`, `:412` | FEK/BIK derivation and rotation | **Ported** - inline tests in `src/keys/manager.zig` (updated for injected key) |
| `src/index/blind_index.zig:161`, `:194`, `:216` | Blind-index storage and lookup | **Ported** - inline tests in `src/index/blind_index.zig` |
| `src/schema/annotations.zig:327`, `:346`, `:363`, `:389` | Annotation parsing and application | **Ported** - inline tests in `src/schema/annotations.zig` |
| `tests/test_fle_lifecycle.zig:7` | End-to-end lifecycle check | **Ported** - `tests/integration.zig` covers full lifecycle |
| `tests/test_tde_kms_integration.zig:16`, `:76`, `:112`, `:149`, `:185`, `:225`, `:266`, `:297` | Geode integration parity after extraction | **Blocked** - requires Geode to import this library; tracked as a Geode-side task |

Benchmarks identified:

- No dedicated standalone FLE benchmark was found in Geode. Extraction should begin with deterministic correctness and interoperability coverage.

## Public API

Exposed through `src/root.zig`:

- `Alg` (algorithm enum: `aes256_gcm`, `chacha20_poly1305`, `xchacha20_poly1305` with `nonceSz()`/`name()`)
- `EnvelopeV1`
- `makeAAD` (via `aead.makeAAD`)
- `encryptField` / `decryptField` (via `aead.*`)
- `wrapKey32` / `unwrapKey32` (standalone XChaCha20 key wrapping, stack-only)
- `hkdfSha256` / `deriveKey32` (general-purpose HKDF-SHA256, RFC 5869)
- `deriveTRK` / `deriveSK` / `deriveFEK` / `deriveBIK` (via `hkdf.*`)
- `KeyIds`
- `KeyManager` (accepts explicit master key or `MasterKeyProvider`)
- `MasterKeyProvider` / `StaticKeyProvider` / `EnvKeyProvider`
- `BlindIndex`
- `AnnotationParser` / `FieldMetadata` / `TypeMetadata`

## Extraction Plan

1. ~~Move crypto primitives, key types, blind index, and annotation parsing into this repo.~~ **Done**
2. ~~Replace `GEODE_MASTER_KEY` loading with an explicit provider interface.~~ **Done** - `KeyManager.init(allocator, master_key)`
3. ~~Collapse the current `fle_*` alias scheme so the library owns its own module graph.~~ **Done** - all imports are relative
4. ~~Port the crypto, blind-index, annotation, and key-manager tests.~~ **Done** - 19 unit tests + 7 integration tests
5. ~~Leave catalog persistence and Geode enforcement wiring in Geode.~~ **Done** - not included
6. ~~Add standalone key wrap/unwrap (GAP-EFS-001) so encrypted-fs can depend on FLE for wrapping.~~ **Done** - `wrapKey32`/`unwrapKey32` in `aead.zig`
7. ~~Extend algorithm enum to cover XChaCha20-Poly1305 (GAP-EFS-002).~~ **Done** - `xchacha20_poly1305 = 3` with `nonceSz()`/`name()`
8. ~~Promote HKDF as a first-class public primitive (GAP-EFS-003).~~ **Done** - doc + root.zig aliases
9. ~~Add `MasterKeyProvider` vtable interface (GAP-SPY-001).~~ **Done** - `provider.zig` + `initWithProvider`
10. ~~Fix audit findings (AUDIT-001 through AUDIT-009).~~ **Done** - all 9 findings resolved

## Acceptance Criteria

- [x] This repo builds without Geode-specific env vars or singleton state.
- [x] `KeyManager` no longer hardcodes `GEODE_MASTER_KEY`.
- [x] `fle_catalog.zig` remains adapter code outside the library boundary.
- [ ] Geode integration tests still pass against the extracted core. *(Blocked - requires Geode to depend on this library)*
- [x] Standalone `wrapKey32`/`unwrapKey32` available without `KeyManager` instance (GAP-EFS-001).
- [x] `Alg` enum covers XChaCha20-Poly1305 with 24-byte nonces (GAP-EFS-002).
- [x] HKDF primitives documented and positioned as general-purpose (GAP-EFS-003).
- [x] `MasterKeyProvider` vtable interface with `StaticKeyProvider` default (GAP-SPY-001).

---

## Audit Findings (2026-03-23)

| ID | Finding | Severity | Required fix | Status |
|---|---|---|---|---|
| AUDIT-001 | `encryptField` hardcodes `key_version = 1` in returned envelope | Critical | Accept `key_version` as parameter | **Closed** - `key_version: u16` parameter added; callers pass the version explicitly |
| AUDIT-002 | `nonce_opt` parameter allows caller-injected nonces, enabling AES-GCM nonce reuse | Critical | Remove `nonce_opt` from public API | **Closed** - parameter removed; nonces are always random from OS CSPRNG |
| AUDIT-003 | `rewrapSK`/`rewrapTRK` are no-ops that discard results | Critical | Remove until persistence layer exists | **Closed** - functions removed; replaced with `clearCache()` for cache invalidation |
| AUDIT-004 | `EnvKeyProvider` SHA-256 fallback for short keys; truncates hex-encoded keys | Critical | Reject short values, add hex decoding | **Closed** - values < 32 bytes rejected; 64-char hex auto-decoded; env var securely zeroed |
| AUDIT-005 | AAD injection via `0x1F` separator enables cross-tenant collisions | High | Use length-prefixed encoding | **Closed** - AAD now uses `[len:u32 LE][data]` per field, canonically unambiguous |
| AUDIT-006 | Cache clearing uses `clearRetainingCapacity` without zeroing key material | High | Iterate and secureZero before clear | **Closed** - added `KeyCache.secureClear()` that zeros keys and frees strings before clearing |
| AUDIT-007 | HKDF tests lack RFC 5869 known-answer vectors | High | Add test case 1 from RFC 5869 Appendix A | **Closed** - RFC 5869 test vector added and passing |
| AUDIT-008 | HKDF intermediates `t_prev`/`t` not securely zeroed; `last_accessed` is dead code | Medium | Add secureZero; remove dead field | **Closed** - `secureZero` added for `t`/`t_prev`; `last_accessed` removed from `CacheEntry` |
| AUDIT-009 | No thread safety documentation | High | Document single-threaded constraint | **Closed** - thread safety section added to `root.zig` doc comment |

## Re-Audit Findings (2026-03-23, pass 2)

| ID | Finding | Severity | Required fix | Status |
|---|---|---|---|---|
| FIX-01 | Double-free in `encryptField` XChaCha20 path — `errdefer` + explicit `free` both fire | Critical | Remove explicit `free`; let `errdefer` handle it | **Closed** — explicit free removed at `aead.zig:164` |
| FIX-02 | `rotateFEK` use-after-free — `key_path` freed via `defer` after `StringHashMap.put` stores pointer | Critical | Remove `defer free`; let HashMap own the string; free old key on re-rotation | **Closed** — `defer` replaced with `errdefer`; `fetchRemove` frees old key; `deinit` frees all owned keys |
| FIX-03 | `EnvKeyProvider` hex fallback silently produces wrong key on partial-hex 64-byte input | High | Make hex decode all-or-nothing for 64-byte values | **Closed** — hex decode failure now returns `MasterKeyUnavailable` immediately |
| FIX-04 | `StaticKeyProvider.deinit` doesn't zero key material | Medium | Add `secureZero` in `deinitFn` | **Closed** — `deinitFn` now zeros `self.key` |
| FIX-05 | Missing tests: XChaCha20 rejection, rotateFEK version persistence, clearCache, makeAAD format | High | Add tests for each gap | **Closed** — 4 new tests added (encryptField XChaCha rejection, makeAAD format, rotateFEK multi-rotation, clearCache re-derivation) |
| FIX-06 | Dead code: `IndexEntry` in blind_index.zig, `KeyMetadata`/`WrappedKeyEnvelope`/`KeyVersion`/`RotationStats` in types.zig | Low | Remove unused types | **Closed** — all dead types removed |

## Audit Pass 3 Findings (2026-03-23)

| ID | Finding | Severity | Required fix | Status |
|---|---|---|---|---|
| P3-01 | `getFEK`/`getBIK` leak `cache_key` on error paths (missing `errdefer`) | Medium | Add `errdefer self.allocator.free(cache_key)` | **Closed** — errdefer added in both functions |
| P3-02 | `BlindIndex.put` dangling pointer on OOM during `dupe`; `owned_id` leak on append OOM | Medium | Allocate owned key before `getOrPut`; add `errdefer` for `owned_id` | **Closed** — key duped before getOrPut; errdefer added for owned_id |
| P3-03 | Dead `setKeyVersion` function; `rotateFEK` u16 overflow; version state loss on OOM between `fetchRemove` and `put` | Medium | Remove dead code; add overflow guard; use `getOrPut` instead of `fetchRemove`+`put` | **Closed** — `setKeyVersion` removed; overflow returns `InvalidKeyVersion`; `getOrPut` replaces `fetchRemove`+`put` |
| P3-04 | `TypeMetadata.deinit` does not free `to_roles`/`tags` slices from `applyAnnotations` | Medium | Iterate fields in deinit and free owned slices | **Closed** — `TypeMetadata` stores allocator; deinit frees `to_roles`/`tags` |

## Audit Pass 4 Findings (2026-03-23)

| ID | Finding | Severity | Required fix | Status |
|---|---|---|---|---|
| P4-01 | `BlindIndex.put` errdefer on `owned_field_key` fires after ownership transferred to map, causing double-free on OOM in subsequent operations | Medium | Replace errdefer with scoped catch on `getOrPut` call | **Closed** — errdefer replaced with explicit `catch` that frees `owned_field_key` only if `getOrPut` fails; after success, map or explicit free handles lifetime |

## Open Gap Summary

All gaps are closed. No open gaps remain.

Remaining low-severity items tracked but not blocking:

- Unused error variants (`NonceReuse`, `SearchNotPermitted`, `RotationInProgress`) — forward-declared for future use
- `KeyManager.wrapKey`/`unwrapKey` lack dedicated test coverage (underlying aead primitives are tested)
- `EnvKeyProvider` lacks dedicated test coverage (requires env var mocking)
- README Quick Start example is stale (correct example in root.zig doc comment)

## Test Results

```text
Unit tests:     29/29 passed
Integration:     7/7  passed
Formatting:     clean
Total:          36 tests
```
