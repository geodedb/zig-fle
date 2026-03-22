# GAP Analysis

Last updated: 2026-03-21

Repository status: bootstrapped from `../zig-template`; no Geode code has been moved yet.

## Goal

Extract the reusable field-level-encryption core from Geode while leaving product-specific persistence, configuration, and enforcement adapters in Geode.

## Intended Boundary

Move into this library:

| Geode source | Why it belongs here |
|---|---|
| `src/crypto/aead.zig:26`, `:81`, `:119`, `:163` | Core AEAD envelope, AAD construction, encrypt/decrypt logic |
| `src/crypto/hkdf.zig:8`, `:59`, `:70`, `:77`, `:84`, `:98` | Portable key-derivation hierarchy |
| `src/crypto/hmac.zig:7`, `:16`, `:41`, `:54` | Blind-index normalization and token helpers |
| `src/keys/types.zig:7`, `:15`, `:33`, `:45`, `:52` | Portable key metadata/value types |
| `src/keys/manager.zig:65`, `:139`, `:170`, `:203`, `:226`, `:235`, `:244`, `:295` | Reusable key management logic once env/config assumptions are removed |
| `src/index/blind_index.zig:2`, `:24`, `:29`, `:61`, `:106`, `:135` | Searchable blind-index implementation |
| `src/schema/annotations.zig:7`, `:37`, `:62`, `:87`, `:129`, `:220`, `:269` | Schema annotation parsing and metadata application |

Keep in Geode:

| Geode source | Why it stays |
|---|---|
| `src/schema/fle_catalog.zig:17`, `:216`, `:339`, `:344`, `:378`, `:463` | Current catalog is global, file-backed, and Geode-runtime specific |
| `src/security/test_fle_enforcement.zig` | Product enforcement behavior should remain Geode integration coverage |

## Concrete Gaps

| Gap | Evidence | Impact | Required fix |
|---|---|---|---|
| Key manager is hard-wired to a Geode env var | `src/keys/manager.zig:73` through `:94` require `GEODE_MASTER_KEY` | Prevents generic reuse | Replace with an injected key provider / master-key source |
| Standalone packaging currently relies on cross-module aliases | `src/keys/manager.zig:2`, `:3`, `:4`, `src/index/blind_index.zig:2` | Direct standalone tests fail without those aliases | Make this repo the canonical owner of those modules and wire them internally |
| Catalog persistence is product-specific | `src/schema/fle_catalog.zig:339`, `:344`, `:378`, `:463` | Should not be part of a reusable crypto core | Keep as Geode adapter or move to a separate storage package later |
| Library/code boundary is blurred by enforcement tests and runtime rules | `src/security/test_fle_enforcement.zig:27`, `:40`, `:64`, `:82`, `:104`, `:119`, `:133`, `:151`, `:172`, `:204`, `:219`, `:232`, `:250`, `:271`, `:289`, `:304`, `:323` | Risk of dragging Geode policy semantics into the library | Keep enforcement and policy logic in Geode |

## Tests And Benchmarks To Carry Over

| Geode test | Coverage provided |
|---|---|
| `src/crypto/aead.zig:215`, `:240`, `:262` | Envelope round-trip and AAD integrity |
| `src/crypto/hkdf.zig:111`, `:142` | Key-derivation hierarchy behavior |
| `src/crypto/hmac.zig:67`, `:87`, `:99` | Blind-index HMAC normalization and token encoding |
| `src/keys/manager.zig:338`, `:369`, `:412` | FEK/BIK derivation and rotation |
| `src/index/blind_index.zig:161`, `:194`, `:216` | Blind-index storage and lookup |
| `src/schema/annotations.zig:327`, `:346`, `:363`, `:389` | Annotation parsing and application |
| `tests/test_fle_lifecycle.zig:7` | End-to-end lifecycle check |
| `tests/test_tde_kms_integration.zig:16`, `:76`, `:112`, `:149`, `:185`, `:225`, `:266`, `:297` | Geode integration parity after extraction |

Benchmarks identified:

- No dedicated standalone FLE benchmark was found in Geode. Extraction should begin with deterministic correctness and interoperability coverage.

## Proposed Public API

Initial public surface should include:

- `EnvelopeV1`
- `makeAAD`
- `encryptField`
- `decryptField`
- `hkdfSha256`
- `deriveTRK` / `deriveSK` / `deriveFEK` / `deriveBIK`
- `KeyIds` / `KeyMetadata`
- `KeyManager`
- `BlindIndex`
- `AnnotationParser`

## Extraction Plan

1. Move crypto primitives, key types, blind index, and annotation parsing into this repo.
2. Replace `GEODE_MASTER_KEY` loading with an explicit provider interface.
3. Collapse the current `fle_*` alias scheme so the library owns its own module graph.
4. Port the crypto, blind-index, annotation, and key-manager tests.
5. Leave catalog persistence and Geode enforcement wiring in Geode.

## Acceptance Criteria

- This repo builds without Geode-specific env vars or singleton state.
- `KeyManager` no longer hardcodes `GEODE_MASTER_KEY`.
- `fle_catalog.zig` remains adapter code outside the library boundary.
- Geode integration tests still pass against the extracted core.
