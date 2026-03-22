# Requirements

Last updated: 2026-03-21

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| FLE-REQ-001 | The library SHALL expose the AEAD envelope and encrypt/decrypt operations. | `src/crypto/aead.zig:26`, `:119`, `:163` |
| FLE-REQ-002 | The library SHALL expose the HKDF-based key hierarchy helpers. | `src/crypto/hkdf.zig:8`, `:70`, `:77`, `:84`, `:98` |
| FLE-REQ-003 | The library SHALL expose blind-index HMAC helpers and token encoding utilities. | `src/crypto/hmac.zig:7`, `:16`, `:41`, `:54` |
| FLE-REQ-004 | The library SHALL expose portable key metadata/value types. | `src/keys/types.zig:7`, `:15`, `:33`, `:45`, `:52` |
| FLE-REQ-005 | The library SHALL expose a key manager that is configured explicitly, not via `GEODE_MASTER_KEY`. | current blocker `src/keys/manager.zig:73` through `:94` |
| FLE-REQ-006 | The library SHALL expose blind-index storage/lookups. | `src/index/blind_index.zig:24`, `:61`, `:106`, `:135` |
| FLE-REQ-007 | The library SHALL expose schema annotation parsing and metadata application. | `src/schema/annotations.zig:129`, `:220`, `:269` |
| FLE-REQ-008 | The library SHALL NOT own Geode’s global file-backed catalog in the initial extraction. | `src/schema/fle_catalog.zig:339`, `:344`, `:378`, `:463` |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| FLE-PKG-001 | Internal module aliases such as `fle_key_types`, `fle_aead`, `fle_hkdf`, and `fle_hmac` SHALL resolve inside this repo. | `src/keys/manager.zig:2`, `:3`, `:4`, `src/index/blind_index.zig:2` |
| FLE-PKG-002 | Catalog persistence SHALL remain outside this repo until it is adapterized. | `src/schema/fle_catalog.zig:17`, `:339`, `:344` |
| FLE-PKG-003 | Geode enforcement and policy logic SHALL remain in Geode. | `src/security/test_fle_enforcement.zig:27` through `:323` |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| FLE-TEST-001 | Port AEAD, HKDF, and HMAC unit tests. | `src/crypto/aead.zig:215`, `:240`, `:262`, `src/crypto/hkdf.zig:111`, `:142`, `src/crypto/hmac.zig:67`, `:87`, `:99` |
| FLE-TEST-002 | Port key-manager, blind-index, and annotation tests. | `src/keys/manager.zig:338`, `:369`, `:412`, `src/index/blind_index.zig:161`, `:194`, `:216`, `src/schema/annotations.zig:327`, `:346`, `:363`, `:389` |
| FLE-TEST-003 | Preserve Geode integration parity after extraction. | `tests/test_fle_lifecycle.zig:7`, `tests/test_tde_kms_integration.zig:16`, `:76`, `:112`, `:149`, `:185`, `:225`, `:266`, `:297` |

## Documentation Requirements

- Document the key hierarchy and blind-index flow.
- Provide one example for field encryption and decryption.
- Provide one example for annotation parsing.
- Document what stays out of scope: catalog persistence and product enforcement policy.

## Migration Requirements

1. Extract the crypto/key/annotation core.
2. Replace env-driven key sourcing with explicit injection.
3. Keep `fle_catalog.zig` and enforcement rules in Geode until adapters exist.
