# Quality Gap Analysis

Last updated: 2026-06-11

Source review: 2026-06-11 codebase audit (duplication, dead code, complexity, documentation, CI). All findings are dispositioned below; no open quality gaps remain.

## Findings

| ID | Finding | Status | Resolution / Rationale | Commit |
|---|---|---|---|---|
| DUP-001 | `encryptFieldsBulk`/`decryptFieldsBulk` duplicated parallel driver logic | Resolved | Unified encrypt/decrypt drivers via a comptime generic driver | `d95f30a` |
| DUP-002 | Duplicated chunk-worker bodies between encrypt and decrypt paths | Resolved | Same comptime unification as DUP-001 | `d95f30a` |
| DUP-003 | `getFEK`/`getBIK` duplicated cache-lookup + derivation logic | Resolved | Unified via shared derivation helper | `2f99192` |
| DC-001 | `Error.NonceReuse` declared but never raised | Resolved | Dead variant removed | `98dd8af` |
| DC-002 | `Error.SearchNotPermitted` declared but never raised | Resolved | Dead variant removed | `98dd8af` |
| DC-003 | `Error.RotationInProgress` declared but never raised | Resolved | Dead variant removed | `98dd8af` |
| DC-004 | `deriveFEK` (unversioned) has no internal callers | Accepted | Kept as tested public API — general-purpose HKDF hierarchy primitive for consumers | — |
| DC-005 | `deriveBIK` (unversioned) has no internal callers | Accepted | Kept as tested public API — same rationale as DC-004 | — |
| DC-006 | `wrapKey`/`unwrapKey` untested at the KeyManager level | Resolved | Dedicated test coverage added | `40e0655` |
| DC-007 | `BlindIndexToken` not re-exported from `root.zig` | Resolved | Re-exported as part of the FLE-006/008 fix | `0f49b10` |
| DC-008 | `tokenToHex`/`hexToToken` have no internal callers | Accepted | Kept as tested public API — token encoding utilities required by FLE-REQ-003 | — |
| CX-001 | Bulk encrypt/decrypt drivers structurally complex and parallel-duplicated | Resolved | Comptime generic driver collapsed the duplicated complexity | `d95f30a` |
| CX-002 | `AnnotationParser.parse` complexity | Accepted | Parser complexity is reasonable for the grammar; further splitting would hurt readability | — |
| CX-003 | `applyAnnotations` complexity | Accepted | Same rationale as CX-002 | — |
| CX-004 | `decryptField` allocated before validating algorithm; duplicated cleanup paths | Resolved | Validate alg before allocating; deduped cleanup | `f8c718d`, `0255245` |
| DOC-001 | Public aliases in `root.zig` undocumented | Resolved | All public aliases documented | `7edbd8e` |
| DOC-002 | Thread-safety contract incomplete (bulk allocator requirement) | Resolved | Thread-safety docs extended, including bulk thread-safe-allocator requirement | `7edbd8e` |
| DOC-003 | Missing rotation threshold / cache-residency guidance | Resolved | Rotation and cache-residency guidance documented | `7edbd8e` |
| CI-001 | CI builds on Zig 0.16.0 while `build.zig.zon` declared floor 0.15.1 | Resolved | `minimum_zig_version` aligned with the validated toolchain (0.16.0); docs aligned | `a4e05e4`, `4a3af6e` |

## Summary

- Resolved: DUP-001, DUP-002, DUP-003, DC-001..003, DC-006, DC-007, CX-001, CX-004, DOC-001..003, CI-001
- Accepted: DC-004, DC-005, DC-008 (kept as tested public API), CX-002, CX-003 (parser complexity reasonable)
- Open: none
