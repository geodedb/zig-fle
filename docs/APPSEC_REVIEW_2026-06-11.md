# fle — Application Security Code Review

Date: 2026-06-11
Reviewer: AppSec code review (defensive, evidence-first)
Target: `/data/home/benji/src/gl/gitlab.com/devnw/zig/fle` @ `main` (`da8d4f6`)
Frameworks: OWASP Top 10:2025, CIS Controls v8.1.2 (adapted for a cryptographic library)

## 1. Scope & Assumptions

**In scope (reviewed in full):**

- Crypto core: `src/crypto/aead.zig`, `src/crypto/bulk.zig`, `src/crypto/hkdf.zig`, `src/crypto/hmac.zig`
- Searchable index: `src/index/blind_index.zig`
- Key lifecycle: `src/keys/manager.zig`, `src/keys/provider.zig`, `src/keys/types.zig`
- Schema parsing: `src/schema/annotations.zig`
- Observability seam: `src/observability.zig`, `src/observability_init.zig`
- Public API: `src/root.zig`
- Build/supply chain: `build.zig`, `build.zig.zon`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`, `.gitleaks.toml`, `Makefile`, `scripts/detect_diamond_deps.py`, `scripts/sync_diamond_deps.py`
- Examples/tests: `examples/basic.zig`, `examples/bulk.zig`, `tests/integration.zig` (and `tests/bench.zig`, `tests/observability_*` referenced)

**Out of scope / excluded:** vendored dependency source under `zig-pkg/` (third-party `thread_pool`, `otel`, `config`, vendored zlib, etc.). These are reviewed only insofar as the pins in `build.zig.zon` are concerned.

**Assumptions:**

- This is a library embedded into consumer services; there is no standalone runtime, network listener, or auth boundary inside `fle`. The trust boundary is the **API surface** (untrusted plaintext to encrypt, and especially **untrusted ciphertext/envelopes** read back from storage), plus the **multi-tenant key hierarchy** (cross-tenant isolation is a primary security property).
- No threat model or `docs/REQUIREMENTS.md` was supplied; I infer the threat model from the data types (DEKs/KEKs, plaintext PII, AEAD ciphertexts, blind-index HMACs) and the multi-tenant TRK→SK→FEK/BIK hierarchy.
- Target compiler is Zig 0.15.1 per `build.zig.zon`; safety-checked builds (Debug/ReleaseSafe) panic on integer overflow / OOB, ReleaseFast/ReleaseSmall do not. CI exercises all four (`.gitlab-ci.yml:116-167`).
- I did not execute code; findings are from static reading with exact citations.

## 2. Executive Summary

- The crypto design is, on the whole, **thoughtful and mostly correct**: AEAD with per-field random nonces, a length-prefixed canonical AAD that binds tenant/schema/field/record/version, a clean TRK→SK→FEK/BIK HKDF hierarchy, full-width (untruncated) HMAC-SHA256 blind indices, key zeroization on most paths, and constant-time tag verification delegated to `std.crypto`. Decryption failure paths zeroize the output buffer and return a single generic error with no oracle leakage.
- **The most serious issue is nonce generation.** Every AEAD nonce and key-wrap nonce is produced by `std.os.linux.getrandom(...)` with the **return value discarded** (`src/crypto/aead.zig:155`, `:283`). If the syscall fails or is blocked (e.g. seccomp sandbox, `ENOSYS`, `EINTR`), the nonce buffer is left as **uninitialized stack memory**, which across repeated calls in the same frame can be identical — driving **nonce reuse in AES-256-GCM / ChaCha20-Poly1305**, which is catastrophic (confidentiality and integrity break). Rated **High** (Critical potential under a syscall-filtered environment).
- **Untrusted-input robustness has a gap:** `EnvelopeV1.deserialize` validates the attacker-controlled length field with `35 + ciphertext_len` computed in `u32`, which can overflow on crafted envelopes — a clean panic/DoS in safe builds and a potential heap over-read path in ReleaseFast (`src/crypto/aead.zig:82-87`).
- **Tenant isolation has a latent key-confusion bug:** cache keys, rotation key-paths, and HKDF derivation contexts use plain `:`/`/` delimiter concatenation rather than the injective length-prefixed encoding the code already uses for AAD. Identifiers containing the delimiter collide, returning a key derived for a *different* tenant/field (`src/keys/manager.zig:128-135`, `:209-213`; `src/crypto/hkdf.zig:86-124`). Rated **Medium**.
- **Supply-chain/secrets tooling has a blind spot:** `.gitleaks.toml` allowlists **all `.zig` files** (`:17`), so the secret scanner never inspects the primary source language of a crypto library; a hardcoded key in any `.zig` would pass CI. Rated **Medium**.
- Remaining items are Low/Info: deterministic-nonce scaling guidance, blind-index plaintext residue, unbounded key cache, borrowed-slice lifetime footgun, thread-safe-allocator contract for the bulk path, a custom (but RFC-tested) HKDF reimplementation, and a dependency pin version/hash mismatch.
- Overall confidence: **High** for the crypto/memory findings (direct code evidence); **Medium** for exploitability of FLE-001/FLE-003 (depends on the host RNG environment and whether tenant identifiers can contain delimiters).

## 3. Findings Table

| ID | Title | Severity | Location | OWASP 2025 / CIS v8.1.2 | Status |
|----|-------|----------|----------|--------------------------|--------|
| FLE-001 | `getrandom` return value discarded → uninitialized/reused AEAD nonce | High | `src/crypto/aead.zig:155`, `:283` | A04 Crypto Failures, A10 Exceptional Conditions / CIS 3, 16.11 | Resolved `4770444` |
| FLE-002 | Integer overflow in untrusted envelope length check → DoS/OOB | Medium | `src/crypto/aead.zig:82-87` | A10 Exceptional Conditions, A05 Injection / CIS 16.11 | Resolved `8838d33` |
| FLE-003 | Ambiguous delimiter encoding → cross-tenant/field key confusion | Medium | `src/keys/manager.zig:128-135`, `:209-213`; `src/crypto/hkdf.zig:86-124` | A01 Broken Access Control, A04 / CIS 3, 16 | Resolved `dfc3634` |
| FLE-004 | Gitleaks allowlists all `.zig` files → secret scanner blind | Medium | `.gitleaks.toml:9-18` | A03 Supply Chain, A02 Misconfig / CIS 16.12, 3.11 | Resolved `bcfaa5f` |
| FLE-005 | Random 96-bit nonce + long-lived shared FEK → birthday-bound reuse at scale | Low | `src/crypto/aead.zig:154-169`, `:36` | A04 Crypto Failures, A06 Insecure Design / CIS 3 | Mitigated-by-docs `7edbd8e` (rotation threshold documented) |
| FLE-006 | Blind-index normalized plaintext not zeroized before free | Low | `src/index/blind_index.zig:55-56`, `:109-110`; `src/crypto/hmac.zig:16-38` | A04 Crypto Failures / CIS 3.11 | Resolved `0f49b10` |
| FLE-007 | Unbounded key cache (no eviction/TTL) → memory growth + key residency | Low | `src/keys/manager.zig:26-58`, `:139-188` | A04, A06 / CIS 3 | Mitigated-by-docs `7edbd8e` (residency + `clearCache` guidance; bounded cache deferred) |
| FLE-008 | `BlindIndex.lookup` returns borrowed internal slice → dangling/UAF footgun | Low | `src/index/blind_index.zig:97-120` | A06 Insecure Design / CIS 16 | Resolved-by-docs `0f49b10` (borrowed lifetime documented) |
| FLE-009 | Bulk path needs a thread-safe backing allocator, not documented/enforced | Low | `src/crypto/bulk.zig:230-263`, `:296-320` | A06 Insecure Design / CIS 16 | Resolved-by-docs `7edbd8e` |
| FLE-010 | Dependency pin ref/hash mismatch; CI compiler ≠ declared minimum | Low | `build.zig.zon:11-14`; `.gitlab-ci.yml:27` | A08 Integrity, A03 Supply Chain / CIS 2, 16.4 | Upstream issue filed (devnw/zig/otel#168) + floor aligned `a4e05e4` |
| FLE-011 | Custom HKDF reimplementation; only 1 of 7 RFC 5869 vectors tested | Low/Info | `src/crypto/hkdf.zig:21-67`, `:127-144` | A04 / CIS 16.1 vetted modules | Resolved `32a7340` (RFC 5869 cases 2-3 added) |
| FLE-012 | "Portable" claim vs Linux-only RNG syscall | Info | `src/root.zig:5-6`; `src/crypto/aead.zig:155` | A06 / CIS 16 | Resolved `4770444` |
| FLE-013 | `EnvKeyProvider` key-format edge cases (silent truncation, 64-byte raw rejected, partial key not zeroized) | Info/Low | `src/keys/provider.zig:100-124` | A04, A07 / CIS 3 | Resolved `74625b7` |
| FLE-014 | `KeyManager` not thread-safe (documented) but mutated counters | Info | `src/root.zig:17-24`; `src/keys/manager.zig:47-58` | A06 / CIS 16 | Resolved `7edbd8e` (bulk docs cross-reference thread-safety contract) |

## 4. Finding Details

---

### FLE-001 — `getrandom` return value discarded → uninitialized / reused AEAD nonce (High)

**Evidence.** Nonce generation for every field encryption:

`src/crypto/aead.zig:154-155`

```zig
var nonce: [12]u8 = undefined;
_ = std.os.linux.getrandom(@ptrCast(&nonce), @sizeOf(@TypeOf(nonce)), 0);
```

And for key wrapping:

`src/crypto/aead.zig:282-284`

```zig
var nonce: [24]u8 = undefined;
_ = std.os.linux.getrandom(@ptrCast(&nonce), @sizeOf(@TypeOf(nonce)), 0);
@memcpy(result[0..24], &nonce);
```

`std.os.linux.getrandom` is the **raw syscall wrapper**: it returns a `usize` that is the byte count on success or a negated errno on failure. The code discards it with `_ =`. On failure (`ENOSYS` on kernels lacking the syscall; `EINTR` while the entropy pool is still initializing at early boot; `EPERM`/blocked when the syscall is filtered by a **seccomp sandbox**), the buffer is **never written** and remains `undefined` — i.e. whatever bytes were on the stack.

The same pattern is replicated in callers that exercise the production RNG path (`examples/bulk.zig:22`, `tests/integration.zig:253`), so it is the project's established idiom, not a one-off.

**Impact.** AEAD nonce uniqueness is the single load-bearing precondition for AES-256-GCM and ChaCha20-Poly1305. Nonce reuse under the same key:

- AES-GCM: leaks the XOR of two plaintexts **and** allows recovery of the GHASH authentication subkey → universal forgery for that key.
- ChaCha20-Poly1305: leaks plaintext XOR and enables Poly1305 key recovery → forgery.

Because the FEK is shared across all records of a `(tenant, schema, field, version)`, a single nonce collision compromises confidentiality/integrity for that whole field. When `getrandom` is filtered (e.g. a hardened container with a seccomp allowlist that omits `getrandom`), the `undefined` nonce in a tight `encryptChunkInline` loop will frequently land on the **same stack address with the same residual bytes**, producing *systematic* nonce reuse — i.e. a deterministic full break, not a rare collision. CIS v8.1.2 Control 16.11/16.1 (use vetted, correctly-used security modules) and Control 3 (data protection) both apply.

**Exploit scenario.** A service deploys `fle` inside a seccomp-restricted sandbox that does not permit the `getrandom` syscall (a common hardening posture). `encryptField` silently uses an uninitialized 12-byte stack nonce; two records of the same field are encrypted under the same FEK with the same nonce. An attacker with read access to the ciphertext store XORs the two ciphertexts to recover plaintext differences and, with a few collisions, recovers the GMAC subkey to forge envelopes that pass `decryptField` authentication.

**Remediation.** Use the infallible Zig CSPRNG (already recommended in this repo's own docstring, `src/root.zig:38` shows `std.crypto.random.bytes(&master_key)`), or a checked, EINTR-looping `getrandom` that hard-fails closed:

```zig
// Preferred: never silently produces a weak nonce; portable.
var nonce: [12]u8 = undefined;
std.crypto.random.bytes(&nonce);
```

or, if a direct syscall is required:

```zig
std.posix.getrandom(&nonce) catch return Error.InvalidInput; // fail closed, never encrypt with a non-random nonce
```

Apply to both `encryptField` and `wrapKey32`, and to the example/test sites. A nonce-generation primitive must **fail closed**: never emit an envelope when randomness could not be obtained. (Consider also wiring the unused `Error.NonceReuse` variant, declared at `aead.zig:36`, into a real check or removing it.)

---

### FLE-002 — Integer overflow in untrusted envelope length validation → DoS / potential OOB (Medium)

**Evidence.** `EnvelopeV1.deserialize` parses an attacker-controlled length field and validates it:

`src/crypto/aead.zig:82-87`

```zig
const ciphertext_len = std.mem.readInt(u32, data[31..35], .little);

if (data.len < 35 + ciphertext_len) return Error.InvalidEnvelope;

const ciphertext = try allocator.alloc(u8, ciphertext_len);
@memcpy(ciphertext, data[35 .. 35 + ciphertext_len]);
```

`ciphertext_len` is a `u32` read directly from untrusted bytes. In `35 + ciphertext_len`, the literal `35` coerces to `u32`, so the addition is performed in `u32` and **overflows** when `ciphertext_len > 0xFFFF_FFDC`. The same overflowing expression is reused to bound the slice `data[35 .. 35 + ciphertext_len]`.

**Impact.**

- Debug / ReleaseSafe (CI runs both, `.gitlab-ci.yml:117-156`): the overflow is a checked illegal behavior → **panic** → denial of service. Since the whole purpose of this function is to parse **ciphertext read back from untrusted storage**, a single crafted envelope crashes the embedding service.
- ReleaseFast / ReleaseSmall: `35 + 0xFFFF_FFFF` wraps to `34`; the guard `data.len < 34` is bypassed, and execution proceeds to `allocator.alloc(u8, 0xFFFF_FFFF)` (likely OOM → handled error) and the wrapped slice expression `data[35..34]` (start > end) → panic, or in pathological cases an out-of-bounds memcpy source. Either way the malformed input controls a crash.

OWASP A10 (Mishandling of Exceptional Conditions) and A05 (untrusted-input parsing).

**Exploit scenario.** A column in the datastore holds serialized `EnvelopeV1` blobs. An attacker who can write a field value (or a malicious replica) stores a blob whose bytes `[31..35]` encode `0xFFFFFFFF`. On the next read, `deserialize` panics, taking down the request handler (and, depending on the host, the process).

**Remediation.** Do the bound check in `usize` with no possibility of overflow; `data.len >= 35` is already guaranteed by the check at `aead.zig:74`:

```zig
if (data.len < 35) return Error.InvalidEnvelope;
const ciphertext_len = std.mem.readInt(u32, data[31..35], .little);
if (ciphertext_len > data.len - 35) return Error.InvalidEnvelope; // overflow-free
const ciphertext = try allocator.alloc(u8, ciphertext_len);
@memcpy(ciphertext, data[35 .. 35 + ciphertext_len]); // now provably in-bounds
```

Add a fuzz/regression test feeding `0xFFFFFFFF` and `data.len-35 ± 1` length fields (the `--fuzz` job at `.gitlab-ci.yml:176-195` is a good home for it).

---

### FLE-003 — Ambiguous delimiter encoding → cross-tenant / cross-field key confusion (Medium)

**Evidence.** The FEK/BIK cache key is built by joining identifiers with `:`:

`src/keys/manager.zig:128-135`

```zig
fn buildCacheKey(allocator: std.mem.Allocator, ids: types.KeyIds) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}:{s}:v{d}", .{
        ids.tenant,
        ids.schema,
        ids.field,
        ids.version,
    });
}
```

The rotation version key-path does the same:

`src/keys/manager.zig:209-213`

```zig
const key_path = try std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}", .{
    tenant, schema, field,
});
```

And the HKDF derivation contexts concatenate with `/` without length framing:

`src/crypto/hkdf.zig:86-124`

```zig
const context = try std.fmt.bufPrint(&context_buf, "geode/trk/{s}", .{tenant_id});
// ... "geode/sk/{s}", "geode/fek/{s}/v{d}", "geode/bi/{s}/v{d}"
```

Notably, `makeAAD` (`aead.zig:104-125`) **already** documents and implements length-prefixed, injective encoding ("canonically unambiguous regardless of field content") — so the project understands the hazard, but the cache/rotation/derivation paths do not apply it.

**Impact.** The cache key is not an injective function of `(tenant, schema, field, version)`. Concretely:

- `tenant="a:b", schema="c"` and `tenant="a", schema="b:c"` both stringify to `"a:b:c:<field>:v1"`.

These are **different tenants**, and they derive **different** TRKs (`deriveTRK` keys on tenant alone: `"geode/trk/a:b"` vs `"geode/trk/a"`), hence different FEKs. But the cache is consulted first (`manager.zig:143-146`, `:169-172`) and returns whichever identity was cached **first**. The second caller therefore receives a FEK derived for a *different tenant*. Because the AAD path **is** correctly length-prefixed and binds the real tenant, this manifests as either a cross-tenant key being used to encrypt/decrypt (a confidentiality/isolation break for tenants able to influence the collision ordering) or silent decryption failures. The rotation key-path has the same collision, so a rotation for one tenant can bump the version state of a colliding tenant. The HKDF contexts add a defense-in-depth gap (e.g. `deriveFEK(sk,"a/v1")` collides with `deriveFEKVersioned(sk,"a",1)` → both `"geode/fek/a/v1"`).

This is OWASP A01 (broken access control / tenant isolation) compounded by A04. Severity is gated on whether `tenant`/`schema`/`field` can contain `:` or `/` in the consuming application; for UUID tenant IDs it is unreachable, but `fle` imposes no such constraint and field/schema names are application-defined.

**Exploit scenario.** A multi-tenant app derives tenant IDs from a customer-supplied slug that may contain `:`. Tenant `acme:prod` and tenant `acme` with schema `prod:Person` collide on the cache key. After `acme` primes the cache, `acme:prod` reads back `acme`'s FEK and writes ciphertext recoverable by `acme`.

**Remediation.** Use the same length-prefixed encoding as `makeAAD` for cache keys, rotation key-paths, and HKDF contexts — or, minimally, an unambiguous scheme that escapes the delimiter and rejects it in identifiers. For HKDF, fold the structured `info` through a canonical encoding (e.g. length-prefixed concatenation of the level tag + each component) rather than `printf`-style joins. Additionally, validate that `tenant`/`schema`/`field` do not contain reserved delimiters at the API boundary, and document the constraint.

---

### FLE-004 — Gitleaks allowlists every `.zig` file → secret scanner is blind to the primary language (Medium)

**Evidence.** `.gitleaks.toml:9-18`

```toml
[allowlist]
description = "Global allowlist"
paths = [
    '''\.zig-cache''',
    '''zig-out''',
    '''\.git''',
    # Zig source files contain crypto function names with "key" in them
    # (wrapKey32, unwrapKey32, deriveKey32, etc.) which trigger false positives.
    '''\.zig$''',
]
```

The final entry excludes **all** `.zig` files from gitleaks scanning. The CI pipeline runs gitleaks as a gate (`.gitlab-ci.yml:14`), and pre-commit's `detect-private-key` additionally excludes `tests/` and `src/tests/` (`.pre-commit-config.yaml:39-40`).

**Impact.** For a cryptographic library, the highest-value secret-leak risk is a developer pasting a real key, test vector that is actually a production key, or `.pem`/hex blob into a `.zig` source or test file. With every `.zig` allowlisted, gitleaks will **never** flag such a leak, and the pre-commit private-key check skips the test tree where fixtures live. The stated rationale (crypto identifiers like `wrapKey32` cause false positives) is legitimate but the remedy is far too broad — it disables secret detection for essentially the entire codebase. OWASP A03 (supply chain) / A02 (misconfiguration); CIS Control 16.12 (code-level secret hygiene) and 3.11.

**Exploit scenario.** A maintainer commits a debugging helper to `src/keys/manager.zig` with a hardcoded 64-hex master key for "local testing." Gitleaks passes (file allowlisted), CI is green, and the key is published in the public Git history of the released package.

**Remediation.** Replace the blanket file allowlist with **targeted regex/stopword allowlists** for the specific false-positive identifiers, keeping content scanning enabled for `.zig`:

```toml
[allowlist]
description = "Global allowlist"
paths = ['''\.zig-cache''', '''zig-out''', '''\.git''']
regexes = [
  '''(?i)(wrap|unwrap|derive|rotate|get|put)key3?2?''',
  '''blindIndexHmac256''',
]
```

Also narrow the pre-commit `detect-private-key` exclusion so real test directories are still scanned (allow only known fixture paths), and keep gitleaks scanning the test tree.

---

### FLE-005 — Random 96-bit nonce with a long-lived shared FEK → birthday-bound reuse at scale (Low)

**Evidence.** Nonces are 96-bit random for the `EnvelopeV1` algorithms:

`src/crypto/aead.zig:154-169` (12-byte nonce; AES-256-GCM and ChaCha20-Poly1305 both use it), and the FEK is keyed on `(tenant, schema, field, version)` only — it is reused across **all records** of a field until rotation. The declared `Error.NonceReuse` (`aead.zig:36`) is never returned anywhere in the code, indicating intended-but-absent nonce-collision protection.

**Impact.** With random 96-bit nonces, NIST SP 800-38D bounds safe usage to roughly 2³² encryptions per key before the collision probability becomes non-negligible. A high-cardinality field (billions of records, plus re-encryption on updates) under a single never-rotated FEK can approach that bound, at which point a random nonce collision yields the FLE-001 failure mode without any RNG fault. This is a design/scaling consideration (A04/A06), distinct from the acute FLE-001 bug.

**Exploit scenario.** A large tenant encrypts the same indexed field for >4 billion records over the system's lifetime without ever calling `rotateFEK`; an eventual nonce collision exposes two plaintexts and the GMAC subkey.

**Remediation.** Document a hard rotation threshold (rotate FEK well before 2³² encryptions per key) and/or offer a misuse-resistant option for high-volume fields: AES-GCM-SIV, or route bulk field encryption through XChaCha20-Poly1305 (192-bit nonce, collision-safe with random nonces) — the primitive is already vendored and used by `wrapKey32`. At minimum, expose an encryption counter per FEK and refuse to encrypt past a configured ceiling.

---

### FLE-006 — Blind-index normalized plaintext not zeroized before free (Low)

**Evidence.** `normalizeForBlindIndex` allocates a lowercase copy of the plaintext field value (`src/crypto/hmac.zig:16-38`). Both `put` and `lookup` free it without zeroizing:

`src/index/blind_index.zig:55-56`

```zig
const normalized = try hmac_mod.normalizeForBlindIndex(self.allocator, plaintext);
defer self.allocator.free(normalized);
```

(identical at `:109-110`).

**Impact.** `normalized` is the sensitive field value (email, SSN, etc.) lowercased — it is plaintext-equivalent. Freeing without `secureZero` leaves the value in reclaimed heap, recoverable via later heap reuse, a core dump, or a memory-disclosure bug elsewhere in the host. The decrypt path elsewhere is careful to zeroize plaintext (`aead.zig:232`, `tests` zeroize decrypted output), so this is an inconsistency. CIS Control 3.11 (encrypt/protect sensitive data) / A04.

**Remediation.**

```zig
defer {
    std.crypto.secureZero(u8, normalized);
    self.allocator.free(normalized);
}
```

Apply in both `put` and `lookup`.

---

### FLE-007 — Unbounded key cache (no eviction/TTL) → memory growth and prolonged key residency (Low)

**Evidence.** `KeyCache` only ever inserts (`src/keys/manager.zig:56-58`); there is no eviction, size cap, or TTL. `getFEK`/`getBIK` insert a 32-byte plaintext key per unique `(tenant, schema, field, version)` (`:156-159`, `:182-185`). Cleanup happens only on `clearCache`/`deinit`.

**Impact.** A workload spanning many tenants/fields/versions causes unbounded growth (availability/DoS) and keeps a large, growing population of **derived key material resident in process memory** for the lifetime of the `KeyManager`, increasing exposure to core-dump/memory-scraping disclosure. A06/A04.

**Remediation.** Add a bounded cache (LRU with a configurable cap) that `secureZero`s evicted entries, and/or a TTL. Document the residency model so callers can size it. The existing `secureClear` (`:61-69`) is correct; pair it with bounded retention.

---

### FLE-008 — `BlindIndex.lookup` returns a borrowed internal slice → dangling/UAF footgun (Low)

**Evidence.** `src/index/blind_index.zig:115-117`

```zig
if (token_map.get(token)) |record_ids| {
    return record_ids.items;
}
```

The returned `?[]const []const u8` aliases the internal `std.ArrayList.items` and its owned `record_id` byte slices.

**Impact.** If the caller holds the returned slice across a subsequent `put` (which may `append` and reallocate the same token's list, `:91-93`) or `remove`/`deinit` (which `swapRemove` + frees IDs, `:138-139`, or frees everything, `:29-34`), the slice and/or its elements dangle → use-after-free / reading freed memory. This is an API-contract hazard rather than an internal bug. A06.

**Remediation.** Either return an owned copy (caller-frees), or document explicitly that the result borrows index-internal storage valid only until the next mutating call and must not outlive it. Prefer returning a duplicated `[][]const u8` for safety given the sensitivity of the data.

---

### FLE-009 — Bulk path requires a thread-safe backing allocator but does not document/enforce it (Low)

**Evidence.** Each worker chunk wraps the shared allocator in a per-chunk arena and also allocates envelope ciphertext directly from the shared allocator, concurrently across threads:

`src/crypto/bulk.zig:230-263`

```zig
var arena = std.heap.ArenaAllocator.init(c.allocator); // c.allocator is the shared backing
...
const env = aead.encryptField(c.allocator, f.alg, f.fek, aad_bytes, ...);
```

The public `encryptFieldsBulk`/`decryptFieldsBulk` accept any `std.mem.Allocator` (`:91-97`, `:534-540`) with no stated thread-safety requirement; `src/root.zig:17-28` documents `KeyManager`/`BlindIndex` thread-safety but says nothing about the allocator passed to the bulk API.

**Impact.** The per-chunk arenas isolate AAD allocations, but they all forward to the **same backing allocator** concurrently, and `encryptField` allocates from it directly on multiple threads. If a caller passes a non-thread-safe allocator (e.g. a bare `ArenaAllocator`, or a `DebugAllocator` configured `thread_safe=false`), concurrent allocation is a data race → heap corruption. The shared `fek` slice itself is read-only and safe to share; the hazard is purely the allocator. A06; CIS 16.

**Remediation.** Document that `pool != null` requires a thread-safe allocator, and consider asserting it or giving each worker a private child allocator/arena that does not share a non-thread-safe parent. Add the requirement to the `root.zig` Thread Safety section.

---

### FLE-010 — Dependency pin ref/hash mismatch; CI compiler differs from declared minimum (Low)

**Evidence.** `build.zig.zon:11-14`

```zig
.otel = .{
    .url = "git+https://gitlab.com/devnw/zig/otel.git?ref=v0.1.10#a1afbfe672d5c0894969d0aa49efa7a66510eda3",
    .hash = "otel-0.1.9-B0v3ltxeNgB4mGDRS7r1dapusir8f7_ISb-MvzYltW1h",
    .lazy = true,
},
```

The URL ref is `v0.1.10` but the integrity hash declares package version `otel-0.1.9-...`. Separately, `.gitlab-ci.yml:27` sets `ZIG_VERSION: "0.16.0"` while `build.zig.zon:5` declares `minimum_zig_version = "0.15.1"` (and the review target is 0.15.1).

**Impact.**

- The ref/hash disagreement is a supply-chain integrity smell: the lockfile appears to have been bumped (tag) without regenerating the content hash, or the `v0.1.10` tag was made to point at `0.1.9` content. Zig verifies content against `hash`, so the build is still hash-pinned (good), but the inconsistency undermines auditability and the recent "diamond sync" churn (`git log`) suggests the lockfile is hand-edited. `otel` is `lazy=true` and only fetched under `-Dwith_otel=true` (off by default), limiting blast radius.
- Building/testing on Zig 0.16.0 in CI while declaring 0.15.1 as the floor means the released artifact is never validated on its stated minimum compiler; 0.15.1-only or 0.16-only behaviors could slip through. A08 (integrity) / A03; CIS 2 (inventory) and 16.4.

**Remediation.** Regenerate `build.zig.zon` via `zig fetch --save` so the `ref`, commit, and `hash` are mutually consistent; or pin both to the same version deliberately and add a comment explaining the intentional mapping. Align CI `ZIG_VERSION` with `minimum_zig_version` (or add a dedicated 0.15.1 job) so the declared floor is actually exercised. The `scripts/detect_diamond_deps.py` guard and SHA-256-verified Zig download (`.gitlab-ci.yml:38-77`) are good; this finding is about pin consistency, not the tooling.

---

### FLE-011 — Custom HKDF reimplementation; only one RFC 5869 vector tested (Low/Info)

**Evidence.** `src/crypto/hkdf.zig:21-67` hand-rolls HKDF-Extract/Expand using `HmacSha256` rather than `std.crypto.kdf.hkdf.HkdfSha256`. Tests cover RFC 5869 Test Case 1 only (`:127-144`) plus determinism checks (`:146-200`).

**Impact.** I traced the implementation and it is correct (PRK extract, `T(0)` empty, counter framing, `secureZero` of `prk`/`t`/`t_prev`, and a correct `counter == 0` overflow guard for >255 blocks). Risk is maintenance/assurance: bespoke crypto is easy to regress, and only 1 of the 7 RFC 5869 vectors is asserted — the zero-length-salt case (Test Case 3) and the longer-output cases are untested. A04 / CIS 16.1 (prefer vetted modules).

**Remediation.** Prefer `std.crypto.kdf.hkdf.HkdfSha256` (well-tested stdlib) unless byte-for-byte Geode interop forbids it; if the custom path stays, add RFC 5869 Test Cases 2-3 (and a SHA-256 long-output case) to lock behavior. No code defect found.

---

### FLE-012 — "Portable, zero-dependency" claim vs Linux-only RNG syscall (Info)

**Evidence.** `src/root.zig:5-6` advertises "A portable, zero-dependency Zig library," yet randomness everywhere uses `std.os.linux.getrandom` (`aead.zig:155`, `:283`; examples/tests). On non-Linux targets this does not provide correct CSPRNG behavior (and `std.os.linux` is Linux-namespaced).

**Impact.** Cross-platform builds (macOS/Windows/BSD) will not get correct OS randomness from this path; combined with FLE-001 the failure is silent. Documentation/design accuracy. A06.

**Remediation.** Switch to `std.crypto.random.bytes` (portable, infallible) as in FLE-001; this resolves both the portability claim and the unchecked-failure bug.

---

### FLE-013 — `EnvKeyProvider` key-format edge cases (Info/Low)

**Evidence.** `src/keys/provider.zig:100-124`

```zig
if (env_val.len == 64) { /* hex-decode; any bad nibble -> MasterKeyUnavailable */ }
if (env_val.len >= 32) { @memcpy(&key, env_val[0..32]); return key; } // silent truncation of >32-byte raw
// < 32 bytes rejected
```

**Impact.** (a) A legitimate 64-byte **raw** key is misinterpreted as hex and rejected. (b) A 33+ byte non-hex value is silently truncated to its first 32 bytes — a long passphrase yields a key derived from only its prefix, reducing effective entropy without warning. (c) On a mid-loop hex-decode error, the partially populated `key` stack array is not zeroized (minor residue). The env copy itself is correctly zeroized before free (`:94-98`), which is good. A04/A07.

**Remediation.** Make the accepted format explicit and unambiguous (e.g. require exactly 32 raw bytes or exactly 64 hex chars; reject everything else rather than truncating), document it, and `secureZero(&key)` on every error return.

---

### FLE-014 — `KeyManager` not thread-safe (documented) but mutates counters (Info)

**Evidence.** `src/root.zig:17-24` clearly documents that `KeyManager` and `BlindIndex` are **not** thread-safe and callers must serialize. The caches mutate `hits`/`misses` and the maps non-atomically (`src/keys/manager.zig:47-58`).

**Impact.** This is correctly documented, so it is an Info note rather than a defect: concurrent use is undefined and the contract says so. The residual risk is that the high-throughput story funnels users to the `bulk` API (which is concurrent) while `KeyManager` (where FEKs are derived) is not — callers must derive/cache keys under their own lock and only fan out the stateless `encryptField` work. Worth making explicit in the bulk docs.

**Remediation.** Cross-reference the thread-safety note from the `bulk` documentation, and consider an opt-in mutex-wrapped manager for convenience.

## 5. Secure Design Notes (what the code does well)

- **Canonical, injective AAD.** `makeAAD` (`aead.zig:104-125`) uses 4-byte length prefixes per field and binds `tenant‖schema‖field‖record_id‖key_version`, explicitly preventing field-boundary ambiguity and ciphertext-swapping across records. This is exactly the right construction (and the model FLE-003 recommends extending to cache/derivation).
- **Proper key hierarchy.** TRK→SK→FEK/BIK via HKDF with domain-separated contexts and distinct FEK vs BIK derivation (`hkdf.zig:84-125`) means an exposed FEK does not yield the BIK or sibling keys, and the master key never directly encrypts data.
- **Full-width blind index.** The blind index uses the complete 32-byte HMAC-SHA256 output (`hmac.zig:7-12`, `blind_index.zig:7`) — **no truncation**, so there is no engineered collision weakness, and the BIK is correctly the HMAC key (no plaintext recovery without the BIK).
- **Authenticated decryption with safe failure handling.** `decryptField` zeroizes and frees the output buffer on auth failure and on unsupported algorithms, returning a single generic `AEADAuthFailed`/`InvalidAlg` with **no oracle differentiation** (`aead.zig:210-262`). The observability seam deliberately omits error names from spans to avoid leaking AEAD failure modes (`observability.zig:155-177`).
- **Constant-time tag verification.** Tag checks are delegated to `std.crypto` AEAD `decrypt`, which is constant-time; the code does not hand-roll secret comparisons.
- **Disciplined zeroization on most paths.** `prk`/`t`/`t_prev` in HKDF (`hkdf.zig:34,59,66`), `master_key` and cached keys in `KeyManager.deinit`/`secureClear` (`manager.zig:41,65,110`), `StaticKeyProvider.deinit` (`provider.zig:62`), env-var copy in `EnvKeyProvider` (`provider.zig:94-98`), and decrypted plaintext in tests/integration are all zeroized.
- **Telemetry never carries secrets.** The observability seam only accepts `operation`/`field`/`algorithm` strings and is currently a hard comptime no-op (`observability.zig:37`); every call site documents that keys/plaintext/ciphertext must never be attributes (`aead.zig:144-146`, `bulk.zig:98-103`). No key material reaches logs or spans.
- **Thoughtful bulk concurrency primitives.** The `WaitGroup.add(n)`-before-submit ordering, inline fallback on submit failure with guaranteed `done()` accounting, and per-chunk arenas (`bulk.zig:148-167`) are correct and avoid the classic underflow/premature-unblock races (modulo the allocator-thread-safety contract in FLE-009).
- **Supply-chain guardrails.** SHA-256-verified Zig toolchain download (`.gitlab-ci.yml:38-77`), SAST/dependency-scanning/secrets/gitleaks/SBOM components, a diamond-dependency detector (`scripts/detect_diamond_deps.py`, hand-rolled parser with correct in-string `//` handling), and subprocess calls using list-arg form (no `shell=True`) in both Python scripts (`scripts/sync_diamond_deps.py:77-86`) — no shell-injection surface.
- **Key sourcing is injected, not ambient.** `KeyManager` takes the master key explicitly or via a pluggable `MasterKeyProvider` (`manager.zig:84-107`), avoiding hardcoded/ambient-env coupling and letting callers source from a KMS/HSM.

## 6. Coverage Gaps & Questions

- **No negative/fuzz tests for malformed envelopes.** There is no test feeding truncated, oversized, or overflow-length envelopes into `deserialize`/`decryptField` (FLE-002). The `--fuzz` CI job exists (`.gitlab-ci.yml:176`) but no fuzz target is visible in the reviewed files — confirm `tests/bench.zig` or another file registers a fuzzer over `deserialize`.
- **No test exercises RNG failure.** FLE-001 cannot be caught by the current suite because tests use a different RNG (`std.Io.Threaded...random`) than production (`std.os.linux.getrandom`). A test injecting a failing RNG, or simply switching production to `std.crypto.random.bytes`, is needed.
- **No cross-tenant key-confusion test.** No test exercises identifiers containing `:`/`/` to confirm/deny FLE-003. Recommend adding adversarial identifier tests.
- **HKDF vector coverage is thin** (FLE-011): only RFC 5869 Test Case 1.
- **`tests/bench.zig`, `tests/observability_disabled_test.zig`, `tests/observability_enabled_test.zig`** were referenced by `build.zig` but not provided in this pass; I reviewed their build wiring (`build.zig:140-236`) but not their contents. Nothing in the wiring is concerning, but a follow-up read is warranted to confirm no secrets/insecure patterns in `bench.zig`.
- **Open questions for the maintainers:**
  1. In the deployment environments, can `tenant`/`schema`/`field` ever contain `:` or `/`? (Determines FLE-003 severity.)
  2. Is `fle` ever run under seccomp/sandbox profiles that could filter `getrandom`? (Determines FLE-001 exploitability — and the answer should be "irrelevant" once you fail closed.)
  3. Is the `v0.1.10` ref / `otel-0.1.9` hash mapping in `build.zig.zon` intentional, and is `-Dwith_otel=true` ever shipped to production? (FLE-010.)
  4. What is the expected maximum number of encryptions per FEK between rotations? (FLE-005.)

## 7. Prioritized Next Actions

1. **FLE-001 (High) — fix nonce generation now.** Replace both `std.os.linux.getrandom` sites in `src/crypto/aead.zig` (and the example/test sites) with `std.crypto.random.bytes`, or a checked `std.posix.getrandom` that fails closed. This is a one-line-per-site change that removes a catastrophic-impact crypto failure. Add a regression test asserting nonces differ across calls and that encryption refuses to proceed without randomness.
2. **FLE-002 (Medium) — make envelope parsing overflow-safe.** Change the bound check in `deserialize` to `if (ciphertext_len > data.len - 35) return Error.InvalidEnvelope;` and add malformed-input fuzz/regression tests. Closes a remotely-triggerable DoS on untrusted ciphertext.
3. **FLE-003 (Medium) — eliminate delimiter ambiguity.** Apply length-prefixed/injective encoding (reuse the `makeAAD` approach) to cache keys, rotation key-paths, and HKDF contexts; validate identifiers do not contain reserved delimiters at the API boundary. Add cross-tenant collision tests.
4. **FLE-004 (Medium) — restore secret scanning for `.zig`.** Replace the blanket `\.zig$` allowlist in `.gitleaks.toml` with targeted regex/stopword allowlists; narrow the pre-commit `detect-private-key` test-dir exclusion.
5. **FLE-005 / FLE-007 (Low) — bound key lifetime and document nonce/rotation limits.** Add a bounded, zeroizing key cache and a documented per-FEK encryption ceiling (or move high-volume fields to XChaCha20/AES-GCM-SIV).
6. **FLE-006, FLE-008, FLE-009, FLE-013 (Low) — tighten data-handling hygiene.** Zeroize normalized blind-index plaintext; document/return-copy for `BlindIndex.lookup`; document the thread-safe-allocator requirement for the bulk API; make `EnvKeyProvider`'s accepted key format explicit and zeroize on all error paths.
7. **FLE-010 / FLE-011 / FLE-012 (Low/Info) — supply-chain and portability polish.** Regenerate `build.zig.zon` pins for consistency, align CI `ZIG_VERSION` with the declared minimum, add RFC 5869 vectors (or switch to stdlib HKDF), and reconcile the "portable" claim by moving to `std.crypto.random`.

No confirmed RCE, authentication bypass, or secret-in-repo was found in the reviewed scope. The headline risks are the nonce-generation failure mode (FLE-001) and untrusted-envelope robustness (FLE-002); both are small, well-bounded fixes.

## 8. Remediation Log (2026-06-11)

All findings in section 3 were remediated or dispositioned in the 2026-06-11 audit remediation pass; per-finding status and commit refs are recorded in the Status column of the findings table.

Supply-chain review (SCR) items from the same pass:

- **SCR-001 / SCR-003 / SCR-004 — Resolved** in `bcfaa5f`: scoped gitleaks allowlist (replacing the blanket `.zig` exclusion), SHA-frozen pre-commit hooks, hash path validation, and CI input validation.
- **SCR-002 + CI catalog component tag pins — Accepted**: the CI component catalog is org-internal; tag pinning is the accepted posture and is recorded here and in the plan's accepted/deferred list.
- **FLE-010a upstream**: filed devnw/zig/otel#168 (`build.zig.zon` `.version` not bumped before tagging, so the v0.1.10 tag ships `otel-0.1.9-...` hash content). The `fle` pin remains content-hash-verified; the CI floor alignment landed in `a4e05e4`/`4a3af6e`.
