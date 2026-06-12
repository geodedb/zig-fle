# Key Hierarchy

How `fle` derives, uses, rotates, and destroys key material. All facts in
this document are sourced from `src/crypto/hkdf.zig`, `src/keys/manager.zig`,
`src/index/blind_index.zig`, `src/crypto/hmac.zig`, and `src/crypto/aead.zig`.

## Key hierarchy diagram

Every derivation is HKDF-SHA256 (RFC 5869) with the library's fixed salt
`"geode-fle-salt"` (`hkdf.default_salt`) and a per-level info context:

```text
                         master key (32 bytes)
                  injected via KeyManager.init or a
                  MasterKeyProvider (KMS/HSM/env/etc.)
                                  |
                                  |  deriveTRK
                                  |  info = "geode/trk/<tenant>"
                                  v
                       TRK — Tenant Root Key (32B)
                                  |
                                  |  deriveSK
                                  |  info = "geode/sk/<schema>"
                                  v
                        SK — Schema Key (32B)
                       /                      \
        deriveFEKVersioned                 deriveBIKVersioned
        info = "geode/fek/<field>/v<N>"    info = "geode/bi/<field>/v<N>"
                     |                                |
                     v                                v
     FEK — Field Encryption Key (32B)   BIK — Blind Index Key (32B)
     used by aead.encryptField /        used by BlindIndex put/lookup
     aead.decryptField                  (HMAC-SHA256 tokens)
```

`KeyManager.getFEK` / `KeyManager.getBIK` perform the full
master → TRK → SK → leaf chain on a cache miss and memoize the leaf key in an
in-process cache keyed by an injective (length-prefixed) encoding of
`(tenant, schema, field, version)`.

## Identifier rules

`tenant`, `schema`, and `field` identifiers must be:

- **non-empty**, and
- **free of `:` and `/`** — these characters are reserved as delimiters in
  the HKDF derivation contexts and rotation key paths.

Violations are rejected at the API boundary with `Error.InvalidIdentifier`
(see `validateIdentifier` in `src/keys/manager.zig`). The HKDF context
strings themselves (`geode/trk/...`, `geode/sk/...`, `geode/fek/.../v<N>`,
`geode/bi/.../v<N>`, salt `geode-fle-salt`) are **compatibility-locked for
Geode interop** — keys derived by this library must match keys derived by
Geode for the same identifiers, so the context format cannot change.

## Envelope format

`aead.EnvelopeV1.serialize` produces:

```text
[alg_id: u8][key_version: u16 LE][nonce: 12B][tag: 16B][ciphertext_len: u32 LE][ciphertext]
```

- `alg_id` — 1 = AES-256-GCM, 2 = ChaCha20-Poly1305 (XChaCha20-Poly1305 is
  reserved for key wrapping and rejected by `encryptField`/`decryptField`).
- `key_version` — the FEK version the field was encrypted under; tells
  readers which key version to request after a rotation.
- Deserialization is bounds-checked (`InvalidEnvelope` on truncated or
  overflowing input) and fuzz-tested.

Ciphertext is bound to its context through AAD built by `aead.makeAAD`:
each of `(tenant, schema, field, record_id)` is length-prefixed with a
`u32` LE, followed by `key_version` as `u16` LE. The length-prefixed
encoding is injective, so an attacker cannot move a ciphertext between
tenants, schemas, fields, records, or key versions without
`Error.AEADAuthFailed`.

## Blind-index flow

`BlindIndex` provides equality search over encrypted fields without
revealing plaintext:

1. **Normalize** — `normalizeForBlindIndex` trims ASCII whitespace and
   lowercases the value (deterministic matching for, e.g., emails).
2. **Tokenize** — `HMAC-SHA256(BIK, normalized)` produces the full
   32-byte `BlindIndexToken` (no truncation).
3. **Map** — the token maps to a list of record IDs per `(schema, field)`;
   `lookup` recomputes the token for a query value and returns matching
   record IDs (the returned slice borrows index storage and is only valid
   until the next mutation).

What it reveals: **equality patterns** — two records with the same
normalized value for the same field produce the same token, so duplicate
counts and query-access patterns are observable to anyone holding the
index. What it does not reveal: the plaintext itself — tokens are keyed
HMACs, so without the BIK an attacker cannot brute-force low-entropy
values offline.

## Rotation

`KeyManager.rotateFEK(tenant, schema, field)` bumps the current version to
`N+1` and returns it:

- New writes should request `getFEK` with the new version; old versions
  remain derivable for reading existing data during migration (versioned
  HKDF contexts mean every historical version is always re-derivable from
  the master key).
- Version state is **in-memory only** and resets when the KeyManager is
  destroyed; persist the current version externally if you need it to
  survive restarts. `rotateFEK` fails with `InvalidKeyVersion` at the
  `u16` ceiling.
- Call `clearCache()` after rotation events to evict cached keys.

**When to rotate:** FEKs are used with random 96-bit AEAD nonces. Per NIST
SP 800-38D, the same key must not perform anywhere near 2^32 encryptions;
plan rotation at or below ~2^28 encryptions per field-version for margin.

## Zeroization guarantees

- **HKDF intermediates** — the PRK and expansion blocks are
  `secureZero`-ed inside `hkdfSha256`; intermediate TRK/SK values in
  `KeyManager.getDerivedKey` are zeroized via `defer` after derivation.
- **Key caches** — `clearCache()`/`secureClear` and `deinit` zeroize every
  cached FEK/BIK before freeing; `KeyManager.deinit` also zeroizes the
  master key copy.
- **Decrypt failure paths** — `decryptField` zeroizes and frees the
  partially written plaintext buffer on any error (including AEAD
  authentication failure); `unwrapKey32` zeroizes its stack plaintext on
  failure.
- **Blind-index buffers** — the normalized-plaintext scratch buffer is
  zeroized and freed after token computation in both `put` and `lookup`.
- **Provider material** — `EnvKeyProvider` zeroizes the environment
  variable copy after parsing; `parseKeyMaterial` zeroizes its partial key
  on invalid hex; `StaticKeyProvider.deinit` zeroizes its stored key.

Not covered: plaintext returned by `decryptField` belongs to the caller —
zeroize it (`std.crypto.secureZero`) before freeing, as the examples do.
