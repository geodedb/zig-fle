# fle Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every actionable finding from the 2026-06-11 appsec review (FLE-001..014), security tool scan (SCR-001..004), quality scan (DUP/DC/CX/DOC), perf scan, and gap analysis (issues #23–#26) in the `fle` Zig library.

**Architecture:** The fixes are grouped into independent tasks ordered security-first. Crypto behavior changes (RNG, envelope parsing, identifier validation) come with regression tests written first (TDD). Derivation contexts (HKDF `geode/...` strings) are **never changed** — compatibility with existing ciphertext is preserved by validating identifiers at the API boundary instead. Each task ends with `zig build test && zig build test-integration` green and a conventional commit.

**Tech Stack:** Zig 0.16.0 (installed), `std.crypto`, GitLab CI, pre-commit, Python 3 (scripts/).

**Repo:** `/data/home/benji/src/gl/gitlab.com/devnw/zig/fle` (work on `main`, commit per task, do NOT push until all tasks pass).

**Canonical check command (run at the end of every task):**

```bash
zig build test --summary all && zig build test-integration --summary all && zig fmt --check src/ tests/ examples/ build.zig
```

---

## Task 1: RNG hardening — replace unchecked `getrandom` with `std.crypto.random.bytes` (FLE-001, FLE-012, perf#4)

**Files:**

- Modify: `src/crypto/aead.zig` (lines 154-155, 282-283, and all test-block getrandom sites: 319, 344, 361, 389-391, 401-408, 429)
- Modify: `src/crypto/bulk.zig` (test sites: lines 333, 361, 401, 467)
- Modify: `tests/integration.zig:253`
- Modify: `examples/bulk.zig:22`
- Modify: `tests/bench.zig:59`

- [ ] **Step 1: Write the failing test** — add to `src/crypto/aead.zig` (end of file):

```zig
test "encryptField produces unique nonces across calls" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.crypto.random.bytes(&fek);

    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    // 64 encryptions of the same plaintext under the same key must
    // yield 64 distinct nonces (random-nonce contract).
    var seen = std.AutoHashMap([12]u8, void).init(allocator);
    defer seen.deinit();
    for (0..64) |_| {
        var env = try encryptField(allocator, .aes256_gcm, &fek, aad, "x", 1);
        defer env.deinit(allocator);
        const gop = try seen.getOrPut(env.nonce);
        try testing.expect(!gop.found_existing);
    }
}
```

- [ ] **Step 2: Run** `zig build test --summary all` — the new test should PASS already on a healthy host (getrandom works here); that's fine — the load-bearing change is the source swap, the test locks the contract.

- [ ] **Step 3: Replace ALL `_ = std.os.linux.getrandom(...)` sites.** In `src/crypto/aead.zig:154-155`:

```zig
    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);
```

In `src/crypto/aead.zig:282-283` (wrapKey32):

```zig
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
```

In every test/example site, replace `_ = std.os.linux.getrandom(@ptrCast(&X), @sizeOf(@TypeOf(X)), 0);` with `std.crypto.random.bytes(&X);`. Verify zero remaining sites: `grep -rn "os.linux.getrandom" src/ tests/ examples/` → must return nothing. (`std.os.linux.clock_gettime` in bench stays.)

- [ ] **Step 4: Update the doc comment** at `src/crypto/aead.zig:130-133` — change "Nonces are always generated randomly from the OS CSPRNG." to "Nonces are always generated from `std.crypto.random` (the process CSPRNG; infallible and portable)."

- [ ] **Step 5: Run the canonical check** — all green.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "fix(crypto): use std.crypto.random for nonces — never silently uses uninitialized memory (FLE-001, FLE-012)"`

---

## Task 2: Envelope parsing hardening — overflow-free length check + negative tests + fuzz (FLE-002)

**Files:**

- Modify: `src/crypto/aead.zig:82-87` (`EnvelopeV1.deserialize`)

- [ ] **Step 1: Write failing tests** — add to `src/crypto/aead.zig`:

```zig
test "deserialize rejects overflow-length envelope without panicking" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Valid 35-byte header, ciphertext_len = 0xFFFFFFFF (overflows 35 + len in u32)
    var data: [40]u8 = @splat(0);
    data[0] = 1; // alg_id
    std.mem.writeInt(u32, data[31..35], 0xFFFF_FFFF, .little);
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &data));
}

test "deserialize rejects truncated and boundary-length envelopes" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Shorter than header
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &[_]u8{0} ** 34));

    // Header claims 5 ciphertext bytes but only 4 present
    var data: [39]u8 = @splat(0);
    std.mem.writeInt(u32, data[31..35], 5, .little);
    try testing.expectError(Error.InvalidEnvelope, EnvelopeV1.deserialize(allocator, &data));

    // Exact boundary: claims 4, has 4 — must succeed
    var ok_data: [39]u8 = @splat(0);
    ok_data[0] = 1;
    std.mem.writeInt(u32, ok_data[31..35], 4, .little);
    var env = try EnvelopeV1.deserialize(allocator, &ok_data);
    defer env.deinit(allocator);
    try testing.expectEqual(@as(usize, 4), env.ciphertext.len);
}
```

- [ ] **Step 2: Run** `zig build test --summary all` — expect the overflow test to FAIL (panic: integer overflow) in Debug.

- [ ] **Step 3: Fix the bound check** at `src/crypto/aead.zig:84`:

```zig
        if (ciphertext_len > data.len - 35) return Error.InvalidEnvelope;
```

(`data.len >= 35` is guaranteed by line 74, so `data.len - 35` cannot underflow; the comparison is in `usize` after the `u32` widens, and no addition can overflow.)

- [ ] **Step 4: Add a fuzz test** (this also closes the "no fuzz harness exists" coverage gap) — append to `src/crypto/aead.zig`:

```zig
test "fuzz EnvelopeV1.deserialize never crashes on arbitrary input" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) anyerror!void {
            var gpa: std.heap.DebugAllocator(.{}) = .init;
            defer _ = gpa.deinit();
            const allocator = gpa.allocator();
            var env = EnvelopeV1.deserialize(allocator, input) catch return;
            env.deinit(allocator);
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}
```

(If the `std.testing.fuzz` signature differs on the installed Zig, adapt to the installed 0.16.0 API — check `zig std` docs; the requirement is a fuzz entry over `deserialize` that ignores expected errors and crashes on panics.)

- [ ] **Step 5: Run the canonical check** — all green. Also run `timeout 30 zig build test --fuzz 2>&1 | tail -5 || true` and confirm no crash is reported (timeout exit is fine).

- [ ] **Step 6: Commit** — `git commit -am "fix(crypto): overflow-safe envelope length validation + malformed-input and fuzz tests (FLE-002)"`

---

## Task 3: `decryptField` — validate before allocating, deduplicate cleanup (perf#5, CX-004)

**Files:**

- Modify: `src/crypto/aead.zig:190-266`

- [ ] **Step 1: Refactor.** Move algorithm resolution BEFORE the plaintext allocation and extract the repeated zeroize+free+span-end sequence. Replace the body section (lines 208-262) with:

```zig
    if (fek.len != 32) return Error.InvalidKey;

    // Resolve and validate the algorithm BEFORE allocating: rejecting a
    // corrupted alg_id must not cost an alloc/free round-trip.
    const alg: Alg = inline for (@typeInfo(Alg).@"enum".fields) |f| {
        if (envelope.alg_id == f.value) break @enumFromInt(f.value);
    } else {
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidAlg;
    };
    if (alg == .xchacha20_poly1305) {
        // XChaCha20 uses 24-byte nonces; not compatible with EnvelopeV1 (12-byte nonce).
        // Use unwrapKey32 for key unwrapping or the raw primitive directly.
        observability.endFleSpan(__obs_span, false);
        return Error.InvalidAlg;
    }

    const plaintext = try allocator.alloc(u8, envelope.ciphertext.len);

    const fail = struct {
        fn cleanup(a: std.mem.Allocator, pt: []u8, span: anytype) Error {
            std.crypto.secureZero(u8, pt);
            a.free(pt);
            observability.endFleSpan(span, false);
            return Error.AEADAuthFailed;
        }
    };

    switch (alg) {
        .aes256_gcm => {
            const AES = std.crypto.aead.aes_gcm.Aes256Gcm;
            AES.decrypt(plaintext, envelope.ciphertext, envelope.tag, aad, envelope.nonce, fek[0..32].*) catch
                return fail.cleanup(allocator, plaintext, __obs_span);
        },
        .chacha20_poly1305 => {
            const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            ChaCha.decrypt(plaintext, envelope.ciphertext, envelope.tag, aad, envelope.nonce, fek[0..32].*) catch
                return fail.cleanup(allocator, plaintext, __obs_span);
        },
        .xchacha20_poly1305 => unreachable, // rejected above
    }
```

Note: the `alg_name` resolution for the span at lines 200-203 stays as-is (it runs before this). If the `anytype` span parameter does not compile cleanly, inline the helper as a local closure-style block or keep two catch blocks with a shared `fail` defer-pattern — the requirements are: (a) no allocation before alg validation, (b) cleanup logic written once, (c) behavior identical (generic `AEADAuthFailed`/`InvalidAlg`, zeroized buffer).

- [ ] **Step 2: Run the canonical check** — all existing AEAD tests (round-trip, wrong-AAD auth failure, xchacha rejection) must still pass.

- [ ] **Step 3: Commit** — `git commit -am "refactor(crypto): validate alg before allocating in decryptField; dedupe cleanup (CX-004)"`

---

## Task 4: Identifier validation + injective cache keys (FLE-003, perf#2)

**Files:**

- Modify: `src/keys/manager.zig` (Error set, `buildCacheKey`, `getFEK`, `getBIK`, `rotateFEK`)
- Modify: `src/index/blind_index.zig` (`buildFieldKey`)

**Design (locked):** HKDF context strings (`geode/...`) are UNCHANGED — existing ciphertext stays decryptable. Instead: (a) `tenant`/`schema`/`field` are validated to reject `:`, `/`, and empty strings at every KeyManager entry point; (b) in-memory cache keys and the blind-index field key become injective (length-prefixed), which is safe because they never persist.

- [ ] **Step 1: Write failing tests** — add to `src/keys/manager.zig`:

```zig
test "getFEK rejects identifiers containing reserved delimiters" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);
    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    // ':' and '/' are reserved (HKDF context + cache delimiters); empty is invalid.
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a:b", .schema = "s", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a", .schema = "s/x", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getFEK(.{ .tenant = "a", .schema = "s", .field = "", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.getBIK(.{ .tenant = "a:b", .schema = "s", .field = "f", .version = 1 }));
    try testing.expectError(Error.InvalidIdentifier, manager.rotateFEK("a:b", "s", "f"));
}

test "cache keys are injective — no cross-identifier collision" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);
    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    // Same concatenation under the old ':' scheme, different identities.
    // "ab"+"c" vs "a"+"bc" — distinct tenants MUST get distinct FEKs even
    // when one primes the cache first.
    const fek1 = try manager.getFEK(.{ .tenant = "ab", .schema = "c", .field = "f", .version = 1 });
    const fek2 = try manager.getFEK(.{ .tenant = "a", .schema = "bc", .field = "f", .version = 1 });
    try testing.expect(!std.mem.eql(u8, &fek1, &fek2));
}
```

- [ ] **Step 2: Run** `zig build test` — first test FAILS (no `InvalidIdentifier`); second currently PASSES only by luck of ':' separators — keep it as the regression lock.

- [ ] **Step 3: Implement.** In `src/keys/manager.zig`, extend the error set:

```zig
pub const Error = error{
    KeyNotFound,
    InvalidKeyVersion,
    InvalidIdentifier,
    OutOfMemory,
    MasterKeyRequired,
};
```

(`RotationInProgress` is removed here if Task 8 has not run yet — coordinate: if Task 8 already removed it, just add `InvalidIdentifier`.)

Add a validator and an injective key builder:

```zig
/// Reserved characters in identifiers: ':' and '/' are delimiters in
/// HKDF derivation contexts and rotation key-paths. Rejecting them at
/// the API boundary keeps every downstream encoding injective without
/// changing the (compatibility-locked) HKDF context format.
fn validateIdentifier(s: []const u8) Error!void {
    if (s.len == 0) return Error.InvalidIdentifier;
    for (s) |c| {
        if (c == ':' or c == '/') return Error.InvalidIdentifier;
    }
}

fn validateIds(ids: types.KeyIds) Error!void {
    try validateIdentifier(ids.tenant);
    try validateIdentifier(ids.schema);
    try validateIdentifier(ids.field);
}

/// Build an injective (length-prefixed) cache key for FEK/BIK lookup.
/// Layout: [len:u32 LE][tenant][len:u32 LE][schema][len:u32 LE][field][version:u16 LE]
fn buildCacheKey(allocator: std.mem.Allocator, ids: types.KeyIds) ![]u8 {
    const total = 4 + ids.tenant.len + 4 + ids.schema.len + 4 + ids.field.len + 2;
    const key = try allocator.alloc(u8, total);
    var pos: usize = 0;
    inline for (.{ ids.tenant, ids.schema, ids.field }) |s| {
        std.mem.writeInt(u32, key[pos..][0..4], @intCast(s.len), .little);
        pos += 4;
        @memcpy(key[pos .. pos + s.len], s);
        pos += s.len;
    }
    std.mem.writeInt(u16, key[pos..][0..2], ids.version, .little);
    return key;
}

/// Stack-buffer variant for the hot cache-hit path: writes the same
/// injective encoding into `buf` and returns the used slice, or null
/// if the identifiers exceed the buffer (caller falls back to heap).
fn buildCacheKeyBuf(buf: []u8, ids: types.KeyIds) ?[]const u8 {
    const total = 4 + ids.tenant.len + 4 + ids.schema.len + 4 + ids.field.len + 2;
    if (total > buf.len) return null;
    var pos: usize = 0;
    inline for (.{ ids.tenant, ids.schema, ids.field }) |s| {
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(s.len), .little);
        pos += 4;
        @memcpy(buf[pos .. pos + s.len], s);
        pos += s.len;
    }
    std.mem.writeInt(u16, buf[pos..][0..2], ids.version, .little);
    return buf[0..total];
}
```

Rewrite `getFEK` (and `getBIK` identically with `bik_cache`/`deriveBIKVersioned`) to validate first and use the stack buffer for the lookup, allocating only on a miss:

```zig
    pub fn getFEK(self: *KeyManager, ids: types.KeyIds) ![32]u8 {
        try validateIds(ids);

        var key_buf: [256]u8 = undefined;
        const stack_key = buildCacheKeyBuf(&key_buf, ids);
        if (stack_key) |sk_key| {
            if (self.fek_cache.get(sk_key)) |entry| return entry.key;
        }

        var trk = try hkdf.deriveTRK(&self.master_key, ids.tenant);
        defer std.crypto.secureZero(u8, &trk);
        var sk = try hkdf.deriveSK(&trk, ids.schema);
        defer std.crypto.secureZero(u8, &sk);
        const fek = try hkdf.deriveFEKVersioned(&sk, ids.field, ids.version);

        const cache_key = try buildCacheKey(self.allocator, ids);
        errdefer self.allocator.free(cache_key);
        if (stack_key == null) {
            // Identifiers too long for the stack buffer — check the heap key
            // before inserting to avoid duplicate-key leaks.
            if (self.fek_cache.get(cache_key)) |entry| {
                self.allocator.free(cache_key);
                return entry.key;
            }
        }
        try self.fek_cache.put(cache_key, .{ .key = fek, .version = ids.version });
        return fek;
    }
```

(Note: the prior code had a key-string leak risk on repeated misses for the same ids — `put` overwrites without freeing the new duplicate key. With the cache-hit check above, a second call for the same ids hits the cache, so `put` is only reached once per unique ids. Keep that invariant.)

Rewrite `rotateFEK`'s key-path (line 209-213) with the same injective encoding via `buildRotationKeyPath`:

```zig
        try validateIdentifier(tenant);
        try validateIdentifier(schema);
        try validateIdentifier(field);

        const total = 4 + tenant.len + 4 + schema.len + 4 + field.len;
        const key_path = try self.allocator.alloc(u8, total);
        {
            var pos: usize = 0;
            inline for (.{ tenant, schema, field }) |s| {
                std.mem.writeInt(u32, key_path[pos..][0..4], @intCast(s.len), .little);
                pos += 4;
                @memcpy(key_path[pos .. pos + s.len], s);
                pos += s.len;
            }
        }
        errdefer self.allocator.free(key_path);
```

In `src/index/blind_index.zig`, make `buildFieldKey` injective (the '.' join has the same ambiguity — `a.b`+`c` vs `a`+`b.c`):

```zig
    fn buildFieldKey(allocator: std.mem.Allocator, schema: []const u8, field: []const u8) ![]u8 {
        const total = 4 + schema.len + 4 + field.len;
        const key = try allocator.alloc(u8, total);
        var pos: usize = 0;
        inline for (.{ schema, field }) |s| {
            std.mem.writeInt(u32, key[pos..][0..4], @intCast(s.len), .little);
            pos += 4;
            @memcpy(key[pos .. pos + s.len], s);
            pos += s.len;
        }
        return key;
    }
```

Add a blind-index collision regression test in `src/index/blind_index.zig`:

```zig
test "BlindIndex field keys are injective across schema/field boundaries" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var index = BlindIndex.init(allocator);
    defer index.deinit();
    var bik: [32]u8 = undefined;
    std.crypto.random.bytes(&bik);

    try index.put("a.b", "c", bik, "v", "r1");
    // Different identity, same '.'-joined string under the old scheme.
    const results = try index.lookup("a", "b.c", bik, "v");
    try testing.expect(results == null);
}
```

- [ ] **Step 4: Run the canonical check.** All tests green, including the new ones. Integration tests use clean identifiers ("tenant1" etc.) so they must not regress.

- [ ] **Step 5: Update doc comments**: on `KeyManager` struct doc, add: "Identifiers (`tenant`, `schema`, `field`) must be non-empty and must not contain `:` or `/` — these are reserved as derivation-context delimiters; violations return `Error.InvalidIdentifier`." Add the same note to `KeyIds` in `src/keys/types.zig`.

- [ ] **Step 6: Commit** — `git commit -am "fix(keys): validate identifiers + injective cache/index keys, stack-buffer cache hits (FLE-003)"`

---

## Task 5: Blind-index hygiene — zeroize normalized plaintext, document lookup lifetime, re-export token type (FLE-006, FLE-008, DC-007, Z3)

**Files:**

- Modify: `src/index/blind_index.zig:55-56, 97-120`
- Modify: `src/root.zig` (convenience aliases)

- [ ] **Step 1: Zeroize.** In `put` (line 55-56) and `lookup` (109-110), change:

```zig
        const normalized = try hmac_mod.normalizeForBlindIndex(self.allocator, plaintext);
        defer {
            std.crypto.secureZero(u8, normalized);
            self.allocator.free(normalized);
        }
```

- [ ] **Step 2: Document the borrowed-slice contract** on `lookup` (replace the doc comment at line 96):

```zig
    /// Lookup record IDs matching a plaintext value.
    ///
    /// LIFETIME: the returned slice borrows index-internal storage and is
    /// valid only until the next mutating call (`put`, `remove`, `deinit`)
    /// on this BlindIndex. Callers that need to retain results must copy
    /// them before mutating the index.
```

- [ ] **Step 3: Re-export the token type** in `src/root.zig` convenience aliases (after the `BlindIndex` line):

```zig
pub const BlindIndexToken = blind_index.BlindIndexToken;
```

- [ ] **Step 4: Run the canonical check**, then commit — `git commit -am "fix(index): zeroize normalized plaintext, document lookup lifetime, export BlindIndexToken (FLE-006, FLE-008)"`

---

## Task 6: EnvKeyProvider — strict key format, zeroize on error, tests (FLE-013)

**Files:**

- Modify: `src/keys/provider.zig:71-132`

- [ ] **Step 1: Extract a testable pure parser + write failing tests.** Add to `src/keys/provider.zig` (file scope, before EnvKeyProvider):

```zig
/// Parse master-key material. Accepted formats (exact, no truncation):
///   - exactly 32 raw bytes, or
///   - exactly 64 hex characters (decoded to 32 bytes).
/// Anything else is rejected — silent truncation of longer values would
/// quietly reduce effective key entropy.
pub fn parseKeyMaterial(value: []const u8) MasterKeyProvider.GetKeyError![32]u8 {
    var key: [32]u8 = undefined;
    if (value.len == 64) {
        for (0..32) |i| {
            const hi = std.fmt.charToDigit(value[i * 2], 16) catch {
                std.crypto.secureZero(u8, &key);
                return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
            };
            const lo = std.fmt.charToDigit(value[i * 2 + 1], 16) catch {
                std.crypto.secureZero(u8, &key);
                return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
            };
            key[i] = @as(u8, hi) * 16 + @as(u8, lo);
        }
        return key;
    }
    if (value.len == 32) {
        @memcpy(&key, value);
        return key;
    }
    return MasterKeyProvider.GetKeyError.MasterKeyUnavailable;
}
```

Tests:

```zig
test "parseKeyMaterial accepts exactly 32 raw bytes" {
    const raw = [_]u8{0xAB} ** 32;
    const key = try parseKeyMaterial(&raw);
    try std.testing.expectEqualSlices(u8, &raw, &key);
}

test "parseKeyMaterial accepts exactly 64 hex chars" {
    const hex = "00112233445566778899aabbccddeeff" ++ "00112233445566778899aabbccddeeff";
    const key = try parseKeyMaterial(hex);
    try std.testing.expectEqual(@as(u8, 0x00), key[0]);
    try std.testing.expectEqual(@as(u8, 0xff), key[15]);
}

test "parseKeyMaterial rejects truncatable / short / bad-hex values" {
    const testing = std.testing;
    const E = MasterKeyProvider.GetKeyError;
    // 33 raw bytes: previously silently truncated — now rejected.
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 33));
    // 48 bytes: rejected (neither 32 raw nor 64 hex).
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 48));
    // 31 bytes: too short.
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(&[_]u8{0xAB} ** 31));
    // 64 chars with an invalid nibble.
    const bad_hex = "zz112233445566778899aabbccddeeff" ++ "00112233445566778899aabbccddeeff";
    try testing.expectError(E.MasterKeyUnavailable, parseKeyMaterial(bad_hex));
}
```

- [ ] **Step 2: Run** `zig build test` — new tests FAIL (function doesn't exist yet) → implement → PASS.

- [ ] **Step 3: Rewire `EnvKeyProvider.getMasterKey`** to use it (replacing lines 100-123):

```zig
        return parseKeyMaterial(env_val);
```

- [ ] **Step 4: Update the EnvKeyProvider doc comment** (lines 71-73) to state the exact accepted formats (32 raw / 64 hex, everything else rejected).

- [ ] **Step 5: Canonical check; commit** — `git commit -am "fix(keys): strict EnvKeyProvider key format, zeroize partial key on error, add tests (FLE-013)"`

**NOTE — BREAKING:** values of length 33–63 or >64 raw bytes that previously truncated to 32 now fail. This is intentional (entropy-loss footgun); call it out in the CHANGELOG entry in Task 16.

---

## Task 7: KeyManager.wrapKey/unwrapKey — tests + comptime AAD (gap item, Z1)

**Files:**

- Modify: `src/keys/manager.zig:237-251` + new tests

- [ ] **Step 1: Write failing test** (none exist for these methods):

```zig
test "KeyManager wrapKey/unwrapKey round-trip" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);
    var manager = try KeyManager.init(allocator, master_key);
    defer manager.deinit();

    var wrapping_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrapping_key);
    var key_to_wrap: [32]u8 = undefined;
    std.crypto.random.bytes(&key_to_wrap);

    var envelope = try manager.wrapKey(&key_to_wrap, &wrapping_key);
    defer envelope.deinit(allocator);

    const unwrapped = try manager.unwrapKey(envelope, &wrapping_key);
    defer {
        std.crypto.secureZero(u8, unwrapped);
        allocator.free(unwrapped);
    }
    try testing.expectEqualSlices(u8, &key_to_wrap, unwrapped);

    var wrong_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);
    try testing.expectError(aead.Error.AEADAuthFailed, manager.unwrapKey(envelope, &wrong_key));
}
```

- [ ] **Step 2: Run → PASS** (methods already work).

- [ ] **Step 3: Eliminate the per-call AAD allocation.** The AAD for key-wrap is constant (`makeAAD(alloc, "system", "sys", "key_wrap", "0", 1)`). Replace both call sites with a comptime constant in `manager.zig`:

```zig
/// Constant AAD for KeyManager.wrapKey/unwrapKey — identical bytes to
/// aead.makeAAD(alloc, "system", "sys", "key_wrap", "0", 1), computed
/// at comptime so the hot path never allocates.
const wrap_key_aad: [4 + 6 + 4 + 3 + 4 + 8 + 4 + 1 + 2]u8 = blk: {
    var buf: [4 + 6 + 4 + 3 + 4 + 8 + 4 + 1 + 2]u8 = undefined;
    var pos: usize = 0;
    for (.{ "system", "sys", "key_wrap", "0" }) |s| {
        std.mem.writeInt(u32, buf[pos..][0..4], s.len, .little);
        pos += 4;
        @memcpy(buf[pos .. pos + s.len], s);
        pos += s.len;
    }
    std.mem.writeInt(u16, buf[pos..][0..2], 1, .little);
    break :blk buf;
};
```

And in `wrapKey`/`unwrapKey`:

```zig
    pub fn wrapKey(self: *KeyManager, key_to_wrap: []const u8, wrapping_key: []const u8) !aead.EnvelopeV1 {
        return aead.encryptField(self.allocator, .aes256_gcm, wrapping_key, &wrap_key_aad, key_to_wrap, 1);
    }

    pub fn unwrapKey(self: *KeyManager, envelope: aead.EnvelopeV1, wrapping_key: []const u8) ![]u8 {
        return aead.decryptField(self.allocator, wrapping_key, &wrap_key_aad, envelope);
    }
```

Add an equivalence test so the constant can never drift from `makeAAD`:

```zig
test "wrap_key_aad matches makeAAD output" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const dynamic = try aead.makeAAD(allocator, "system", "sys", "key_wrap", "0", 1);
    defer allocator.free(dynamic);
    try std.testing.expectEqualSlices(u8, dynamic, &wrap_key_aad);
}
```

- [ ] **Step 4: Canonical check; commit** — `git commit -am "test(keys): wrapKey/unwrapKey coverage; comptime wrap AAD constant (Z1)"`

---

## Task 8: Remove dead error variants (DC-001..003)

**Files:**

- Modify: `src/crypto/aead.zig:33-42` (remove `NonceReuse`, `SearchNotPermitted`)
- Modify: `src/keys/manager.zig:11-17` (remove `RotationInProgress`)
- Modify: `src/crypto/bulk.zig:203-215` (remove the two dead `toFleError` arms)

- [ ] **Step 1: Remove** `NonceReuse,` and `SearchNotPermitted,` from `aead.Error`; remove `RotationInProgress,` from `manager.Error`; remove the lines `error.NonceReuse => Error.NonceReuse,` and `error.SearchNotPermitted => Error.SearchNotPermitted,` from `toFleError` in bulk.zig.

- [ ] **Step 2: Build** — `zig build check && zig build test`. Fix any remaining references the compiler reports (there should be none beyond the three above; grep to confirm: `grep -rn "NonceReuse\|SearchNotPermitted\|RotationInProgress" src/ tests/ examples/ docs/GAP_ANALYSIS.md`). Update the `docs/GAP_ANALYSIS.md` "unused error variants" note in Task 19 (not here).

- [ ] **Step 3: Canonical check; commit** — `git commit -am "refactor: remove never-raised error variants NonceReuse/SearchNotPermitted/RotationInProgress (DC-001..003)"`

---

## Task 9: Bulk serial-path arena + per-chunk ok_count + chunk default (perf#1, perf#7, Z4)

**Files:**

- Modify: `src/crypto/bulk.zig`

- [ ] **Step 1: Serial arena.** Change `encryptOne`/`decryptOne` to take a separate AAD allocator, and wrap the serial loops in an arena. In `encryptFieldsBulk` (lines 114-123):

```zig
    // Serial fallback. Arena amortizes per-field AAD allocations exactly
    // like the chunked path; envelopes still come from `allocator` because
    // they outlive this call.
    if (pool == null or fields.len == 1) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const aad_alloc = arena.allocator();
        var ok_count: usize = 0;
        for (fields, 0..) |f, idx| {
            out_results[idx] = encryptOne(aad_alloc, allocator, f);
            if (out_results[idx] == .ok) ok_count += 1;
        }
        observability.endFleSpan(__obs_span, true);
        return ok_count;
    }
```

And `encryptOne` becomes:

```zig
fn encryptOne(aad_allocator: std.mem.Allocator, out_allocator: std.mem.Allocator, f: BulkField) BulkResult {
    const aad = aead.makeAAD(
        aad_allocator,
        f.tenant_id,
        f.schema,
        f.field,
        f.record_id,
        f.key_version,
    ) catch |e| return .{ .err = toFleError(e) };
    // No free: aad_allocator is an arena owned by the caller.

    const env = aead.encryptField(
        out_allocator,
        f.alg,
        f.fek,
        aad,
        f.plaintext,
        f.key_version,
    ) catch |e| return .{ .err = toFleError(e) };

    return .{ .ok = env };
}
```

Mirror exactly for `decryptOne` and the serial branch of `decryptFieldsBulk`.

- [ ] **Step 2: Per-chunk ok_count.** Add `ok_count: usize = 0` to `ChunkCtx` and `DecryptChunkCtx`. In `encryptChunkInline`/`decryptChunkInline`, increment `c.ok_count` when storing an `.ok` result. After `wg.wait()` in both bulk functions, replace the O(N) scan:

```zig
    var ok_count: usize = 0;
    for (ctxs) |c| ok_count += c.ok_count;
```

(The serial paths already count inline.)

- [ ] **Step 3: Chunk default.** Line 28: `pub const default_chunk_size: usize = 1024;` and update its comment to cite the 2026-06-11 bench plateau (cs=1024 ≈ cs=4096 within 1%).

- [ ] **Step 4: Canonical check** (the 10k-field parallel tests exercise both counters and arenas). Then run `zig build bench -Doptimize=ReleaseFast 2>/dev/null || zig build bench` once and record the serial number in the commit message — expect serial to improve dramatically (~39x gap closing to near single-thread parallel rate).

- [ ] **Step 5: Commit** — `git commit -am "perf(bulk): arena for serial path, per-chunk ok_count, default_chunk_size 1024 (perf#1,#7,Z4)"`

---

## Task 10: Deduplicate bulk encrypt/decrypt drivers (DUP-001, DUP-002, CX-001)

**Files:**

- Modify: `src/crypto/bulk.zig`

- [ ] **Step 1: Extract the shared driver.** The encrypt/decrypt pipelines differ only in: span name, field type, result type, ctx type, and the per-field operation. Introduce one generic driver and have both public functions delegate:

```zig
fn BulkCtx(comptime F: type, comptime R: type) type {
    return struct {
        allocator: std.mem.Allocator,
        fields: []const F,
        out_slice: []R,
        wg: *tp.WaitGroup,
        ok_count: usize = 0,
    };
}

/// Shared bulk driver. `runOne(aad_alloc, out_alloc, field) R` performs the
/// per-field operation; `isOk(R) bool` classifies results.
fn bulkRun(
    comptime F: type,
    comptime R: type,
    comptime span_name: []const u8,
    comptime runOne: fn (std.mem.Allocator, std.mem.Allocator, F) R,
    comptime isOk: fn (R) bool,
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const F,
    out_results: []R,
    options: BulkOptions,
) !usize {
    const Ctx = BulkCtx(F, R);
    const chunkInline = struct {
        fn run(c: *Ctx) void {
            var arena = std.heap.ArenaAllocator.init(c.allocator);
            defer arena.deinit();
            const aad_alloc = arena.allocator();
            for (c.fields, 0..) |f, idx| {
                c.out_slice[idx] = runOne(aad_alloc, c.allocator, f);
                if (isOk(c.out_slice[idx])) c.ok_count += 1;
            }
        }
        fn task(ctx_: *anyopaque, _: *tp.TaskContext) void {
            const c: *Ctx = @ptrCast(@alignCast(ctx_));
            run(c);
            c.wg.done();
        }
    };

    var __obs_span = observability.startFleSpan(span_name, "", "");
    defer __obs_span.end(null);
    errdefer observability.endFleSpan(__obs_span, false);

    std.debug.assert(out_results.len == fields.len);
    if (fields.len == 0) {
        observability.endFleSpan(__obs_span, true);
        return 0;
    }

    if (pool == null or fields.len == 1) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const aad_alloc = arena.allocator();
        var ok_count: usize = 0;
        for (fields, 0..) |f, idx| {
            out_results[idx] = runOne(aad_alloc, allocator, f);
            if (isOk(out_results[idx])) ok_count += 1;
        }
        observability.endFleSpan(__obs_span, true);
        return ok_count;
    }

    const chunk_size = if (options.chunk_size == 0) default_chunk_size else options.chunk_size;
    const p = pool.?;
    const n_chunks = (fields.len + chunk_size - 1) / chunk_size;
    const ctxs = try allocator.alloc(Ctx, n_chunks);
    defer allocator.free(ctxs);

    var wg = p.waitGroup();
    var i: usize = 0;
    var ci: usize = 0;
    while (i < fields.len) : (ci += 1) {
        const end = @min(i + chunk_size, fields.len);
        ctxs[ci] = .{ .allocator = allocator, .fields = fields[i..end], .out_slice = out_results[i..end], .wg = &wg };
        i = end;
    }

    // WaitGroup.add(n_chunks) BEFORE any submission — prevents a fast-finishing
    // task from calling done() before add() runs (underflow / premature unblock).
    wg.add(@intCast(n_chunks));

    // Submit each chunk. On submit failure, run remaining chunks inline so that
    // partial-success semantics are preserved and wg.done() is always called.
    for (ctxs, 0..) |*c, k| {
        _ = p.submit(chunkInline.task, c, .{ .lane = options.lane }) catch {
            for (ctxs[k..]) |*rest| {
                chunkInline.run(rest);
                rest.wg.done();
            }
            break;
        };
    }
    wg.wait();

    var ok_count: usize = 0;
    for (ctxs) |c| ok_count += c.ok_count;
    observability.endFleSpan(__obs_span, true);
    return ok_count;
}
```

Then:

```zig
fn encryptResultOk(r: BulkResult) bool {
    return r == .ok;
}
fn decryptResultOk(r: BulkDecryptResult) bool {
    return r == .ok;
}

pub fn encryptFieldsBulk(
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const BulkField,
    out_results: []BulkResult,
    options: BulkOptions,
) !usize {
    return bulkRun(BulkField, BulkResult, "bulk_encrypt", encryptOne, encryptResultOk, allocator, pool, fields, out_results, options);
}

pub fn decryptFieldsBulk(
    allocator: std.mem.Allocator,
    pool: ?*tp.ThreadPool,
    fields: []const BulkDecryptField,
    out_results: []BulkDecryptResult,
    options: BulkOptions,
) !usize {
    return bulkRun(BulkDecryptField, BulkDecryptResult, "bulk_decrypt", decryptOne, decryptResultOk, allocator, pool, fields, out_results, options);
}
```

Delete the now-unused `ChunkCtx`, `DecryptChunkCtx`, `encryptChunk`, `decryptChunk`, `encryptChunkInline`, `decryptChunkInline`. Preserve ALL existing doc comments on the public functions (move the SECURITY span comments onto `bulkRun` or keep on the wrappers).

- [ ] **Step 2: Canonical check** — the 4 bulk tests (serial round-trip, partial success, 10k parallel encrypt, 10k parallel round-trip) are the regression net. Also re-run the bench once to confirm no throughput regression vs Task 9's numbers (±10%).

- [ ] **Step 3: Commit** — `git commit -am "refactor(bulk): unify encrypt/decrypt drivers via comptime generic (DUP-001/002, CX-001)"`

---

## Task 11: Deduplicate getFEK/getBIK (DUP-003)

**Files:**

- Modify: `src/keys/manager.zig`

- [ ] **Step 1: Extract.** After Task 4's rewrite, `getFEK`/`getBIK` differ only in cache field and leaf derivation. Extract:

```zig
    fn getDerivedKey(
        self: *KeyManager,
        cache: *KeyCache,
        comptime deriveLeaf: fn ([]const u8, []const u8, u16) anyerror![32]u8,
        ids: types.KeyIds,
    ) ![32]u8 {
        try validateIds(ids);

        var key_buf: [256]u8 = undefined;
        const stack_key = buildCacheKeyBuf(&key_buf, ids);
        if (stack_key) |sk_key| {
            if (cache.get(sk_key)) |entry| return entry.key;
        }

        var trk = try hkdf.deriveTRK(&self.master_key, ids.tenant);
        defer std.crypto.secureZero(u8, &trk);
        var sk = try hkdf.deriveSK(&trk, ids.schema);
        defer std.crypto.secureZero(u8, &sk);
        const leaf = try deriveLeaf(&sk, ids.field, ids.version);

        const cache_key = try buildCacheKey(self.allocator, ids);
        errdefer self.allocator.free(cache_key);
        if (stack_key == null) {
            if (cache.get(cache_key)) |entry| {
                self.allocator.free(cache_key);
                return entry.key;
            }
        }
        try cache.put(cache_key, .{ .key = leaf, .version = ids.version });
        return leaf;
    }

    /// Get Field Encryption Key (FEK). Derives TRK -> SK -> FEK using HKDF.
    pub fn getFEK(self: *KeyManager, ids: types.KeyIds) ![32]u8 {
        return self.getDerivedKey(&self.fek_cache, hkdf.deriveFEKVersioned, ids);
    }

    /// Get Blind Index Key (BIK). Derives TRK -> SK -> BIK using HKDF.
    pub fn getBIK(self: *KeyManager, ids: types.KeyIds) ![32]u8 {
        return self.getDerivedKey(&self.bik_cache, hkdf.deriveBIKVersioned, ids);
    }
```

(If the comptime fn-pointer parameter type fights the compiler over the error-set, accept `anyerror` in the signature as shown and `try` normally.)

- [ ] **Step 2: Canonical check** (FEK caching, BIK derivation, rotation, identifier tests all green); commit — `git commit -am "refactor(keys): unify getFEK/getBIK via shared derivation helper (DUP-003)"`

---

## Task 12: Bench methodology fixes (B1, B2, B3)

**Files:**

- Modify: `Makefile` (bench target), `tests/bench.zig`

- [ ] **Step 1: Module optimize (B1).** In `Makefile`, change the bench target recipe to pass ReleaseFast for the whole graph: `zig build bench -Doptimize=ReleaseFast`. (The bench exe already hardcodes ReleaseFast for its own module; this aligns the `fle` module it imports.)

- [ ] **Step 2: Allocator (B2).** In `tests/bench.zig:53-56`, replace the DebugAllocator with the std SMP allocator:

```zig
pub fn main() !void {
    const allocator = std.heap.smp_allocator;
```

(Remove the `gpa`/`defer gpa.deinit()` lines. If `std.heap.smp_allocator` is unavailable on the installed Zig, use `std.heap.c_allocator` if libc is linked, else `var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};`.)

- [ ] **Step 3: Parallel warmup (B3).** After the existing serial warmup (line 74), add:

```zig
    _ = try runOnce(allocator, &pool, fields, 1024); // parallel warmup
```

- [ ] **Step 4: Run** `make bench` — record the new numbers (they are the new methodology baseline; expect serial to be much faster than the old 19.9µs/field due to Task 9 + allocator change).

- [ ] **Step 5: Commit** — `git commit -am "fix(bench): ReleaseFast module graph, SMP allocator, parallel warmup (B1-B3)"`

---

## Task 13: HKDF RFC 5869 vector coverage (FLE-011)

**Files:**

- Modify: `src/crypto/hkdf.zig` (tests)

- [ ] **Step 1: Add RFC 5869 Test Case 2 (long inputs) and Test Case 3 (zero-length salt/info) for SHA-256.** Exact vectors from RFC 5869 Appendix A:

```zig
test "HKDF-SHA256 RFC 5869 test case 2 (long inputs)" {
    // IKM = 0x00..0x4f (80 bytes), salt = 0x60..0xaf (80 bytes), info = 0xb0..0xff (80 bytes), L = 82
    var ikm: [80]u8 = undefined;
    for (&ikm, 0..) |*b, i| b.* = @intCast(i);
    var salt: [80]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(0x60 + i);
    var info: [80]u8 = undefined;
    for (&info, 0..) |*b, i| b.* = @intCast(0xb0 + i);

    var okm: [82]u8 = undefined;
    try hkdfSha256(&okm, &ikm, &salt, &info);

    const expected = [_]u8{
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
        0x1d, 0x87,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA256 RFC 5869 test case 3 (zero-length salt and info)" {
    const ikm = [_]u8{0x0b} ** 22;
    var okm: [42]u8 = undefined;
    try hkdfSha256(&okm, &ikm, "", "");

    const expected = [_]u8{
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}
```

(Check `hkdfSha256`'s parameter order at `src/crypto/hkdf.zig:21` — it is `(out, ikm, salt, info)`; adjust the calls to match the actual signature if it differs. If a zero-length salt is currently rejected by the implementation, that IS the bug this task fixes — RFC 5869 defines empty salt as a HashLen array of zeros; fix the implementation accordingly.)

- [ ] **Step 2: Run → fix if needed → PASS. Canonical check; commit** — `git commit -am "test(hkdf): add RFC 5869 test cases 2 and 3 (FLE-011)"`

---

## Task 14: API documentation + security guidance docs (DOC-001..003, FLE-005, FLE-007, FLE-009, FLE-014)

**Files:**

- Modify: `src/root.zig` (module doc + all convenience aliases)
- Modify: `src/schema/annotations.zig` (`applyAnnotations` doc)
- Modify: `src/crypto/bulk.zig` (allocator thread-safety doc)
- Modify: `src/keys/manager.zig` (cache residency doc)

- [ ] **Step 1: `///` doc comment on every convenience alias** in `src/root.zig:112-133`. One line each, e.g.:

```zig
/// AEAD algorithm selector (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 for key wrap).
pub const Alg = aead.Alg;
/// Serialized encrypted-field envelope (alg, key version, nonce, tag, ciphertext).
pub const EnvelopeV1 = aead.EnvelopeV1;
/// Wrap a 32-byte key with XChaCha20-Poly1305 (stack-only, no allocator).
pub const wrapKey32 = aead.wrapKey32;
/// Unwrap a 32-byte key previously wrapped with `wrapKey32`.
pub const unwrapKey32 = aead.unwrapKey32;
/// RFC 5869 HKDF-SHA256 (arbitrary output length).
pub const hkdfSha256 = hkdf.hkdfSha256;
/// Derive a single 32-byte key via HKDF-SHA256.
pub const deriveKey32 = hkdf.deriveKey32;
/// Hierarchical key manager: master -> TRK -> SK -> FEK/BIK, with caching and rotation.
pub const KeyManager = key_manager.KeyManager;
/// Identifier tuple (tenant/schema/field/version) for key derivation. Identifiers must not contain ':' or '/'.
pub const KeyIds = key_types.KeyIds;
/// In-memory searchable blind index: HMAC(BIK, normalize(value)) -> record IDs.
pub const BlindIndex = blind_index.BlindIndex;
/// 32-byte blind-index token (full-width HMAC-SHA256 output).
pub const BlindIndexToken = blind_index.BlindIndexToken;
/// Pluggable master-key source vtable interface.
pub const MasterKeyProvider = key_provider.MasterKeyProvider;
/// MasterKeyProvider backed by a static in-memory key (tests, pre-sourced keys).
pub const StaticKeyProvider = key_provider.StaticKeyProvider;
/// MasterKeyProvider reading exactly 32 raw bytes or 64 hex chars from an env var.
pub const EnvKeyProvider = key_provider.EnvKeyProvider;
/// Parser for `@fle(...)`-style schema annotations.
pub const AnnotationParser = annotations.AnnotationParser;
/// Per-field encryption/search metadata produced by annotation parsing.
pub const FieldMetadata = annotations.FieldMetadata;
/// Per-type metadata map produced by annotation parsing.
pub const TypeMetadata = annotations.TypeMetadata;
/// One field's input for `encryptFieldsBulk`.
pub const BulkField = bulk.BulkField;
/// One field's input for `decryptFieldsBulk`.
pub const BulkDecryptField = bulk.BulkDecryptField;
/// Per-field bulk encrypt result (owned envelope or error).
pub const BulkResult = bulk.BulkResult;
/// Per-field bulk decrypt result (owned plaintext or error).
pub const BulkDecryptResult = bulk.BulkDecryptResult;
/// Tunables (chunk size, task lane) for bulk calls.
pub const BulkOptions = bulk.BulkOptions;
/// Encrypt many fields, optionally fanned out across a thread pool. Requires a thread-safe allocator when pooled.
pub const encryptFieldsBulk = bulk.encryptFieldsBulk;
/// Decrypt many envelopes, optionally fanned out across a thread pool. Requires a thread-safe allocator when pooled.
pub const decryptFieldsBulk = bulk.decryptFieldsBulk;
```

Adjust the annotation alias one-liners to match what `annotations.zig` actually exposes (read it first). Also add `///` docs to the `observability`/`observability_init` re-exports.

- [ ] **Step 2: Thread Safety + key-lifetime guidance** in the `src/root.zig` module doc (extend the existing `## Thread Safety` section):

```zig
//! The allocator passed to `encryptFieldsBulk`/`decryptFieldsBulk` MUST be
//! thread-safe when a pool is supplied — worker chunks allocate from it
//! concurrently. (`std.heap.smp_allocator`, `std.heap.page_allocator`, and
//! the default-config DebugAllocator are thread-safe; a bare
//! `ArenaAllocator` is not.)
//!
//! ## Key Lifetime & Rotation
//!
//! - FEKs use random 96-bit AEAD nonces. Per NIST SP 800-38D, rotate a FEK
//!   (via `KeyManager.rotateFEK`) well before 2^32 encryptions under the
//!   same key; plan rotation at or below ~2^28 encryptions per field-version
//!   for margin.
//! - The KeyManager FEK/BIK caches are unbounded and hold derived keys in
//!   process memory for the manager's lifetime. Call `clearCache()` after
//!   rotation events or on a residency schedule; `deinit` zeroizes all
//!   cached key material.
```

- [ ] **Step 3:** Add `///` doc comment to `applyAnnotations` in `src/schema/annotations.zig` describing inputs/outputs/errors (read the fn signature first; one short paragraph). Add the same thread-safe-allocator sentence to the `//!` module doc of `src/crypto/bulk.zig`. Add a sentence to the `KeyCache` doc in `manager.zig`: "Unbounded: entries persist until `clearCache`/`deinit`. See root.zig 'Key Lifetime & Rotation'."

- [ ] **Step 4: Canonical check; commit** — `git commit -am "docs(api): document all public aliases, thread-safety, rotation and cache-residency guidance (DOC-001..003, FLE-005/007/009/014)"`

---

## Task 15: Real examples wired into the build (#24, #25)

**Files:**

- Rewrite: `examples/basic.zig`
- Create: `examples/annotations.zig`
- Modify: `build.zig` (add `examples` step; make `check` cover them)

- [ ] **Step 1: Rewrite `examples/basic.zig`** as a complete runnable encrypt→decrypt walk-through (issue #24):

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic field-level encryption example: derive a key, encrypt a field,
//! serialize the envelope, deserialize, and decrypt.

const std = @import("std");
const fle = @import("fle");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Master key — source from your KMS/HSM in production.
    var master_key: [32]u8 = undefined;
    std.crypto.random.bytes(&master_key);

    var km = try fle.KeyManager.init(allocator, master_key);
    defer km.deinit();

    // 2. Derive the field encryption key for (tenant, schema, field, version).
    const ids: fle.KeyIds = .{ .tenant = "tenant1", .schema = "Person", .field = "ssn", .version = 1 };
    const fek = try km.getFEK(ids);

    // 3. Bind the ciphertext to its context via AAD, then encrypt.
    const aad = try fle.aead.makeAAD(allocator, ids.tenant, ids.schema, ids.field, "record-42", ids.version);
    defer allocator.free(aad);

    var envelope = try fle.aead.encryptField(allocator, .aes256_gcm, &fek, aad, "123-45-6789", ids.version);
    defer envelope.deinit(allocator);

    // 4. Serialize for storage; deserialize on read.
    const stored = try envelope.serialize(allocator);
    defer allocator.free(stored);

    var loaded = try fle.EnvelopeV1.deserialize(allocator, stored);
    defer loaded.deinit(allocator);

    // 5. Decrypt (fails with AEADAuthFailed if AAD or ciphertext was tampered).
    const plaintext = try fle.aead.decryptField(allocator, &fek, aad, loaded);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    std.debug.print("decrypted: {s}\n", .{plaintext});
}
```

- [ ] **Step 2: Create `examples/annotations.zig`** (issue #25). Read `src/schema/annotations.zig` tests (lines 328-406) and `tests/integration.zig:176-197` for the real parser API, then write a ~40-line example that parses an annotation string (e.g. `@fle(alg=aes256_gcm, search=exact)`), applies it via `applyAnnotations`, and prints the resulting `FieldMetadata`. Follow the structure of Step 1's file (gpa setup, defer cleanup, `std.debug.print` output).

- [ ] **Step 3: Wire into `build.zig`** — after the bench step, add:

```zig
    // Examples — compiled in `check`, runnable via `zig build examples`.
    const examples_step = b.step("examples", "Build and run examples");
    inline for (.{ "basic", "annotations", "bulk" }) |ex_name| {
        const ex = b.addExecutable(.{
            .name = "example_" ++ ex_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ ex_name ++ ".zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "fle", .module = module },
                    .{ .name = "thread_pool", .module = thread_pool_module },
                },
            }),
        });
        const run_ex = b.addRunArtifact(ex);
        examples_step.dependOn(&run_ex.step);
        check_step.dependOn(&ex.step); // examples can't rot: compile in check
    }
```

Note: `check_step` is declared after the bench step in the current file — place this block after the check step declaration (end of `build()`), or hoist as needed so both `examples_step` and `check_step` are in scope.

- [ ] **Step 4: Run** `zig build examples` — both new examples plus bulk run and print expected output. Run the canonical check (`zig build check` now compiles examples too).

- [ ] **Step 5: Commit** — `git commit -am "feat(examples): real basic encrypt/decrypt and annotation examples, wired into build (#24, #25)"`

---

## Task 16: Narrative docs — key hierarchy, README, SECURITY.md, CHANGELOG, CODEOWNERS (#23, #26, FLE-012, SECURITY.md gap, CODEOWNERS gap)

**Files:**

- Create: `docs/KEY_HIERARCHY.md`
- Modify: `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CODEOWNERS`

- [ ] **Step 1: `docs/KEY_HIERARCHY.md`** (issue #23) — write the narrative doc with these required sections (source the facts from `src/crypto/hkdf.zig`, `src/keys/manager.zig`, `src/index/blind_index.zig`, `src/crypto/aead.zig`):
  1. **Key hierarchy diagram** (ASCII): master key → `deriveTRK` (`geode/trk/<tenant>`) → `deriveSK` (`geode/sk/<schema>`) → `deriveFEKVersioned` (`geode/fek/<field>/v<N>`) and `deriveBIKVersioned` (`geode/bi/<field>/v<N>`); all HKDF-SHA256 with the library's fixed salt.
  2. **Identifier rules**: non-empty, no `:` or `/` (rejected with `Error.InvalidIdentifier`); contexts are Geode-interop-locked.
  3. **Envelope format**: the `[alg_id:u8][key_version:u16 LE][nonce:12][tag:16][ciphertext_len:u32 LE][ciphertext]` layout and the length-prefixed AAD binding `(tenant, schema, field, record_id, key_version)`.
  4. **Blind-index flow**: normalize (trim+ASCII-lowercase) → HMAC-SHA256(BIK) full 32-byte token → token→record-ID map; what it reveals (equality patterns) and what it doesn't (plaintext).
  5. **Rotation**: `rotateFEK` semantics, version state is in-memory, rotate before ~2^28-2^32 encryptions/FEK.
  6. **Zeroization guarantees**: what is zeroized when (HKDF intermediates, cache clear/deinit, decrypt failure paths, blind-index normalize buffers).

- [ ] **Step 2: README.md.** Replace the stale Quick Start (lines 42-51, `fle.init(...)` doesn't exist) with the working snippet from `src/root.zig:32-54`. Add an **Out of Scope** section (issue #26): catalog persistence stays in Geode (`fle_catalog.zig`), policy/enforcement stays in Geode, no KMS integration (bring your own via `MasterKeyProvider`). Link `docs/KEY_HIERARCHY.md`. Update the Features bullet "Zero Dependencies" → "Minimal dependencies (thread-pool; optional otel)" — the current claim is false. Keep "Cross-Platform" (true after Task 1).

- [ ] **Step 3: SECURITY.md.** Replace the "No Undefined Behavior: Strict adherence to defined semantics" claim with accurate language: "Safety-checked builds (Debug/ReleaseSafe) are exercised in CI alongside ReleaseFast/ReleaseSmall; randomness comes from `std.crypto.random` (never silently uninitialized); untrusted envelope parsing is bounds-checked with fuzz coverage." Also add the identifier constraint and the FEK rotation guidance to its hardening notes if a suitable section exists.

- [ ] **Step 4: CHANGELOG.md.** Replace the stub with real entries derived from `git log --oneline` grouped by version tag (v0.1.0..v0.1.4 history: extraction from Geode, bulk API, otel seam, dependency convergence) plus an `## [Unreleased]` section listing this remediation: security fixes (RNG, envelope overflow, identifier validation, EnvKeyProvider strictness — **breaking**: lengths 33-63/>64 raw rejected; identifiers with `:`/`/` rejected; dead error variants removed — **breaking** if matched exhaustively), perf (serial arena, cache-hit fast path, chunk default 1024), docs/examples.

- [ ] **Step 5: CODEOWNERS.** Replace `* @your-username` with `* @benjiv`.

- [ ] **Step 6:** `markdownlint` via pre-commit if available (`pre-commit run markdownlint --files README.md docs/KEY_HIERARCHY.md SECURITY.md CHANGELOG.md || true`). Canonical check (docs don't affect it, but run anyway). Commit — `git commit -am "docs: key hierarchy guide, fixed README quick start, out-of-scope, real changelog, owners (#23, #26)"`

---

## Task 17: Supply-chain hardening — gitleaks, pre-commit pins, script + CI input validation (FLE-004, SCR-001, SCR-003, SCR-004)

**Files:**

- Modify: `.gitleaks.toml`, `.pre-commit-config.yaml`, `scripts/detect_diamond_deps.py`, `.gitlab-ci.yml`

- [ ] **Step 1: gitleaks (FLE-004).** Replace the `\.zig$` path allowlist with targeted regexes (verified: the only FPs are the `wrapKey32`/`deriveKey32`-style identifiers):

```toml
[allowlist]
description = "Global allowlist"
paths = [
    '''\.zig-cache''',
    '''zig-out''',
    '''\.git''',
    '''zig-pkg''',
]
# Crypto API identifiers that trip entropy/keyword rules but are not secrets.
regexes = [
    '''(?i)(wrap|unwrap|derive|rotate|get|put)Key(32|Material)?''',
    '''blindIndexHmac256''',
]
```

Verify: `gitleaks detect --source . --no-banner` → exit 0, no findings. If new false positives surface in `.zig` files, add targeted regex entries (NOT path entries) until clean.

- [ ] **Step 2: pre-commit detect-private-key.** Narrow the exclusion at `.pre-commit-config.yaml` (detect-private-key hook): remove `tests/|src/tests/` from the exclude — new value: `exclude: ^(certs/|test.*certs/|.*test.*\.pem$|docker/zig-packages/)`. Run `pre-commit run detect-private-key --all-files` → must pass.

- [ ] **Step 3: Freeze hook pins to SHAs (SCR-003).** For each of the 6 external repos in `.pre-commit-config.yaml`, resolve the current tag to its commit SHA: `git ls-remote https://github.com/<org>/<repo> refs/tags/<rev>` (use the `^{}` peeled line when present). Replace `rev: <tag>` with `rev: <40-char-sha>  # frozen: <tag>`. Then `pre-commit run --all-files` to confirm hooks still resolve (if pre-commit is unavailable offline, validate YAML syntax and proceed).

- [ ] **Step 4: Hash path validation (SCR-001).** In `scripts/detect_diamond_deps.py`, function `_zon_path_for_hash`, before constructing the path:

```python
    # Defense: a malicious transitive .zon could embed path traversal in its
    # .hash field; a hash is never a path. Reject anything non-hash-shaped.
    if "/" in pkg_hash or "\\" in pkg_hash or ".." in pkg_hash:
        return None
```

Run `python3 scripts/detect_diamond_deps.py` → still reports clean.

- [ ] **Step 5: CI ZIG_VERSION validation (SCR-004).** In `.gitlab-ci.yml`, at the top of the `*install-zig` script block (before first use of `ZIG_VERSION`), add:

```yaml
    - |
      if ! echo "$ZIG_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "ERROR: invalid ZIG_VERSION '$ZIG_VERSION'" >&2
        exit 1
      fi
```

(Match the existing script style — if it's a YAML list of commands, insert as the first command.) Validate the YAML: `python3 -c "import yaml,sys; yaml.safe_load(open('.gitlab-ci.yml'))"`.

- [ ] **Step 6: Commit** — `git commit -am "fix(supply-chain): scoped gitleaks allowlist, SHA-frozen hooks, hash path validation, CI input validation (FLE-004, SCR-001/003/004)"`

---

## Task 18: Zig version floor — verify or correct `minimum_zig_version` (FLE-010b, CI-001)

**Files:**

- Possibly modify: `build.zig.zon:5`, `.gitlab-ci.yml`

- [ ] **Step 1: Try the declared floor.** Download Zig 0.15.1 to /tmp and run the suite:

```bash
cd /tmp && curl -sL https://ziglang.org/download/0.15.1/zig-x86_64-linux-0.15.1.tar.xz -o zig-0.15.1.tar.xz && tar xJf zig-0.15.1.tar.xz
cd /data/home/benji/src/gl/gitlab.com/devnw/zig/fle && /tmp/zig-x86_64-linux-0.15.1/zig build test --summary all
```

(The 0.15.1 archive name may be `zig-linux-x86_64-0.15.1`; check `https://ziglang.org/download/` if the URL 404s.)

- [ ] **Step 2a: If 0.15.1 PASSES** — keep `minimum_zig_version = "0.15.1"` and add a CI job to `.gitlab-ci.yml` test stage validating the floor: duplicate the unit-test job as `test:unit:zig-min` with a job-level `variables: { ZIG_VERSION: "0.15.1" }`.

- [ ] **Step 2b: If 0.15.1 FAILS** (likely — `std.Io.Threaded` and `std.ArrayList.empty` are 0.16-era APIs) — set `minimum_zig_version = "0.16.0"` in `build.zig.zon` and note the floor bump in the CHANGELOG Unreleased section. CI already runs 0.16.0; no job change needed.

- [ ] **Step 3: Canonical check; commit** — `git commit -am "fix(build): align declared minimum_zig_version with validated toolchain (CI-001)"`

---

## Task 19: Upstream + tracking close-out (FLE-010a, gap docs, issue closure)

**Files:**

- Modify: `docs/GAP_ANALYSIS.md`, create `docs/QUALITY_GAP_ANALYSIS.md`, `docs/PERF_GAP_ANALYSIS.md`, update `docs/APPSEC_REVIEW_2026-06-11.md` (status column)

- [ ] **Step 1: File the otel upstream issue (FLE-010a):**

```bash
glab issue create --repo devnw/zig/otel --title "build.zig.zon .version not bumped before tagging (v0.1.10 content declares 0.1.9)" --description "Consumers pinning ref=v0.1.10 get a package whose build.zig.zon declares .version = \"0.1.9\", so the Zig package hash reads otel-0.1.9-... while the URL says v0.1.10 (same pattern at v0.1.8/0.1.7). Please bump .version before tagging releases so hash and tag agree. Found during fle supply-chain audit 2026-06-11."
```

- [ ] **Step 2: Update tracking docs.**
  - `docs/GAP_ANALYSIS.md`: remove the now-fixed open notes (dead error variants — removed; wrapKey/unwrapKey tests — added; EnvKeyProvider tests — added; stale README — fixed) and move them to `docs/GAP_ANALYSIS_RESOLVED.md` with a 2026-06-11 resolution note + commit refs.
  - Create `docs/QUALITY_GAP_ANALYSIS.md`: table of DUP/DC/CX/DOC findings → status (Resolved in this pass / Accepted: deriveFEK-deriveBIK and tokenToHex-hexToToken kept as public API; BlindIndex.remove O(T*R) accepted at current scale).
  - Create `docs/PERF_GAP_ANALYSIS.md`: the perf findings table → status (Resolved: serial arena, cache-hit fast path, ok_count, chunk default, bench methodology, wrap AAD; Accepted/Deferred: zero-copy deserializeView (Z2), BlindIndex stack buffers (security-bias decision: zeroized heap kept), reverse-map remove (#6), RNG batching (superseded by std.crypto.random)).
  - `docs/APPSEC_REVIEW_2026-06-11.md`: add a `Status` column to the findings table: FLE-001..006, 008, 009, 011, 012, 013 → Resolved (commit refs); FLE-005/007 → Mitigated-by-documentation (rotation guidance, cache docs — bounded cache deferred); FLE-010 → upstream issue filed + floor aligned; FLE-014 → docs updated. SCR-001/003/004 → Resolved; SCR-002 + CI catalog tag pins → Accepted (org-internal catalog; documented).
- [ ] **Step 3: Close GitLab issues** #30 (FLE-001), #31 (FLE-002), #32 (FLE-003), #33 (FLE-004) with a comment referencing the fixing commits; close #23, #24, #25, #26 (docs/examples now exist) with comments pointing at `docs/KEY_HIERARCHY.md`, `examples/basic.zig`, `examples/annotations.zig`, README Out-of-Scope. Leave #14 open (externally blocked on Geode). Leave #34/#35 open as requirement-tracking issues (or close them if the team prefers requirements only in REQUIREMENTS.md — default: add the requirement entries to `docs/REQUIREMENTS.md` as FLE-REQ-009 bulk and FLE-REQ-010 observability, then close #34/#35 referencing the doc).

```bash
glab issue close 30 31 32 33 23 24 25 26 34 35  # close each with --comment via separate calls
```

- [ ] **Step 4: Final full validation:**

```bash
make ci   # clean build + full test matrix locally
zig build test -Doptimize=ReleaseSafe --summary all
zig build test -Doptimize=ReleaseFast --summary all
python3 scripts/detect_diamond_deps.py
gitleaks detect --source . --no-banner
pre-commit run --all-files || true  # report failures
```

- [ ] **Step 5: Commit** — `git commit -am "docs(tracking): close out 2026-06-11 audit — gap/quality/perf analyses updated, issues closed"`

---

## Explicitly Accepted / Deferred (do NOT implement)

- **HKDF context format change** — would break decryption of existing Geode ciphertext. Mitigated by identifier validation (Task 4).
- **Bounded/LRU key cache (FLE-007)** — deferred; documented residency + `clearCache` guidance instead (Task 14). Revisit if a consumer reports unbounded tenant cardinality.
- **`BlindIndex.lookup` owned-copy return (FLE-008)** — API break; documented borrowed lifetime instead.
- **CI catalog component SHA pins** — org-internal catalog; tag pinning accepted, recorded in tracking docs.
- **`deserializeView` zero-copy (Z2), BlindIndex reverse map (perf#6)** — YAGNI at current scale; recorded as deferred in PERF_GAP_ANALYSIS.md.
- **AES-GCM-SIV / per-FEK encryption counters (FLE-005)** — documented rotation threshold instead.
