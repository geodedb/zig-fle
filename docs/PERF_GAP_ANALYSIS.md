# Performance Gap Analysis

Last updated: 2026-06-11

Source review: 2026-06-11 performance audit of the AEAD/bulk/blind-index hot paths and the benchmark methodology. All findings are dispositioned below.

## Resolved Findings

| Finding | Status | Resolution | Commit |
|---|---|---|---|
| Serial bulk path allocated per-field instead of using an arena | Resolved | Arena allocator for the serial path; ~30x serial improvement at 100k×64B (1.52s → 49ms) | `8d3ada6` |
| Cache-hit path heap-allocated the cache key on every lookup | Resolved | Stack-buffer cache keys on the hit path (part of the FLE-003 injective-key rework) | `dfc3634` |
| `ok_count` updated with shared atomic contention per field | Resolved | Per-chunk `ok_count` accumulation, merged once per chunk | `8d3ada6` |
| `default_chunk_size` too small for thread-pool dispatch amortization | Resolved | Default chunk size raised to 1024 | `8d3ada6` |
| Wrap AAD rebuilt at runtime on every `wrapKey` call | Resolved | Comptime wrap AAD constant (Z1) | `40e0655` |
| Bench methodology flaws: Debug module graph, GPA allocator, no parallel warmup | Resolved | ReleaseFast module graph, SMP allocator, parallel warmup (B1-B3) | `7a1d287` |
| `decryptField` allocated output before validating the algorithm | Resolved | Validate before allocate (CX-004) | `f8c718d` |

## Deferred / Accepted

| Finding | Status | Rationale |
|---|---|---|
| `deserializeView` zero-copy envelope parsing (Z2) | Deferred | YAGNI at current scale; revisit if envelope deserialization shows up in profiles |
| `BlindIndex.remove` is O(T*R) without a reverse map | Accepted | Acceptable at current index cardinality; a reverse map adds memory and invariant-maintenance cost |
| `BlindIndex` normalize could use a stack buffer instead of heap | Accepted | Security bias: the zeroized heap allocation is kept so normalized plaintext is reliably `secureZero`'d |
| `BulkCtx` false-sharing padding between worker slots | Deferred | No measurable contention at current chunk sizes (1024); revisit with the follow-up below |

## New Follow-Up Finding (2026-06-11)

**PERF-FU-001 — parallel bulk slower than serial at the 100k×64B workload under the fixed methodology.**

Under the corrected benchmark methodology (smp_allocator + ReleaseFast module graph + serial-arena fix), parallel bulk now measures **~590 ns/field** while serial measures **~434 ns/field** at 100k fields × 64 bytes. Thread-pool dispatch overhead dominates at this field size: the per-field AEAD work is too cheap relative to chunk submission, wakeup, and join costs.

Recommended next steps (not yet implemented):

- Revisit chunk sizing and pool tuning (larger chunks, fewer submissions) for small-payload workloads.
- Alternatively, document bulk's break-even point (payload size × field count) so consumers choose serial vs parallel deliberately, or auto-fall-back to the serial arena path below the break-even threshold.

Status: Open (tracked as the only open performance item).
