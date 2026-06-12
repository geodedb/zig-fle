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

Status: **Resolved (documented break-even)** — measured the serial/parallel break-even across payload sizes and documented it instead of adding auto-fallback heuristics. The break-even sits around **~128–256 bytes per field**: serial wins below it, parallel wins above. Guidance added to the `src/crypto/bulk.zig` module doc; `tests/bench.zig` now sweeps payload sizes {64B, 1KiB, 16KiB} so the break-even stays visible in future runs.

Measured 2026-06-11 (ReleaseFast, smp_allocator, 8-thread pool, cs=1024, best of 3):

| Payload | N | Serial ns/field | Parallel ns/field | Winner |
|---|---|---|---|---|
| 64 B | 100,000 | 421.0 | 575.1 | serial |
| 128 B | 100,000 | 473.0 | 508.2 | serial (marginal) |
| 256 B | 100,000 | 768.2 | 631.3 | parallel |
| 512 B | 50,000 | 890.1 | 641.5 | parallel |
| 1 KiB | 20,000 | 1062.4 | 594.5 | parallel |
| 4 KiB | 10,000 | 2988.8 | 1319.4 | parallel |
| 16 KiB | 4,000 | 10133.6 | 4899.6 | parallel |

Chunk-size tuning (cs=256 → cs=4096) moves throughput only a few percent; payload size is the deciding factor. Recommendation for consumers: pass `pool = null` for batches of small fields (below ~256 B each); supply a pool above that.
