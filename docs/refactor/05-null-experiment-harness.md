# 05 — Null / experiment harness dedup

> One-line: extract the copy-pasted "real statistic + matched within-message
> shuffle null + positive control + add-one p-value + null band" orchestration
> into one generic harness, then migrate the ~10 null-bearing modules onto it —
> killing the largest duplication cluster in the maintainability track without
> moving a single reported number.
> Status: not started · Depends on: 01 (golden-master safety net) · Blocks: —
> (helps 06, 07B) · Size: L

## Goal & why it matters

`src/null.rs` already centralizes the primitives — `SplitMix64`
(`src/null.rs:38`), `fisher_yates` (`src/null.rs:143`), `shuffled_permutation`
(`src/null.rs:159`), `random_index_below` (`src/null.rs:123`),
`add_one_p_value` (`src/null.rs:91`), `scaled_quantile_index`
(`src/null.rs:637`), `median_usize`/`median_f64` (`src/null.rs:610`/`586`). What
it does **not** centralize is the *orchestration* that sits on top of those
primitives, and that orchestration is copy-pasted across the structural battery:

- a private `shuffled_messages(message_values, rng)` that clones
  `Vec<Vec<TrigramValue>>` and Fisher-Yates each message in place — verbatim in
  **five** modules (`src/isomorph_null.rs:293`, `src/zero_adjacency_null.rs:412`,
  `src/perseus.rs:818`, `src/conditional_structure.rs:1383`,
  `src/modular_diff.rs:989`);
- a private `null_band(samples)` / `scalar_null_band(samples)` that sorts a
  sample vector and emits `{trials, mean, min, q025, median, q975, max}` into a
  per-module band struct — in **eight** modules
  (`src/isomorph_null.rs:304`, `src/zero_adjacency_null.rs:423`,
  `src/tree_residual.rs:648`, `src/perseus.rs:829`,
  `src/conditional_structure.rs:1183`, `src/periodicity.rs:775`,
  `src/orientation_homogeneity.rs:586`; plus `src/modular_diff.rs:1180`
  `scalar_band`);
- a private `mean(samples)` (`src/isomorph_null.rs:317`,
  `src/zero_adjacency_null.rs:437`, `src/perseus.rs:851` `mean_usize`,
  `src/tree_residual.rs:662` `mean_usize`, `src/conditional_structure.rs:1197`,
  `src/modular_diff.rs:1194` `mean_f64`, `src/orientation_homogeneity.rs:600`)
  and a private `quantile_from_sorted(sorted, num, den)` wrapping
  `scaled_quantile_index` (`src/isomorph_null.rs:324`,
  `src/zero_adjacency_null.rs:444`, `src/tree_residual.rs:669`,
  `src/perseus.rs:858`, `src/conditional_structure.rs:1213`,
  `src/periodicity.rs:801`, `src/orientation_homogeneity.rs:607`,
  `src/modular_diff.rs:1208` `quantile_f64`);
- the trial loop itself — `for _trial in 0..trials { shuffled =
  shuffled_messages(...); count = statistic(&shuffled); if count <relation>
  observed { p_count += 1 }; samples.push(count) }` followed by `null_band(...)`
  + `add_one_p_value(...)` — written out longhand in every module
  (`src/isomorph_null.rs:181`, `src/zero_adjacency_null.rs:298`,
  `src/perseus.rs:356`, `src/conditional_structure.rs:1010`,
  `src/tree_residual.rs:294`, `src/modular_diff.rs:973`,
  `src/orientation_homogeneity.rs:505`).

The ten modules in scope total **9,954 lines** (`null.rs` itself is 832). A large
fraction is genuinely unique statistic logic (e.g. `dof_null`'s cell calibration,
`modular_diff`'s control families, `perseus`'s partition reconstruction) and must
not be touched. But the shuffle-null *scaffolding* — the four helper kinds above
plus the trial loop — is mechanical, identical-by-eye, and exactly the kind of
copy-paste the overview flags (`docs/refactor/00-OVERVIEW.md` §"Evidence (the structural smells)": "`fisher_yates`
is centralized, but ~20 modules re-implement the matched-null orchestration
around it"). Centralizing it removes a class of drift bug (a fix to the band /
p-value convention today must be applied in eight places) and gives briefs 06
and 07B a single typed seam to render (06) and relocate (07B).

This brief is **purely behavior-preserving** (the overview's first ground rule,
`docs/refactor/00-OVERVIEW.md` §"Shared ground rules" ("Behavior-preserving")): every pinned regression — e.g.
`eye_zero_adjacency_headline_numbers_are_pinned` (`src/zero_adjacency_null.rs:642`,
`empirical_p == 0.000_199_960_007_998_400_3`), `eye_headline_counts_are_pinned`
(`src/tree_residual.rs:850`), `perseus_seed_12345_recurrence_null_matches_headline_regression`
(`src/perseus.rs:996`), `real_eye_headline_counts_are_pinned`
(`src/orientation_homogeneity.rs:737`) — must produce byte-identical output, and
brief 01's golden masters must not diff after any commit here.

## Current state (grounded, with file:line)

**The primitives already shared (do not duplicate, reuse):** `SplitMix64::new`/
`next_u64` (`src/null.rs:45`/`51`), `fisher_yates` (`src/null.rs:143`),
`shuffled_permutation` (`src/null.rs:159`), `random_index_below`
(`src/null.rs:123`), `add_one_p_value` (`src/null.rs:91`), `RandomBoundError`
(`src/null.rs:112`) with its `bound` field that every module re-maps into its own
`RandomBoundTooLarge { bound }` variant (e.g. `src/isomorph_null.rs:80`,
`src/zero_adjacency_null.rs:89`, `src/perseus.rs:95`, `src/tree_residual.rs:120`,
`src/conditional_structure.rs:119`, `src/modular_diff.rs:121`,
`src/orientation_homogeneity.rs:108`), `scaled_quantile_index`
(`src/null.rs:637`), `median_usize`/`median_f64` (`src/null.rs:610`/`586`),
`random_orientation_grids_like` (`src/null.rs:419`), and the
`run_standard36_null_with` template (`src/null.rs:327`).

`null.rs` itself already demonstrates the "harness + injected generator" pattern
that this brief generalizes: `run_standard36_null_with` takes
`generate: impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>`
(`src/null.rs:329`) and `pipeline_null` reuses it by passing a different
generator (`src/pipeline_null.rs:79`). `dof_null` does the same with
`run_dof_null_with` (`src/dof_null.rs:360`). That injected-sampler idiom is the
seed of the `NullSampler` trait this brief introduces — but those grid-level
nulls are a **different** axis (resample grid *contents*) from the within-message
shuffle nulls that are the duplication cluster here.

**The duplication cluster — within-message shuffle nulls.** Each of these resamples
by Fisher-Yates-shuffling each message's value multiset in place, then recomputes
a statistic and compares to the real observation:

| Module | run fn | trial loop | shuffle helper | band helper | statistic T | tail / p |
| ------ | ------ | ---------- | -------------- | ----------- | ----------- | -------- |
| `isomorph_null` | `report_from_message_values` `:167` | `:181` | `shuffled_messages` `:293` | `null_band → IsomorphNullBand` `:304` | per-window vector of `usize` (`repeated_signature_kinds`) | upper, `add_one_p_value` `:205` |
| `zero_adjacency_null` | `analyze_message_values` `:286` | `:298` (seed_count × trials_per_seed) | `shuffled_messages` `:412` | `null_band → AdjacencyNullBand` `:423` | scalar `usize` (`adjacent_equal`) | lower, `add_one_p_value` `:311` |
| `perseus` | `report_from_partition` `:343` | `:356` | `shuffled_messages` `:818` | `recurrence_null_band` `:829` | scalar `usize` (`recurrent_occurrences`) | lower, `add_one_p_value` `:366` |
| `tree_residual` | `report_from_segment_messages` `:280` | `:294` (seed_count × trials) | `shuffled_segment_messages` `:598` (segment-shape-preserving) | `null_band → CrossTailNullBand` `:648` | scalar `usize` per (scope,k) row | two-sided, `add_one_p_value` `:409` |
| `conditional_structure` | `null_comparisons` `:1001` + `no_repeat_null_comparisons` `:1032` | `:1010`/`:1042` | `shuffled_messages` `:1383` (+ MCMC `run_no_repeat_sweeps` `:1092`) | `scalar_null_band` `:1183` | vector of `f64` (10 statistics) | two-sided, custom `two_sided_add_one_p` `:1173` |
| `modular_diff` | `shuffle_baseline` `:961` | `:973` | `shuffled_messages` `:989` | `scalar_band → ScalarBand` `:1180` (within `fingerprint_band` `:1138`) | vector of `f64` (7-field `Fingerprint`) | band-only (no p-value) |
| `orientation_homogeneity` | `repartition_null_comparisons` `:496` | `:505` (seed_count × trials_per_seed) | `repartition_table` `:527` (pooled-multiset repartition, **not** per-message) | `scalar_null_band` `:586` | vector of `f64` (Pearson, G) | two-sided, `null_comparison` `:561` |

**Grid-content nulls (the other family in scope).** `pipeline_null`
(`run_pipeline_null` `:74`) and `dof_null` (`run_dof_null_with` `:360`) already
funnel through injected generators; they do *not* re-implement the trial loop the
way the shuffle nulls do, but they each still hand-roll their own quantile/band
helpers (`dof_null`'s `sorted_quantile` `:1022`, `Quantile` enum `:1015`).

**Tail / p-value conventions that must be preserved exactly:**

- add-one estimator `(count + 1) / (trials + 1)` via `add_one_p_value`
  (`src/null.rs:91`), used directly by isomorph/zero-adjacency/perseus/tree-residual.
- two-sided "double the smaller tail, cap at 1": `tree_residual.rs:411`
  (`(2.0 * lower.min(upper)).min(1.0)`), `conditional_structure.rs:1173`,
  `orientation_homogeneity.rs:573`. These are subtly different in *which* counts
  they take (`tree_residual` doubles already-add-one'd p-values; the other two
  double an add-one of `min(lower,upper)` counts) — the harness must let each
  caller keep its own combiner, **not** impose one.
- band quantile convention `scaled_quantile_index(len, 25|975, 1000)` for q025/q975
  (every `quantile_from_sorted`), `median_*` for median, raw `min`/`max` from the
  sorted ends, arithmetic `mean`.
- `<=` for the observed sample in lower-tail counting
  (`src/zero_adjacency_null.rs:303`, `src/perseus.rs:359`), `>=` for upper-tail
  (`src/isomorph_null.rs:192`, `src/tree_residual.rs:402`), and `<= && >=` both
  counted for two-sided (the observed value is counted in **both** tails — see
  `RowAccumulator::observe_sample` `src/tree_residual.rs:398`).

**Existing numeric anchors (in-module pinned tests) that lock behavior.** These
are the real regression net today; brief 01 adds byte-exact golden masters on
top. Key ones: `src/null.rs:766` (standard36 1000-trial), `src/zero_adjacency_null.rs:642`,
`src/perseus.rs:996`, `src/tree_residual.rs:866`, `src/dof_null.rs:1322`,
`src/orientation_homogeneity.rs:737`, `src/conditional_structure`'s reproducibility
tests, `src/modular_diff.rs:1308`. The migration must keep every one of these green
**unchanged** (do not edit assertions; if an assertion would need to change, the
migration is wrong).

**No `Cipher`/`Sequence`/`NullSampler` trait exists yet** — the crate has zero
traits (`docs/refactor/00-OVERVIEW.md` §"Why these refactors exist: the reframe"). `modular_diff` already imports cipher
free functions (`incrementing_wheel_encrypt` etc., `src/modular_diff.rs:13`); this
brief does **not** depend on brief 02's `Cipher` trait — leave those calls as-is.

## Target design (concrete API / types / layout)

Add to `src/null.rs` (the overview proposes a `crate::nulls` home,
`docs/refactor/00-OVERVIEW.md` §"Target module layout"; we keep it in `null.rs` for now to avoid a
module move colliding with brief 07B — brief 07B relocates the file wholesale
into the role-directory layout. Note this deviation explicitly in the commit
message).

### 1. `NullSampler` trait — one shape per resampling scheme

```rust
/// A resampling scheme: produces one synthetic draw from `rng`, of the same
/// shape as the real observation it is calibrating.
pub trait NullSampler {
    /// The unit of data a statistic consumes (e.g. `Vec<Vec<TrigramValue>>`).
    type Draw;
    /// Produces one synthetic draw. Fallible because Fisher-Yates index draws
    /// can in principle exceed the PRNG bound (see [`RandomBoundError`]).
    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError>;
}
```

Rationale for an associated `Draw` type rather than the overview's
`fn sample(&self, rng) -> Vec<Glyph>` (`docs/refactor/00-OVERVIEW.md` §"3. Null/experiment harness — kill the copy-paste (brief 05)"):
the real draws are `Vec<Vec<TrigramValue>>` (message-boundary-preserving),
`Vec<MessageSegments>` (segment-shape-preserving, `tree_residual`),
`Vec<[usize; 5]>` (`orientation_homogeneity` repartition tables), and
`Vec<GlyphGrid>` (grid-content nulls). A single `Vec<Glyph>` cannot represent
these without discarding the boundary structure the nulls exist to preserve. This
is a **deliberate, documented deviation** from the overview's proposed signature,
as already recorded in `docs/refactor/00-OVERVIEW.md` §"Documented deviations from this overview".

Concrete samplers (free structs, each a few lines, replacing the per-module
`shuffled_messages`):

```rust
/// Within-message Fisher-Yates shuffle: clones each message's value multiset
/// and shuffles it in place, preserving per-message length and multiset.
pub struct WithinMessageShuffle<'a, T: Clone> { pub messages: &'a [Vec<T>] }
impl<'a, T: Clone> NullSampler for WithinMessageShuffle<'a, T> {
    type Draw = Vec<Vec<T>>;
    fn sample(&self, rng) -> Result<Vec<Vec<T>>, RandomBoundError> { /* exact body of today's shuffled_messages */ }
}
```

`tree_residual`'s segment-preserving shuffle and `orientation_homogeneity`'s
pooled repartition stay **module-local** sampler structs (their draw type and
invariants are bespoke); they implement `NullSampler` so they still flow through
the harness. `dof_null`/`pipeline_null` grid generators may optionally adopt
`NullSampler<Draw = Vec<GlyphGrid>>` but are **out of primary scope** (see
"Out of scope").

### 2. `run_null_test` — the generic trial loop

```rust
/// Outcome of comparing a real statistic to a Monte-Carlo shuffle null.
#[derive(Clone, Debug, PartialEq)]
pub struct NullResult<T> {
    pub observed: T,
    pub samples: Vec<T>,        // in draw order; callers that pin sample order rely on this
    pub lower_tail_count: usize, // #samples <= observed
    pub upper_tail_count: usize, // #samples >= observed
    pub trials: usize,
}

/// Runs `trials` shuffle draws, scoring each with `statistic`, counting both
/// tails against `observed`. Deterministic in `seed`. Generic over the scalar
/// statistic type `T` and the statistic's error type `E`.
///
/// The `statistic` is **fallible** — it returns `Result<T, E>` — so modules whose
/// statistic is naturally fallible (`perseus`, `isomorph_null`) pass their closure
/// directly. The loop propagates the first `Err` as `NullRunError::Statistic(e)`;
/// a Fisher-Yates bound failure surfaces as `NullRunError::Random`.
pub fn run_null_test<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<NullResult<T>, NullRunError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy;
```

`NullRunError<E>` is a small enum folding the harness's own
`RandomBoundError` and the statistic's error `E` into one type:
`Random(RandomBoundError)` plus `Statistic(E)`, with
`From<RandomBoundError>`. Each caller maps it into its own error variant exactly
as it maps `RandomBoundError` today; an infallible statistic uses
`E = Infallible` (or `core::convert::Infallible`) so the `Statistic` arm is
uninhabited.

`NullResult` carries the raw `samples` and both tail counts only; it deliberately
does **not** compute p-values or bands, because the conventions differ per module
(add-one vs. doubled-min-tail; usize band vs. f64 band; some modules report no
p-value at all — `modular_diff`). Callers finish with the existing shared helpers
`add_one_p_value` and a new shared band constructor (below). This keeps the
harness a pure mechanical loop and lets every numeric convention stay where the
caller controls it — the key to behavior preservation.

For **vector-valued** statistics (`isomorph_null` per-window,
`conditional_structure` 10 stats, `modular_diff` 7-field fingerprint,
`periodicity` per-period/lag profiles) provide a sibling that scores into
columns without N separate passes:

```rust
/// Like `run_null_test` but the statistic emits a fixed-width row of scalars;
/// returns one `NullResult<T>` per column. `width` must equal the row length
/// the statistic returns every trial. The `row_statistic` is fallible, like
/// `run_null_test`'s, so columnar callers (`isomorph_null`,
/// `conditional_structure`, `periodicity`) pass their naturally-fallible row
/// closures directly.
pub fn run_null_test_columns<S, T, E>(
    row_statistic: impl Fn(&S::Draw) -> Result<Vec<T>, E>,
    observed: Vec<T>,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<Vec<NullResult<T>>, NullColumnError<E>>
where S: NullSampler, T: PartialOrd + Copy;
```

(`NullColumnError<E>` is a new small enum: `WidthMismatch { expected, observed }`
plus `Random(RandomBoundError)` and `Statistic(E)`, with `From<RandomBoundError>`.
Each caller maps it into its own error variant, exactly as they map
`RandomBoundError` today.)

For modules whose loop is **seed_count × trials_per_seed** with a re-seeded RNG
per stream (`zero_adjacency_null:298`, `tree_residual:294`,
`orientation_homogeneity:505`, `conditional_structure:1010`), add a thin
multi-stream wrapper:

```rust
/// Runs `run_null_test` once per derived seed stream and concatenates samples,
/// reproducing the seed-stream derivation each module does by hand. The
/// `derive_seed(stream_index)` closure stays caller-supplied because the
/// derivation differs (next_u64 chaining vs. xor-mix vs. wrapping_add stride),
/// and it is **`FnMut`** because some derivations are *stateful*: e.g.
/// `zero_adjacency_null` advances **one base RNG** per stream
/// (`SplitMix64::new(stream_rng.next_u64())`, `:296`) — a pure `Fn` cannot mutate
/// the captured base RNG, but an `FnMut` can. (Callers whose derivation is pure —
/// xor-mix, wrapping stride — pass a closure that happens not to mutate.)
pub fn run_null_test_streams<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    streams: usize,
    trials_per_stream: usize,
    derive_seed: impl FnMut(usize) -> u64,
) -> Result<NullResult<T>, NullRunError<E>>
where S: NullSampler, T: PartialOrd + Copy;
```

(A caller that already has its seeds in hand may instead pass a precomputed seed
iterator — equivalent, and likewise side-steps the `Fn`-can't-mutate limitation.)

The derivation closures must reproduce existing streams bit-for-bit:
`zero_adjacency_null` chains `SplitMix64::new(stream_rng.next_u64())` from one
base RNG (`:296`) — the **stateful** case the `FnMut` bound exists for —
`tree_residual` uses `seed_batches` (`:634`), `orientation_homogeneity` uses
`seed_for_index` wrapping stride (`:521`), `conditional_structure` uses
`derived_seed` xor-mix (`:1404`). **Do not unify these derivations** — pass each
module's existing one in as the closure. This is load-bearing for byte-identity.

### 3. Shared band constructors

```rust
/// `{trials, mean, min, q025, median, q975, max}` over a usize sample set,
/// using `scaled_quantile_index(_, 25|975, 1000)` and `median_usize`.
pub struct UsizeBand { pub trials, mean: f64, min, q025, median: f64, q975, max: usize }
pub fn usize_band(samples: &[usize]) -> UsizeBand;

/// Same over f64 samples, using `f64::total_cmp` sort and `median_f64`.
pub struct F64Band { pub trials: usize, pub mean, min, q025, median, q975, max: f64 }
pub fn f64_band(samples: &[f64]) -> F64Band;
```

Each module keeps its **named** band struct (`IsomorphNullBand`,
`AdjacencyNullBand`, `ScalarNullBand`, …) in its public report API — those are
part of the report surface and renaming them would be a visible API change. The
module-local `null_band`/`scalar_null_band` shrinks to a one-line `From<UsizeBand>`
/ `From<F64Band>` conversion (or a direct field copy), so the *sorting + quantile*
logic lives once. `perseus`'s `recurrence_null_band` (`:829`) additionally
derives rate fields from the count band; it builds on `usize_band` and keeps its
extra rate math local. `modular_diff`'s `ScalarBand` keeps `mean` (which today's
`scalar_band` `:1180` computes) — `f64_band` includes `mean`, so it maps directly.

## Implementation steps (ordered, each independently committable & green)

Each step is one module (or one harness addition) and one commit. Run
`make verify` + brief 01's golden-master diff after each. **Never** edit a pinned
assertion; if numbers move, revert and find the divergence (usually RNG call
order or `<` vs `<=`).

1. **Harness core, no callers yet.** Add to `src/null.rs`: `NullSampler` trait,
   `WithinMessageShuffle`, `NullResult<T>`, `run_null_test`,
   `run_null_test_streams`, `run_null_test_columns`, `NullColumnError`,
   `UsizeBand`/`usize_band`, `F64Band`/`f64_band`. Document every public item
   (`missing_docs`). Add unit tests: a hand-checked tiny shuffle null, a
   width-mismatch error, a stream-concatenation order check, band-quantile
   equality against the existing `quantile_from_sorted` math. No behavior changes
   anywhere yet — green by construction.

2. **`zero_adjacency_null`** (cleanest scalar-usize, lower-tail, multi-stream).
   Replace `shuffled_messages` (`:412`) with `WithinMessageShuffle`, the loop in
   `analyze_message_values` (`:298`) with `run_null_test_streams`. Its
   `derive_seed` is the existing `stream_rng.next_u64()` chain off one base RNG;
   pass an **`FnMut`** closure that *owns* (captures `mut`) the base
   `SplitMix64` and returns `stream_rng.next_u64()` per stream — the `FnMut` bound
   is exactly what lets the closure advance that captured RNG (a plain `Fn` could
   not). Replace `null_band` (`:423`) with `usize_band` + a
   `From<UsizeBand>` for `AdjacencyNullBand`. Keep `add_one_p_value` and
   `classify_band_position` (`:451`) exactly. Pinned test
   `eye_zero_adjacency_headline_numbers_are_pinned` (`:642`) must stay green
   untouched.

3. **`perseus`** (scalar-usize, lower-tail, single-stream, partition-masked
   statistic). Swap `shuffled_messages` (`:818`) → `WithinMessageShuffle`, loop
   (`:356`) → `run_null_test` with the **fallible** statistic closure
   `|shuffled| recurrence_statistic(keys, shuffled, &partition).map(|s| s.recurrent_occurrences)`.
   The statistic is naturally fallible (`PerseusError` on a
   `MessageMaskMismatch`, `:738`), and `run_null_test` now takes
   `impl Fn(&Draw) -> Result<T, E>` — so pass the closure **directly**; the
   harness propagates the first `Err` as `NullRunError::Statistic(PerseusError)`,
   which `report_from_partition` maps into its own error variant exactly as it
   maps `RandomBoundError` today. No infallible-only workaround, no contortion of
   the loop. `recurrence_null_band` keeps its rate math, built on `usize_band`.
   Pre-validating the mask shape before the loop is still **allowed** (it cannot
   change across shuffles, since the shuffle preserves per-message length) and may
   read cleaner, but it is **no longer required** — with the fallible signature the
   per-trial `Err` path is handled by the harness either way. Pinned tests
   `:899`,`:996` stay green.

4. **`isomorph_null`** (vector-usize per window, upper-tail). Use
   `run_null_test_columns` with the **fallible** row closure `row_statistic =
   |shuffled| summarize_window_range(shuffled, min, max).map(|s|
   s.repeated_signature_kinds)`. Since `run_null_test_columns` now takes
   `impl Fn(&Draw) -> Result<Vec<T>, E>`, pass it **directly**; the harness
   propagates any `Err` as `NullColumnError::Statistic(_)`. Pre-validating the
   window range up front is **optional** (it does not depend on the shuffle, so it
   is a fine place to surface an obviously-bad range early) but **not required** —
   the fallible signature already carries any per-trial error out of the loop.
   `null_band` → `usize_band` + `From` for `IsomorphNullBand`. Per-window
   `empirical_p_count`/`empirical_p` come from the returned `upper_tail_count` +
   `add_one_p_value`. Pinned/reproducibility tests `:338`,`:355` stay green.

5. **`tree_residual`** (scalar-usize, two-sided, multi-stream, **segment-shape**
   sampler). Introduce a module-local `ResidualSegmentShuffle` sampler
   implementing `NullSampler<Draw = Vec<MessageSegments>>` wrapping today's
   `shuffled_segment_messages` (`:598`)/`repartition_segments` (`:619`). Drive
   the per-row accumulation through `run_null_test_streams` per `(scope, k)` row —
   or keep the multi-row `RowAccumulator` loop (`:294`) and only swap the sampler
   + `null_band`→`usize_band`, whichever yields zero numeric drift. The
   `observe_sample` both-tails counting (`:398`) maps onto `NullResult`'s
   `lower_tail_count`/`upper_tail_count`; the `two_sided_p` combiner (`:411`,
   doubling already-add-one'd p-values) stays in the module. `seed_batches`
   (`:634`) feeds `derive_seed`. Pinned test `eye_headline_counts_are_pinned`
   (`:850`) stays green.

6. **`orientation_homogeneity`** (vector-f64, two-sided, multi-stream, **pooled
   repartition** sampler — not per-message shuffle). Module-local
   `PooledRepartition` sampler implementing `NullSampler<Draw = Vec<[usize; 5]>>`
   wrapping `repartition_table` (`:527`). `repartition_null_comparisons` (`:496`)
   → `run_null_test_columns` over `[pearson, g_test]`, `scalar_null_band`
   (`:586`) → `f64_band` + `From` for `ScalarNullBand`. Keep `null_comparison`'s
   two-sided combiner (`:561`) and `seed_for_index` (`:521`) derivation. Both the
   real null and the `positive_control` null (`:614`) reuse the same path. Pinned
   test `real_eye_headline_counts_are_pinned` (`:737`) stays green.

7. **`conditional_structure`** (vector-f64 ×10, two-sided, multi-stream, **plus**
   an MCMC no-repeat null). Migrate the plain shuffle path: `shuffled_messages`
   (`:1383`) → `WithinMessageShuffle`, `null_comparisons` (`:1001`) →
   `run_null_test_columns` over `COMPARISON_STATISTICS` (`:523`),
   `scalar_null_band` (`:1183`) → `f64_band`, keep `comparison_from_samples`
   (`:1152`) and `two_sided_add_one_p` (`:1173`). Leave `no_repeat_null_comparisons`
   (`:1032`) — the MCMC swap-chain via `run_no_repeat_sweeps` (`:1092`) is **not**
   a `NullSampler` (it carries state across trials and is not an independent
   resample); only its band/quantile helpers move to `f64_band`. `bias_calibration`
   (`:1220`) and `planted_controls` (`:1251`) reuse the migrated plain path.
   Reproducibility tests stay green.

8. **`modular_diff`** (vector-f64 7-field, band-only, no p-value). `shuffled_messages`
   (`:989`) → `WithinMessageShuffle`, `shuffle_baseline` loop (`:973`) →
   `run_null_test_columns` over the 7 `Fingerprint` fields (`:714`), `scalar_band`
   (`:1180`) → `f64_band`. The control-family fixture loops
   (`calibrate_control_order` `:779`) are **generators**, not shuffle nulls — they
   build wheel/Vigenere/deck/flat fixtures, not resamples — so leave them; only
   `fingerprint_band`/`scalar_band` consolidate. Pinned test
   `real_headline_statistics_are_stable` (`:1308`) stays green.

9. **`periodicity`** (vector-f64 profile bands, grid-shape-matched **content**
   null, band-only). This is a content null (`random_message_values_like` `:477`
   draws fresh uniform values, not a shuffle), so it does **not** use
   `WithinMessageShuffle`. Migrate only its band/quantile plumbing: `null_band`
   (`:775`) and the `quantile_from_sorted`/`Quantile` machinery (`:801`) →
   `f64_band`. Its `ProfileSamples` column accumulator (`:451`) already does the
   per-row collection `run_null_test_columns` would do; converting it is optional
   — prefer the minimal band-helper swap to guarantee zero drift. Pinned tests
   `:825`,`:862` stay green.

10. **Cleanup pass.** Remove now-dead per-module `mean`/`mean_usize`/`mean_f64`,
    `quantile_from_sorted`/`quantile_f64`, leftover `Quantile` enums where fully
    superseded. `cargo machete` + `-D unused` will catch stragglers. Confirm no
    module still defines a private `shuffled_messages`/`null_band` duplicate.

> If any module's migration cannot be made byte-identical (most likely risk:
> `perseus`/`isomorph_null` fallible-statistic refactor changes an early-return
> path, or `tree_residual`'s row ordering), **stop at the minimal sampler+band
> swap for that module** and leave its loop longhand. A partial win across 9
> modules is acceptable; a moved number is not.

## Files to create / change / delete

- **Change** `src/null.rs`: add `NullSampler`, `WithinMessageShuffle`,
  `NullResult<T>`, `run_null_test`, `run_null_test_streams`,
  `run_null_test_columns`, `NullColumnError`, `UsizeBand`/`usize_band`,
  `F64Band`/`f64_band` + their unit tests. (~150–200 net new lines, paid back
  several times over by the deletions.)
- **Change** (migrate, net **shrink**): `src/zero_adjacency_null.rs`,
  `src/perseus.rs`, `src/isomorph_null.rs`, `src/tree_residual.rs`,
  `src/orientation_homogeneity.rs`, `src/conditional_structure.rs`,
  `src/modular_diff.rs`, `src/periodicity.rs`. Each loses its
  `shuffled_messages`/`null_band`/`scalar_band`/`mean*`/`quantile_from_sorted`
  privates; keeps its report structs, error enum, statistic logic, p-value
  combiner, and seed derivation.
- **No new file, no deletion of a module.** (The `crate::nulls` directory move is
  brief 07B's job; do not pre-empt it.)
- **No test file changes** beyond the new harness unit tests in `null.rs`. The
  CLI characterization tests (`tests/nulls_cli.rs`, `tests/perseus_cli.rs`,
  `tests/tree_residual_cli.rs`, `tests/conditional_cli.rs`,
  `tests/modular_diff_cli.rs`, `tests/orientation_homogeneity_cli.rs`,
  `tests/periodicity_cli.rs`) and every in-module pinned regression must stay
  green **unedited**.

## Expected line savings

Quantified from the current duplication: the within-message `shuffled_messages`
is ~10 lines × 5 copies; `null_band`/`scalar_null_band`/`scalar_band` ~12–18
lines × 9 copies; `mean*` ~6 lines × 7 copies; `quantile_from_sorted`/`quantile_f64`
~5 lines × 8 copies; per-module `Quantile` enums ~6 lines × 3. That is roughly
**280–330 lines of mechanical duplication** collapsed into ~150 shared lines
plus thin `From`/closure adapters, for a net reduction of **~150–250 lines** and,
more importantly, **9 → 1** sites for the band/p-value/shuffle conventions. The
trial-loop consolidation removes another ~8–15 lines per migrated module on top
(another ~80–120 lines) where the full `run_null_test*` swap lands cleanly.

## Success criteria

- `NullSampler` + `run_null_test`/`run_null_test_streams`/`run_null_test_columns`
  exist in `src/null.rs`, fully documented, with unit tests. Their statistic
  parameter is fallible (`impl Fn(&Draw) -> Result<T, E>`), they return
  `NullRunError<E>`/`NullColumnError<E>`, and `run_null_test_streams`'s
  `derive_seed` is `impl FnMut(usize) -> u64` (so the stateful `zero_adjacency`
  base-RNG chain compiles). `perseus`/`isomorph_null` pass their fallible closures
  directly with no infallible-only workaround.
- At least steps 2–6 migrated (the clean cases); 7–9 migrated or explicitly
  left at minimal band-swap with a one-line code comment explaining why.
- No module in scope defines its own `shuffled_messages` (within-message variant),
  `null_band`/`scalar_null_band`/`scalar_band`, `mean`/`mean_usize`/`mean_f64`,
  or `quantile_from_sorted`/`quantile_f64` after the cleanup pass (segment- and
  pooled-repartition samplers excepted — those stay local but implement the trait).
- Every in-module pinned regression and every brief-01 golden master is
  byte-identical. `make verify` green at every commit; `make check` green before
  the final push.
- House invariants intact: no `unsafe`, no `unwrap`/`panic`/`indexing_slicing`/
  `unused_results` in lib code, `missing_docs` satisfied, `--locked`, no new
  dependency (the harness uses only existing `null.rs` primitives).

## Verification (exactly how to prove it)

1. `make verify` after **every** commit (fmt + clippy `-D` + tests + rustdoc `-D`
   + cargo-deny).
2. Brief 01's golden-master diff after every commit: it must be empty. Treat any
   diff as a hard failure and bisect to the offending closure (RNG call order,
   tail comparator, or seed derivation).
3. The canonical 1000-trial `#[ignore]` regressions are the strongest numeric
   proof — run them explicitly after each migration:
   `cargo test --locked -- --ignored zero_adjacency` / `perseus` / `tree_residual`
   / `dof_null` / etc. They assert exact p-values and histograms
   (e.g. `perseus.rs:996` pins `empirical_p == 0.006_993_006_993_006_99`;
   `zero_adjacency_null.rs:642` pins `0.000_199_960_007_998_400_3`).
4. Determinism spot-check: each module already has a "reproducible for fixed seed"
   test (e.g. `isomorph_null.rs:338`, `zero_adjacency_null.rs:593`); these prove
   the seed threading through the new harness is unchanged.
5. Diff-review the migrated trial loop against the original side-by-side to
   confirm: same number of `next_u64`/`fisher_yates` calls per trial, same
   `<=`/`>=` comparators, same sample push order.

## Risks & honesty caveats

- **RNG call-order is the dominant risk.** `SplitMix64` is a deterministic stream
  (`src/null.rs:31` doctest); any change to *how many* draws happen *in what
  order* moves every downstream number. The within-message shuffle draws one
  `random_index_below` per swap per message in message order — the harness sampler
  must reproduce that order exactly (iterate messages in the same order, shuffle
  in place, no extra clones that consume draws). Multi-stream derivation closures
  must be the verbatim existing derivation, not a unified one.
- **Fallible statistics.** `perseus`/`isomorph_null` statistics return `Result`,
  and so does the harness statistic parameter (`impl Fn(&Draw) -> Result<T, E>`,
  yielding `NullRunError<E>`/`NullColumnError<E>`). These callers pass their
  naturally-fallible closures **directly**, and the loop propagates the first
  `Err`; an infallible caller uses `E = Infallible`. The earlier "hoist the only
  failure mode to a pre-loop check so the per-trial call is infallible" workaround
  is **no longer required** — pre-validating invariant shape is still allowed where
  it reads naturally, but is purely optional. (A statistic with a genuinely
  unexpected error path now simply surfaces it as `NullRunError::Statistic`, rather
  than forcing the module back to a longhand loop.)
- **`modular_diff` and `periodicity` are not pure shuffle nulls.** `modular_diff`'s
  control families and `periodicity`'s `random_message_values_like` are content
  *generators*; only their band helpers consolidate. Do not force them into
  `WithinMessageShuffle` — that would change the resampling model and the numbers.
- **`conditional_structure`'s no-repeat null is MCMC**, not i.i.d. resampling
  (`run_no_repeat_sweeps` `:1092` carries chain state across trials). It is
  explicitly excluded from the sampler abstraction; only its band math moves.
- **Deviation from the overview's `NullSampler` signature.** The overview proposes
  `fn sample(&self, rng) -> Vec<Glyph>` (`docs/refactor/00-OVERVIEW.md` §"3. Null/experiment harness — kill the copy-paste (brief 05)"); this
  brief uses an associated `Draw` type to preserve message/segment/table
  structure. This is a conscious, documented deviation — already recorded in
  `docs/refactor/00-OVERVIEW.md` §"Documented deviations from this overview".
- **Claim discipline unaffected.** This refactor touches no decode and no reported
  statistic; the claim ceiling (`docs/refactor/00-OVERVIEW.md` §"Shared ground rules" ("Claim discipline is the crown jewel")) is untouched.
  No candidate cleartext is produced here.

## Out of scope / non-goals

- **Grid-content nulls** (`dof_null` `run_dof_null_with` `:360`, `pipeline_null`
  `run_pipeline_null` `:74`, the `standard36` null itself). They already use the
  injected-generator pattern and do not duplicate the trial loop; optionally
  adopting `NullSampler<Draw = Vec<GlyphGrid>>` is a follow-up, not part of this
  brief's behavior-critical path.
- **Moving the harness into a `crate::nulls` directory** — that is brief 07B's
  role-directory module-layout job (`docs/refactor/00-OVERVIEW.md` §"Target module layout"). Keep everything in
  `src/null.rs` here to avoid a file-move conflict.
- **Renaming the per-module report band structs** (`IsomorphNullBand`,
  `AdjacencyNullBand`, `ScalarNullBand`, …) — they are public report API; leave
  them, bridge via `From`.
- **The `Report`/`Experiment` traits and error `Display` impls** — brief 06.
- **`controls.rs`, `chaining_graph.rs`, `agl_gak.rs`, `gak_attack.rs`,
  `perfect_isomorphism.rs`, `cipher_attack.rs`** — they also contain
  `add_one_p_value`/`quantile_from_sorted` uses but are outside this brief's named
  ten; a later sweep can fold them onto the harness once it is proven on the core
  battery.
