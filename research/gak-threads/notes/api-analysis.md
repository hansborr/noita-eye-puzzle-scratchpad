# GAK-threads API map: reusable analysis primitives

Read-only survey of the public surfaces the GAK threads will reuse. This is a
*mapping-independent* inventory: every primitive listed operates on ciphertext
symbol **equality** and group/positional structure only. None of them invents a
symbol->meaning mapping, and a new GAK module must preserve that discipline.

Source of truth for symbols: `crate::trigram::TrigramValue` (reading-layer value
`0..=82`, `READING_LAYER_ALPHABET_SIZE = 83`) and the opaque `crate::glyph::Glyph`
(`u16`). The verified streams come from `corpus.rs` via the `orders` helpers
below.

---

## Shared corpus / reading helpers (`orders.rs`) — the standard entry path

Every Experiment-7 module starts the same way; a GAK module should too:

```rust
let grids = orders::corpus_grids()?;                       // Vec<GlyphGrid>, verified corpus
let order = orders::accepted_honeycomb_order();            // const ReadingOrder
let keys: Vec<&'static str> =
    grids.iter().map(GlyphGrid::message_key).collect();    // 9 message keys
let message_values: Vec<Vec<TrigramValue>> =
    orders::read_corpus_message_values(&grids, order)?;    // per-message streams, boundaries kept
```

- `pub fn corpus_grids() -> Result<Vec<GlyphGrid>, GridError>` — the nine verified grids.
- `pub fn read_corpus_message_values(&[GlyphGrid], ReadingOrder) -> Result<Vec<Vec<TrigramValue>>, GridError>`
  — per-message reading-layer streams (the unit all nulls shuffle/scan). Keep
  message boundaries intact; do not concatenate across messages.
- `pub fn read_corpus_values(...) -> Result<Vec<TrigramValue>, GridError>` — flat concatenation, when a single stream is wanted.
- `pub const fn accepted_honeycomb_order() -> ReadingOrder` and
  `pub fn standard36_orders() -> Vec<ReadingOrder>` — the accepted order and the
  36-permutation family used for selection-corrected nulls.
- `pub const READING_LAYER_ALPHABET_SIZE: usize = 83`.

---

## `analysis.rs` — frequency / chi-square / IoC baselines (over `Glyph`)

All encoding-agnostic; operate on `&[Glyph]`. Reuse for any per-column /
per-position frequency test in a GAK attack.

- `pub fn frequencies(&[Glyph]) -> BTreeMap<Glyph, usize>` — symbol counts.
- `pub fn shannon_entropy(&[Glyph]) -> f64` — bits/glyph; `0.0` for empty.
- `pub fn index_of_coincidence(&[Glyph]) -> f64` — P(two draws equal); `0.0` for `len<2`.
- `pub fn message_weighted_index_of_coincidence(&[Vec<Glyph>]) -> f64` — pair-count-weighted pooled IoC (skips `len<2`).
- `pub fn message_weighted_entropy(&[Vec<Glyph>]) -> f64` — length-weighted pooled entropy.
- `pub fn chi_square_goodness_of_fit_uniform(&[usize]) -> f64` — Pearson vs uniform over observed buckets.
- `pub fn chi_square_goodness_of_fit(observed: &[usize], expected_weights: &[f64]) -> Result<f64, ChiSquareError>`
  — vs an arbitrary expected distribution (weights normalized internally).
- `pub fn chi_square_upper_tail_p_value(statistic: f64, degrees_of_freedom: usize) -> Option<f64>`
  — upper-tail p via `statrs` ChiSquared; `None` on df=0/NaN/negative.
- `pub fn ngrams(&[Glyph], n: usize) -> BTreeMap<Vec<Glyph>, usize>` — contiguous n-gram counts.

How a GAK module calls these: convert a candidate column/region to `Vec<Glyph>`
(or feed count vectors directly), then chi-square/IoC against a uniform or
model-implied baseline. **Note** these take `Glyph` not `TrigramValue`; a GAK
module working in the reading layer must either map `TrigramValue.get()` into
`Glyph(u16)` or count buckets itself before calling the chi-square fns.

---

## `null.rs` — centralized Monte-Carlo PRNG primitives **(reuse, do not reimplement)**

This is the canonical RNG/shuffle layer. Any new null MUST build on it so the
seed stream stays reproducible and regression-locked.

- `pub struct SplitMix64`; `pub const fn new(seed: u64) -> Self`; `pub fn next_u64(&mut self) -> u64`.
- `pub fn stateless_splitmix(seed: u64) -> u64` — one-shot hash of a seed (= `SplitMix64::new(seed).next_u64()`); use for per-symbol/per-trial derived seeds without threading a generator.
- `pub fn random_index_below(bound: usize, &mut SplitMix64) -> Result<usize, RandomBoundError>` — unbiased rejection-sampled index draw.
- `pub fn fisher_yates<T>(&mut [T], &mut SplitMix64) -> Result<(), RandomBoundError>` — **(b) the in-place within-slice shuffle** every within-message null uses.
- `pub fn shuffled_permutation(n: usize, &mut SplitMix64) -> Result<Vec<usize>, RandomBoundError>` — random permutation of `0..n` (use for index/keystream permutation nulls).
- `pub struct RandomBoundError { pub bound: usize }` — each module maps this into its own `RandomBoundTooLarge { bound }` via `From`.
- Significance helpers / stats: `pub fn wilson_95(count, trials) -> WilsonInterval`,
  `pub fn analytic_headline_bounds(family_size, trigrams) -> AnalyticBounds` (Bonferroni/Sidak),
  and the selection-corrected `pub fn run_standard36_null_with(config, generate: impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>) -> Result<NullReport, GridError>`
  (pluggable synthetic-corpus generator; reuse to get the 36-order selection
  correction for free).
- `pub fn random_orientation_grids_like(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>` — uniform-orientation grid resampler (content null, not arrangement).

**Message-weighted stats live in `analysis.rs`** (the two `message_weighted_*`
fns above), not in `null.rs`; `null.rs` provides the RNG + the standard-36
report scaffolding and Wilson/analytic significance.

Add-one Monte-Carlo p-value `(count+1)/(trials+1)` is *not* a shared fn — each
null reimplements `add_one_p_value` privately (see isomorph_null / perseus). A
GAK module should follow the same convention (or, better, the spec may propose
promoting it to `null.rs`).

---

## `isomorph.rs` — first-occurrence equality patterns **((a) alignment primitive)**

Pure, mapping-independent: `A B C A B` and `X Y Z X Y` both become `0,1,2,0,1`.
Generic over `T: Eq + Copy`, so it works directly on `TrigramValue` *and* on any
group-element type a GAK module defines.

- `pub struct PatternSignature` with:
  - `pub fn from_window<T: Eq + Copy>(window: &[T]) -> Self` — build the equality pattern. **This is the exact reusable primitive for cross-message isomorph alignment (a):** compute `from_window` over each message at a candidate offset and compare/equate signatures across messages by `==`.
  - `pub fn has_repeated_symbol(&self) -> bool`, `pub fn render(&self) -> String`, `pub fn values(&self) -> &[usize]`.
- `pub struct SignatureGroup { pub signature: PatternSignature, pub occurrences: Vec<usize> }` — one repeated signature and its ascending window-start positions.
- `pub fn detect_isomorphs<T: Eq + Copy>(seq: &[T], window, min_period, max_period) -> Result<IsomorphDetection, IsomorphError>`
  — scans windows of length `window` **within one sequence**, keeps only
  *informative* (repeat-bearing) signatures, groups equal ones, and reports
  period signals. `IsomorphDetection` exposes `repeated_signature_kinds()`,
  `max_repeat_count()`, `period_matches(p)`, `best_period()`, `strongest_signatures(p)`.
- `pub fn signature_period_matches(group: &SignatureGroup, period: usize) -> usize`
  — counts occurrence pairs whose start-distance is a positive multiple of `period` (assumes ascending occurrences).

**Caveat for (a):** `detect_isomorphs` is *within-sequence*. For cross-message
alignment a GAK module reuses `PatternSignature::from_window` directly (the
load-bearing primitive) and does its own cross-message bookkeeping; it should not
expect `detect_isomorphs` to align two messages for it.

---

## `isomorph_null.rs` — the within-message multiset-shuffle null (Exp 7A)

This is the reference implementation of **(b)**: preserve each message's exact
symbol multiset and length, randomize order within the message, recompute the
statistic.

- `pub fn run_isomorph_null(config: IsomorphNullConfig) -> Result<IsomorphNullReport, IsomorphNullError>` — full run on the verified corpus.
- Mechanism (copy this shape): `let mut rng = SplitMix64::new(config.seed);` then per trial `shuffled = message_values.to_vec(); for v in &mut shuffled { fisher_yates(v, &mut rng)?; }`. The multiset and length are conserved; only arrangement varies.
- Significance attached as an **add-one one-sided empirical p**: count shuffles whose statistic `>=` real, then `empirical_p = (count+1)/(trials+1)` (`IsomorphNullRow.empirical_p_count` / `empirical_p`), alongside a percentile band (`IsomorphNullBand`: mean/q025/median/q975/max).
- Positive/negative controls baked into tests (`isomorph_rich_*` fires; `uniform_random_*` stays inside band) — the matched-null + positive-control pattern a GAK null must replicate.

A GAK module that needs the within-message shuffle null should reuse
`fisher_yates` over `message_values.to_vec()` exactly as here; the only thing
that changes is the statistic recomputed per shuffle.

---

## `perseus.rs` — shared-run reconstruction + message-start alignment anchors (Exp 7C)

Reconstructs same-offset shared regions across messages, then a within-message
shuffle null over a fixed position mask.

- `pub fn run_perseus(config: PerseusConfig) -> Result<PerseusReport, PerseusError>`.
- Alignment anchors (the reusable concepts; the fns are private, so a spec must
  decide whether to promote them):
  - same-offset common runs: walk two equal-length-aligned messages position-by-position and emit maximal runs where `left == right` and `len >= MIN_SHARED_RUN_LEN (=2)` (private `same_offset_common_runs` / `collect_pair_runs`).
  - **leading-family anchor**: `SharedPartition.leading_start: Option<usize>` = earliest same-offset shared-run start; runs starting there are `LeadingFamily`.
  - **East/West counterpart anchor**: `is_counterpart_pair` matches `eastN`/`westN` keys; such runs are `Counterpart` (roles in `SharedRunRole`).
  - `GlobalSharedPrefix` = all-message common prefix at the leading start — the message-start alignment anchor.
- Public result types worth reusing as spec vocabulary: `SharedSpan { start, len, end() }`, `SharedRunSummary`, `MessagePartitionSummary { shared_spans, .. }`, `CounterpartRunSummary`, `SharedPartition` (note its `masks` field is private; only `pub(crate) masks()`).
- Its null (the mask is held fixed): within-message `fisher_yates` shuffle, **lower-tail** add-one p (`empirical_p_count` = shuffles with recurrence count `<=` observed; `empirical_p = (count+1)/(trials+1)`), with `RecurrenceNullBand` and a `significant` flag at `SIGNIFICANCE_ALPHA = 0.05`. `DOCUMENTED_REFERENCE_CHANCE = 0.00192` is carried only for comparison, never as a finding.

For GAK: perseus is the template for "reconstruct a positional alignment, freeze
it as a mask, shuffle within message to null it." Cross-message start alignment
(`leading_start` / `GlobalSharedPrefix` / counterpart pairing) is the reusable
anchor logic, but it is currently private — a spec must request promotion or
reimplement it.

---

## `chaining.rs` — Experiment-7B additive chaining **(CYCLIC-ONLY; keep as-is)**

Model-conditional (additive-shift assumption); **do not modify**. A GAK module
may *call* it but must not change its semantics.

- `pub fn run_chaining(config: ChainingConfig) -> Result<ChainingReport, ChainingError>`.
- `pub fn chaining_signature(message_values: &[Vec<TrigramValue>], period: usize, alphabet_size: usize) -> Result<ChainingSignature, ChainingError>`
  — the single procedure shared by real stream and controls.
- **Cyclic by construction and must stay so:** columns are `position % period`
  (reset at message boundaries); adjacent pairs include the wrap `to = (from+1) % period`;
  the signature closes the cycle via `cycle_residual = sum(shifts) mod alphabet_size`
  and `chain_score = mean_alignment_quality * cycle_closure`. This is the
  Experiment-7B *cyclic* additive model; the graph-chaining thread must build a
  **separate** module, not generalize this one.
- Result vocabulary: `PairAlignment { from_column, to_column, shift, best_overlap, second_overlap, quality }`, `ChainingSignature`, calibration `ScalarBand`/`ResidualBand`/`CalibrationBands`, and `ChainingClassification` (CalibrationOverlaps / MatchesKnownFail / MatchesKnownSucceed / BetweenBands). Calibrated against generated Vigenere succeed + independent-substitution fail controls (matched-null + positive-control discipline).

---

## Flagged primitives for the GAK threads

- **(a) cross-message isomorph alignment** → `isomorph::PatternSignature::from_window`
  (the load-bearing, mapping-independent primitive). `detect_isomorphs` is
  within-sequence only; cross-message bookkeeping is the caller's job.
- **(b) within-message shuffle null** → `null::fisher_yates` applied per message
  over `message_values.to_vec()`, exactly as `isomorph_null` / `perseus` do; pair
  with an add-one empirical p (`(count+1)/(trials+1)`) and a percentile band.
- **(c) connected-components / graph utility** → **NONE EXISTS.** A repo-wide
  search found only sequence-adjacency (consecutive-symbol) code and grid
  geometry; there is no union-find, no connected-components, no graph traversal,
  no `petgraph`. **The chaining-graph thread (thread-5) must add a new module**
  providing the graph primitive (e.g. union-find / component labeling over a
  symbol-relation graph). It should sit beside `chaining.rs`, not inside it, and
  reuse `null.rs` for any Monte-Carlo calibration.

Discipline reminder for all threads: keep every choice mapping-independent
(equality + group structure only), match every structural negative with a null
and every positive control with known signal, cite the exact wiki page tested,
and never report a number more strongly than its construction supports.
