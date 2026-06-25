# Refactor briefs — overview & constitution

Status as of **2026-06-25**. These are **self-contained engineering briefs for
handing individual refactors to other agents**, modelled on
`research/gak-threads/thread-N-*.md`. Each `NN-*.md` can be picked up cold: it
states the goal, the current grounded state, the target design, an ordered
implementation plan, success criteria, how to verify, and the honesty caveats.

**Read this overview first.** It fixes the shared vocabulary (trait names, module
layout, sequencing, ground rules) so the briefs stay mutually consistent. The
type/trait names below are **proposals** — the implementing agent must reconcile
them with the actual types in the code (verify against `glyph.rs`, `null.rs`,
`ciphers.rs`, etc.) and may rename, but should keep the *shape* and update every
brief's cross-references if a name changes.

---

## Why these refactors exist: the reframe

The workbench is **~90% structural diagnostics and ~10% decode engine**, and the
decode engine is the half that matters for the end goal (reading the eye
messages). A sample cipher (`/tmp/gak_cipher_example`) that *does* contain a real
English message was **not** cracked by our tooling — not because the message was
unrecoverable, but because we have two dozen-plus experiments (26 CLI subcommands)
that mostly *constrain* the hypothesis space and almost nothing that *searches* it.

The decode path today is split across four modules that do not compose:

- `ciphers.rs` (2,910 lines) — 7 cipher families as bespoke `*_encrypt`/`*_decrypt`
  free functions, **no `Cipher` trait** (the crate has **zero traits** in 44,827
  lines).
- `cipher_attack.rs` — decodes + language-scores, but only under **declared**
  symbol→letter mappings ("Every mapping here is a declared guess"). **No mapping
  search exists anywhere.**
- `gak_attack.rs` (8,147 lines) — beam-search permutation recovery. Its GCTAK gate
  and synthetic GAK/deck fixtures (Units 1a/2a/2b) are **synthetic-only**; Unit 2c
  (`run_gak_attack_eyes`, Step 3) *does* run against the verified **embedded** eye
  corpus (matched within-message nulls, asserts no decode — the standing **BLOCKED**
  conclusion). Either way there is **no external-ciphertext (file/stdin) ingest** —
  the eye corpus it touches is the embedded `corpus`, not loaded data.
- `language.rs` — a real English/Finnish scorer, wired only into the
  declared-mapping path.

A real cipher with an unknown mapping slips straight through that. Closing the gap
is half "build the solve engine" (Tier 1) and half "stop the codebase from
growing god-files so the engine has clean abstractions to sit on" (Tier 2).

## Evidence (the structural smells)

| Smell | Data | Brief |
| ----- | ---- | ----- |
| No abstractions | 0 traits in 44,827 lines | 02, 05, 06 |
| God-files | `gak_attack.rs` 8,147 lines; `report.rs` 5,694 lines (31% of crate in 2 files) | 06, 07 |
| `report.rs` is a coupling hub | 23 hand-written `format_*_error` + 27 `print_*_report` public entry points (plus ~140 private render helpers); imports 27 sibling modules | 06 |
| Per-experiment boilerplate | 22 `Config` + 24 `Args` + 22 `From<Args>` + 28 `run_*` CLI dispatchers in `main.rs` ≈ 4 scattered edits per experiment | 05, 08 |
| Duplicated null scaffolding | `fisher_yates` is centralized, but ~20 modules re-implement the matched-null orchestration around it | 05 |
| No data ingest | the only non-test `fs` use writes candidate records (no `stdin` path at all); nothing loads an external ciphertext | 03 |
| No mapping search | `cipher_attack` only scores declared mappings; no hill-climb/anneal | 04 |

---

## Target architecture (the shared spine)

Five small abstractions, introduced incrementally. **Names are proposals; verify
exact existing types before coding.**

### 1. `trait Cipher` — unify the cipher zoo (brief 02)

```rust
// crate::ciphers
pub trait Cipher {
    type Key;
    fn encrypt(&self, key: &Self::Key, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;
    fn decrypt(&self, key: &Self::Key, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;
    fn name(&self) -> &'static str;
}
```

The associated `Key` makes the trait non-object-safe, so heterogeneous search uses
a dispatch enum (pick the cleanest of these in brief 02):

```rust
pub enum AnyCipher { Caesar(CaesarKey), Vigenere(VigenereKey), /* ... */ Gak(GakKey) }
impl AnyCipher { fn encrypt(&self, pt: &[Glyph]) -> Result<Vec<Glyph>, CipherError>; fn decrypt(...) ; }
```

### 2. `Sequence` ingest — one way in (brief 03)

```rust
// crate::core (or crate::glyph)
pub fn load_sequence(input: Input, alphabet: &Alphabet) -> Result<Vec<Glyph>, IngestError>;
pub enum Input<'a> { Str(&'a str), Path(&'a Path), Stdin }
```

Parses digit/glyph strings (the `0..4` + `5`-delimiter convention, and the 83-symbol
honeycomb layer) into the existing `Glyph` sequence type. This is the missing
front door: today the only data source is the embedded `corpus`.

### 3. Null/experiment harness — kill the copy-paste (brief 05)

```rust
// crate::nulls (new home for the matched-null pattern)
pub trait NullSampler { fn sample(&self, rng: &mut SplitMix64) -> Vec<Glyph>; }
pub fn run_null_test<T: PartialOrd + Copy>(
    statistic: impl Fn(&[Glyph]) -> T,
    real: &[Glyph],
    null: &impl NullSampler,
    trials: usize,
    seed: u64,
) -> NullResult<T>;          // { observed, null_mean, p_value, z, percentile, ... }
```

Every experiment collapses to "define the statistic + the null sampler"; the
orchestration, p-value, and positive-control plumbing live once.

### 4. `Experiment` + `Report` — dissolve the report god-file (brief 06)

```rust
pub trait Experiment { type Config; type Report: Report; fn run(cfg: &Self::Config) -> Result<Self::Report, Error>; }
pub trait Report { fn render(&self) -> String; }   // replaces report.rs print_* fns
```

Each error enum gets a `Display`/`thiserror` impl (replaces the 23
`format_*_error` functions). `report.rs` keeps only shared formatting helpers.

### 5. The solve pipeline — the prize (brief 04)

```rust
// crate::attack::solve
pub struct SolveRequest<'a> {
    ciphertext: &'a [Glyph],
    space: HypothesisSpace,        // cipher families × key/param ranges × mapping search
    scorer: &'a LanguageModel,     // reuse crate::language
}
pub struct Candidate { cipher: AnyCipher, mapping: Mapping, plaintext: String, score: f64, round_trip_ok: bool }
pub fn solve(req: &SolveRequest) -> Result<Vec<Candidate>, SolveError>;   // ranked, round-trip-verified
```

Phase 2 adds the **mapping search** (hill-climb / simulated annealing over
symbol→letter), the capability that would have caught the sample's English
message.

### Target module layout

Group the 32 flat `pub mod`s in `lib.rs` (`src/lib.rs:72-103`) into role directories (brief 07):

```
src/
  core/         glyph, trigram, sequence/ingest, alphabet      (data primitives)
  data/         corpus, generator
  analysis/     analysis, isomorph, periodicity, conditional_structure,
                modular_diff, grouping, orientation_homogeneity, transitivity, ...
  nulls/        null + the matched-null harness; isomorph_null, zero_adjacency_null,
                dof_null, pipeline_null, tree_residual, perseus, ...
  ciphers/      mod.rs (trait + AnyCipher) + one file per family
  attack/       cipher_attack, agl_gak, gak/ (split from gak_attack.rs), solve/
  experiments/  the structural-battery modules (each impl Experiment)
  report/       shared formatting helpers only
  main.rs       thin CLI over an Experiment registry (brief 08)
```

---

## The briefs & sequencing

| # | Brief | Tier | Depends on | Size |
| - | ----- | ---- | ---------- | ---- |
| 01 | [Golden-master safety net](01-golden-master-safety-net.md) | **prereq** | — | M |
| 02 | [`Cipher` trait + `ciphers.rs` refactor](02-cipher-trait.md) | 1 | 01 | M |
| 03 | [External-ciphertext ingest](03-external-ingest.md) | 1 | 01 | S |
| 04 | [Solve pipeline + mapping search](04-solve-pipeline.md) | 1 | 02, 03 | **L** |
| 05 | [Null / experiment harness dedup](05-null-experiment-harness.md) | 2 | 01 | **L** |
| 06 | [Dissolve `report.rs` + error `Display`](06-dissolve-report.md) | 2 | 01 (05 helps) | M |
| 07 | [Split god-files + module layout](07-split-godfiles-layout.md) | 2 | 01 | M |
| 08 | [CLI registry + args dedup](08-cli-registry.md) | 2 | 06 (02/05 help) | M |

**Recommended order.** `01` first, always — it is the safety net every other
brief leans on. Then the end-goal track `02 → 03 → 04` (the engine) can run in
parallel with the maintainability track `05`, `06`, `07`. `08` lands after `06`.
`04` is the only Large end-goal item and the highest reward; do not start it until
`02` and `03` are green.

The end-goal track (`02–04`) and the maintainability track (`05–08`) touch mostly
different files and can be staffed concurrently on separate branches. The likely
conflict point is `gak_attack.rs` (brief 07 splits it; brief 04 may reuse its
beam-search) — sequence those two on the same branch or coordinate explicitly.

---

## Shared ground rules (apply to every brief)

- **Behavior-preserving.** No refactor may change a reported statistic or a
  decode. The byte-for-byte corpus cross-check and every null calibration must
  produce identical numbers. Brief **01** pins these with golden-master tests
  *before* any other brief touches code — land 01 first.
- **`make verify` stays green at every commit** (fmt + clippy `-D` + tests +
  rustdoc `-D` + cargo-deny). `make check` before the final push. Each
  implementation step in a brief should be independently committable and green.
- **No big-bang.** Land traits one family / one module at a time. A brief that
  cannot be split into independently-green steps is mis-scoped — re-scope it.
- **House invariants hold.** `unsafe` forbidden; no `unwrap`/`panic`/
  `indexing_slicing`/`unused_results` in library/CLI code (relaxed in tests via
  `clippy.toml`); document every public item (`missing_docs`); `--locked`
  everywhere; justify any new dependency against `deny.toml` + `cargo-machete`.
- **Claim discipline is the crown jewel.** The solve engine (brief 04) *searches*
  and *scores* — it must never present a scored candidate as a decode. Round-trip
  verification is mandatory; every emitted candidate is a labelled HYPOTHESIS and
  is logged to `research/gak-threads/candidates/` per the standing directive. The
  strongest defensible claim ceiling is unchanged: *the eyes are deterministic,
  engine-generated, strikingly structured data of unknown meaning; unsolved.*
- **Ground every claim in the code.** Cite `file:line` for the current-state
  problem and for each touch-point. Re-read the actual module before writing the
  plan; do not trust line numbers second-hand.

## Documented deviations from this overview

The briefs refined three proposals above after reading the code; each deviation is
justified in-brief. Honor the brief's version:

- **Brief 03** — `load_sequence` takes a `SequenceLayer` selector, **not**
  `&Alphabet`. The two in-scope layers map positionally (`d → Glyph(d)`,
  `v → Glyph(v)`) and an `Alphabet` cannot express "drop the `5` delimiter" or
  "multi-digit `0..=124` tokens."
- **Brief 05** — `NullSampler` carries an associated `Draw` type rather than
  returning `Vec<Glyph>`, because the nulls must preserve varied draw shapes
  (`Vec<Vec<TrigramValue>>`, `MessageSegments`, `Vec<[usize;5]>`, `Vec<GlyphGrid>`).
  `conditional_structure`'s stateful no-repeat MCMC null is explicitly excluded.
- **Brief 06** — two non-struct renderers (`print_report` over `&Sequence`,
  `print_orders_report` over three report sub-objects: a `&GridSummary` plus two
  slices) stay as shared `render_* -> String` free fns rather than `Report` impls.
  `thiserror` is **not** added (absent from `Cargo.toml`; six error enums already
  hand-write `Display`).

## Brief template (each `NN-*.md` follows this)

```
# NN — Title

> One-line: what this delivers and which goal(s) it serves.
> Status: not started · Depends on: … · Blocks: … · Size: S/M/L

## Goal & why it matters
## Current state (grounded, with file:line)
## Target design (concrete API / types / layout)
## Implementation steps (ordered, each independently committable & green)
## Files to create / change / delete
## Success criteria
## Verification (exactly how to prove it: make verify, golden-master diff, new tests)
## Risks & honesty caveats
## Out of scope / non-goals
```
