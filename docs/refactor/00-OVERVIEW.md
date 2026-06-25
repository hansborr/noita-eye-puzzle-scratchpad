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
messages). The capability gap is **real and architectural, independent of any
sample**: the crate has **no mapping-search / unified solve component at all**
(`cipher_attack` only *scores declared* mappings — `cipher_attack.rs:13` "Every
mapping here is a declared guess"; there is no hill-climb/anneal anywhere), **and
no codec / transduction (grouping) layer at all** — nothing widens a small cipher
alphabet up to a natural-language alphabet, even though the eye honeycomb reading
layer (base-5 trigrams → values `0..=124`, accepted `0..=82`; `orders.rs`,
`READING_LAYER_ALPHABET_SIZE = 83`) is exactly such a transduction. Until brief 03
there was no external-ciphertext ingest path either. We have two dozen-plus
experiments (26 CLI subcommands) that mostly *constrain* the hypothesis space and
almost nothing that *searches* it.

The reframe is therefore: build a **general classical-cipher cracker** (solve
engine, brief 04; codec, brief 04a) whose correctness is **validated on
`research/data/practice-puzzles/`** — an external corpus of seven samples believed
decryptable to English (see that directory's `README.md`). That corpus is the
**credibility ladder**: an engine that reliably cracks recoverable-English samples
is one we can *trust* on the eyes. The **eyes remain the primary end goal** and the
**sole honest-negative** (decode BLOCKED on the unknown symbol→meaning mapping) —
the broadening must not dilute the eye focus. The corpus splits along the capability
gap: `three`/`four`/`five`/`seven` (letters + space + punctuation, word structure
preserved) are **letter substitution** — i.e. the missing mapping search over a
letter alphabet — while `one`/`two`/`six` (small digit/letter alphabets) **need the
codec** to widen the alphabet before any mapping can carry English. None of these
"modes" is a confirmed cipher identification; each is a structural HYPOTHESIS from
inspecting the ciphertext.

Two of those samples make the codec gap concrete (both are recovery goals, *neither*
is an honest-negative): puzzle `two` (`research/data/practice-puzzles/two`, formerly
`/tmp/gak_example_two`; 698 symbols over a 12-letter alphabet `{A..L}`, near-flat
marginal) is a maintainer-held **English** cleartext that is deliberately **not
committed** (so the engine cannot be tuned to it; embed as a checked-in test constant
only once a human confirms it); puzzle `one` (`research/data/practice-puzzles/one`,
formerly `/tmp/gak_cipher_example`; 266 symbols over `{0..4}`; every one of the 265
transitions is ±1 mod 5, an observed walk on the pentagon C5) is an **external**
sample **hypothesized** to decrypt to English — we do **not** currently hold its
ground-truth cleartext, so any surviving candidate is a labelled HYPOTHESIS, never an
established decode. Both samples share one obstacle: a 5- or 12-symbol alphabet
**cannot** carry 26–29-letter English under a *direct* symbol→letter substitution, so
recovery requires the missing **codec / transduction layer** to widen the alphabet
first (decrypt → codec → mapping → text). The sole **honest-negative** in these
briefs is the **eyes** (decode BLOCKED on the unknown symbol→meaning mapping) — the
engine must load them, confirm round-trips, and correctly surface nothing.

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
| God-files | `gak_attack.rs` 8,147 lines; `report.rs` 5,694 lines (31% of crate in 2 files) | 06, 07a, 07b |
| `report.rs` is a coupling hub | 23 hand-written `format_*_error` + 27 `print_*_report` public entry points (plus ~140 private render helpers); imports 27 sibling modules | 06 |
| Per-experiment boilerplate | 22 `Config` + 24 `Args` + 22 `From<Args>` + 28 `run_*` CLI dispatchers in `main.rs` ≈ 4 scattered edits per experiment | 05, 08 |
| Duplicated null scaffolding | `fisher_yates` is centralized, but ~20 modules re-implement the matched-null orchestration around it | 05 |
| No data ingest | the only non-test `fs` use writes candidate records (no `stdin` path at all); nothing loads an external ciphertext | 03 |
| No mapping search | `cipher_attack` only scores declared mappings; no hill-climb/anneal | 04 |
| No codec / transduction | nothing widens a small cipher alphabet to a language alphabet; the honeycomb base-5→`0..=82` regrouping (`orders.rs`) is unimplemented as a reusable layer | 04a |

**Validation corpus (the engine's external test suite).**
`research/data/practice-puzzles/` (see its `README.md` for the verified
inventory table) holds seven external samples believed decryptable to English. It is
the credibility ladder for the solve engine — not the goal; the **eyes** stay the
primary end goal and sole honest-negative. The corpus splits by capability:
`three`/`four`/`five`/`seven` are **letter substitution** (mapping search, brief 04);
`one`/`two`/`six` need the **codec** to widen a small alphabet before any mapping can
carry English (brief 04a). Every "mode" is a structural HYPOTHESIS, not a confirmed
identification, and no ground-truth cleartext is committed (so the engine cannot be
tuned to any answer).

---

## Target architecture (the shared spine)

Six small abstractions, introduced incrementally. **Names are proposals; verify
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

The associated `Key` does **not** outright forbid trait objects — you *can* name a
`dyn Cipher<Key = …>` by binding the associated type — but binding it pins one key
type, so any single trait object represents only **one family's** key and gives no
heterogeneous dispatch across the families. So heterogeneous search uses a
dispatch enum instead (pick the cleanest of these in brief 02):

```rust
pub enum AnyCipher { Caesar(CaesarKey), Vigenere(VigenereKey), /* ... */ Gak(GakKey) }
impl AnyCipher { fn encrypt(&self, pt: &[Glyph]) -> Result<Vec<Glyph>, CipherError>; fn decrypt(...) ; }
```

**Hypothesis-space breadth (general classical, not just GAK).** The solve engine is
a general classical-cipher cracker, so the families it ranges over (broadened in
brief 04 from the GAK-centric seven; brief 02's enum stays as-is and 04 extends it)
are:

- **Monoalphabetic substitution** — in this engine this *is* the symbol→letter
  **mapping search** run with an `Identity` cipher. Searching the mapping over a
  letter alphabet recovers a substitution, so `three`/`four`/`five`/`seven` fall out
  of the existing mapping search **once** ingest handles letter alphabets +
  transparent symbols. Mostly an enablement, not a new family.
- **Polyalphabetic** — `Vigenère` is already a family and stays; keyed/periodic
  polyalphabetic is covered by the Vigenère key search.
- **Transposition** — a **NEW** family (route/columnar). It permutes *positions*,
  not symbols, so it needs its own key search (period / column permutation) and a new
  `AnyCipher` variant (added in brief 04 as part of the broadened scope; brief 02's
  enum itself is untouched). **Honest note:** no current corpus puzzle looks like
  transposition (the letter puzzles preserve word boundaries ⇒ substitution), so it
  is included for general coverage and marked lower-priority / no-current-instance.
- **The GAK families** stay — the eyes, plus `one`/`two` via the codec.

**Mapping-invertibility nuance (the pipeline handles both).** For letter
substitution the cipher alphabet ≤ language alphabet, so the mapping is
**injective ⇒ invertible** and a *mapping* round-trip DOES exist (an extra gate). For
the eyes (83→29) the mapping is **many-to-one ⇒ non-invertible**, no mapping
round-trip can exist, and held-out scoring + the matched null carry the load. Do not
assume one case universally.

### 2. `Sequence` ingest — one way in (brief 03)

```rust
// crate::core (or crate::glyph)
/// Pure parse — no I/O. The unit-testable core.
pub fn parse_sequence(text: &str, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;
/// I/O wrapper: reads a path/file, then delegates to parse_sequence.
pub fn load_sequence(input: Input<'_>, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;
pub enum Input<'a> { Str(&'a str), Path(&'a Path) }
// `SequenceLayer<'_>` carries a lifetime: its `CipherAlphabet { alphabet, transparent }`
// variant borrows an `&Alphabet` + `&TransparentSet`; the two eye layers are alphabet-free.
```

`ParsedSequence.glyphs` is the `Vec<Glyph>` cipher stream; `.transparent` records the
passed-through spaces/punctuation positions (see §"Transparent symbols" below).

Parses digit/glyph strings (the `0..4` + `5`-delimiter convention, and the 83-symbol
honeycomb layer) into the existing `Glyph` sequence type. This is the missing
front door: today the only data source is the embedded `corpus`. The parser is
**pure** (no I/O) so it never reads global stdin; **reading stdin is the CLI's
job** — `main.rs` slurps stdin to a `String` when no positional arg / `--input-file`
is given, then calls `parse_sequence`.

**Transparent symbols (spaces & punctuation).** The letter practice puzzles preserve
word boundaries and punctuation — a strong crib. A sequence may therefore contain
**transparent symbols** (space, punctuation, newline) that are NOT cipher symbols:
ingest (brief 03) preserves them and records their positions, separate from the
cipher-symbol stream, rather than rejecting them as `InvalidToken`. The cipher /
codec / mapping operate **only on the cipher symbols**; transparent symbols pass
through unchanged and are reinserted at their positions into `rendered_text` (brief
04). Scoring is letters-only — `crate::language`'s `normalize_text` already strips
non-letters (`language.rs:192-213`), so transparent symbols are skipped for scoring
but kept for readability. This passthrough is plumbing, not a decode.

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
pub struct Candidate {
    cipher: AnyCipher,                 // winning family + key (brief 02)
    decrypted_symbols: Vec<Glyph>,     // cipher-layer output; cipher symbols, NOT language; pre-codec
    crypto_round_trip_ok: bool,        // encrypt(key, decrypted)==ciphertext; proves cipher/key only
    codec: AnyCodec,                   // transduces decrypted_symbols → mapping domain (brief 04a); Identity when cipher alphabet ≥ language alphabet (the eyes)
    mapping: Mapping,                  // symbol→language-index; for the eyes (83→29) many-to-one ⇒ non-invertible
    rendered_text: String,             // mapping.apply(codec.transduce(decrypted_symbols)) → text; for verbatim logging
    score: f64,                        // in-sample bigram log-likelihood (search objective; overfit-prone)
    heldout_mapping_score: f64,        // mapping fitted on a train fold, scored on a disjoint held-out fold
    null_mean: f64, beats_null: bool,  // matched-null guard (informational, never a "decode")
}
pub fn solve(req: &SolveRequest) -> Result<Vec<Candidate>, SolveError>;   // ranked; three independent gates
```

Phase 2 adds the **mapping search** (hill-climb / simulated annealing over
symbol→letter), the missing capability. The full pipeline is **decrypt → codec
(transduce) → mapping → text**: `rendered_text =
mapping.apply(codec.transduce(cipher.decrypt(key, ciphertext)))`. The codec stage
(brief 04a) widens a small cipher alphabet to the language alphabet; it is
`AnyCodec::Identity` when the cipher alphabet already spans the language (the
**eyes**, 83 symbols). The proof it works is a synthetic plant-through-codec
positive control (known English → inverse codec → known cipher → ciphertext;
`solve` recovers key + codec + mapping). The external small-alphabet samples
remain **English-recovery targets owned by brief 04a**: puzzle `two`
(`research/data/practice-puzzles/two`; maintainer-held English, deliberately not
committed; once a human confirms it, the criterion is recovering a held-out-validated
candidate that matches the known cleartext) and puzzle `one`
(`research/data/practice-puzzles/one`; English hypothesized, no cleartext yet; any
surviving candidate is logged as a labelled HYPOTHESIS, never a hard-coded decode);
puzzle `six` is the clearest base-N-grouping codec case and also exercises
transparent-symbol passthrough. The sole
**honest-negative** — the **eyes** — must correctly surface nothing. Three concepts
are never conflated — decrypted cipher symbols, the transduced codec output, and the
(possibly many-to-one / non-invertible) symbol→letter mapping into rendered text —
and there are **three independent gates** plus a codec round-trip:
`crypto_round_trip_ok` (cipher/key consistency only, not a decode proof),
`heldout_mapping_score` (mapping confidence via held-out scoring — the analogue of
round-trip for the many-to-one eye mapping, where no mapping round-trip can exist),
and `beats_null` (matched-null overfit guard); an invertible codec adds a
`codec_round_trip` check (re-expand + re-encrypt must reproduce the ciphertext).

### 6. `trait Codec` — widen the alphabet so small ciphers can carry English (brief 04a)

```rust
// crate::codec
pub trait Codec {
    fn transduce(&self, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError>;
    fn output_alphabet_size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn is_invertible(&self) -> bool;
}
pub enum AnyCodec { Identity, FixedGrouping(GroupingCodec), Delta(DeltaCodec) }
```

The codec regroups/transduces the **decrypted** cipher-symbol stream into a
(usually larger) value alphabet, so a symbol→letter mapping can span a
natural-language alphabet. This is the layer that lets a *small* cipher alphabet
(5 digits, 12 letters) carry English: a direct substitution cannot (5 < 26,
12 < 26); a grouping/transduction first widens the alphabet. The eye honeycomb
reading layer (base-5 trigrams → `0..=124`, accepted `0..=82`; `orders.rs`) is the
canonical instance — `Identity` covers the eyes, where the alphabet is already
wide enough; `FixedGrouping` generalizes the honeycomb (group `group_len` base-`b`
digits); `Delta` captures the ±1-walk structure observed in puzzle `one`
(`research/data/practice-puzzles/one`).
The codec sits **between** decrypt and mapping in the solve pipeline (§5); brief
04a designs both the declared (`Fixed`) and searched (`Search`) codec families and
the codec round-trip gate. See brief 04a (depends on 04).

### Target module layout

Group the 32 flat `pub mod`s in `lib.rs` (`src/lib.rs:72-103`) into role directories
(the repo-wide role-dir move is **brief 07B**; the `gak_attack.rs` god-file split
into `gak/` is **brief 07A**):

```
src/
  core/         glyph, trigram, sequence/ingest, alphabet      (data primitives)
  data/         corpus, generator
  analysis/     analysis, isomorph, grouping, chaining, chaining_graph,
                perfect_isomorphism, honeycomb, orders   (shared structural primitives)
  nulls/        null + the matched-null harness; isomorph_null, zero_adjacency_null,
                dof_null, pipeline_null, tree_residual, perseus
  ciphers/      mod.rs — today's ciphers.rs verbatim (trait + AnyCipher land in it
                via brief 02); a thin 07B move, contents unchanged
  codec/        the Codec trait + AnyCodec (brief 04a)
  attack/       cipher_attack, agl_gak, gak/ (split from gak_attack.rs), solve/
  experiments/  periodicity, conditional_structure, modular_diff,
                orientation_homogeneity, transitivity, pyry_conditions, controls
                (the structural-battery experiment drivers, each impl Experiment)
  report/       mod.rs — today's report.rs (a thin 07B move); the report god-file
                dissolve is brief 06, not 07B
  main.rs       thin CLI over an Experiment registry (brief 08)
```

Each module appears in exactly one directory, assigned by primary role; an
experiment-vs-analysis-ambiguous module is placed by primary role and may be
re-homed when brief 08 wraps it as `impl Experiment`.

For `ciphers/` and `report/`, **brief 07B is a thin move only**: `ciphers.rs →
ciphers/mod.rs` and `report.rs → report/mod.rs` with contents unchanged. 07B does
**not** split families: the one-file-per-family split of `ciphers.rs` is a
**deferred** follow-up (a future brief-02 extension, owned by no current brief),
and the `report.rs` dissolve into per-report renderers is owned by **brief 06**.

---

## The briefs & sequencing

| # | Brief | Tier | Depends on | Size |
| - | ----- | ---- | ---------- | ---- |
| 01 | [Golden-master safety net](01-golden-master-safety-net.md) | **prereq** | — | M |
| 02 | [`Cipher` trait + `ciphers.rs` refactor](02-cipher-trait.md) | 1 | 01 | M |
| 03 | [External-ciphertext ingest](03-external-ingest.md) | 1 | 01 | S |
| 04 | [Solve pipeline + mapping search](04-solve-pipeline.md) | 1 | 02, 03 | **L** |
| 04a | [Codec / transduction layer](04a-codec-transduction.md) | 1 | 04 (02, 03, 01) | **L** |
| 05 | [Null / experiment harness dedup](05-null-experiment-harness.md) | 2 | 01 | **L** |
| 06 | [Dissolve `report.rs` + error `Display`](06-dissolve-report.md) | 2 | 01 (05 helps) | M |
| 07a | [Split `gak_attack.rs` god-file](07a-split-gak-godfile.md) | 2 | 01 (coordinates with 04) | M |
| 07b | [Role-directory module layout](07b-role-directory-layout.md) | 2 | 01 (07A; 02–06/08) | M |
| 08 | [CLI registry + args dedup](08-cli-registry.md) | 2 | 06 (02/05 help) | M |

**Recommended order:**
`01 → 03 → 02 → 07A → 04 (Phase 1/2) → 04a → then 05, 06, 08 → and only at the very end 07B.`

- `01` first, always — it is the safety net every other brief leans on.
- `03` before `02` (small, independent; `04` needs ingest).
- `07A` before `04` — splitting `gak_attack.rs` first gives `04` a clean
  `crate::gak_attack::marginalization::*` / `solver::*` seam to import the beam
  search.
- `04` after `02` + `03` + `07A`. It is a Large end-goal item and the
  highest reward; do not start it until those are green.
- `04a` after `04` — the codec/transduction layer extends `04`'s solve pipeline
  and mapping search; it is what lets the small-alphabet samples (puzzles `two`,
  `one`, `six` in `research/data/practice-puzzles/`) carry English. Also Large.
- `05` / `06` / `08` are the maintainability track (`08` after `06`).
- `07B` **dead last** — the repo-wide role-directory move is high-conflict and
  mostly cosmetic; do it only after the engine + maintainability tracks have
  settled.

The end-goal track (`03 → 02 → 07A → 04 → 04a`) and the maintainability track
(`05`, `06`, `08`) touch mostly different files and can be staffed concurrently on
separate branches. The historic conflict point — `gak_attack.rs` (brief 04 may
reuse its beam-search) — is resolved by sequencing `07A` (which splits it) before
`04` on the same branch, or coordinating explicitly.

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
  "multi-digit `0..=124` tokens." It also returns `ParsedSequence` (glyphs +
  transparent marks), **not** a bare `Vec<Glyph>` — the §2 sketch above reflects
  that.
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
