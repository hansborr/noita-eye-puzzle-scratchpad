# Architecture

This document describes the as-built architecture of `noita-eye-puzzle`: a Rust
command-line workbench for analyzing — and attempting to decode — the **Noita
eye-glyph puzzle**, a set of nine eye-symbol sequences hidden in the game.

It is a map of what exists today, for a reader who wants to understand the
codebase before changing it. For research status and the strongest defensible
claim, see `README.md`.

## The two glyph layers

Two representations of the data are kept strictly distinct, and conflating them
is the classic way to manufacture a false signal:

- The **storage / engine layer** is how the game stores the messages: base-7 over
  64-bit integers, with symbols in `-1..5` where `5` is a row delimiter. The
  decoder for this layer lives in `data/generator.rs`, which re-derives the
  messages and cross-checks `data/corpus.rs` byte-for-byte.
- The **reading layer** is the honeycomb interpretation: base-5 trigrams of
  rendered orientations `0..4`, giving values `0..124`, of which 83 are actually
  used. `core/trigram.rs` is this layer; `analysis/orders.rs` reconstructs the 2D
  glyph grids and reads them under documented order families.

`core/glyph.rs` provides the opaque `Glyph` (a `u16` index into an `Alphabet`,
deliberately not a closed enum) and the `Sequence` type. `core/ingest.rs` is the
external-ciphertext front door: a pure `parse_sequence` plus a thin
`load_sequence` wrapper, so the library never touches global stdin.

## Source layout: grouping by role

Source lives in `src/`, grouped into role directories: `core/`, `data/`,
`analysis/`, `nulls/`, `ciphers/`, `attack/`, `experiments/`, and `report/`. The
grouping is **organizational, by role** — it is not a module-path hierarchy.

Be precise about the module graph as it stands today: almost every leaf module is
declared **flat at the crate root** and redirected into its role directory with a
`#[path = "..."]` attribute in `src/lib.rs`. So `analysis/chaining.rs` is the
module `crate::chaining`, not `crate::analysis::chaining` — the directory tells
you the file's *role*; the crate path stays flat. For example:

```rust
#[path = "analysis/chaining.rs"]
pub mod chaining;        // public path: crate::chaining
#[path = "nulls/null.rs"]
pub mod null;            // public path: crate::null
#[path = "attack/keystream.rs"]
pub mod keystream;       // public path: crate::keystream
```

Two role directories are genuine directory modules (declared without `#[path]`,
with a real `mod.rs`): `ciphers/` is `crate::ciphers`, and `report/` is
`crate::report`. A handful of flat modules do own nested submodules — notably
`crate::gak_attack` (with `solver`, `generator`, `marginalization`, `eyes`,
`error` under it) and `crate::solve` (with `search`, `eval`, `record`, `types`,
`codec_search`) — so paths like `crate::solve::search` are real. The thing that
does **not** exist is an `analysis::` / `nulls::` / `experiments::` namespace
layer over the leaf modules.

Roughly, the roles are:

| Directory       | Role                                                                    |
| --------------- | ----------------------------------------------------------------------- |
| `core/`         | alphabet + glyph/sequence types, base-5 reading layer, ingest front door |
| `data/`         | the verified nine-message corpus and the engine base-7 decoder          |
| `analysis/`     | encoding-agnostic statistics + structural analyses (orders, isomorphs, chaining, grouping, honeycomb) |
| `nulls/`        | matched-null distributions, the DoF-calibrated null driver, shared held-out helpers |
| `ciphers/`      | candidate-cipher primitives with exact round-trip controls              |
| `attack/`       | cipher attacks, language models, codec layer, and the solve/keystream/ragbaby pipelines |
| `experiments/`  | the structural-battery experiment drivers                               |
| `report/`       | CLI report rendering and domain-error formatting                        |

## The recurring per-module shape

Most analysis, null, experiment, and attack modules follow the same internal
skeleton, which is worth recognizing once:

1. **Config / error types.** A `*Config` struct (seed, trial counts, search
   bounds) with documented `DEFAULT_*` constants, and a module-local error enum.
   Edge cases surface as `Result`, never panics or silent failures.
2. **Result structs.** Plain data describing what was measured — the headline
   statistic, the null band, gate verdicts — with no presentation logic.
3. **A `Report` render block.** The result struct implements
   `crate::report::Report` (`fn render(&self) -> String`), colocated with the
   computation so the numbers and their prose stay together.
4. **The compute path.** A `run_*` entry point taking the config and returning
   `Result<SomeReport, SomeError>`.
5. **Nulls / controls.** The matched null (typically a within-message shuffle)
   and, where relevant, a positive control proving the tool fires on real signal.
6. **Tests.** Pinning the headline numbers, determinism, and the control behavior.

### Shared infrastructure

- **Null harness (`crate::null`).** Home of the in-crate `SplitMix64` PRNG —
  deterministic, seed-only state, kept for reproducible null models rather than
  because crates.io is unavailable. It also provides the shuffle/permutation
  primitives (`fisher_yates`, `shuffled_permutation`), seed mixing, and add-one
  p-value helpers that the matched nulls across the crate reuse. `crate::dof_null`
  layers a calibrated adaptive null over researcher degrees of freedom (traversal,
  grouping, headline-statistic choice).
- **Held-out helpers (`crate::heldout`).** The alternating held-out fold
  extraction and the matched-null full/held-out aggregation that the survival
  gates share, so the generalization check always compares fold-against-fold (not
  fold-against-full-stream, an earlier bug centralized away here).
- **Report rendering (`crate::report`).** The `Report` trait plus shared
  formatters (probabilities, histograms, percentages, spans). The CLI stays thin:
  uniform experiments flow through one generic `dispatch`/`emit` pair that runs a
  config, then either renders the report to stdout or prefixes the error to
  stderr.

## Attack pipelines

Four attack pipelines live under `attack/`. Each is search-and-score, and each
gates its output so an in-sample score can be told apart from a genuine recovery.
The shared gates are a cipher-layer round-trip, a matched-null overfit bar, and a
held-out fold that must generalize fold-vs-fold.

- **`solve` — the unified solve pipeline.** Enumerates a hypothesis space
  (cipher family × codec × symbol→letter mapping), decrypts, and scores against
  English/Finnish n-gram models. A `codec` transduction layer (`attack/codec.rs`)
  can widen a small cipher alphabet by grouping digits, with every pruned codec
  logged rather than silently dropped. Every emitted `Candidate` carries the three
  gates above, and `candidate_survives` requires all three. On the real eyes the
  pipeline runs end-to-end; it currently surfaces no surviving candidate, and each
  run logs a candidate record.
- **`gak_attack` — the GCTAK go/no-go gate.** Generates **synthetic** Group-
  Ciphertext-Autokey ciphertext whose key it holds and proves an extended-chaining
  solver recovers the key at a rate that clears a documented floor *and* beats a
  matched within-message shuffle null — a true positive control. The single unit
  that touches the real corpus (`gak-attack-eyes`) runs that matured solver
  against the eyes under matched nulls. Synthetic ground truth does not transfer
  to the eyes, and the module says so in its output.
- **`keystream` — polyalphabetic cracker for the practice letter-puzzles.** Four
  keystream families (Vigenère, Beaufort, plaintext-autokey, ciphertext-autokey)
  over letter indices, with an annealed multi-restart key search scored by the
  quadgram model. Survival requires clearing **two** complementary nulls — a
  matched null (reruns the search on shuffled ciphertext, catching search
  overfit) and a random-key null (catching the ciphertext-autokey key-independence
  leak) — plus a held-out fold.
- **`ragbaby` — keyed-alphabet (non-keyword Ragbaby) cracker.** Recovers the
  keyed alphabet via simulated annealing with basin-hopping, gated against a
  matched null and a held-out fold, and ships a planted-recovery positive control
  that demonstrates the cracker works at a given length.

The practice letter-puzzles that these last three pipelines attack are **external
practice samples**, not the eyes; they exist to validate the tooling end-to-end on
material whose structure is known.

## The command-line interface

`src/main.rs` is intentionally thin: `clap` owns argument parsing and usage text,
and all logic lives in the library so it stays testable. Each subcommand builds a
config, calls a library `run_*`, and renders the returned report. The binary is
`noita-eye`; the structural battery, null tests, controls, and attack pipelines
each have their own subcommand (see `README.md` for the full list).

## Extension points

Where new work goes, and what discipline applies to it:

- **A new CLI subcommand.** Add a `Command` variant and its `*Args` in
  `src/main.rs`, build a config, call a library `run_*`, and render the returned
  `Report`. Add a golden-master fixture for the new stdout (see Guardrails).
- **A new analysis or experiment.** Add a module under the matching role
  directory and wire it into `src/lib.rs`, following the recurring per-module
  shape above (config/error → result structs → `Report` render → `run_*` → tests).
- **Reading or importing external data.** `core/ingest.rs` is the front door for
  external ciphertext; report rendering and shared formatters live in `report/`.
- **Nulls and controls — scoped to claims.** An analysis whose output *asserts
  something about the eyes* pairs its statistic with a matched null and, where a
  ground truth exists, a positive control. General-purpose tooling that makes no
  claim about the eyes — parsers, exporters, format converters, community-facing
  utilities — does not need a null to earn its place.

## Guardrails

Correctness is enforced mechanically rather than by convention. The piece worth
describing here, because it shapes the test layout, is the **golden-master
harness**: `tests/golden_master.rs` runs the compiled binary across the
subcommand surface and asserts its stdout/stderr byte-for-byte against checked-in
fixtures under `tests/golden/`. A fixture change is a behavior change to review
line-by-line, never blindly regenerated; the regeneration recipe is recorded in
the test file itself.

The rest — the `unsafe`-forbidden lint wall, the file-size ratchet, and the
`cargo-deny` / `cargo-machete` supply-chain gates — is catalogued in the AGENTS.md
guardrail map and run by `make verify` / `make check`.
