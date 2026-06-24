# noita-eye-puzzle

A Rust workbench for **trustworthy** analysis of the **Noita eye-glyph puzzle** —
the sequences of eye symbols hidden in the game that are widely suspected to
encode something and that the community has not conclusively cracked.

The aim is cryptanalysis that *constrains the hypothesis space* and *computes the
null distributions the community never did*, rather than making premature claims
about what the glyphs mean. Every statistic is paired with a null or a positive
control so a negative result is meaningful rather than a blind spot.

## Status

The analysis library and a nine-experiment investigation are complete, tested,
independently reviewed, and gate-green. The crate is **`std`-only** (an in-crate
`SplitMix64` PRNG; no external crates — crates.io was unreachable at init and the
design stayed dependency-free). The corpus is **real and verified** — see below.

## The strongest defensible claim

> The eye data is **deterministic, engine-generated, strikingly structured data
> of unknown meaning**. Under the honeycomb reading order (`standard36-u012-d012`)
> it shows **no recoverable simple-cipher signal**. The puzzle is **unsolved**;
> no primary developer source confirms it encodes recoverable plaintext.

Nothing in this repo prints anything stronger. See [Results](#results).

## The data is real (Experiment 0)

`src/corpus.rs` holds the nine real eye messages with provenance. A test
independently re-derives the engine base-7 decode from Xkeeper0's `[u32, u32]`
integer pairs and asserts it equals the ngraham20 transcription **byte-for-byte
for all nine messages**. Vendored raw inputs live in
`research/data/eye-messages/` (`ng_eyes.json`, `xk_eye.php`). Transcription is the
single biggest risk in this kind of work, so it is cross-validated, not trusted.

## Layout

Two glyph layers are kept strictly distinct: the **storage/engine** layer (base-7
over 64-bit integers, symbols −1..5, `5` = delimiter) and the **reading** layer
(base-5 trigrams of orientations 0–4 → values 0–124, of which 83 are used).

```
src/
  glyph.rs        Orientation 0–4 + delimiter; StorageSymbol −1..5; generic Glyph/Alphabet
  trigram.rs      base-5 reading layer (trigram values 0–124)
  generator.rs    engine storage-layer base-7 decode (cross-checks the corpus)
  corpus.rs       the nine verified eye messages + provenance
  analysis.rs     frequencies, Shannon entropy, index of coincidence, n-grams, chi-square
  orders.rs       grid reconstruction; honeycomb walk + standard36 family; per-order stats
  null.rs         standard36 reading-order null (SplitMix64, Wilson intervals)
  dof_null.rs     calibrated adaptive null for traversal/grouping/statistic researcher DoF
  pipeline_null.rs  Exp 2 — base-7 generation-pipeline artifact null + negative control
  isomorph.rs     first-occurrence pattern-signature isomorph detector
  isomorph_null.rs  Exp 7A — within-message shuffle null for isomorph structure
  perseus.rs      Exp 7C — Perseus shared-region recurrence null
  periodicity.rs  Exp 5A — IoC-by-period / autocorrelation / Kasiski vs a random null band
  chaining.rs     Exp 7B — alphabet-chaining success/fail signatures
  grouping.rs     Exp 8 — base-N grouping comparison + independent state-count estimate
  controls.rs     Exp 11 — positive controls on monoalphabetic + polyalphabetic ciphers
  language.rs     Exp 5B-1 — English/Finnish n-gram language scorer (calibrated)
  ciphers.rs      Exp 12 — candidate cipher primitives (+ inverses, round-trip tested)
  cipher_attack.rs  Exp 12 — attack/language-scoring/null harness with a positive control
  main.rs         thin std-only CLI (`noita-eye`)
```

## CLI

```sh
cargo run -- demo                  # analysis on the verified nine-message corpus
cargo run -- stats <sequence>      # freq / entropy / IoC for rendered digits 0–4
cargo run -- orders                # reading-order audit + Experiment 4 flatness
cargo run -- nulltest      [--seed <u64>] [--trials <n>]    # Exp 1B multiple-comparisons null
cargo run -- dofnull       [--seed <u64>] [--trials <n>] [--calib-trials <n>]
                                                                 # calibrated researcher-DoF null
cargo run -- pipelinenull  [--seed <u64>] [--trials <n>]    # Exp 2 generation-pipeline null
cargo run -- periodicity   [--seed <u64>] [--trials <n>] [--max-period <n>] [--max-lag <n>]
cargo run -- isomorphnull  [--seed <u64>] [--trials <n>]    # Exp 7A shuffle null
cargo run -- chaining      [--seed <u64>] [--trials <n>] [--min-period <n>] [--max-period <n>]
cargo run -- perseus       [--seed <u64>] [--trials <n>]    # Exp 7C recurrence null
cargo run -- grouping                                       # Exp 8 grouping + state-count
cargo run -- cipherattack  [--seed <u64>] [--samples <n>] [--null-trials <n>]
cargo run -- controls monoalphabetic [--seed <u64>]         # Exp 11 positive control
cargo run -- controls isomorph       [--seed <u64>]         # (alias: polyalphabetic)
```

## Results

Each experiment pairs a measurement with a null or a positive control. The
decryption/cipher findings are uniformly **negative** for the eyes and
**positive** for the calibration controls — i.e. the tools provably fire on known
signal, and the eyes do not light them up. The strongest positive structural
result remains the bounded 83-state reading-layer support under the fixed
standard36 null. The broader researcher-DoF correction does **not** deflate that
headline: the empirical adaptive min-p run is finite-resolution and floor-censors
the eyes, while the analytic multiplicity correction remains astronomically
small.

- **Exp 4 — frequency/entropy/IoC across orders.** Per-symbol frequency is flat
  (reproduces the community IoC ≈ 1.066, mean frequency 12.48); the honeycomb
  order is the only standard36 order fully inside 0–82. Flat frequency **rules out
  monoalphabetic substitution**; it does not rule a real message *in*.
- **Researcher-DoF adaptive null.** `dofnull` calibrates each
  traversal/grouping/statistic cell to its own calibration-set random-grid
  marginal tail, then scores both the eyes and an independent resampling set
  against that same external reference before taking the best min-p across the
  configured search space (57 traversals, 5 groupings, 4 statistics; 916 valid
  cells after engine-storage skips). With seed 12345, 1000 calibration trials,
  and 1000 resampling trials, the eyes' min marginal p is at the calibration
  floor (`1/1001`), but 199/1000 resampling grids also reach an equally small
  calibrated min-p somewhere in the configured search. The add-one adaptive
  p-value is **200/1001 = 0.199800**, Wilson **0.176198..0.225697**, effective
  comparisons ≈ **173**. This is a finite-resolution diagnostic: with only 1000
  calibration grids, any cell smaller than `1/1001` is censored up to that floor,
  so the 0.199800 value measures floor hits times look-elsewhere multiplicity,
  not the probability of reproducing the eyes' contiguity. The accepted
  honeycomb trigram contiguous-0..=82 cell has analytic per-order bound
  `(83/125)^1036 = 5.836e-185`; correcting over all 1140 configured
  traversal×grouping×statistic cells gives Bonferroni/Šidák ≈ **6.653e-182**,
  and correcting over the empirical effective comparisons gives ≈
  **1.010e-182**. Resolving that empirically would require about **1.7e184**
  calibration draws, so the analytic correction is the honest headline result:
  the bounded 0..=82 anomaly **survives** the configured DoF correction.
- **Exp 5A — periodicity / autocorrelation.** No period or lag clears a random
  null band, beyond the order-contingent distance-4 spike (honestly reconciled
  with Exp 1B's targeted distance-4 result; family-wise vs pointwise).
- **Exp 7A — isomorph shuffle null** (the null the community never computed). The
  eyes carry **no isomorph structure beyond a within-message shuffle of their own
  symbols**.
- **Exp 7B — alphabet chaining.** The eyes match the **known-fail signature** of
  data with unrelated alphabets, not the known-succeed Vigenère signature (for the
  additive-relationship model).
- **Exp 7C — Perseus recurrence null.** Operationalized as same-offset shared
  runs of length ≥2 in the earliest leading-family alignment or an East/West
  counterpart pair, the eyes have **0/185** non-shared→later-shared recurrences.
  With seed 12345 and 1000 within-message shuffles, the add-one lower-tail
  p-value is **7/1001 = 0.006993**. This corroborates a structural
  permutation-cipher direction, but it decodes nothing.
- **Exp 8 — grouping + state count.** No grouping (single/pairs/trigrams/
  tetragrams/storage) is both alphabet- and entropy-compatible with a natural
  language. An independent collision estimator (calibrated on known-N ciphers,
  *not* assuming 83) puts the state count at ≈ 73–90 — **~83 genuine near-uniform
  states, no hidden smaller alphabet**.
- **Exp 12 — candidate ciphers.** Caesar, Vigenère, incrementing-wheel,
  Chaocipher, and an S₈₃ deck cipher, scored against English/Finnish under several
  *guessed* (unverifiable) symbol→letter mappings, yield **no decryption above
  chance**; the only excesses are tiny pointwise tails reflecting the eyes' known
  mild structure, ~21–293× below a plant the same harness recovers.
- **Positive controls.** Exp 11 (solved monoalphabetic + polyalphabetic ciphers),
  Exp 5B-1 (English-vs-Finnish discrimination), and the Exp 12 plant all confirm
  the tooling recovers known signal — so the eye negatives are meaningful.

**Caveat:** `dofnull` now resamples the configured
traversal/grouping/statistic researcher degrees of freedom instead of leaving
that as an unmodeled caveat. It is still finite-resolution Monte Carlo
(default marginal floor `1/(calib-trials+1)`) and a configured search space, not
a proof over every imaginable post-hoc analysis. For sub-floor effects like the
bounded-contiguity headline, use the printed analytic DoF-corrected bound rather
than the empirical floor diagnostic. It supports "structured data of unknown
meaning," not "decoded message."

## Commands

```sh
make verify   # correctness gate: fmt + clippy(-D) + tests + rustdoc(-D) + cargo-deny
make check    # verify + cargo-machete + codespell + shellcheck + release build (full local CI)
make setup    # install the git pre-commit hook
```

`make check` (or at least `make verify`) must be green before every commit.

## Guardrails

- **`unsafe` is forbidden** (`unsafe_code = "forbid"`).
- **No panics / silent failures** in library/CLI code (`unwrap`/`panic`/
  `indexing_slicing`/`unused_results` are `-D warnings`; relaxed in tests).
- **Every public item documented** (`missing_docs`); doc examples compile
  (`RUSTDOCFLAGS="-D warnings"`).
- **Clippy `all` + `pedantic`** as `-D warnings`; **`rustfmt`** enforced;
  **pinned toolchain** (Rust 1.96.0); **`--locked`** everywhere.
- Supply chain gated by `cargo-deny` + `cargo machete`; CI runs the full gate.

See `AGENTS.md` for the full working agreement and `HANDOFF.md` for the
experiment-by-experiment record.

## License

Dual-licensed under MIT or Apache-2.0.
