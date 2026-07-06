# 07 — Bridge: how the findings map onto this Rust workbench

This research folder lives inside the `noita-eye-puzzle` Rust crate (`../src`).
This document is the index from the code-investigation plan
([05-code-investigations.md](05-code-investigations.md)) to the code that now
exists: which module implements each experiment, and the handful of items that
remain genuinely open. The plan described here has largely landed — the layered
glyph model, the verified corpus, the reading-order and generation-pipeline
nulls, the structural battery, the positive-control fixtures, and the
candidate-cipher frontier all live in `../src` today.

## Why the fit is good

The crate's stated ethos (`../AGENTS.md`) is *"trustworthy cryptanalysis:
primitives that constrain the hypothesis space, not premature claims."* The
research independently converged on the same conclusion from the opposite
direction: the community's headline results are largely artifacts of a reading
order chosen because it looked clean, and the missing ingredient across the
whole corpus was null distributions (see Experiments 1, 2, 7). The crate hosts
exactly that kind of work, and two of its rules map straight onto the research's
main warnings:

| Crate rule (`AGENTS.md`)                                  | Research finding it anticipates / how it is now satisfied                     |
| -------------------------------------------------------- | ----------------------------------------------------------------------------- |
| "Never present unverified numbers as findings."          | The corpus rested on order-selected stats with no family-wise correction; the null harnesses (Experiments 1/2/7 + the researcher-DoF correction) now supply that. |
| "Transcription is the risk… cross-check real data."      | Experiment 0: the vendored corpus is cross-checked byte-for-byte against the ngraham20 transcription for all nine messages via an independent base-7 re-decode. |
| `Glyph` is an opaque `u16`, not a closed enum.           | The rendered 0–4 + delimiter inventory is **confirmed**; the crate now carries a closed `Orientation` type while keeping `Glyph`/`Alphabet` generic (below). |

## The layered glyph model (settled and implemented)

`AGENTS.md` said to promote `Glyph` from `u16` to a closed `enum` "once the
inventory is settled." The *rendered orientation alphabet* is settled — exactly
5 displayed orientations → digits 0–4, plus 5 = row delimiter (never rendered)
[confirmed] — but that alone never justified collapsing `Glyph` itself, because
the code also has to represent the storage layer, the trigram reading values,
and future transcription corrections. The crate resolves this by encoding the
two layers as distinct types and keeping `Glyph`/`Alphabet` generic:

- **Storage/engine layer:** base-7 over 64-bit integers emitting −1..5 (5 =
  newline). Types: `core::glyph::StorageSymbol` and the base-7 decoder in
  `data::generator`.
- **Reading layer:** base-5 trigrams of the rendered 0–4 glyphs → 0–124. Types:
  `core::glyph::Orientation` (0–4) and `core::trigram::{ReadingTrigram,
  TrigramValue}` (`value()` in `0..=124`).

The generic `core::glyph::{Glyph, Alphabet, Sequence}` container remains for the
broader analysis alphabet. **Caveat, updated 2026-07-06:** the *direction* each
digit denotes (1=up, 2=right, …) is binary-verifiable from the shipped binary
(eye sprites are hardcoded in the drawing function; maintainer-confirmed
2026-07-06, independent re-extraction in this repo still pending) rather than
merely image-sourced as earlier drafts of this doc treated it. The types still
keep digit identities and deliberately do not bake pixel-direction semantics
in — the labeling is a convention no statistic in this crate depends on, not
an unknown being protected.

## Where each experiment lives now

Line numbers rot, so these cite modules and functions, not `file:line`. The
priorities mirror §"What would actually move the needle" in
[05-code-investigations.md](05-code-investigations.md); every tier below is
implemented and exercised by tests.

### Tier 1 — prerequisites and the decisive tests

| Experiment | What it establishes | Where it lives |
| ---------- | ------------------- | -------------- |
| **0 — verified corpus** | Engine decode cross-checked against the transcription, per message | `data::corpus` (integrity test `experiment_0_cross_validates_transcription_against_engine_decode`); independent base-7 decoder in `data::generator`; external-ciphertext front door `core::ingest::{parse_sequence, load_sequence}` |
| **1 — reading orders + null** | Family-wise null over the reading orders the community's `(83/125)^1036` omits | `analysis::orders` (`read`/`stats`/`context`) + the null harness `nulls::null`; the researcher-degrees-of-freedom correction is `nulls::dof_null`. Subcommands: `nulltest`, `dofnull` |
| **2 — generation-pipeline artifact** | Feeds structure-matched random 64-bit ints through the *real* base-7 decode to ask whether the reading-layer structure is a by-product of base-7 expansion | `data::generator` + `nulls::pipeline_null`. Subcommand: `pipelinenull` |

The Experiment-1 null keeps its randomness on the in-crate deterministic
`SplitMix64` PRNG, seeded from a CLI flag, so runs are reproducible and
`--locked` stays honest (per the "no hidden nondeterminism" ethos). The
Experiment-2 null is constrained to the real structure — per-message
`[u32,u32]` block count, output lengths, delimiter layout, and the "no internal
−1" property; unconstrained random base-7 noise is only a separate negative
control.

### Tier 2 — signal characterization

| Experiment | What it establishes | Where it lives |
| ---------- | ------------------- | -------------- |
| **3 — divisibility / trigram counts** | `{297,309,354,306,411,372,357,360,342}`, sum 1036, as invariants that can't regress (with the "count eyes, not delimiters" caveat) | Encoded as corpus constants + tests across `data::corpus`, `analysis::leak_ceiling`, `analysis::grouping` |
| **4 — frequency / entropy / IoC / chi-square** | How order-dependent the corpus "flatness" is | Primitives in `analysis::analysis` (`frequencies`, `shannon_entropy`, `index_of_coincidence`, `chi_square_goodness_of_fit`) run across orders via `analysis::orders::stats` |
| **5 — periodicity / Kasiski / autocorrelation; short-key brute** | Period structure; Caesar + short-Vigenère brute scored against English/Finnish models | `experiments::periodicity`; scoring in `attack::language` + `attack::quadgram`; brute-force in `attack::cipher_attack`, `attack::keystream` |
| **6 — adjacency / recurrence** | "adjacent-equal == 0" as an independent reading-order discriminator; recurrence-distance nulls | `analysis::chaining` + `analysis::chaining_graph`; `nulls::zero_adjacency_null`; the Perseus recurrence null `nulls::perseus` |

### Tier 3 — structure and candidate ciphers

| Experiment | What it establishes | Where it lives |
| ---------- | ------------------- | -------------- |
| **7 — isomorph detection + shuffle null** | Isomorphs measured against a shuffle-based null (the null was the missing contribution) | `analysis::isomorph`, `analysis::isomorph_map`, `analysis::translate_isomorph`, `analysis::perfect_isomorphism`, `analysis::isomorph_imperfection`; null in `nulls::isomorph_null`. Subcommands: `isoscan`, `isomap`, `isomorphnull`, `perfectiso`, `isomorphimperf` |
| **8 — grouping / base-N** | Internal state count estimated *independently* (not assuming 83) | `analysis::grouping` (`grouping::run_experiment8`). Subcommand: `grouping` (`groupscan` is a different tool — the D4/A4/S4 hidden-group discriminator for practice puzzle `two`) |
| **11 — solved-cipher positive controls** | Matched positive-control fixtures per tool; if the matched controls fail, an eye null is meaningless | `experiments::controls` (highest-value calibration step) |
| **12 — candidate ciphers** | Incrementing-wheel / Chaocipher / S₈₃ deck implementations — the research frontier, not verification | Primitives in `ciphers::{mechanics, keys_gak, transforms}`; deck-cipher machinery in `attack::gak_attack` (`lymm_deck/`, `generator/`, `solver/`, `hidden_state_solver/`), plus `attack::agl_gak`. The completed GAK campaign is written up in [gak-threads/](gak-threads/) |

## Still open (genuinely remaining work)

Most of the original plan has landed. Two items remain, and both are gated on
*external* inputs rather than on unwritten Rust:

- **Experiment 9 (seed-invariance) — the byte-for-byte cross-seed diff.** The
  repo owner reports, from direct in-game observation across multiple seeds,
  that eye-message content is identical [likely → corroborated by direct
  observation], but no second-seed transcription is vendored, so the analysis
  half — a cross-seed trigram diff test — has nothing to compare against. The
  moment a second-seed transcription lands under `research/data/`, the diff test
  needs no game access; only the transcription does.
- **Experiment 10 (sprite-state clustering) — image work.** This is out of pure
  Rust scope; it is better as a small side-tool over the sprite pixels than
  inside the core crate. Not implemented.

## Honest framing to carry into the code

The strongest defensible statement (per the verification verdicts in
[03-confirmed-vs-speculation.md](03-confirmed-vs-speculation.md)) is: *"The Eye
Messages are deterministic, engine-generated, strikingly structured data of
unknown meaning; they are unsolved, and no primary developer source confirms
they encode recoverable plaintext."* A developer statement (Arvi, relayed by
FuryForged) attests that the eyes carry an *intentional* message and are "very
difficult," but discloses no cipher, key, or method — intentionality is
dev-attested; recoverable plaintext is not. The crate must never print stronger
than the statement above.
