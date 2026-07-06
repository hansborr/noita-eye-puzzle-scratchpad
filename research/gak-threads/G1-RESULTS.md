# G1 — Known-answer validation of the GAK recovery machinery

**Date:** 2026-06-26. **Thread:** G1 (validate `solve_gctak` against
externally-sourced GAK samples with known structure). **Status:** Done.

## The gap G1 closes

Before G1, the GCTAK solver
([`solve_gctak`](../../src/attack/gak_attack/solver/mod.rs)) and the chaining substrate
it consumes ([`chaining_graph`](../../src/analysis/chaining_graph/mod.rs), `compute_graph`)
had only self-generated positive controls: the synthetic fixtures in
[`generator`](../../src/attack/gak_attack/generator/mod.rs), whose ground truth the
generator itself produced. That is the weakest form of validation — the tool was
only ever shown ciphers it built. Meanwhile two practice puzzles in
[`research/data/practice-puzzles/`](../data/practice-puzzles/README.md) are
externally-sourced GAK-family ciphers but were only ever run through the
classical `solve` pipeline (Identity/Caesar/Transposition + monoalphabetic
mapping in [`solve/mod.rs`](../../src/attack/solve/mod.rs)), which structurally
cannot represent a GCTAK keystream. G1 points the GAK machinery at them.

- **`one`** (formerly `/tmp/gak_cipher_example`): 266 symbols over `{0..4}`, a `±1`
  walk on `C5` — a cyclic GCTAK (trivial hidden subgroup → bijective readout).
- **`two`** (formerly `/tmp/gak_example_two`): 698 symbols over `{A..L}`, a 12-symbol
  GAK with hidden state (the visible readout is many-valued).

## What was built

- [`src/attack/gak_attack/known_answer.rs`](../../src/attack/gak_attack/known_answer.rs)
  — a test-only (`#[cfg(test)]`) module wired into `gak_attack` that drives `one`
  and `two` through `solve_gctak` exactly as the synthetic positive controls are
  driven (parse → `glyphs/values` → `solve_gctak(ciphertext, initial_readout,
  phrase_len, group_order)`), then scores the recovered permutations and decoded
  partition against ground truth.
- Three tests: `one_recovers_c5_cyclic_gctak_keystream` (positive control),
  `one_matched_null_does_not_recover` (matched within-message shuffle null),
  `two_real_gak_dies_at_seeding_honest_negative` (honest negative + death-point
  diagnostic).
- `make verify` is green. No public API surface was added (the module is
  test-only; the only non-test change is a 1-line `mod` declaration in
  `gak_attack/mod.rs`, kept within the file-size ratchet by tightening an adjacent
  comment).

## Result on `one` — the recovery path fires (clean)

`solve_gctak`, given the true state-group order (`5`) and a genuine `C5` entry
state, recovers the cyclic-GCTAK keystream of `one` completely:

| Quantity | Ground truth | Recovered |
| --- | --- | --- |
| State group | `C5` (order 5) | order-5 permutations recovered |
| Generators (the two "letters") | `+1` cycle `{0→1,1→2,2→3,3→4,4→0}`, `-1` cycle `{0→4,1→0,2→1,3→2,4→3}` | **both present**; at `phrase_len ∈ {4,6,8}` the distinct recovered set is exactly `{+1, -1}` |
| Transitions decoded | 265 | **265 / 265** (no sentinels) |
| Keystream partition (`+1` vs `-1`) | `+1`×125, `-1`×140 | recovered partition equals ground truth byte-for-byte |

Matched null: a within-message multiset shuffle of `one` reproduced the `±1`
partition 0 / 12 times — the recovery is the `C5` Cayley structure, not the
solver always emitting two classes.

This is the first known-answer positive control for the GCTAK recovery gate, and it
passes cleanly. It validates the cyclic/GCTAK path on a real, externally-sourced
sample — not the *hidden-state* GAK machinery (which `two` shows still fails). Per
the practice-puzzle README, `one` is external and *believed decryptable to English* via
a decrypt -> codec -> mapping pipeline, with no in-repo cleartext; G1 validated the
recovered `C5` keystream/structure layer only and did not attempt the
English/codec decode.

### Honesty notes on `one`

- The recovery needs a genuine `C5` predecessor as the entry state. The solver
  always prepends `initial_readout`; if it is chosen as the first symbol itself
  (`one` starts with `4`) the prepend is a `4→4` self-loop, which injects a spurious
  fixed-point permutation. That is a *driver* artifact, not a solver defect — the
  synthetic gate likewise feeds a key-derived (genuine) readout. Using a real `±1`
  predecessor removes it.
- At `phrase_len ∈ {10,12}` the recovered list also contains a spurious non-
  bijective size-5 map (the solver keeps any completion of `len == group_order`
  without a bijectivity/dedup filter). It is harmless here — the true generators are
  matched first, so the decoded partition is still exactly correct — but it is a
  minor solver-robustness wart worth recording. The clean claim (distinct set ==
  `{+1,-1}`) is asserted only at `phrase_len ∈ {4,6,8}`.

## Result on `two` — honest negative; recovery dies at seeding

`solve_gctak` recovers zero complete permutations on `two` at every plausible
state-group order (`{6, 8, 11, 12}`) and every `phrase_len ∈ {4,6,8,10,12}`. This is
the expected, valuable negative, and the death point is precise:

- **Obstruction = hidden-state multivaluedness.** Every one of the 12 symbols has
  out-degree exactly 8 (min = max = 8). A clean GCTAK has a *bijective* readout,
  so each symbol's out-degree equals the number of letters and each `(prev, next)`
  edge belongs to a single letter. Out-degree 8 on 12 symbols is the signature of a
  non-trivial hidden subgroup (a true GAK): one visible symbol transitions to
  many next-symbols under the same letter depending on the unseen state.
- **Where it dies = the seed-cluster stage.** Replicating the solver's per-column
  seeding shows that for window lengths 4/6/8/10, 0 of the seed columns are
  forward-functional — every aligned equality-pattern column has some `prev`
  mapping to two different `next` symbols across occurrences, so every cluster is
  non-functional and is dropped *before any per-letter permutation is built*. At
  window length 12 only 3 occurrences align and the largest functional partial
  reaches size 3 (need 12), so still nothing completes. Recovery never reaches the
  permutation-completion or decode stages.
- **Not forced.** At the *wrong* order `group_order = 3`, the completer emits 6 tiny
  order-3 maps. These are wrong-structure false positives, explicitly not counted
  as a recovery (the honesty discipline: a score on the wrong structure is never a
  recovery).

This is exactly the structural limit the thread predicted: `solve_gctak` is a GCTAK
solver (trivial hidden subgroup); `two` is a real GAK whose hidden state it cannot
model. Cracking `two` would require the hidden-state machinery
([`marginalization`](../../src/attack/gak_attack/marginalization/mod.rs) / the deck
attack), not the bijective-readout GCTAK gate — and even there the measured
`(n-1)!` tractability wall (Thread 4, wave 2) would apply.

## Bottom line

The GAK recovery machinery now has its first known-answer validation on
externally-sourced data: on `one` it recovers the `C5` cyclic-GCTAK keystream
exactly (both generators, full partition, all transitions, matched null clean), so
the GCTAK gate is no longer validated only against ciphers it generated itself. On
`two` it returns a clean honest negative, dying at the seed-cluster stage because the
hidden-state readout (out-degree 8) violates GCTAK's bijective-readout assumption —
the correct, expected behaviour, not a bug. None of this touches the eyes or the
standing claim ceiling: the eyes remain unsolved and the decode remains blocked on
missing key material, a method disclosure, or known plaintext — not a fixed
symbol→meaning mapping (no such fixed mapping exists for a polyalphabetic cipher).
