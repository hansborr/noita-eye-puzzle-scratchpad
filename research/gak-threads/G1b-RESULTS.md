# G1b — Hidden-state GAK attack on practice puzzle `two`

**Date:** 2026-06-26. **Thread:** G1b (push a *hidden-state-capable* GAK attack at
`two`, the closest verifiable miniature of the eyes' blocker). **Status:** DONE —
positive control fires; **`two` is an honest negative** with a precise failure point.

## The gap G1b closes

G1 pointed the *bijective-readout* GCTAK solver
([`solve_gctak`](../../src/attack/gak_attack/solver.rs)) at `two` and reported a clean
honest negative: it **dies at seeding** because `two`'s readout is many-valued
(out-degree 8 on all 12 symbols), which violates GCTAK's bijective-readout
assumption. G1 explicitly deferred the *hidden-state* machinery
([`marginalization.rs`](../../src/attack/gak_attack/marginalization.rs)) to G1b. G1b
builds a hidden-state attack, validates it on a known-answer synthetic matched to
`two`'s exact signature, and runs it on `two`.

## What `two` actually is (recon, repo-verified)

`two` is 698 symbols over `A..L`. Its 12 symbols partition into **3 classes by index
mod 3** (`{A,D,G,J}`, `{B,E,H,K}`, `{C,F,I,L}`), and **consecutive symbols never
share a class**: every symbol has out-degree **and** in-degree exactly 8 (the 8
symbols outside its own class), with **zero adjacent-equal** pairs. So the visible
symbol factors as `class (mod 3) × rank (0..3)`: the class is a fast coordinate that
always advances, the rank is freer. This is the hidden-state signature in miniature.

## What was built

All new code is `#[cfg(test)]` (a child of the G1 `known_answer` module — no public
surface, no edit to a file-size-pinned god-file):
[`src/attack/gak_attack/hidden_state.rs`](../../src/attack/gak_attack/hidden_state.rs).

- **A synthetic hidden-state GAK generator matched to `two`'s signature.** State
  `(class ∈ Z₃, deck ∈ S₄)`; visible symbol `class + 3·rank` where `rank` is the
  deck position of a marked card (the deck is the hidden state, `|H| = (4-1)! = 6`).
  Each letter applies a non-zero class shift (so the class always changes → no
  same-class successor) and a deck permutation to the cards (so the next rank depends
  on the *whole* hidden deck). Ground truth held: the keystream and the per-letter
  visible coset-edge marginals. With **5 letters** it reproduces `two`'s signature
  **exactly** (out-degree 8 on every symbol, asserted on the instance).
- **The hidden-state recovery** reuses the existing idea-3 beam
  (`run_marginalization_attack`, `split_column_evidence`, `beam_recover_column`) — it
  does **not** die at the bijective seeding stage — plus a new whole-stream
  **keystream-decode coverage** instrument that measures whether the recovered
  marginals can be assembled into a per-position keystream (the bridge a codec needs).
- Four tests: signature assertion, the binding positive control + matched null, the
  substrate-lever obstruction demo on ground truth, and the `two` honest negative.

## Result — positive control FIRES, matched null fails 0/N

On the synthetic hidden-state GAK (repeated-phrase plaintext, 8 independent seeds):

| Quantity | Value |
| --- | --- |
| Signature | out-degree **exactly 8** on all 12 symbols; class always changes; held truth many-valued (a `from` with several `to`) |
| Real recovery (true per-letter coset edges) | **26–34 per trial**, 241 total; **fires 8/8** |
| Matched within-instance Fisher-Yates shuffle null | **0–5 per trial**, 7 total; **matched the real recovery 0/8** |
| Real vs null | real total **241 ≫ null 7** (>10×) |

This is the first known-answer positive control for the *hidden-state* recovery (G1
only validated the bijective GCTAK path). The matched null recovers only coincidental
single-edge noise and never reaches the real recovery — the recovery is the cipher
structure, not an artifact.

## Result — the substrate is the lever (on ground truth)

The SAME hidden-state cipher, repeated-phrase vs realistic (i.i.d., non-repeated)
plaintext, 8 seeds, scored against held truth:

| Plaintext | True per-letter coset edges recovered (8 seeds) |
| --- | --- |
| Repeated-phrase | **255** |
| Realistic (no dominant repeated phrase) | **89** (≈2.9× fewer) |

The recoverable signal is a **dominant repeated phrase**: one isomorph signature then
maps to one plaintext letter per aligned column, and the beam recovers that letter's
marginal. Without it, the same equality-pattern signature lumps many distinct
plaintext letters, so the recovered "columns" are mixtures and recovery collapses.
This pins the `two` obstruction on a synthetic where we *hold* the truth.

## Result on `two` — honest negative; the attack runs but cannot decode

The hidden-state attack **runs** on `two` (unlike `solve_gctak` it does not die at
seeding): real text repeats equality patterns, so an isomorph signature aligns and
the beam emits a few column marginals. But `two` is real text with **no dominant
repeated phrase** (its largest length-4 isomorph signature, `(0,1,2,1)`, has 76
occurrences spanning many different plaintext contexts), so those marginals are tiny
and cover only a sliver of the stream:

| phrase_len | aligned occurrences | recovered columns | recovered edges | transitions uniquely covered | **undecidable** |
| --- | --- | --- | --- | --- | --- |
| 4 | 76 | 3 | 12 | 105 (15%) | **581 / 697 (83%)** |
| 6 | 52 | 4 | 23 | 164 (24%) | **527 / 697 (76%)** |
| 8 | 25 | 4 | 17 | 121 (17%) | **567 / 697 (81%)** |
| 10 | 7 | 0 | 0 | 0 | 697 / 697 (100%) |

**Failure point:** 76–83% of `two`'s 697 transitions are left **undecidable** by any
recovered marginal — there is **no whole-stream keystream** to feed the codec. This
is the same collapse the substrate-lever test demonstrates on synthetic ground truth,
now confirmed on the real sample. Per the honesty discipline, **no candidate text is
logged** (a coverage of <25% of the stream is not a recovery, and an n-gram score on
the wrong structure is never a decode). The existing classical record
([`candidates/solve-two-…md`](candidates/solve-two-seed-0000736f6c766504.md)) already
documents the gate-failing classical attempt; G1b adds nothing stronger.

## Bottom line

The GAK machinery now has a **known-answer positive control for the hidden-state
regime**: on a synthetic GAK matched to `two`'s exact out-degree-8 signature, the
idea-3 marginalization recovers the true per-letter coset edges and the matched null
fails 0/N. Applied to `two`, the attack runs without dying at seeding (the G1 wall),
but recovers structure for only a sliver of the stream — **76–83% of transitions are
undecidable** — so there is no whole-stream keystream to feed the codec. The precise
blocker, pinned on synthetic ground truth and confirmed on `two`, is the **absence of
a dominant repeated phrase**: real text's isomorph signatures are degenerate (one
signature lumps many plaintext letters), so the repeated-phrase substrate the
recovery depends on does not exist. This is the eyes' blocker in miniature — a
verifiable, honest negative. None of this touches the eyes or the standing claim
ceiling: deterministic, engine-generated, strikingly structured data of unknown
meaning; unsolved.
