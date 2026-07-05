# G1b — Hidden-state GAK attack on practice puzzle `two`

**Date:** 2026-06-26. **Thread:** G1b (push a *hidden-state-capable* GAK attack at
`two`, a verifiable candidate miniature of the eyes' blocker). **Status:** Done —
positive control fires; `two` is an honest negative with a measured (attack-
conditional) failure point.

## The gap G1b closes

G1 pointed the *bijective-readout* GCTAK solver
([`solve_gctak`](../../src/attack/gak_attack/solver/mod.rs)) at `two` and reported a clean
honest negative: it dies at seeding because `two`'s readout is many-valued
(out-degree 8 on all 12 symbols), which violates GCTAK's bijective-readout
assumption. G1 explicitly deferred the *hidden-state* machinery
([`marginalization`](../../src/attack/gak_attack/marginalization/mod.rs)) to G1b. G1b
builds a hidden-state attack, validates it on a known-answer synthetic matched to
`two`'s observable signature, and runs it on `two`.

## What `two` actually is (recon, repo-verified)

`two` is 698 symbols over `A..L`. Its 12 symbols partition into 3 classes by index
mod 3 (`{A,D,G,J}`, `{B,E,H,K}`, `{C,F,I,L}`), and consecutive symbols never
share a class: every symbol has out-degree and in-degree exactly 8 (the 8
symbols outside its own class), with zero adjacent-equal pairs. So the visible
symbol factors as `class (mod 3) × rank (0..3)`: the class is a fast coordinate that
always advances, the rank is freer. This is the hidden-state signature in miniature.

**Group-framing caveat (2026-06-26 observation, superseded framing).** This
`class (mod 3) × rank (0..3)` recon predates the 2026-07-04 route reset of `two`
(`research/handoff/two-cross-agent-recon.md`), which establishes the live surface as
the full 12-symbol stream whose isomorph column-maps close to an order-48 observable
shadow of a reported order-96 group. The mod-3 class law and the degree-8 signature
survive as model-free measurements, but the direct-product `class × rank` reading is
not the current canonical group framing. G1b's honest-negative conclusion (the attack
runs but cannot decode `two` for lack of a dominant repeated phrase) is unaffected.

## What was built

All new code is `#[cfg(test)]` (a child of the G1 `known_answer` module — no public
surface, no edit to a file-size-pinned god-file):
[`src/attack/gak_attack/hidden_state.rs`](../../src/attack/gak_attack/hidden_state.rs).

- **A synthetic hidden-state GAK generator matching `two`'s observable signature.**
  State `(class ∈ Z₃, deck ∈ S₄)`; visible symbol `class + 3·rank` where `rank` is the
  deck position of a marked card (the deck is the hidden state, `|H| = (4-1)! = 6`).
  Each letter applies a non-zero class shift (so the class always changes → no
  same-class successor) and a deck permutation to the cards (so the next rank depends
  on the *whole* hidden deck). Ground truth held: the keystream and the per-letter
  visible coset-edge marginals. With 5 letters it matches `two`'s observable
  signature (out- and in-degree 8 on every symbol, asserted on the instance). The
  signature assertions guard against the main bijective / no-hidden-state
  degeneracies — not against every conceivable easy substrate.
- **The hidden-state recovery** reuses the existing idea-3 beam
  (`run_marginalization_attack`, `split_column_evidence`, `beam_recover_column`) — it
  does not die at the bijective seeding stage — plus a new whole-stream
  keystream-decode coverage instrument that measures whether the recovered
  marginals can be assembled into a per-position keystream (the bridge a codec needs).
- Four tests: signature assertion, the binding positive control + matched null, the
  substrate-lever obstruction demo on ground truth, and the `two` honest negative.

## Result — positive control fires

On the synthetic hidden-state GAK (repeated-phrase plaintext, 8 independent seeds):

| Quantity | Value |
| --- | --- |
| Signature | out- and in-degree exactly 8 on all 12 symbols; class always changes; held truth many-valued (a `from` with several `to`) |
| Real recovery (true per-letter coset edges) | **26–34 per trial**, 241 total; fires 8/8 |
| Matched within-instance Fisher-Yates shuffle null | **0–5 per trial**, 7 total; matched-or-exceeded real recovery 0/8 |

This is the first known-answer positive control for the *hidden-state* recovery (G1
only validated the bijective GCTAK path): the idea-3 marginalization recovers true
per-letter coset edges on every trial.

The Fisher-Yates shuffle null is a noise-floor / pipeline-artifact control, not
the discriminating test: it destroys *all* stream structure, so it can only ever
return a few coincidental stray edges (7 total over 8 trials) and never matches the
real recovery (0/8). It *supports* — it does not prove — that the recovered edges are
cipher structure rather than a pipeline quirk. The meaningful separation is the
substrate ablation below.

## Result — the substrate is the lever (on ground truth) — the headline signal

This is the discriminating result. The same hidden-state cipher, repeated-phrase vs
realistic (i.i.d., non-repeated) plaintext, 8 seeds, scored against held truth:

| Plaintext | True per-letter coset edges recovered (8 seeds) |
| --- | --- |
| Repeated-phrase | **255** |
| Realistic (i.i.d., no dominant repeated phrase) | **89** (≈2.9× fewer) |

Holding the cipher fixed and changing only the plaintext substrate cuts recovery
~2.9×. The recoverable signal is a dominant repeated phrase: one isomorph
signature then maps to one plaintext letter per aligned column, and the beam recovers
that letter's marginal. Without it the same equality-pattern signature lumps many
distinct plaintext letters, so the recovered "columns" are mixtures and recovery
degrades. This is an ablation on a synthetic where we *hold* the truth; the
load-bearing property — shared with `two` — is the absence of a single dominant
repeated phrase.

## Result on `two` — honest negative; the attack runs but cannot decode

The hidden-state attack runs on `two` (unlike `solve_gctak` it does not die at
seeding): real text repeats equality patterns, so an isomorph signature aligns and
the beam emits a few column marginals. But those marginals are tiny and cover only a
sliver of the stream (its largest length-4 isomorph signature, `(0,1,2,1)`, has 76
occurrences, but with no in-repo cleartext we cannot attribute them to plaintext
letters):

| phrase_len | aligned occurrences | recovered columns | recovered edges | transitions uniquely covered | **undecidable** |
| --- | --- | --- | --- | --- | --- |
| 4 | 76 | 3 | 12 | 105 (15%) | **581 / 697 (83%)** |
| 6 | 52 | 4 | 23 | 164 (24%) | **527 / 697 (76%)** |
| 8 | 25 | 4 | 17 | 121 (17%) | **567 / 697 (81%)** |
| 10 | 7 | 0 | 0 | 0 | 697 / 697 (100%) |

**Measured failure (attack-conditional):** with this attack, 76–83% of `two`'s 697
transitions are left undecidable by any recovered marginal — there is no
whole-stream keystream to feed the codec (coverage collapse). This is the same
*kind* of collapse the substrate-ablation shows on synthetic ground truth. The
causal link is a hypothesis, not proven on `two`: the synthetic ablation used an
i.i.d. realistic arm, whereas `two` is natural-language text with more local structure
than i.i.d.; the property shared by both — and the one we claim — is the absence of a
single dominant repeated phrase, not the full i.i.d. model. Per the honesty
discipline, no candidate text is logged (a coverage of <25% of the stream is not a
recovery, and an n-gram score on the wrong structure is never a decode). The existing
classical record
([`candidates/solve-two-…md`](candidates/solve-two-seed-0000736f6c766504.md)) already
documents the gate-failing classical attempt; G1b adds nothing stronger.

Reproducibility of the figures. All integers above (241/7, 26–34, 0–5, 255/89, the
83/76/81% undecidable table, the phrase_len=10 100% row) are deterministic at the
stated seeds (`SYNTH_SEED` / `trial_seed`). The committed tests guard only the
qualitative bounds — recovery fires 8/8, the null matches-or-exceeds real 0/8, real
>10× the null floor, the repeated-phrase substrate recovers >2× the realistic arm, and
on `two` the undecidable fraction >0.5 and unique fraction <0.4 at phrase_len ∈
{4,6,8} — not the exact integers.

## Bottom line

The GAK machinery now has a known-answer positive control for the hidden-state
regime: on a synthetic GAK matching `two`'s observable out-/in-degree-8 signature,
the idea-3 marginalization recovers true per-letter coset edges on every trial
(8/8), and a synthetic substrate-ablation shows the recoverable lever is a dominant
repeated phrase (recovery drops ~2.9× without it). Applied to `two`, the attack runs
without dying at seeding (the G1 wall), but recovers structure for only a sliver of
the stream — 76–83% of transitions are undecidable — so there is no whole-stream
keystream to feed the codec. The most consistent hypothesis for this coverage
collapse (supported by the synthetic ablation, not proven on `two`) is the absence of
a single dominant repeated phrase: the repeated-phrase substrate the recovery depends
on is not present in `two`'s natural-language text. This is a candidate miniature of
the eyes' blocker — a verifiable, honest negative. None of this touches the eyes or
the standing claim ceiling: deterministic, engine-generated, strikingly structured
data of unknown meaning; unsolved.
