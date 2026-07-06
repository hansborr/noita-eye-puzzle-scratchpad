# NEXT-STEPS — work plan index · refreshed 2026-07-06

> **Re-ranked 2026-06-26.** See `research/handoff/` for the active backlog.
> `git log` is the source of truth for what has merged; this file is now a
> navigation/status index, not the live priority queue.

The 2026-07-06 Tier-1 cycle in
[`research/handoff/next-cycle-2026-07-06.md`](handoff/next-cycle-2026-07-06.md)
has landed: planning hygiene, the transcription-perturbation harness, AGL
robustness, Stutter sensitivity, and the structural summary are all merged.

Start new work from [`research/handoff/README.md`](handoff/README.md). The current
best next action is `T11`, the bounded external-anchor criteria/status document.
After that, only optional formalization remains: `T04` for the already-hedged
`D166` robustness caveat and `T06` for a certification-degree appendix. `T07` is
sample-suite cleanup and should stay opportunistic because it transfers poorly to
the eyes.

> **Honesty ceiling (binding, project-wide):** the eye data is deterministic,
> engine-generated, strikingly structured data of unknown meaning; unsolved; no
> primary developer source confirms recoverable plaintext. A high n-gram or
> structure score on the wrong structure is not a recovery. Label
> model-conditional results as such. See `AGENTS.md`.

---

## Current Answer

The old July-4 ladder was correct for its time, but it is no longer the work
queue. G1, G1b, T1, G2, G3, the two near-free eyes wins, and the Thread-4 GAK
attack arc have all landed. Practice puzzle `two` is no longer an open
hidden-state target: the original G1b hidden-state attack remains an honest
negative, and later `shadowfinish` + `substfinish` work produced a
maintainer-confirmed plaintext-level solve. That solve is still only
letter-level computationally and still lacks an original-generator round trip,
so it does not upgrade any eyes claim.

The next useful work is not another broad decode search. The publish-blocking
robustness gap has been closed and the structural summary is published in
`research/findings/eyes-structural-summary.md`. The remaining high-leverage item
is external rather than computational: write down what would count as a real
symbol-to-meaning anchor and the current status of each candidate source (`T11`).

## Landed Status

Every "done" item below cites either a commit named in recent history or the
result document that now owns the claim.

| Item | Status | Source of truth |
| --- | --- | --- |
| **G1** — known-answer GAK validation | **DONE.** `one` validates the cyclic GCTAK path; `two` is the expected hidden-state honest negative for the bijective-readout solver. | `b681c35`; [`gak-threads/G1-RESULTS.md`](gak-threads/G1-RESULTS.md) |
| **Near-free win: AGL exclusion** | **DONE.** AGL(1,83)-GAK `C83:C82` and `C83:C41` are exhaustively excluded under the point-stabilizer, single-shared-running-key model. | `1d3a005`, `06bed9b`; [`findings/agl-exclusion.md`](findings/agl-exclusion.md) |
| **Near-free win: base-5 first trigram** | **DONE.** The first-trigram wiki question is computed and regression-locked; the only sharp storage-order regularity reduces to a shared rendered eye. | `419851a`, `fb43620`, `37407cb`; [`findings/base5-first-trigram.md`](findings/base5-first-trigram.md) |
| **T1** — held-out gate fix | **DONE.** Fold-vs-fold held-out scoring is fixed through the shared helper used by the solve pipeline and eyes Gate 1. | `34cac21`; [`findings/T1-heldout-gate-fix.md`](findings/T1-heldout-gate-fix.md) |
| **G1b** — hidden-state attack on practice `two` | **DONE.** The hidden-state attack fires on synthetic controls but leaves `two` without enough stream coverage; this is an honest negative, not a decode. | `93a0c71`, `51b307a`, `c4ddb6e`; [`gak-threads/G1b-RESULTS.md`](gak-threads/G1b-RESULTS.md) |
| **Practice `two` finish** | **DONE at plaintext level / maintainer-confirmed.** `shadowfinish` produced the candidate and `substfinish` recovered the monoalphabetic letter hypothesis; punctuation/hyphenation came from source/syntax alignment, not the Rust finisher. | `4dcc376`; [`findings/two-shadowfinish-substitution-candidate.md`](findings/two-shadowfinish-substitution-candidate.md), [`findings/two-original-generator-roundtrip-blocker.md`](findings/two-original-generator-roundtrip-blocker.md) |
| **G2** — isomorph-imperfection falsifier | **DONE.** Perfect isomorphism is supported within the tested envelope; GAK is not falsified. This is not a proof that the eyes are GAK. | `5d5c149`, `61dac1c`, `cbf163f`; [`gak-threads/G2-isomorph-imperfection.md`](gak-threads/G2-isomorph-imperfection.md) |
| **G3** — isomorph leak ceiling | **DONE.** The leak shortfall is quantified: the richest repeated signature is far below the `S83` coset-permutation certification demand. | `8f052b6`, `dfd7139`; [`gak-threads/G3-leak-ceiling.md`](gak-threads/G3-leak-ceiling.md) |
| **Thread 4 / T6-T7 attack arc** | **DONE.** The GAK attack spike produced synthetic gates, measured hidden-state limits, and an honest-negative eyes Step 3 with no surviving candidate. | `e7b88f8`, `d3b30fd`, `aaa9e9a`, `1d928a2`, `8aa7c53`, `44d4ec4`; [`gak-threads/PROGRESS.md`](gak-threads/PROGRESS.md) §6 |
| **Deck-swap tooling side path** | **BUILT + MERGED.** The general swap-recovery instrument and practice-puzzle results are reference material, not the next eyes queue. | [`data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`](data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md), [`handoff/README.md`](handoff/README.md) |
| **T00** — planning refresh | **DONE.** `NEXT-STEPS.md` was converted from stale queue to status/navigation index. | `9c60769`; [`handoff/T00-refresh-next-steps.md`](handoff/T00-refresh-next-steps.md) |
| **T01** — transcription-perturbation harness | **DONE.** Source-layer counterfactuals now perturb rendered orientation digits and rebuild reading-layer values through the accepted honeycomb order. | `3290d84`; [`../src/analysis/perturbation.rs`](../src/analysis/perturbation.rs) |
| **T02** — AGL robustness | **DONE.** The AGL exclusion survives 324 one-digit and 5,184 bounded two-digit prefix-region counterfactuals. | `5052f10`; [`findings/agl-exclusion.md`](findings/agl-exclusion.md#7-transcription-robustness) |
| **T03** — Stutter sensitivity | **DONE.** The perfect-isomorphism negative survives all 180 one-digit and 5,039/5,040 two-digit Stutter-region counterfactuals; the single flip is named. | `68fcca9`; [`gak-threads/G2-isomorph-imperfection.md`](gak-threads/G2-isomorph-imperfection.md#transcription-sensitivity-around-the-stutter-region-t03) |
| **T05** — structural summary | **DONE.** The eyes frontier is packaged as a standalone, postable synthesis. | `a314f42`; [`findings/eyes-structural-summary.md`](findings/eyes-structural-summary.md) |

## Active Priority

Tier 1 is complete. The active backlog is now the remaining Tier-2/Tier-3 work in
[`research/handoff/README.md`](handoff/README.md):

1. `T11` — external-anchor criteria/status document. This is the only remaining
   item likely to change the decode outcome without new ciphertext.
2. `T04` — optional `D166` transcription robustness; it only sharpens an
   already-hedged, conditional verdict.
3. `T06` — optional certification-degree appendix; it formalizes G3's existing
   numbers and does not move decode odds.
4. `T07` — proving-ground status/menu only if sample-suite progress is explicitly
   prioritized over eyes work.

## Re-Ranking Rationale

G4/T6 were demoted to formalization because G3 already computed the key numbers
they were meant to chase: the sharp `S83` certification degree is `t = N - 1 =
82`, and the harmonic coupon demand for `N = 83` is 332.2 aligned observations
to pin one element on at least `N - 1` cosets. T7/G5 are confirmatory now that
the Thread-4 attack arc has completed with an honest-negative eyes run. T8/T2
remain triage-only because mapping-dependent language scoring cannot supply the
missing symbol-to-meaning anchor. With the transcription certificates and summary
now landed, the next useful work is documenting the external-anchor bar and
current source status, not searching the same ciphertext harder.

## Coordination Notes

- A new CLI subcommand belongs in `src/cli/` and the library, not in `src/main.rs`.
- New findings need a positive control and a matched null when they make a
  negative or discriminator claim.
- Any candidate cleartext belongs under `research/gak-threads/candidates/` and
  must be called a candidate unless independently confirmed.
- Research results worth keeping belong in `research/`, not in agent memory.

## Standing Sources

- Dossier index: [`research/README.md`](README.md)
- Claim ceiling: [`03-confirmed-vs-speculation.md`](03-confirmed-vs-speculation.md)
- Methodology lessons: [`attack-methodology.md`](attack-methodology.md)
- Completed GAK campaign: [`gak-threads/README.md`](gak-threads/README.md) and
  [`gak-threads/PROGRESS.md`](gak-threads/PROGRESS.md)
- Active backlog: [`handoff/README.md`](handoff/README.md)
