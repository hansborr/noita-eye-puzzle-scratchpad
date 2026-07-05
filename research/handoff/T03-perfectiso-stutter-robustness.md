# T03 — Perfect-iso / G2 Stutter-region transcription *sensitivity*

**Tier:** 1 · **Size:** S · **Type:** code+doc · **Status:** Todo
**Depends on:** T01 · **Conflicts with:** other `isomorph_imperfection/` edits
**Touches:** `src/analysis/isomorph_imperfection/` (+ test),
`research/gak-threads/G2-isomorph-imperfection.md`

## Goal
Quantify how fragile the G2 disproof-negative ("GAK not falsified") is to a
transcription error. G2 already surfaced two loose candidates and audited their
benign attribution; this task adds only the perturbation-sensitivity layer: does
any 1–2 orientation-digit mis-read in the Stutter region flip either loose candidate
from *benign* to a *promoted robust internal violation* (which would eject the eyes
from the perfectly-isomorphic family)?

## Scope correction (do not redo the audit)
G2 is landed in `src/analysis/isomorph_imperfection/` (it consumes
`perfect_isomorphism/` read-only). It already has the extended-window scan, the
loose-bar matched null, the word-boundary discount, and the named-benign-Stutter
attribution, and it lists both loose candidates:

| pair | offsets | island | far-run | internalness | region |
| --- | --- | --- | --- | --- | --- |
| east4 / west4 | 65 / 67 | 1 | 11 | 11 | Stutter |
| east4 / east5 | 68 / 69 | 1 | 29 | 29 | Stutter |

The negative is conditional on both being benign. Do not re-implement the audit
or edit `perfect_isomorphism/`; build on the existing `isomorph_imperfection/`.

## Why
The benign-Stutter attribution is the only thing between these two candidates and
two promoted violations. A sensitivity number ("the verdict survives all but K
single-digit mis-reads; the K that flip it are <list>") makes the existing
load-bearing caveat precise before publication.

## Steps
1. Find the orientation-digit window(s) producing the Stutter region around
   reading-layer offsets 65–69 in messages east4/west4/east5.
2. Verdict closure (via the T01 harness) = "still 0 promoted robust internal
   violations" — i.e. re-run the existing `run_isomorph_imperfection` scan on the
   re-derived stream and check neither loose candidate promotes.
3. Single- then (bounded) double-digit certification. Report the count that keep the
   negative and any perturbation that promotes a candidate (which message, digit,
   old→new, which candidate flips).
4. Append a "Transcription sensitivity" section to `G2-isomorph-imperfection.md`.

## Definition of done
- [ ] Sensitivity counts asserted in a test; `make verify` green.
- [ ] `G2-isomorph-imperfection.md` documents whether the negative is robust to a
      Stutter-region mis-read; any flipping perturbation named explicitly.
- [ ] Existing G2 verdict/positive-controls unchanged (this only adds a layer).
- [ ] Committed.

## Honesty guardrails
A flip under a counterfactual mis-read is a *fragility* finding, not a falsification
of GAK — the verified transcription stands. The verdict stays "SUPPORTED, not
proven" / "GAK not falsified" unless real data changes it.

## Pointers
- `src/analysis/isomorph_imperfection/`: `run_isomorph_imperfection` drives the scan
  (`mod.rs`); `collect_loose_candidates` / `is_loose_candidate` and the `benign_stutter`
  attribution live in `detector.rs`; the `LooseCandidate` fields (`benign_stutter`,
  `far_run`, `internalness`, word-boundary discount) are in `mod.rs`; report rendering
  in `report.rs`, tests in `tests.rs`
- `research/gak-threads/G2-isomorph-imperfection.md` ("Both loose candidates" ~:132,
  the load-bearing benign-attribution caveat)
- T01 harness
