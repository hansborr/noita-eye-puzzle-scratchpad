# T04 — D₁₆₆ dihedral-exclusion transcription robustness

**Tier:** 3 (optional) · **Size:** S · **Type:** code+doc · **Status:** Todo
**Depends on:** T01 · **Conflicts with:** other `transitivity/` edits
**Touches:** `src/experiments/transitivity/` (+ test), `research/gak-threads/thread-1-dihedral-and-transitivity.md`

**Rationale update (2026-07-06):** within the point-stabilizer GAK model, the
D₁₆₆-GAK exclusion itself is no longer merely "conditional, medium confidence"
— it is now excluded as a special case of the exhaustive AGL sweep, inheriting
the AGL conditions (one global configuration, the `(66,5)`-prefix gate, T02
hardening). What stays conditional/medium is only the Thread-1B single-witness
argument below, which now survives purely as corroboration. This task still has
value: it hardens that corroborating witness, it just no longer determines the
overall D₁₆₆ verdict.

## Goal
The Thread-1B D₁₆₆ witness is already the most fragile eyes verdict component:
conditional, medium confidence, resting on exactly one pinned witness triple
(`core_only=0`). Quantify exactly how a 1-glyph mis-read in that witness's
region affects it.

## Why
It is the one verdict the cross-model review downgraded ("single-witness-fragile,
report at medium confidence"). A robustness number makes the existing hedge precise
rather than vibes-based. Lower value than T02/T03 only because the verdict is
*already* hedged — but it is cheap once T01 exists.

## Steps
1. Use the T01 harness over the region of the single pinned witness triple (the
   order-83 forcing + commutativity-conflict columns; note hole 1 reuses col6/col9).
2. Verdict closure = "D₁₆₆ still excluded (witness triple still yields the
   contradiction)". Certify single- then double-glyph.
3. Report how many perturbations dissolve the single witness (the wiki's own hole 1
   says one strategic typo at col6/col9 does). Append a robustness section to the
   dihedral thread doc.

## Definition of done
- [ ] Certification counts asserted in a test; `make verify` green.
- [ ] Dihedral thread doc gets a robustness section quantifying hole 1.
- [ ] The medium/conditional verdict is preserved (this only sharpens the hedge).
- [ ] Committed.

## Honesty guardrails
Do not upgrade the Thread-1B witness off the back of this — it stays
conditional/medium in its own right (the overall D₁₆₆-GAK exclusion already
rides on the AGL sweep, per the rationale update above). A high-fragility
result *strengthens* the existing hedge on the witness; it is not a new claim.

## Pointers
- `src/experiments/transitivity/`: the `ExclusionWitness` / `core_only` witness model and
  the hole 1/2 + Assumptions A1–A5 caveat text live in `mod.rs`; the pinned-witness
  assertions are in `tests.rs`
- `research/gak-threads/PROGRESS.md` §1 Thread 1B; wiki-audit ledger (hole 1 quote)
- T01 harness
