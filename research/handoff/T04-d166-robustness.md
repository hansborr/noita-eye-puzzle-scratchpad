# T04 — D₁₆₆ dihedral-exclusion transcription robustness

**Tier:** 3 (optional) · **Size:** S · **Type:** code+doc · **Status:** TODO
**Depends on:** T01 · **Conflicts with:** other `transitivity.rs` edits
**Touches:** `src/experiments/transitivity.rs` (+ test), `research/gak-threads/thread-1-dihedral-and-transitivity.md`

## Goal
The D₁₆₆ exclusion is already the most fragile eyes verdict: conditional, MEDIUM
confidence, resting on **exactly one** pinned witness triple (`core_only=0`).
Quantify exactly how a 1-glyph mis-read in that witness's region affects it.

## Why
It is the one verdict the cross-model review downgraded ("single-witness-fragile,
report at medium confidence"). A robustness number makes the existing hedge precise
rather than vibes-based. Lower value than T02/T03 only because the verdict is
*already* hedged — but it is cheap once T01 exists.

## Steps
1. Use the T01 harness over the region of the single pinned witness triple (the
   order-83 forcing + commutativity-conflict columns; note HOLE 1 reuses col6/col9).
2. Verdict closure = "D₁₆₆ still excluded (witness triple still yields the
   contradiction)". Certify single- then double-glyph.
3. Report how many perturbations dissolve the single witness (the wiki's own HOLE 1
   says one strategic typo at col6/col9 does). Append a robustness section to the
   dihedral thread doc.

## Definition of done
- [ ] Certification counts asserted in a test; `make verify` green.
- [ ] Dihedral thread doc gets a robustness section quantifying HOLE 1.
- [ ] The MEDIUM/conditional verdict is preserved (this only sharpens the hedge).
- [ ] `docs/deslop-audit` merged in; committed.

## Honesty guardrails
Do NOT upgrade D₁₆₆ off the back of this — it stays conditional/MEDIUM. A
high-fragility result *strengthens* the existing hedge; it is not a new claim.

## Pointers
- `src/experiments/transitivity.rs` (the pinned witness; HOLE 1/2 + A1–A5 text)
- `research/gak-threads/PROGRESS.md` §1 Thread 1B; wiki-audit ledger (HOLE 1 quote)
- T01 harness
