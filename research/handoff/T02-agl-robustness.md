# T02 — AGL-exclusion transcription robustness

**Tier:** 1 · **Size:** S · **Type:** code+doc · **Status:** Todo
**Depends on:** T01 · **Conflicts with:** other `agl_gak/` edits
**Touches:** `src/attack/agl_gak/` (+ test), `research/findings/agl-exclusion.md`

## Goal
Quantify how fragile the AGL(1,83)-GAK exclusion is to a transcription error in its
load-bearing region. The exclusion's tightest clincher is the all-nine shared
prefix: nine distinct first symbols then a length-2 varying run `[66, 5]`
at offset 1. Certify which 1- and 2-glyph perturbations of that region preserve the
exclusion.

## Why
`agl-exclusion.md` §7 already flags transcription as "the underlying risk" — a
single mis-read glyph in the prefix region would need re-checking. This task turns
that caveat into a number: e.g. "exclusion survives all but K of the N
single-glyph perturbations; the K that dissolve it are <list>." Mapping-independent,
directly publishable, hardens the strongest eyes claim before release.

## Steps
1. Identify the small orientation-digit window whose digits produce the
   load-bearing reading-layer region (the nine first symbols + the `[66,5]` shared
   run at offset 1). Per T01, perturb at the source digit level and let the
   harness re-derive reading-layer values. Define the verdict closure = "AGL still
   excluded" by calling the existing exclusion logic (the `(66,5)`-prefix
   obstruction + the fixed-point/varying-run check) on each re-derived stream.
2. Run single-change, then double-change certification. Capture: count that still
   exclude, and each perturbation that dissolves the exclusion (which glyph, which
   value, why — e.g. "collapses the varying run to constant").
3. Add a `Report` section + a test pinning the certification counts
   (seed-independent, exhaustive over the tiny region).
4. Append a "Transcription robustness" section to `findings/agl-exclusion.md` with
   the table and an honest read (a single specific mis-read could dissolve it iff it
   makes the shared run constant; otherwise robust).

## Definition of done
- [ ] Certification counts asserted in a test; `make verify` green.
- [ ] `findings/agl-exclusion.md` has a robustness section with the exact counts.
- [ ] The dissolving perturbations (if any) are named explicitly, not summarized away.
- [ ] Committed.

## Honesty guardrails
A perturbation that dissolves the exclusion is a *sensitivity* result, not evidence
that the transcription is wrong (it is verified byte-for-byte, Ghidra-confirmed).
State the conditional plainly: "the exclusion is exact GIVEN the verified prefix;
it would need re-checking only if glyph X were mis-read as Y."

## Pointers
- `src/attack/agl_gak/`: `first_obstruction` / `global_prefix_obstruction` in `mod.rs`;
  `fixed_point_of` / `fixed_point_count` / `fixed_point_enumeration` in `groups.rs`
  (report rendering in `report.rs`, tests in `tests.rs`)
- `research/findings/agl-exclusion.md` §4.4 (the `[66,5]` prefix kill), §7 (claim ceiling)
- T01 harness
