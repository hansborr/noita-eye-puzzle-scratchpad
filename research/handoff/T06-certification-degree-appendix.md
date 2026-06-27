# T06 — Certification-degree appendix (G3 formalization, sourced numbers only)

**Tier:** 2 (optional) · **Size:** S · **Type:** doc · **Status:** TODO
**Depends on:** none · **Conflicts with:** none
**Touches:** new `research/findings/certification-degree.md`

## Goal
A short, postable write-up of the **edge-overlap certification degree `t`** — how
many overlapping chaining edges certify "same transformation" — framed against the
group's transitivity degree, using **only the numbers G3 already computed**. This
is the clean formalization of the wiki's stated half-solved problem.

## Why — and why it is optional/Tier 2
G3 already computed the load-bearing values: `t = N−1 = 82` for the sharply-`N`-
transitive S₈₃/S₈₂ regime, `t ≈ 2` for the dihedral-like low-transitivity regime,
and the coupon-collector full-pin demand `N·(H_N−1) = 332.2` (N=83). So this is
**write-up, not discovery** — it will NOT move decode odds. Do it only after
Tier 1; skip if time-boxed.

## Scope guard (codex P1 — do NOT invent math)
G3 sourced `t` for **two regimes** (sharp-S_N and dihedral-like), **not** a per-
group value for each of the six transitive groups. Computing `t` for the
intermediate groups (C₈₃:C₄₁, AGL, A₈₃ …) is **new derivation** — out of scope here.
Either (a) keep this a doc that only restates the two sourced regimes + the demand-
vs-supply read, or (b) if you genuinely derive per-group `t`, re-scope it as a
*proof* task with its own validation, and stop claiming "no new derivation."

## Steps
1. Restate (with citation, not re-derivation) G3's `t` for the sharp-S_N and
   dihedral regimes, and the coupon demand 332.2.
2. State the demand-vs-supply conclusion for the surviving {A₈₃, S₈₃} family: it
   sits in the sharp regime → `t = N−1` (all edges) → demand 332.2 ≫ richest real
   isomorph supply 26 → the same calibrated NO G3 reached.
3. Frame explicitly as a formalization of an already-quantified result.

## Definition of done
- [ ] `certification-degree.md` restates only G3-sourced numbers (or is re-scoped as
      a proof task with validation).
- [ ] Every number cites G3; `make check` green (doc-only → codespell clean).
- [ ] `docs/deslop-audit` merged in; committed.

## Honesty guardrails
Do not present the appendix as a new finding or as progress toward a decode. No
per-group `t` claim beyond the two regimes G3 sourced, unless actually derived.

## Pointers
- `research/gak-threads/G3-leak-ceiling.md` Part B (~:99–108: `t=N−1=82`, `t≈2`, 332.2),
  Part C (supply vs demand; richest supply 26)
- `research/frontier.md` (the certification sub-problem, transitivity framing)
- `research/threads-eyes.md` G4/T6 (original scoping)
