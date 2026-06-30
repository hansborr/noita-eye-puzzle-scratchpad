# Modular-form exclusion ledger (Thread D — resolution)

**Status:** documentation note — **no standalone scanner was built**, by an explicit
honesty-discipline decision (below). The load-bearing part of the modular-form
exclusion is already established by Thread C's gap discriminant.

## Community-reported exclusions (source)

From `community-docs-firsthand-digest.md` §5 (all `[likely]`, reading-order-conditional,
never re-derived in-repo):

- `c = (m·p + s·x) mod 83` → "forces the unique `m=25, s=51`"
- `c = (p + f) mod 83` → needs alphabet ≥ 69
- `c = (p · f) mod 83` → needs alphabet ≥ 61
- `c = c₋₁ + a·b^p mod 83` → "reduces nothing"

## Why no independent (m,s)-sweep scanner was built

The source is **too terse to faithfully reproduce**. It never defines the operands
(`p` = plaintext value? `x` = position?) nor the operational criterion behind "forces
the unique `m,s`" or the "needs alphabet ≥ N" bounds. Sweeping `(m,s) ∈ [0,83)²` and
applying a *guessed* discriminant would emit a survivor set that cannot be validated
against the community's "25,51" claim — manufacturing an unverifiable number, which
violates the repo's binding rule (AGENTS.md: never present unverified numbers; a
bounded search must state its limits). A faithful regeneration would require Toboter's
original derivation (likely an external community doc), which is not in the repo.

## The verifiable core IS captured (Thread C)

The load-bearing content of the modular-form exclusion is the **gap-recurrence
discriminant**: the position-affine family `(char + N·pos) mod 83` recurs only at
multiples of 83, so it can never produce a dense contiguous low-gap recurrence run
with no doubled trigrams. Thread C's `predscan` predicate (a) tests exactly this and
finds, under the accepted honeycomb order, an only-1-missing **run length M = 36** at
**p ≈ 0.001** (within-message shuffle null) — empirically excluding the position-affine
family. See `predicate-battery-meta-analysis.md` §1 and §2.

> **Correction to the community claim:** the literal phrasing "the only missing gap
> size is 1" does **not** reproduce (the actual missing set is `{1, 37, 69, …}` over
> the full realized range); `M = 36` is the honest, defensible restatement of what is
> actually true and discriminating.

The shared `missing_gap_sizes()` primitive (`src/analysis/predicates/`, built on
`orders::count_message_recurrence`, extended past the old `d ≤ 6` cap) is the reusable
engine a faithful `modscan` would consume if the operational definition were ever
pinned.

## Deferred

A faithful `modscan` (the `(m,s)` sweep + the `+f` / `×f` alphabet-size bounds) is
deferred pending an operational definition of the modular form from the original
community derivation. The part that matters for the elimination ledger — excluding the
position-affine family — is already established by Thread C's gap discriminant, so this
deferral costs the ledger nothing material.
