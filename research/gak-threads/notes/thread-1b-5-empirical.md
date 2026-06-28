# Threads 1B + 5 — Dihedral exclusion + chaining graph: empirical prototype results

Honesty banner. Mapping-independent structural work: only ciphertext-symbol
equality and group/coset structure are used. No symbol→meaning mapping is
asserted; `display` chars are exactly `value+32` and used only for human echo.
The strongest claim about the eyes themselves remains: deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved; no
primary developer source confirms recoverable plaintext. This note reports
structural support for a candidate-cipher *exclusion* (`D₁₆₆`) and two *premises*
(non-commutativity, transitivity) — not a decode.

This is a Python prototype under
`scratchpad/t1b5/` (a Rust module comes in a later wave). It is not wired into
the build gate and nothing under `src/` was touched.

Scratch (throwaway): `scratchpad/t1b5/{common,chainlib,engine}.py` (primitives);
`step1_locate.py`, `step2_chain.py`, `step3_search.py`, `step3b_strict.py`,
`step3c_redundancy.py`, `genuine_isomorphs.py`, `genuine_core_analysis.py`,
`maximal_iso.py`, `inspect_family.py`, `collision_check.py`, `survey_families.py`,
`positive_control.py`, `null_calibration.py`, `consolidate.py`.

Wiki pages tested: `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`,
`Graph-Chaining.md`, `Chaining-Conflicts.md`, `Chaining-Conflict-Rates.md`
(content current to 2026-01-16; several claims there are explicitly *tentative* —
preserved below). Logic verdict cross-referenced:
`notes/thread-1b-dihedral-verification.md`.

Input data: `scratchpad/streams.json` — the nine Experiment-0-verified corpus
streams (values `0..=82`, order `standard36-u012-d012`), with
`wiki_validation.result == "reproduced"`. The loader refuses to run if that
field is not `"reproduced"`.

Conservative-extension flag. `scratchpad/safe_isomorphs.json` (Thread 3's
safe-isomorph list) is absent. Per the thread docs we therefore extended
conservatively: chains are built only *within* a single isomorph family at one
fixed window length (never across allomorphic boundaries, never past where the gap
signature breaks), and we additionally separate a strict genuine same-plaintext
tier (literal-repeat-anchored) from a broad gap-isomorph tier. The genuine
tier is the defensible core; the broad tier is calibrated against a null.

---

## 1. The cited isomorph triple — located and alignment verified

The wiki's triple reproduces byte-for-byte in the real streams at exactly the
offsets `streams.json` records (these are three column-aligned instances of one
isomorph, *not* corpus messages 1/2/3 at a shared absolute offset):

| wiki label | corpus location | display | gap signature |
|---|---|---|---|
| iso1 | `west1 @ 40` | `OLPJ3P-O3QL` | `(0,0,0,0,0,3,0,7,4,0,9)` |
| iso2 | `east2 @ 45` | `` &-`=Q`_&Q?- `` | `(0,0,0,0,0,3,0,7,4,0,9)` |
| iso3 | `west1 @ 70` | `dN1D-15d-)N` | `(0,0,0,0,0,3,0,7,4,0,9)` |

All three gap signatures are equal ⇒ they are mutually isomorphic. The proof's
3×3 letter block at columns `{4,6,9}` is recovered exactly: `{3-Q / Q_? / -5)}`.
A 4th, uncited instance of the same isomorph exists at `east2 @ 80` (`IhY47YaI72h`).
Alignment verified; nothing failed loudly.

## 2. The dihedral contradiction — reconstructed (and its two halves separated)

Working only from symbol equality, contexts `a = iso1→iso2`, `b = iso1→iso3`:

- **Order-83 forcing (high confidence).** Under `a` the chain `L → - → _` and
  under `b` the chain `3 → - → 5` each have 3 distinct symbols (`>2`), forcing
  both contexts to order 83. This survives restriction to the high-confidence
  9-core (columns 0–8), the twice-repeated backbone — confirmed by direct
  recomputation. No true (non-permutation) conflicts.
- **Commutativity conflict (lower confidence).** Starting from `3`,
  `a;b: 3→Q→)` vs `b;a: 3→-→_` (`) ≠ _`). On the full 11-wide window this
  conflict is present ⇒ the conjunction is a genuine `D₁₆₆` contradiction. But on
  the core columns 0–8 the conflict vanishes — it lives entirely at col9
  (the 2-trigram over-extension), through `Q→)`.

This empirically confirms the logic-note's hole 2 exactly: the order-83 half is
robust on the repeated core, the conflict half is over-extension-bound.

## 3. Strengthening: full-corpus search (two honest tiers)

### Tier A — strict genuine same-plaintext isomorphs (the defensible core)

We anchored "same plaintext" on literal exact value-sequence repeats (≥9-long,
recurring) and adopted the wiki main-isomorph under its labeled assumption A1
(its 4 instances encode one phrase). Only 3 genuine families result (the
4-instance wiki isomorph + a short `PJ3P…` repeat). On these:

- order-83-forcing contexts: 6; true conflicts: 0.
- shared-pivot order-83 + commutativity-conflict witness triangles: exactly 1,
  and it is the wiki's own cited triple (`pivot west1@40`, the `3→Q→)` vs
  `3→-→_` conflict). No independent genuine witness was found.
- **Robustness:** under both a within-window-repeat *core* test (`step3b`) and a
  cross-occurrence *corroboration* test (`step3c`), 0 of the 131 shared-pivot
  candidate conflicts are typo-robust — every commutativity conflict's
  load-bearing links require columns outside a redundantly-witnessed backbone.

**Verdict (Tier A):** the dihedral exclusion, restricted to provably-same-plaintext
isomorphs, rests on essentially one example — the cited triple — whose
conflict half is its lowest-confidence column. A single strategic typo at col9
dissolves *this* witness; no second genuine witness backs it up. This is the
wiki's own stated escape hatch, now quantified.

### Tier B — broad gap-isomorph search (calibrated, not trusted at face value)

Over families of length `L ∈ {10..15}` with any ≥2 gap-isomorphic occurrences:

| quantity | value |
|---|---|
| contexts | 492 |
| contexts forcing order-83 (`chain>2`) | 392 |
| max chain length (distinct symbols) | 5 |
| raw `(a,b,s)` order-83+conflict triples | 17 124 |
| distinct unordered context-pairs with a conflict | 5 242 |
| distinct underlying occurrence-sets (independence proxy) | 4 988 |
| greedy mutually-**disjoint** witnesses (no shared window) | 32 |

Caveat (decisive). Tier B conflates genuine repeats with coincidental
gap-isomorphs — windows sharing a gap pattern but encoding *different* plaintext
(e.g. `jX$j3g$S` shares only `(0,0,0,3,0,0,4,…)` with `PJ3P-O3Q`). `inspect_family.py`
shows a 6-occurrence `L=15` "family" with zero fully-shared columns — these are
not 6 renderings of one phrase. `Chaining-Conflicts.md` explicitly warns that
over-extended / non-same-plaintext isomorphs manufacture spurious conflicts.
So Tier B's large counts are an upper bound on evidence, not same-plaintext
evidence; the genuine signal is Tier A.

## 4. Thread 5 — chaining-graph coverage (transitivity premise)

Treating every non-fixed link `x↦y` as an edge on the 83 symbols:

- **Broad (Tier B):** 79 / 83 symbols touched (95%), in 1 connected
  component. Untouched values: `{1, 27, 28, 76}`. (All 83 symbols *do* appear
  somewhere in the corpus; the 4 are simply never in a chained position.)
- **Genuine (Tier A):** 28 / 83 symbols touched, in 5 components
  (sizes `[14,4,4,4,2]`).

"Nearly all symbols in one component" is well-supported by the broad graph but
much weaker on the genuine-only graph. Coverage is *evidence for* a transitive
action, not proof of it (per the thread doc's honesty note).

## 5. Null calibration — within-message multiset shuffle

Same Tier-B pipeline on 30 within-message shuffles (preserve per-message symbol
frequencies, destroy isomorphy). Real exceeds null on every structural metric;
`p = 1/31 ≈ 0.032` is the resolution floor (no shuffle reached real on any metric):

| metric | real | null mean | null max | p(≥real) |
|---|---:|---:|---:|---:|
| contexts | 492 | 21.9 | 52 | 0.032 |
| order-83 contexts | 392 | 17.5 | 42 | 0.032 |
| raw conflicts | 17 124 | 18.8 | 126 | 0.032 |
| independent conflict sets | 4 988 | 7.3 | 41 | 0.032 |
| coverage touched | 79 | 52.3 | 72 | 0.032 |
| largest component | 79 | 28.7 | 70 | 0.032 |
| #components | 1 | 9.1 | 18 | (real has *fewer*) |

The real chaining structure is emphatically not a within-message frequency
artifact: ~900× the null conflict count, and a single 79-node component where the
null fragments into ~9. (The null does not, however, address the
genuine-vs-coincidental distinction of §3 — it bounds frequency artifacts, not the
same-plaintext assumption.)

## 6. Positive control — synthetic non-commutative GAK

`positive_control.py` emits 5 isomorph instances of one 10-letter phrase under a
known non-commutative transitive state group `AGL(1,83) = C₈₃⋊C₈₂` (one of the
surviving candidates; not dihedral). The identical detector reports:
order-83-forcing contexts 13/20, commutativity conflicts 6, coverage
42/42 touched in 1 component, max chain 3. The pipeline fires on true
non-commutative GAK signal — the negatives in §3 are real, not detector failure.

---

## Verdict — how strongly does this support the three claims?

1. **Dihedral exclusion (`D₁₆₆`).** *Supported, with the wiki's own caveat
   quantified.* The full contradiction (order-83 forcing under both contexts ∧
   commutativity conflict) reproduces on the cited triple. But on
   provably-same-plaintext isomorphs it rests on exactly one witness whose
   conflict half is over-extension-bound (col9); no independent genuine witness
   makes it typo-robust. The exclusion holds conditional on assumptions
   A1 (same plaintext) + A5 (one global configuration) for that triple, exactly
   as the logic note concluded. Claim ceiling: this constrains the candidate group
   set to `{C₈₃:C₄₁, C₈₃:C₈₂, A₈₃, S₈₃}`; it says nothing about recoverable
   plaintext.
2. **Non-commutativity.** *Supported as a structural fact of the broad chaining
   graph* (thousands of conflicts, ~900× null), but the count of typo-robust,
   same-plaintext-corroborated conflicts is 0–1, not "a dozen independent." The
   broad abundance matches `Chaining-Conflict-Rates.md`'s point that conflicts are
   "the norm" for non-commutative groups — but most broad conflicts ride
   coincidental gap-isomorphs and cannot be cited as same-plaintext evidence.
3. **Transitivity coverage.** *Quantified.* Broad graph: 79/83 (95%) in one
   component — good support for the transitivity *assumption*. Genuine-only graph:
   28/83 in 5 components — weak. State it at the broad strength as evidence for,
   not proof of, a transitive action.

**Bottom line:** the empirical work reproduces the dihedral contradiction and
confirms the detector on a positive control, while honestly bounding how
much independent, typo-robust, same-plaintext evidence actually backs the
non-commutativity premise (little) versus how much rides coincidental
gap-isomorphs (a lot). The exclusion and the two premises are supported but
single-witness-fragile on the genuine isomorphs — precisely the gap a later
Thread-3 safe-isomorph list, or a fresh independent isomorph family, would need to
close.
