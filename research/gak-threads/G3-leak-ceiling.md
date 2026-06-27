# G3 — the isomorph leak's information ceiling for the eyes

**Date:** 2026-06-26. **Thread:** G3 (quantify the isomorph leak's
information-theoretic ceiling). **Status:** DONE — the wiki's soft pessimism is
converted into a stated, mapping-independent feasibility number. The conclusion
rests on the **robustness** of the leak shortfall (the eyes are 98.6–99.9%
undecidable for *any* geometry constant `G ∈ {1,2,3}`), not on the single-point
`two` calibration, which is a **sanity check, not a licensing gate**.

**No new attack code; no symbol→meaning mapping.** All of this is supply we can
measure plus demand we can compute. The module is
[`src/analysis/leak_ceiling.rs`](../../src/analysis/leak_ceiling.rs); the public
entry is `run_leak_ceiling(config) -> Result<LeakCeilingReport, …>`.

## The question

The community wiki states plainly that it "might be unrealistic to expect
chaining to ever work for the eyes" given ~1036 trigrams against a near-`S₈₃`
group — but **nobody has quantified that ceiling** (`research/frontier.md`).
G3 answers: *is chaining recovery even possible for the eyes, and by how much
does the leak fall short?*

**Headline:** a quantified **NO** at this trigram budget. The eyes' **richest**
aligned isomorph signature (26 occurrences) falls **~13× short** of the **332**
aligned observations needed to pin even *one* `S₈₃` coset-permutation (the exact
`≥ N−1` demand `N·(H_N−1) = 332.2`; the full-collection asymptotic `N·ln N` is a
slightly larger 366.8), and a coverage model predicts **98.6–99.8%** of the 1036
transitions **undecidable** — and crucially **98.6–99.9% for any** geometry
constant `G ∈ {1,2,3}`, so the conclusion does **not** depend on the single-point
`two` calibration. The near-identity (≤4-swap) prior is what makes recovery even
*conceivable* (underdetermination drops from 71× to 7×), but it remains **> 1**
(still underdetermined).

This bounds **recoverability only**. It makes **no** claim that the eyes are or
are not GAK. The standing claim ceiling holds: the eyes are deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved.

---

## Honesty labels (binding)

| Quantity | Status |
| --- | --- |
| Part A supply (M, out-degree, chaining edges, isomorph occurrences) | **MEASURED** (read-only, real corpus) |
| Part B certification degree, coupon-collector demand | **ANALYTIC** (model-conditional) |
| Part C per-element shortfall, key-entropy needs, coverage prediction | **ANALYTIC & model-conditional** |
| MI figure (`M·H_emp`) | **UPPER bound** on leaked bits |
| Coupon demand `N·ln N` | for **maximal** `H = S₈₂` (`N = 83` cosets); **scales down** with a larger `H` |
| Coverage model geometry constant `G` | **single fitted constant** (one-parameter fit to one G1b `two` band — only `G=2` lands; not an independent prediction); **eyes result robust to it** (98.6–99.9% for any `G ∈ {1,2,3}`) |

---

## Part A — empirical supply (MEASURED)

Read from the accepted honeycomb reading layer
(`orders::read_corpus_message_values(corpus_grids, accepted_honeycomb_order)`).

- **M = 1036** trigrams over **N = 83/83** distinct symbols (9 messages,
  east1:99 … east5:114).
- **Raw successor out-degree** (the eyes' analogue of G1b's "out-degree 8 on all
  12 `two` symbols"): mean **10.24**, min **3**, max **19** over all 83 source
  symbols ⇒ per-step branching **log2(10.24) = 3.36 bits**. Unlike `two`'s flat
  degree-8, the eyes' readout is uneven (histogram peak at degree 10).
- **Chain-link supply** (`chaining_graph::compute_graph`), default window/core
  **11/9**: **23 232** links, **2112** contexts, **20 982** distinct directed
  edges, coverage **83/83**, 1 component (and at w9/c7: 15 273/1697/13 495;
  w13/c11: 28 145/2165/25 779 — all 83/83). **Caveat:** this is the *broad
  gap-isomorph graph* (collision-prone); full 83/83 coverage is **not**
  same-plaintext genuine supply (see `chaining_graph.rs`). It is *evidence*, not
  recoverable keystream.
- **Repeated-isomorph occurrence-pair supply** (pooled across messages, via the
  `isomorph::PatternSignature` primitive). The `ΣC(occ,2)` column counts aligned
  occurrence *pairs*, but these are **redundant** constraints over only ~`occ`
  *independent* coset observations, so the operative supply unit is `occ`
  (max-repeat), **not** the pair count — see the Part C supply-unit
  reconciliation:

  | window | repeated kinds | max repeat (dominant) | aligned occurrence pairs `ΣC(occ,2)` (redundant — see Part C) | informative windows |
  | --- | --- | --- | --- | --- |
  | 4 | 3 | **9** | 56 | 19 |
  | 6 | 10 | **26** | 845 | 109 |
  | 8 | 21 | 25 | 1382 | 218 |
  | 11 | 49 | 24 | 2112 | 428 |

  The **dominant** length-4 signature (matched to `two`'s length-4 dominant) has
  only **9** occurrences; the **richest** signature across all windows has **26**
  — "a few dozen," exactly as the wiki anticipated, versus `two`'s **76**.
- **Empirical per-symbol entropy** `H_emp = 5.79 bits` (message-weighted; the
  flat 83-symbol ceiling is `log2(83) = 6.375`).

---

## Part B — demand (ANALYTIC, model-conditional)

Each isomorph pair exposes `a⁻¹b` acting by right-multiplication on the `N`
right cosets of the hidden subgroup `H`; the chaining-graph edge color is a
Schreier coset edge (`frontier.md`).

- **Edge-overlap certification degree `t(N)`** (how many overlapping edges
  certify "same transformation"): in the sharply-`N`-transitive `S_N` (`S₈₃/S₈₂`)
  regime, **`t = N−1 = 82`** ("all edges"); in a low-transitivity (dihedral-like)
  regime, **`t ≈ 2`**.
- **Coupon-collector full-pin demand** to observe one element's permutation on
  `≥ N−1` of `N` cosets is the harmonic-exact `N·(H_N − 1)`: **N=83 → 332.2**
  (this exact `≥ N−1` value is the headline demand used in Part C). The full-`N`
  collection asymptotic `N·ln N` is a slightly larger **366.8** (and
  **N=12 → 29.8**). This is for the **maximal** `H = S₈₂`; a larger hidden
  subgroup means fewer cosets `N` and a proportionally smaller demand.

---

## Part C — the ceiling (supply vs demand)

1. **Per-element recurrence shortfall.** Demand to fully pin one `S₈₃` element on
   `≥ N−1` cosets = **332.2** (`N·(H_N−1)`; the full-collection asymptotic
   `N·ln N = 366.8` is slightly larger). Eyes supply: dominant length-4 signature
   **9** → **36.9×** short; richest signature **26** → **12.8×** short. **⇒ the
   eyes cannot fully pin even ONE element's `S₈₃` coset-permutation.** Contrast
   `two`: demand 29.8, supply 76 → ratio **0.39 < 1** (it *can* pin one element —
   and G1b confirms `two` recovers a few edges/columns, yet still fails by stream
   coverage).

   **Supply-unit reconciliation (Part A → Part C).** Part A's aligned-pair counts
   `ΣC(occ,2)` (56 / 845 / 1382 / 2112) are **redundant** constraints generated by
   only ~`occ` *independent* coset observations of the dominant element, so the
   operative supply unit here is `occ` (9, 26), **not** the pair count — several
   of those pair counts exceed the demand 332.2 yet still cannot pin an element.
   The `two` calibration confirms the unit empirically: feeding the
   `C(76,2) = 2850` aligned pairs as supply to the coverage model would falsely
   predict **~0%** undecidable, contradicting G1b's measured **76–83%** collapse;
   feeding `occ = 76` reproduces it.

2. **Information-theoretic UPPER bound** (on the **per-position keystream**, not a
   GAK seed). Total info the ciphertext can leak is `≤ M·H_emp = 1036 × 5.79 =
   `**`6002 bits`**. The `M·log2(neighborhood)` construction below treats all `M`
   positions as **independent** `S_N` draws — the **maximal-hidden-state**
   (`H = S₈₂`) regime — so it bounds the cost of pinning the *per-position
   transformation stream* a **model-free chaining recovery** must solve, **not** a
   single GAK deck seed (one seed is only ~`log2(83!) ≈ 414 bits`, which 6002 bits
   *over*-determines by ~15×). Needed per-position entropy:
   - **(i) unconstrained `S_N`:** `M·log2(83!) = `**`428 800 bits`** →
     underdetermination **71.4×** (hopeless).
   - **(ii) near-identity (≤4 swaps/letter):** the neighborhood is
     `Σ_{k=0}^{4} C(83,2k)·(2k−1)!!`, `log2 = 41.9 bits/letter` →
     `M· = `**`43 424 bits`** → underdetermination **7.2×**.

   The near-identity prior is *what makes recovery even conceivable* (71× → 7×),
   but it is **still > 1**: even with the strongest stated prior, the ciphertext
   leaks ~7× too little information **to pin the per-position keystream** (the
   object a model-free chaining recovery must solve). The factor is **per-symbol**
   (`41.9 / 5.79`, independent of the 1036-symbol budget). *Caveat:* this assumes
   the **maximal** `H = S₈₂`; with far fewer independent permutations (a smaller
   hidden subgroup) the leak could suffice.

3. **Coverage / undecidable-fraction model.** `decodable = min(M, G·occ·(1 −
   (1−1/N)^occ))`, where `(1 − (1−1/N)^occ)` is the coupon-collector coset
   coverage of one recurring element after `occ` aligned observations, `occ` is
   the dominant-signature occurrence count, and `G` is the dominant-signature
   multiplicity. When `occ ≪ N` this collapses to `≈ G·occ²/N`. For the eyes this
   predicts **99.8% undecidable** (w4-matched, occ=9) / **98.6% undecidable**
   (richest, occ=26).

---

## Part D — single-point geometry calibration (one fitted constant)

**What carries the conclusion is robustness, not this calibration.** The length-4
dominant signature gives undecidable = **99.9% / 99.8% / 99.7%** for
`G ∈ {1, 2, 3}`, and the richest signature gives **98.6%** at the calibrated
`G = 2` (and `> 98%` across the same `G` range) — so across the realistic spread
the eyes are **98.6–99.9% undecidable regardless of `G`**, and the headline NO
does **not** depend on fixing it. The calibration below is a **sanity check**,
not a licensing gate.

The coverage model is fed **G1b's measured `two` parameters** (N=12, M=698,
dominant length-4 occurrences = 76, out-degree = 8):

> **Model predicts `two`: 78.3% undecidable (21.7% uniquely covered).**
> **G1b measured: 76–83% undecidable (15–24% uniquely covered)
> ([G1b-RESULTS.md](G1b-RESULTS.md)). → lands in band.**

**This is a single-point, one-free-parameter fit, not an independent
prediction.** The one free constant is the geometry multiplicity `G` (the number
of comparably-dominant repeated signatures supplying coverage; G1b recovered ~3–4
columns across ~2 dominant signatures). Sweeping it, **only `G = 2` lands in the
measured band `[0.76, 0.83]`** (`G = 1 → ~89%`, `G = 3 → ~67%`): `G = 2` is *fit
to* the band, not predicted, and because `G` is continuous the model essentially
**cannot fail** the single-band check. The committed regression test
`two_calibration_lands_in_band` pins this arithmetic (78.3% ∈ `[0.76, 0.83]`, and
the eyes stay > 95% across `G`) as a deterministic **sanity check** — **not** a
falsifiable positive control, and **not** something that "licenses" the eyes
number.

### Two real weaknesses of the calibration

1. **Length-matched miss.** Fed `two`'s own length-4 point (occ=76), the model
   predicts **78.3%** undecidable, but G1b's **measured length-4** undecidable is
   **83%** — the band's **high** edge. Equivalently the model's decodable count is
   **151.8** versus G1b's measured length-4 uniquely-covered **105** — the model
   is **~45% optimistic on the very point it is fed**, and only "lands in band"
   because the band `[0.76, 0.83]` also spans the (longer-phrase) length-6 row.
2. **Regime mismatch (the load-bearing factor was never exercised).** For `two`,
   `occ = 76 > N = 12`, so the coupon-coverage factor `(1 − (1 − 1/N)^occ) =
   0.9987` is **saturated** (`≈ 1`) and the fit reduces to pinning `G·occ/M`. But
   for the **eyes** `occ ≪ N` (9, 26 vs 83), so that coverage factor
   (**0.10 / 0.27**) is the **load-bearing** term — and it was **never exercised**
   by the `two` calibration. The eyes conclusion survives this anyway: even at the
   saturated `coverage = 1`, the eyes are still **≈ 95%** undecidable (richest
   occ=26).

**Model scope (honest limitation):** the model is calibrated *at the length-4
reference window* (same window used for the eyes prediction). It is not claimed to
track the phrase-length dependence of G1b's table (it is too pessimistic at L=6,8
because `occ` alone undercounts the extra columns longer phrases recover). The
eyes conclusion does not depend on this: the eyes' occ (9 at L=4, 26 richest) is
so much smaller than `two`'s 76 that the prediction is 98.6–99.8% either way.

### Scaling law

`undecidable_fraction(N)` at fixed **M = 1036**, with the analytic dominant-repeat
supply `occ(N) = M/N` (near-uniform) and `G = 2`:

| N | occ(N) | undecidable | note |
| --- | --- | --- | --- |
| 4 | 259 | **50.0%** | 50% crossing |
| 12 | 86 | **83.4%** | ≈ `two` |
| 20 | 51.8 | **90.7%** | 90% crossing |
| 32 | 32.4 | 96.1% | |
| 50 | 20.7 | 98.6% | |
| 83 | 12.5 | **99.7%** | **the eyes** |

The undecidable fraction **crosses 50% at N≈4 and 90% at N≈20**, so across the
whole eyes-relevant range (`N = 12 … 83`) it never drops below ~83%. `two`
(N=12) and the eyes (N=83) sit on this curve at its lower and upper ends.

---

## Bottom line

The isomorph leak is the eyes' load-bearing object, but at **1036 trigrams over
83 symbols** it is too thin to drive a chaining recovery: it cannot pin even one
near-`S₈₃` element (**~13–37×** short of the exact `≥ N−1` demand 332.2; 366.8 on
the full-collection asymptotic), the ciphertext leaks **~7×** too little
information **to pin the per-position keystream** (the object a model-free
chaining recovery must solve) even under the near-identity prior, and a coverage
model predicts **98.6–99.8%** of transitions undecidable — and **98.6–99.9% for
any** geometry constant `G ∈ {1,2,3}`. The verdict rests on that **robustness**,
the **per-element shortfall**, and the **information-theoretic
underdetermination** (~7×), **not** on the single-point `two` calibration. The
quantified answer to the wiki's open question is **no** — at this budget, with
these assumptions.

This is a **recoverability** ceiling, not a verdict on GAK. The eyes remain
deterministic, engine-generated, strikingly structured data of unknown meaning;
unsolved; no primary developer source confirms recoverable plaintext.

**Reproducibility.** Every supply integer (M=1036, out-degree 10.24/3/19,
chaining 23 232/2112/20 982, isomorph 9/26, …), the analytic figures
(332.2 / 366.8, 6002, 71.4×, 7.2×), the `two` calibration (78.3% ∈ band), and the
sweep crossings (N=4, N=20) are deterministic and asserted in `leak_ceiling.rs`'s
`#[cfg(test)]` battery (`measured_supply_is_pinned`,
`demand_and_ceiling_are_consistent`, `two_calibration_lands_in_band`,
`scaling_sweep_crossings_are_located`).
