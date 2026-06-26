# G3 — the isomorph leak's information ceiling for the eyes

**Date:** 2026-06-26. **Thread:** G3 (quantify the isomorph leak's
information-theoretic ceiling). **Status:** DONE — the wiki's soft pessimism is
converted into a stated, mapping-independent feasibility number, anchored on a
**passing** calibration against G1b's measured `two` collapse.

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
aligned isomorph signature (26 occurrences) falls **~14× short** of the **367**
aligned observations needed to pin even *one* `S₈₃` coset-permutation, and the
coverage model — calibrated to reproduce G1b's measured `two` collapse —
predicts **98.6–99.8%** of the 1036 transitions **undecidable**. The
near-identity (≤4-swap) prior is what makes recovery even *conceivable*
(underdetermination drops from 71× to 7×), but it remains **> 1** (still
underdetermined).

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
| Coverage model geometry constant `G` | **calibrated** to G1b's `two`; eyes result robust to it |

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
  `isomorph::PatternSignature` primitive), the supply of group-element
  (Schreier coset-edge) constraints:

  | window | repeated kinds | max repeat (dominant) | aligned pairs `ΣC(occ,2)` | informative windows |
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
  `≥ N−1` of `N` cosets is `≈ N·ln N`: **N=12 → 29.8**, **N=83 → 366.8**
  (harmonic-exact `N·(H_N − 1) = 332.2`). This is for the **maximal** `H = S₈₂`;
  a larger hidden subgroup means fewer cosets `N` and a proportionally smaller
  demand.

---

## Part C — the ceiling (supply vs demand)

1. **Per-element recurrence shortfall.** Demand to fully pin one `S₈₃` element =
   **367**. Eyes supply: dominant length-4 signature **9** → **40.8×** short;
   richest signature **26** → **14.1×** short. **⇒ the eyes cannot fully pin even
   ONE element's `S₈₃` coset-permutation.** Contrast `two`: demand 29.8, supply
   76 → ratio **0.39 < 1** (it *can* pin one element — and G1b confirms `two`
   recovers a few edges/columns, yet still fails by stream coverage).

2. **Information-theoretic UPPER bound.** Total info the ciphertext can leak
   about the key is `≤ M·H_emp = 1036 × 5.79 = `**`6002 bits`**. Needed key
   entropy:
   - **(i) unconstrained `S_N`:** `M·log2(83!) = `**`428 800 bits`** →
     underdetermination **71.4×** (hopeless).
   - **(ii) near-identity (≤4 swaps/letter):** the neighborhood is
     `Σ_{k=0}^{4} C(83,2k)·(2k−1)!!`, `log2 = 41.9 bits/letter` →
     `M· = `**`43 424 bits`** → underdetermination **7.2×**.

   The near-identity prior is *what makes recovery even conceivable* (71× → 7×),
   but it is **still > 1**: even with the strongest stated prior, the ciphertext
   leaks ~7× too little information to determine the key.

3. **Coverage / undecidable-fraction model.** `decodable = min(M, G·occ·(1 −
   (1−1/N)^occ))`, where `(1 − (1−1/N)^occ)` is the coupon-collector coset
   coverage of one recurring element after `occ` aligned observations, `occ` is
   the dominant-signature occurrence count, and `G` is the dominant-signature
   multiplicity. When `occ ≪ N` this collapses to `≈ G·occ²/N`. For the eyes this
   predicts **99.8% undecidable** (w4-matched, occ=9) / **98.6% undecidable**
   (richest, occ=26).

---

## Part D — calibration (the BINDING positive control)

The coverage model is fed **G1b's measured `two` parameters** (N=12, M=698,
dominant length-4 occurrences = 76, out-degree = 8) and must reproduce G1b's
**measured** collapse band before any eyes number is licensed.

> **Model predicts `two`: 78.3% undecidable (21.7% uniquely covered).**
> **G1b measured: 76–83% undecidable (15–24% uniquely covered)
> ([G1b-RESULTS.md](G1b-RESULTS.md)). → calibration PASSES.**

The single geometry constant is `G = 2` (the number of comparably-dominant
repeated signatures supplying coverage; G1b recovered ~3–4 columns across ~2
dominant signatures). The eyes prediction is **robust to it**: undecidable =
**99.9% / 99.8% / 99.7%** for `G ∈ {1, 2, 3}`. The committed test
`two_calibration_positive_control_passes` asserts the `two` prediction lands
inside the measured band `[0.76, 0.83]` and that the eyes stay > 95% across `G` —
this is the passing positive control the honesty discipline requires.

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
near-`S₈₃` element (**14–41×** short), the ciphertext leaks **~7×** too little
information to determine the key even under the near-identity prior, and a model
**calibrated to G1b's `two`** predicts **98.6–99.8%** of transitions
undecidable. The quantified answer to the wiki's open question is **no** — at this
budget, with these assumptions.

This is a **recoverability** ceiling, not a verdict on GAK. The eyes remain
deterministic, engine-generated, strikingly structured data of unknown meaning;
unsolved; no primary developer source confirms recoverable plaintext.

**Reproducibility.** Every supply integer (M=1036, out-degree 10.24/3/19,
chaining 23 232/2112/20 982, isomorph 9/26, …), the analytic figures (367, 6002,
71.4×, 7.2×), the `two` calibration (78.3% ∈ band), and the sweep crossings
(N=4, N=20) are deterministic and asserted in `leak_ceiling.rs`'s `#[cfg(test)]`
battery (`measured_supply_is_pinned`, `demand_and_ceiling_are_consistent`,
`two_calibration_positive_control_passes`, `scaling_sweep_crossings_are_located`).
