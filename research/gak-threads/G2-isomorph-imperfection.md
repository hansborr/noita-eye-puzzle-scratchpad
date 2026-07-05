# G2 — forward isomorph-imperfection disproof (the GAK whole-family falsifier)

**Date:** 2026-06-26. **Thread:** G2 (push the only live whole-family GAK
falsifier — isomorph imperfection — forward as a *generative* test). **Status:**
done — a hardened negative: under extended windows, a matched loose-bar null,
and an explicit word-boundary discount, the eyes show 0 robust non-benign
internal violations *within the tested envelope* (single/double-column islands
with a far resync ≥ 8). The eyes are therefore not falsified by perfect
isomorphism (consistent with it); equivalently they trivially place at the
imperfect-isomorph family's ε = 0 end. This means GAK is not falsified
(mildly strengthened) — it does *not* prove the eyes are GAK, and it is
conditional on the benign attribution of the loose candidates and on the tested
break geometry (see scope below).

Mapping-independent throughout (ciphertext symbol equality and
first-occurrence gap structure only; no symbol→meaning mapping). The module is
[`src/analysis/isomorph_imperfection`](../../src/analysis/isomorph_imperfection/mod.rs);
the public entry is `run_isomorph_imperfection(config) -> Result<…>`. It consumes
[`perfect_isomorphism`](../../src/analysis/perfect_isomorphism/mod.rs) read-only
(no edits to that module).

## The falsifier

GAK is *proven* to produce perfect isomorphs: `c(ga) = c(a) ⇔ c(gb) = c(b)`
(the CT map partitions the group into right cosets of `H`). So one robust
same-plaintext isomorph that *breaks* where repeated plaintext predicts a match
— and is not explainable as a word boundary — would eject the eyes from the
entire perfectly-isomorphic family (CTAK < GCTAK < GAK < XGAK ≤
perfectly-isomorphic). That is the single most decisive possible result on the
disproof side (`research/frontier.md`). The honest expectation, going in, was a
clean negative; the contribution is making that negative hardened and
generative rather than a soft "we didn't find one."

---

## Honesty labels (binding)

| Quantity | Status |
| --- | --- |
| Window-scan robust / loose counts on the eyes | **Measured** (real corpus, extended windows) |
| Hardened matched-null bands (loose & robust) | **Measured** (within-message multiset-preserving shuffle, SplitMix64) |
| east4/west4 localization + benign-Stutter attribution | **Measured** geometry; attribution rests on the community's prior Stutter characterization (see caveat) |
| Imperfect-isomorph family + ε-sweep fit | **Model-conditional** — one constructed family, not all imperfect ciphers; the ε-axis comparison is qualitative only (5 synthetic messages vs the eyes' 9) |
| "Best-fit ε = 0" | **Degenerate** when observed robust = 0 — a restatement of "robust count = 0," not an independent gradient fit |
| Verdict (GAK not falsified / mildly strengthened) | follows from 0 robust violations given a firing positive control, within the tested far_run ≥ 8 / island ≤ 2 envelope, and conditional on the benign attribution of both loose candidates |

---

## (a) Hardened violation push on the eyes

### Extended windows

The canonical perfect-isomorphism scan ran windows `[8, 9, 11]`. G2 extends to
`[8, 9, 11, 13, 15, 17]` (bounded by the shortest message, east1 = 99 symbols;
the longest extended window 17 ≪ 99, validated at runtime). Longer isomorphs
localize breaks deeper and lower the chance-collision rate.

| window set | robust internal violations | loose candidates |
| --- | --- | --- |
| base `[8,9,11]` | **0** | 0 |
| extended `[8,9,11,13,15,17]` | **0** | 2 |

Extending the windows surfaces 2 loose candidates but 0 robust ones.

### Hardened matched nulls (the loose bar)

The existing scan nulls the *strong* bar; G2 adds a matched within-message-shuffle
null specifically for the loose-candidate class (two-sided break, short island
≤ `MAX_ISLAND_COLS` = 2, far resync run ≥ `POST_MIN` = 8 carrying a cross-island
back-reference). The shuffle preserves each message's symbol multiset
(SplitMix64-seeded Fisher–Yates), 2000 trials.

| null class | observed | null mean | q97.5 | max | add-one p |
| --- | --- | --- | --- | --- | --- |
| loose-candidate | 2 | 0.001 | 0 | 1 | **4.998e-4** |
| robust internal | **0** | 0.001 | 0 | 1 | **1.000000** |

Read this carefully — the within-message shuffle is structure-destroying, so
it is a *weak* null for the robust falsifier and the family-falsifier statistic
is not calibrated by it. The shuffle *destroys the isomorphs themselves*, so:

- The loose p = 5e-4 is not a falsification: any genuine
  isomorph-internal divergence will trivially exceed a null in which no isomorphs
  survive. The loose excess is evidence that the eyes' isomorphs are real,
  not evidence of imperfection.
- The robust add-one p = 1.0 carries no evidential weight: observed
  robust = 0 is the count's minimum, so the upper-tail p is pinned to the
  trivial count floor by construction, regardless of structure.

The binding calibration of the robust (family-falsifier) statistic is the
generative ε = 0 family (mean robust 0, §(b) below) — a
structure-*preserving* reference — not the shuffle. Under that calibration
the eyes' robust count of 0 matches the perfect-isomorph baseline and a robust
violation (the thing that would eject the family) is what is absent.

### Word-boundary discount

A break with no resync (trailing-edge divergence, no cross-island
back-reference) is exactly what perfect isomorphism predicts when the shared
plaintext ends — a possible word/segment boundary. G2 makes this explicit: such
breaks are discounted to internalness 0. Only a two-sided break that
flanks a short island (≤ 2 columns) and is followed by a far resync run (≥ 8)
carrying a cross-island back-reference earns positive internalness. A
family-ejecting violation must have high internalness and sit in the upper
tail of the matched robust null (add-one p ≤ α = 0.05) and not sit in a named
benign desync region. (See the verdict-gating note below: a robust count > 0 that
sits *within* the weak shuffle null is only a *candidate requiring follow-up*,
not an ejection.)

### Detector blind spot (tested envelope) — named explicitly

A break is counted a robust violation only if `far_run ≥ POST_MIN (8)` and
`island_cols ≤ MAX_ISLAND_COLS (2)` and a cross-island back-reference exists;
anything else is discounted to internalness 0 — invisible. The eye scan and
the entire positive-control family exercise only one geometry: a single
fresh-singleton island (= 1) with a long far resync. So "the detector fires on
imperfections" is demonstrated only for that shape.

Therefore the negative explicitly rules out only imperfections that produce
single/double-column islands with a far resync ≥ 8. Two named classes are
outside the tested envelope and would be missed:

- **short-resync** imperfections (`far_run < 8`) — too little re-synced flank to
  qualify;
- **wide-island** imperfections (`island_cols > 2`) — desync wider than the
  short-island bar.

This is a stronger statement than the generic "model-conditional" label: the
detection floor is the `far_run ≥ 8 / island ≤ 2` blind spot, and it is named so
a reader does not over-read "0 violations" as "0 imperfections of any shape."

### Both loose candidates (chased — the negative is conditional on *both*)

The extended scan surfaces two loose candidates, and the report now lists
every one (not only the east4/west4 pair). Both are localized precisely and
both fall in the named benign Stutter desync region (messages
east4/west4/east5):

| pair | offsets | island | far-run | internalness | region | promoted? |
| --- | --- | --- | --- | --- | --- | --- |
| east4 / west4 | 65 / 67 | 1 | 11 | **11** | Stutter | **no** |
| east4 / east5 | 68 / 69 | 1 | 29 | **29** | Stutter | **no** |

Both are genuinely *internal-shaped* (long, two-sided re-synced divergences, not
trailing boundaries). Note the second candidate (east4@68 / east5@69) is the
*more* internal-looking of the two (internalness 29 vs 11) — it was previously
invisible in the write-up, which is exactly why Fix F surfaces the full list.
Neither promotes to a robust violation because both fall inside the named benign
Stutter region. Under the GAK / perfect-isomorphism hypothesis a
delayed-hidden-state desync in this region is *expected* and benign; the community
has independently shown the Stutter section is reproducible by deck ciphers
(`frontier.md`), so attributing these there is grounded in prior work, not
assumed.

**Honest caveat (load-bearing):** the benign-Stutter attribution is the *only*
thing standing between these internalness-11 and internalness-29 candidates and
two promoted robust violations. The negative is conditional on the benign
attribution of both loose candidates — both happen to sit in the same Stutter
region, so a single rejection of the community's Stutter characterization would
turn east4@68/east5@69 (the most-internal-looking break in the corpus) and
east4@65/west4@67 into robust violations warranting direct scrutiny. This is not
an unconditional "no internal structure exists."

---

## (b) Imperfect-isomorph family + fit comparison (model-conditional)

To give the negative teeth, G2 constructs a generative imperfectly-isomorphic
cipher family parametrized by an imperfection rate ε: a GAK-like stream that, with
probability ε at each same-plaintext repeat, breaks the isomorph (emits a
non-matching ciphertext equality where perfect isomorphism predicts a match). The
same extended-window scan is run on synthetic streams across the ε grid.

### Firing positive control (binding)

Without a detector that *fires* on real imperfections, "0 violations on the eyes"
is meaningless. The control is asserted in `#[cfg(test)]`
(`imperfect_family_positive_control_fires`, four seeds; and
`single_broken_instance_is_an_internal_violation`, which shows one designed break
localizes as exactly one robust internal violation):

| ε | mean robust | max robust | mean loose | max loose |
| --- | --- | --- | --- | --- |
| 0.00 | **0.000** | 0 | 0.000 | 0 |
| 0.10 | 1.625 | 6 | 1.625 | 6 |
| 0.25 | 3.350 | 6 | 3.350 | 6 |
| 0.50 | 4.975 | 6 | 4.975 | 6 |
| 0.75 | 5.400 | 6 | 5.400 | 6 |
| 1.00 | 4.000 | 4 | 4.000 | 4 |

> **Positive control: ε = 1.00 mean-robust 4.000 vs baseline 0.000 → FIRED.**
> Detection threshold (first rate with mean-robust ≥ 1): **ε = 0.10**.

The detector finds robust internal violations as soon as ε ≥ 0.10, and is clean
(0) at ε = 0. (The slight dip at ε = 1.00 vs ε = 0.75 is expected: when *every*
repeat breaks there are fewer clean references for an aligned cross-message pair to
re-sync against, so some breaks fail the two-sided/far-run shape — the detector is
deliberately conservative.)

### The "fit" — degenerate, and qualitative only

The eyes' observed robust count is 0, which the code reports as best-fit
ε = 0.00. This is a degenerate restatement, not an independent fit. Because
ε = 0 gives mean robust 0 while *every* ε > 0 in the grid gives mean robust
≥ 1.625, the argmin of `|mean_robust(ε) − observed|` at `observed = 0` is
forced to 0 with no gradient to speak of. "Best-fit ε = 0 / not better
explained by any ε > 0" therefore says nothing more than "**robust count = 0**."

The ε-axis comparison is qualitative only for two further reasons: the
constructed family has 5 synthetic messages vs the eyes' 9 (robust counts
scale with the number of same-plaintext message *pairs*), and the synthetic motif
geometry differs from the eyes'. So the table maps *direction* (more ε → more
robust violations, detection from ε ≥ 0.10) but its absolute counts are not
commensurable with the eyes'. The community's borderline `A.B..B.A` pattern
(~13% chance coincidence) is captured here by the loose counts; the discriminating
non-benign robust statistic is 0 at every window.

**Scope (honest):** this is one constructed imperfect family. It populates the
alternative-hypothesis space the wiki asked for and shows the eyes do not exhibit
the robust signature it produces — it does not enumerate all ways a cipher could be
imperfectly isomorphic, and (per the blind-spot section) only probes the
`far_run ≥ 8 / island ≤ 2` break shape.

---

## Verdict

> **HARDENED NEGATIVE → GAK NOT FALSIFIED (mildly strengthened).** Under extended
> windows `[8,9,11,13,15,17]`, the eyes show **0 robust non-benign internal
> violations** *within the tested envelope* (single/double-column islands with a
> far resync ≥ 8). The robust-null add-one p = 1.0 is the **trivial count floor**
> (no evidential weight); the **binding calibration** is the generative ε = 0
> family (mean robust 0). **Both** high-internalness loose candidates
> (east4@65/west4@67, internalness 11; **east4@68/east5@69, internalness 29**) are
> attributed to the named benign Stutter region and do not promote. A firing
> positive control confirms the detector finds imperfections at ε ≥ 0.10 (for the
> tested break shape). The eyes are therefore **NOT FALSIFIED by perfect
> isomorphism (consistent with it)** — equivalently they trivially place at the
> family's **ε = 0.00** end. This **does not prove the eyes are GAK** (XGAK's
> upper edge is `≤`, not equality) and is **conditional** on the benign attribution
> of both loose candidates and on the tested geometry.

Verdict gating (Fix B). The family-ejecting branch fires only when a
robust non-benign count both survives the word-boundary discount and sits in
the upper tail of the matched robust null (add-one p ≤ α = 0.05). A robust
count > 0 that lands *within* the (weak, structure-destroying) shuffle null is
rendered as a "candidate violation requiring follow-up," not an ejection — the
code does not claim "survives the hardened null" unless it actually checks the
tail.

This is the disproof-side outcome the brief anticipated: a *legitimate*
GAK-not-falsified result, made rigorous by an explicit word-boundary discount, a
null-gated ejection branch, and a generative positive control — not merely the
absence of a find. It does not prove the eyes are GAK (XGAK's upper edge is
`≤`, not equality), and it is conditional on the benign-Stutter attribution of
both loose candidates and on the `far_run ≥ 8 / island ≤ 2` blind spot above.

**Claim ceiling:** the eyes remain deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.

Reproducibility. The hardened-negative assertions (0 robust at base and
extended windows; robust-null p > 0.05; loose candidates > 0 and exceeding the
shuffle null; the surfaced loose-candidate list matches the loose count and every
entry is benign and unpromoted; positive control fires; eyes best-fit ε = 0) are
pinned in the `isomorph_imperfection` module's `#[cfg(test)]` battery at a cheap
deterministic config. The headline integers in this note (loose-null
p = 4.998e-4, family-fit table, the two loose candidates east4@65/west4@67
[internalness 11] and east4@68/east5@69 [internalness 29], detection threshold
ε = 0.10) are the full-config canonical run (null_trials = 2000,
family_trials = 80), reproducible via
`cargo test --lib isomorph_imperfection -- --ignored --nocapture canonical_report_snapshot`.
