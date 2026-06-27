# G2 — forward isomorph-imperfection disproof (the GAK whole-family falsifier)

**Date:** 2026-06-26. **Thread:** G2 (push the only live whole-family GAK
falsifier — isomorph imperfection — forward as a *generative* test). **Status:**
DONE — a **hardened NEGATIVE**: under extended windows, a hardened loose-bar null,
and an explicit word-boundary discount, the eyes show **0 robust non-benign
internal violations**, and the eyes best-fit an imperfect-isomorph family at
**ε = 0** (perfectly isomorphic). This **strengthens GAK** rather than falsifying
it.

**Mapping-independent throughout** (ciphertext symbol equality and
first-occurrence gap structure only; no symbol→meaning mapping). The module is
[`src/analysis/isomorph_imperfection.rs`](../../src/analysis/isomorph_imperfection.rs);
the public entry is `run_isomorph_imperfection(config) -> Result<…>`. It consumes
[`perfect_isomorphism.rs`](../../src/analysis/perfect_isomorphism.rs) read-only
(no edits to that file).

## The falsifier

GAK is *proven* to produce **perfect** isomorphs: `c(ga) = c(a) ⇔ c(gb) = c(b)`
(the CT map partitions the group into right cosets of `H`). So **one robust**
same-plaintext isomorph that *breaks* where repeated plaintext predicts a match
— and is **not** explainable as a word boundary — would eject the eyes from the
entire perfectly-isomorphic family (CTAK < GCTAK < GAK < XGAK ≤
perfectly-isomorphic). That is the single most decisive possible result on the
disproof side (`research/frontier.md`). The honest expectation, going in, was a
clean negative; the contribution is making that negative **hardened** and
**generative** rather than a soft "we didn't find one."

---

## Honesty labels (binding)

| Quantity | Status |
| --- | --- |
| Window-scan robust / loose counts on the eyes | **MEASURED** (real corpus, extended windows) |
| Hardened matched-null bands (loose & robust) | **MEASURED** (within-message multiset-preserving shuffle, SplitMix64) |
| east4/west4 localization + benign-Stutter attribution | **MEASURED** geometry; attribution rests on the **community's prior Stutter characterization** (see caveat) |
| Imperfect-isomorph family + ε-sweep fit | **MODEL-CONDITIONAL** — one constructed family, not all imperfect ciphers |
| Verdict (GAK strengthened) | follows from 0 robust violations **given** a firing positive control |

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

Extending the windows surfaces **2 loose candidates** but **0 robust** ones.

### Hardened matched nulls (the loose bar)

The existing scan nulls the *strong* bar; G2 adds a matched within-message-shuffle
null **specifically for the loose-candidate class** (two-sided break, short island
≤ `MAX_ISLAND_COLS` = 2, far resync run ≥ `POST_MIN` = 8 carrying a cross-island
back-reference). The shuffle preserves each message's symbol multiset
(SplitMix64-seeded Fisher–Yates), 2000 trials.

| null class | observed | null mean | q97.5 | max | add-one p |
| --- | --- | --- | --- | --- | --- |
| loose-candidate | 2 | 0.001 | 0 | 1 | **4.998e-4** |
| robust internal | **0** | 0.001 | 0 | 1 | **1.000000** |

**Read this carefully — the loose p = 5e-4 is NOT a falsification.** The
within-message shuffle *destroys the isomorphs themselves*, so any genuine
isomorph-internal divergence will trivially exceed a null in which no isomorphs
survive. The loose excess is therefore evidence that the eyes' isomorphs are
**real**, not evidence of **imperfection**. The discriminating statistic for the
falsifier is the **robust non-benign** count, which is **0** and sits squarely
**within** its matched null (add-one p = 1.0, the count's minimum). A robust
violation is what would eject the family; there are none.

### Word-boundary discount

A break with **no resync** (trailing-edge divergence, no cross-island
back-reference) is exactly what perfect isomorphism predicts when the shared
plaintext ends — a possible word/segment boundary. G2 makes this explicit: such
breaks are discounted to **internalness 0**. Only a **two-sided** break that
flanks a short island (≤ 2 columns) and is followed by a far resync run (≥ 8)
carrying a cross-island back-reference earns positive internalness. A
family-ejecting violation must have high internalness **and** survive the
hardened null **and** not sit in a named benign desync region.

### The east4/west4 Stutter candidate (chased)

The one within-chance loose candidate previously noted in the canonical scan is
localized precisely:

> **east4@65 / west4@67**: island 1, far-run 11, **internalness 11**,
> benign-Stutter **true**, **promoted to robust violation: false**.

This candidate is genuinely *internal-shaped* (internalness 11 — a long, two-sided
re-synced divergence, not a trailing boundary). It does **not** promote to a robust
violation because it falls inside the **named benign Stutter desync region**
(messages east4/west4/east5). Under the GAK / perfect-isomorphism hypothesis a
delayed-hidden-state desync in this region is *expected* and benign; the community
has independently shown the Stutter section is reproducible by deck ciphers
(`frontier.md`), so attributing east4/west4 there is grounded in prior work, not
assumed.

**Honest caveat:** this is the load-bearing judgement of the whole negative. The
benign-Stutter attribution is the *only* thing standing between this internalness-11
candidate and a promoted robust violation. If the community's Stutter
characterization were rejected, east4@65/west4@67 would be the single
most-internal-looking break in the corpus and would warrant direct scrutiny. The
negative is conditional on that attribution; it is not an unconditional "no
internal structure exists."

---

## (b) Imperfect-isomorph family + fit comparison (model-conditional)

To give the negative teeth, G2 constructs a **generative** imperfectly-isomorphic
cipher family parametrized by an imperfection rate ε: a GAK-like stream that, with
probability ε at each same-plaintext repeat, **breaks** the isomorph (emits a
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

### The fit

The eyes' observed robust count is **0**, which lands the eyes at **best-fit
ε = 0.00** on this family — the perfectly-isomorphic end. The eyes are *not*
better explained by any ε > 0 in the constructed family. The community's borderline
`A.B..B.A` pattern (cited at ~13% chance coincidence) is captured here by the loose
counts; the discriminating non-benign robust statistic is 0 at every window.

**Scope (honest):** this is one constructed imperfect family. It populates the
alternative-hypothesis space the wiki asked for and shows the eyes do not prefer it
over perfect isomorphism — it does not enumerate all ways a cipher could be
imperfectly isomorphic.

---

## Verdict

> **HARDENED NEGATIVE → GAK STRENGTHENED.** Under extended windows
> `[8,9,11,13,15,17]`, the eyes show **0 robust non-benign internal violations**
> (within the matched null, add-one p = 1.0); the one high-internalness loose
> candidate (east4@65/west4@67) is attributed to the named benign Stutter region
> and does not promote; a firing positive control confirms the detector finds
> imperfections at ε ≥ 0.10; and the eyes best-fit the imperfect family at
> **ε = 0.00**. The eyes remain (at least very close to) **perfectly isomorphic**,
> consistent with GAK and inconsistent with the constructed imperfect family.

This is the disproof-side outcome the brief anticipated: a *legitimate*
GAK-strengthening result, made rigorous by a hardened null, an explicit
word-boundary discount, and a generative positive control — not merely the absence
of a find. It does **not** prove the eyes are GAK (XGAK's upper edge is `≤`, not
equality), and it is conditional on the benign-Stutter attribution above.

**Claim ceiling:** the eyes remain deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.

**Reproducibility.** The hardened-negative assertions (0 robust at base and
extended windows; robust-null p > 0.05; loose candidates > 0 and exceeding the
shuffle null; east4/west4 benign and unpromoted; positive control fires; eyes
best-fit ε = 0) are pinned in `isomorph_imperfection.rs`'s `#[cfg(test)]` battery
at a cheap deterministic config. The headline integers in this note
(loose-null p = 4.998e-4, family-fit table, internalness 11, detection threshold
ε = 0.10) are the **full-config** canonical run (null_trials = 2000,
family_trials = 80), reproducible via
`cargo test --lib isomorph_imperfection -- --ignored --nocapture canonical_report_snapshot`.
