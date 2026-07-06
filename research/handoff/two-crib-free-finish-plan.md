# `two` — crib-free finish plan (ns=3 lesson transfer)

Status: **PARTIAL RESULT / follow-up narrowed** (2026-07-06). The ordered plan
below was driven through Phase 2 far enough to surface a strong plaintext
hypothesis; see
`research/findings/two-shadowfinish-substitution-candidate.md` and
`research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`.
We still do **not** call this a verified decode until original-generator or
withheld-ground-truth confirmation lands.

Original scope: the crib-free finish of practice puzzle `two`. We held no
plaintext, no crib, no key; the maintainer's withheld snippet remained a
last-resort fallback.

## 2026-07-06 update

Phases 1-2 produced a `shadowfinish` candidate (`null_ge 0/49`,
`p_emp 0.0200`). The raw mixed-case candidate had exactly 26 non-space symbols,
and the new `substfinish` monoalphabetic finisher recovered a readable
octal-system / Proto-Indo-European plaintext hypothesis (`null_ge 0/20`,
`p_emp 0.0476`) against space-position-preserving shuffles. The remaining
cleanup is punctuation/hyphen/source alignment, not broad search.

Current next actions:

- keep the result labelled candidate/hypothesis until ground-truth confirmation;
- optionally add punctuation-aware finishing if exact punctuation matters;
- only build the stage-(ii)-replaying null if we need a full-pipeline statistical
  claim rather than a practice-puzzle solve record.

This plan applies the ns=3 methodology lesson (`attack-methodology.md` #12: *a
caution/limit you assumed rather than measured is not a result*) to `two`, and
folds in a two-family design consult (Codex `gpt-5.5` + Gemini `3.1-pro`,
both read-only; provenance at the end).

## TL;DR — ordered plan

| Phase | Lever | Prio | Why here |
| --- | --- | --- | --- |
| 0 | **Pair-IC class ranking** (codec-free diagnostic) | P0, ms | Cheapest-decisive-first; may collapse the class axis for free |
| 1 | **Fix the finish discriminator + Tier-A retention** | P0 | The current scorer is broken; measuring against it just measures noise faster |
| 2 | **Powered conditional measurement** (≥20–49 nulls) | P0 | Turn the runtime-limited non-answer into a real *measured* verdict |
| 3 | **Broaden the null** (pipeline-level claim) | P1 | Only needed to upgrade "given these 24 classes" → a pipeline exclusion |
| 4 | **Supergroup lift (order-48 → 96)** | P1 | True-key recovery / parity-trap escape; does **not** close the finish gap |

The spine: **decompose the finish into cheap invariant layers and settle them
before the expensive one** — the crib-free analogue of ns=3's substitution-first
coordinate descent. Do not build a faster monolithic 13.5M brute enumerator.

## The reframe (why we reopen this)

`shadowfinish` reduced `two` to **24 canonical q-pattern classes** and then
enumerated the finish surface = `24 classes × 8! label→digit perms × 2 digit
orders (HL/LH) × 7 tables ≈ 13.5M interpretations`, returning verdict
**`LowPowerNoExclusion`**. Two facts frame it:

1. **Re-encode round-trip is tautological here** (`attack-methodology.md` #11,
   `shadow_finish/mod.rs:39`): the readout codec is co-searched and bijective, so
   every in-range candidate re-encodes to the ciphertext by construction.
   Round-trip has **zero** power to select the interpretation and must be kept as
   an internal invariant only, never an acceptance driver.
2. The verdict was `LowPowerNoExclusion` **because only 2 matched nulls were
   affordable** (a 20-null run was "runtime-impractical for this unoptimized
   implementation"). With 2 nulls you cannot reach α=0.05. The recon doc itself
   calls this "a runtime/power limitation to fix before making a stronger call"
   (`two-cross-agent-recon.md:324`).

So the current stopping point is a **runtime verdict wearing a power verdict's
clothes** — the exact ns=3 trap one level up. We have not actually measured
whether language resolves the ~10^6 residual crib-free. There is **no
information floor** against doing so: ~10^6 candidates need ~20 bits to resolve,
and 349 characters of English carry >300 bits of redundancy (both consults
concur). The gap is closable in principle; the question is a real measurement.

## The verified obstruction (fix this before "more nulls")

Codex read the code and found the nearest obstruction, verified in this session:
**the finish discriminator itself is not yet trustworthy**, so running a bigger
null battery against it would only measure a broken scorer faster.

- **No coverage penalty.** `combined_score = 0.05·quadgram + 0.65·word.mean_logp
  + 0.30·anchor_mean` (`scoring.rs:185`) ranks on *mean* word/anchor logprob.
  `normalize_letters` (`scoring.rs:173`) and `score_quadgrams` (`scoring.rs:163`)
  drop every non-alphabetic byte before scoring. A candidate that is mostly
  punctuation/symbols but whose few real letters happen to form words scores
  well on the mean. The logged "winning" hypothesis
  (`research/gak-threads/candidates/shadowfinish-two-shadowfinish-null2-seed-736861646f776603.md`)
  is a 349-char string dominated by symbol soup — exactly this failure.
- **Tier-A retention prunes on the wrong statistic.** Tier A keeps the top-K
  per class by **quadgram only** (`engine.rs:196` → `offer_top_a` at
  `engine.rs:204/444`). If the final acceptance statistic is word-DP / self-crib,
  a truth interpretation that is strong on the final statistic but weak on
  quadgram is discarded before Tier B ever sees it.

## Phase 0 — Pair-IC class ranking (cheapest-decisive-first)

**Insight (Gemini, mathematically checked):** the codec reads 2 octal digits per
letter, so a class's 698-symbol q-stream is 349 `(q_hi, q_lo)` pairs, each a value
in `0..63`. The finish surface's three free knobs — the 8! label→digit
permutation, the HL/LH digit order (transpose), and any **injective** 6-bit→char
table — are *all bijections on the 64 pair-values*. The index of coincidence of
the pair-value sequence, `IC = Σ_v n_v(n_v−1) / (N(N−1))`, is invariant under any
relabeling of the value set, hence **invariant across the entire 13.5M codec
surface**. Because each pair-value is exactly one plaintext letter (injective
table), a class's pair-IC equals its underlying letter monogram IC — English
≈ 0.0667, flat junk ≈ 1/26 ≈ 0.038 or lower.

**Do:** compute pair-IC (phase-0 pairing) for each of the 24 classes and rank by
closeness to the English monogram IC. This costs milliseconds and pays for
nothing in the codec search. Build it as a self-validating instrument
(`build-reusable-cli-tools`): a self-test that plants English → codec → applies a
random 8!/HL-LH/injective-table and asserts pair-IC is **unchanged** (invariance),
plus a matched null showing a flat class scores away from English.

**Reconciliation of the consult disagreement — read this before over-trusting it.**
Gemini framed Pair-IC as a decisive class selector; Codex cautioned it is a cheap
feature, not a verdict. Both are right about different things: the invariance is
real (the 8! genuinely *cannot* move pair-IC), so it is a valid **free class-axis
ranker / necessary-condition filter**; but at N=349 across 24 classes a junk class
can land near 0.0667 by chance, so it must **not** be an acceptance verdict. Use
it to (a) order which classes get the expensive anchored finish first, and (b) as
one feature. If the ranking turns out sharply peaked (one class English-like, 23
flat), that is a large free win that shrinks Phases 1–2 to a handful of classes;
if it is flat, you have spent milliseconds and proceed with all 24.

## Phase 1 — Fix the finish discriminator + Tier-A retention (P0)

Make the discriminator score *real text*, not sparse normalized letter islands:

- **Coverage-aware acceptance.** Add a strict natural-language byte-coverage term:
  fraction of bytes in the strict text set (`tables.rs:160`), alphabetic+space
  ratio, and explicit penalties for digit/symbol spam. The verdict statistic must
  punish a 349-char decode that is mostly punctuation.
- **Repeated-anchor phrase plausibility, not equality.** The two occurrences of
  the ~30-letter span are already equal by q-anchor construction (that equality is
  *baked in* and carries no evidence). The evidence is that the span is *plausible
  English with real character coverage* — score that (word-segmentation of the
  span), and guard it with dirty/boundary-aware controls (#8): after trimming, the
  span may start/end mid-word, so a clean planted anchor would miss the real
  boundary failure mode.
- **Fix Tier-A retention.** Retain the top-K per class by a **union / cheap
  approximation of the final statistic** — strict/natural-byte coverage + letter/
  space ratio + anchor coverage + quadgram — not quadgram alone, so a truth
  interpretation that is strong on the final statistic survives to Tier B.
- **Drop round-trip from acceptance** (#11): keep it as an internal invariant with
  the existing vacuity self-test; the verdict is language only.

**Strongest discriminator (both families, reconciled):** coverage-aware full-byte
English word-segmentation / MDL over the whole 349-char decode, plus a separate
repeated-anchor phrase score. IC / space-rate / strict-byte-rate are cheap
filters and features, **not** verdicts. Do not expect IC or positional frequency
to out-resolve a coverage-aware full-text model; the 8! can tune weak marginals
and broad scoring has shown multiple-comparison swamping (`CODEC-RESULTS.md`
Round 8 lessons).

**Positive control (end-to-end, per #2):** plant real English → codec → shadow
key → run the *whole* fixed finish → assert the truth interpretation survives
Tier A and wins Tier B with margin. A control that only checks the optimizer
certifies nothing about the negatives.

## Phase 2 — Powered conditional measurement (P0)

With the fixed discriminator, run the real measurement on the existing 24-class
conditional surface:

- **≥20 matched nulls, preferably 49** if candidate acceptance wants p ≤ 0.02.
- Use the Phase-0 pair-IC ranking to order class evaluation (cheap classes first).
- **Pre-register the exact claim:** this is a *conditional* verdict — "given these
  24 max-soft classes, does the true finish separate from matched nulls." That is
  a legitimate, scoped claim; it is **not** yet a pipeline-level exclusion.
- **Outcome vocabulary:** `Candidate` (separates with margin — then log as a
  HYPOTHESIS per `candidate-cleartext-logging`, still not a verified decode without
  an independent anchor), `NoCandidate`, or a **measured** `LowPowerNoExclusion`
  (distinct from today's runtime-limited one — this would be real evidence the
  conditional surface lacks power, and progress).

## Phase 3 — Broaden the null for the pipeline-level claim (P1)

The current null is explicitly only decoy label-shuffles of the retained max-soft
classes; it does not replay stage-(ii) survivor / non-max selection over the full
104,096 survivors (`two-cross-agent-recon.md:319`, candidate file "Matched-null
scope"). That is fine for the Phase-2 conditional claim but **invalid for a
pipeline-level exclusion**. To make a pipeline claim, the null must replay the
stage-(ii) selection pressure. Per #12b, **pre-register which question each null
answers** — conditional-finish, full stage-(ii)+finish, and supergroup-expanded
nulls are three different claims; do not let one adjudicate another.

## Phase 4 — Supergroup lift, order-48 → 96 (P1, post-finish)

Escape the parity trap (#9): all strong repeated-plaintext anchors have even gaps,
so the isomorph closure could only expose an index-2, order-48 shadow of the true
order-96 group. Enumerate small block-preserving supergroups consistent with the
same invariants and redo the key search. **Caveat (both families):** this
constrains the *key*, not the co-searched codec — it does **not** restore
round-trip power and does not remove the codec-selection problem. Sequence it
*after* the finish gate can adjudicate candidates, where it completes true-key
recovery rather than being on the critical path to a crib-free reading.

## What does NOT transfer (honest limit)

The ns=3 solve was **known-plaintext** with direct `perm[0]` anchors from exact
message starts, which is what let substitution-first coordinate descent settle a
layer *by equality* and defuse the avalanche in 14 s. `two` crib-free has **no
direct letter observations**: the self-crib and pair-IC constrain by *language and
invariant statistics*, not by equality, so there is no clean layer to pin exactly.
The transfer buys us **a measurement we skipped**, not a guaranteed solve. If the
powered Phase-2 battery still shows no separation, that is finally a *measured*
low-power verdict, and the honest fallback (the maintainer's withheld snippet,
not requested) stands.

## Operational constraints

Heavy search runs on this host have OOM-killed the container before
(`practice-puzzles-one-two-analysis` memory; `CODEC-RESULTS.md` Round 4/5). The
Phase-1/2 finish work is CPU-bound, not the 11 GB beam, but keep it
memory-bounded and get maintainer sign-off before any large run. Land every
capability as a file-driven, self-validated CLI instrument exercised by tests
through the same library functions (`build-reusable-cli-tools`); no throwaway
scripts.

## Definition of done (per phase)

- **P0:** pair-IC instrument + invariance self-test committed; 24-class ranking
  reported (peaked or flat).
- **P1:** fixed discriminator + retention committed; end-to-end positive control
  passes; dirty-boundary anchor control passes; round-trip demoted; the symbol-soup
  candidate no longer out-scores real text.
- **P2:** ≥20-null conditional run with a pre-registered claim; a measured verdict
  (Candidate / NoCandidate / measured-LowPower) replaces the runtime-limited one.
- **P3:** stage-(ii)-replaying null built; pipeline-level claim adjudicated.
- **P4:** supergroup enumeration + lifted key search (only if a finish candidate
  earns it).

## Consult provenance (read-only design consults, 2026-07-05)

- Codex `gpt-5.5`, session `019f34e2-ff10-7813-a3b7-3afaa8430a75`. Found the
  verified discriminator/Tier-A obstruction (`scoring.rs:173/185`,
  `engine.rs:196/204`); demoted IC to a feature; ordered fix-scorer-before-nulls;
  added coverage gate, per-null pre-registration, dirty-boundary controls.
- Gemini `3.1-pro-preview` via Copilot, session
  `874cf5c6-28fb-49f1-bb40-2dca5ab06139`. Confirmed no information floor;
  contributed the pair-IC invariance (a codec-free class-axis ranker) and the
  layer-decomposition framing.
- Brief: `scratchpad/two-consult-brief.md` (this session).
