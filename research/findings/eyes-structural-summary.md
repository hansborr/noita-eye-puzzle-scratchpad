# Eyes structural summary: current computational frontier

This is a synthesis of the mapping-independent structural work on the Noita eye
messages. It is not a new computation and it does not propose a plaintext. The
results below use ciphertext-symbol equality, isomorph structure, and group
structure over the verified reading-layer corpus. Where the GAK candidate-family
argument is discussed, the assumptions are the shared-plaintext interpretation of
the shared sections and one global cipher configuration; rejecting those
assumptions weakens the whole transitivity/GAK framing, not just one exclusion.

The substrate is fixed but not decoded: 9 messages, 1036 reading-layer trigrams,
83 distinct symbols under the accepted honeycomb reading order, and no public
method-backed plaintext. Those corpus facts and the broader solvability caveat
are summarized in
[`03-confirmed-vs-speculation.md`](../03-confirmed-vs-speculation.md), with the
GAK-frontier framing in [`frontier.md`](../frontier.md).

## What the structural program asked

The community GAK framing leaves two useful, mapping-independent questions:

1. Can the isomorph leak recover information, ideally the plaintext-to-group
   action or enough of it to attack the eyes?
2. Can GAK be falsified without a symbol-to-meaning mapping?

The completed workbench answer is asymmetric. GAK is not falsified: the eyes
remain consistent with perfect isomorphism within the tested envelope. Recovery,
however, is not supported at the current data budget: the measured isomorph leak
is too thin, and the matured GAK attack produces no surviving eye candidate.

## Candidate group family

Under the GAK/transitive-action hypothesis, the state group on 83 symbols is one
of exactly six transitive groups:

`C₈₃`, `D₁₆₆`, `C₈₃:C₄₁`, `AGL(1,83)=C₈₃:C₈₂`, `A₈₃`, `S₈₃`.

That six-group count is an audited theorem application: the solvable part is
`τ(82)=4`, and the non-solvable prime-degree cases contribute only `A₈₃` and
`S₈₃`, conditional on the standard classification of 2-transitive groups of
prime degree. The proof note also records the remaining tooling gap: no direct
GAP `NrTransitiveGroups(83)` cross-check was available. Source:
[`thread-1a-transitivity-proof.md`](../gak-threads/notes/thread-1a-transitivity-proof.md).

After the wave-2 structural landings, the working candidate set is narrowed to
`{A₈₃, S₈₃}`, with `D₁₆₆` kept as a conditional/medium-confidence exclusion:
`C₈₃` is out by the non-commuting chaining evidence, both affine variants are
excluded by the AGL result, and `D₁₆₆` is single-witness-fragile but conditionally
excluded. This narrowing is explicitly model-conditional on shared plaintext plus
a single global configuration. Sources:
[`wave-2-summary.md`](../gak-threads/notes/wave-2-summary.md) and
[`PROGRESS.md`](../gak-threads/PROGRESS.md).

## AGL is excluded, and the verdict is transcription-hardened

The AGL result covers the point-stabilizer AGL-GAK model: right-multiplication
state update, a single shared running key, and ciphertext symbol equal to the
moved reference point. In that model, a non-identity affine discrepancy over
`ℤ/83` fixes at most one point. A varying shared run after a differing
predecessor is therefore impossible.

The eyes have the all-nine shared prefix witness: nine distinct first symbols,
then a shared length-2 run at offset 1 with values `[66, 5]`. The exhaustive
enumeration confirms the lemma over the two affine candidates:

| Subgroup | Discrepancies | Fixing at least 2 points | Max fixed points |
| --- | ---: | ---: | ---: |
| `C₈₃:C₈₂` | 6724 | 0 | 1 |
| `C₈₃:C₄₁` | 3362 | 0 | 1 |

That moves the wiki's tentative AGL exclusion to an exhaustive exclusion for this
model. Source: [`agl-exclusion.md`](agl-exclusion.md).

The T02 source-layer robustness certificate then perturbs the rendered
orientation digits that feed the load-bearing prefix region and rebuilds through
`GlyphGrid` plus the accepted honeycomb order. It does not edit reading-layer
values directly. The AGL verdict survives all enumerated counterfactuals:

| Perturbation scope | Variants | AGL still excluded | Dissolving perturbations |
| --- | ---: | ---: | ---: |
| Exactly 1 source digit | 324 | 324 | 0 |
| Exactly 2 source digits within one message | 5184 | 5184 | 0 |

The preferred all-nine `[66, 5]` witness is locally fragile as a witness: it is
preserved exactly in 78 one-digit variants and 257 bounded two-digit variants,
and 51 / 1516 variants respectively leave the accepted 83-symbol alphabet. The
verdict, not that exact witness, is what is robust in the bounded perturbation
model. Source: [`agl-exclusion.md`](agl-exclusion.md#7-transcription-robustness).

## Perfect isomorphism is supported, not proved

The whole-family falsifier is isomorph imperfection: one robust same-plaintext
isomorph that breaks where perfect isomorphism predicts a match, and is not a
word boundary or named benign desync, would eject the eyes from the
perfectly-isomorphic region containing GAK.

G2 extended the scan windows to `[8, 9, 11, 13, 15, 17]` and found 0 robust
non-benign internal violations in the tested envelope: single/double-column
islands with far resync at least 8. It surfaced 2 loose candidates, both in the
named Stutter region: `east4@65 / west4@67` with internalness 11, and
`east4@68 / east5@69` with internalness 29. Both are attributed to the benign
Stutter region and do not promote. The detector's positive control fires at
epsilon >= 0.10 in the constructed imperfect-isomorph family, while epsilon 0
has mean robust 0. Source:
[`G2-isomorph-imperfection.md`](../gak-threads/G2-isomorph-imperfection.md).

This is a hardened negative, not proof that the eyes are GAK. It depends on the
benign-Stutter attribution of both loose candidates and on the stated detector
geometry. Short-resync and wide-island imperfections are outside the tested
envelope. Source:
[`G2-isomorph-imperfection.md`](../gak-threads/G2-isomorph-imperfection.md#verdict).

The T03 source-layer sensitivity certificate quantifies the Stutter caveat over
messages `east4`, `west4`, and `east5`, reading offsets `65..69`, and the source
orientation digits that feed those offsets:

| Perturbation scope | Variants | Negative survives | Promoted robust variants |
| --- | ---: | ---: | ---: |
| Exactly 1 source digit | 180 | 180 | 0 |
| Exactly 2 source digits within one message | 5040 | 5039 | 1 |

The single flipping counterfactual is two coordinated `east5` edits:
`east5#219 (raw224) 4->3` and `east5#220 (raw225) 1->3`, promoting
`east4@86 / east5@87` to a non-benign robust candidate. This is a fragility
certificate over counterfactual source edits; the verified transcription remains
the data. Source:
[`G2-isomorph-imperfection.md`](../gak-threads/G2-isomorph-imperfection.md#transcription-sensitivity-around-the-stutter-region-t03).

## The isomorph leak is too thin for recovery at this budget

G3 asks whether chaining recovery is feasible from the measured isomorph leak. It
answers no for the current corpus and assumptions.

The eyes have `M = 1036` reading-layer trigrams over `N = 83` symbols. The
richest aligned isomorph signature supplies 26 occurrences; the dominant
length-4 signature supplies 9. The demand to pin even one near-`S₈₃`
coset-permutation on at least `N-1` cosets is the harmonic-exact
`N * (H_N - 1) = 332.2` observations; the full-collection asymptotic is 366.8.
So the richest eye signature is 12.8x short, and the length-4 signature is 36.9x
short. Source: [`G3-leak-ceiling.md`](../gak-threads/G3-leak-ceiling.md).

The same note gives the information bound: the ciphertext leak is at most
`M * H_emp = 6002` bits. Pinning an unconstrained per-position `S₈₃` stream would
need 428800 bits, a 71.4x underdetermination. Even with the near-identity
`<=4`-swaps-per-letter prior, the demand is 43424 bits, still a 7.2x
underdetermination. The coverage model predicts 98.6% to 99.8% of transitions
undecidable at the calibrated point, and 98.6% to 99.9% undecidable for geometry
constant `G in {1, 2, 3}`. Source:
[`G3-leak-ceiling.md`](../gak-threads/G3-leak-ceiling.md#bottom-line).

This is only a recoverability ceiling. It does not say the eyes are or are not
GAK; it says the currently measured leak is not enough to drive a model-free
chaining recovery in the near-`S₈₃` regime.

## The matured GAK attack gives a fair honest negative on the eyes

Thread 4 built the attack rather than merely arguing about it. The synthetic
gates are positive: GCTAK is solved in a rate-beats-null setup, and the
hidden-state deck attack recovers partial visible-coset action on synthetic GAK,
with truth-free marginalization improving recovery by about 5.9x / 3.9x / 4.9x /
2.8x for `n = 5..8` before the `(n-1)!` hidden-state wall dominates. These are
tractability results, not eye decodes. Source:
[`wave-2-summary.md`](../gak-threads/notes/wave-2-summary.md#3-thread-4--the-gak-attack-end-to-end).

The one unit that touches the real eyes is Step 3. It uses the verified entry
path, preserves message boundaries, enforces Thread-3 safe isomorph extents, and
scores against a matched within-message shuffle null. The result is a clean
negative:

| Gate-1 quantity | Value |
| --- | ---: |
| Real hits | 0 |
| Real misses | 0 |
| Ambiguous held-out edges | 84 |
| Coverage-weighted score | 0 |
| Matched-null trials with score >= real | 2000 / 2000 |
| Add-one p | 1.0000 |
| Eyes material-effect bar | 1722 |
| Eyes max-achievable score | 6888 |

The eyes could have passed: the material-effect bar is below their own
max-achievable score, and the held-out positive control fires on synthetic
signal. Gate 2 is consistent with Thread 3, with 0 robust internal violations.
Gate 3, the speculative cleartext plausibility gate, is correctly not run
because Gate 1 fails. No candidate cleartext, English or Finnish, arises.
Sources:
[`wave-2-summary.md`](../gak-threads/notes/wave-2-summary.md#3-thread-4--the-gak-attack-end-to-end)
and the stable candidate record
[`eyes-seed-657965735f737470-trials-2000-beam-8.md`](../gak-threads/candidates/eyes-seed-657965735f737470-trials-2000-beam-8.md).

## Bottom line

GAK survives as a model. It is not falsified by the perfect-isomorphism tests,
and the surviving transitive family is the hard `A₈₃`/`S₈₃` region, with `D₁₆₆`
kept conditional.

Recovery is not supported at the current data budget. The leak ceiling says the
isomorph supply is far below the demand for near-`S₈₃` recovery, and the matured
attack scores 0 on held-out eye signal against its matched null.

The decode remains blocked on the symbol-to-meaning mapping. A structural
candidate family, an isomorph consistency result, or a high-scoring search trace
is not a plaintext. The result worth publishing is therefore the computational
frontier itself: exact structural pruning where possible, measured robustness
where a conclusion depends on transcription, and an honest boundary around what
the current corpus can recover.

## What would change this

The most direct unblocker is an external anchor: a primary or otherwise
verifiable mapping between eye symbols and meaning, a developer/game-data source
that identifies a key or plaintext layer, or a known-answer sample tied to the
same cipher family. That is the standing non-computational hunt captured in
[`T11-external-anchor-hunt.md`](../handoff/T11-external-anchor-hunt.md).

Computationally, the bar for moving the frontier is also clear: a new attack must
fire on planted positive controls, beat a matched null under the same scoring
rule, preserve held-out gates, and report an eye output as a candidate unless an
external anchor upgrades it. A new transcription or reading-order proposal would
need the same treatment: explicit assumptions, source-layer perturbation or
primary provenance, and no stronger conclusion without independent evidence.
