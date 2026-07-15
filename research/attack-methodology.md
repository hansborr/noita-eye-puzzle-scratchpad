# Attack methodology — building trustworthy cipher attacks

Cross-cutting *process* lessons learned (usually the hard way) while building the
`solve` / `keystream` / `ragbaby` attacks in this workbench. They transfer to any new
attack even when the cipher math does not — each was paid for with a real false
negative or false positive, and the demonstrating write-up is cited.

The overarching rule (see also `AGENTS.md` and `NEXT-STEPS.md`): a high n-gram or
structure score is not a decode, and "ruled out" is meaningless without a *passing*
positive control and an adequate model/wordlist.

## Recurring misconceptions (do not regenerate)

The repo already disputes several claims that agents keep regenerating from priors
or a superficial read of community write-ups. Check here before re-deriving any of
these — the correction is already established and cited in-repo:

- **"Pyry is a Nolla dev."** Unverified; the known team is Purho/Harjola/Teikari.
  Treating Pyry's autokey-Alberti demo as an insider signal is unsupported.
  (`research/03-confirmed-vs-speculation.md` §5.)
- **"~83 internal states."** Superseded, not merely disputed: the surviving
  cipher-family theories (GAK on a near-S₈₃ state group) imply an S₈₃-scale state
  space (83! ≈ 10¹²⁴). (`research/03-confirmed-vs-speculation.md` §3/§5/§7,
  `research/01-overview.md`, `research/02-theories-and-encoding.md`.)
- **"We need a symbol-to-meaning mapping."** No such fixed mapping exists — the
  cipher is polyalphabetic. The plaintext-letter→group-action assignment IS the
  key: it is the thing to be recovered, and would never be externally supplied.
  (`research/05-code-investigations.md`.)
- **"The digit→direction mapping is unverifiable."** Binary-verifiable: the eye
  sprites are hardcoded in the engine's drawing function and extractable from the
  shipped binary (maintainer-confirmed 2026-07-06). A different labeling would
  only be a fixed substitution — cryptanalytically immaterial either way.
  (`research/03-confirmed-vs-speculation.md` §3.)
- **"Alternative substitution-equivalent reading orders are a live concern."**
  Immaterial: every statistic this workbench computes is substitution-invariant
  or conditioned on the fixed digit sequence, so a substitution-equivalent
  reorder changes no computed result. (`research/03-confirmed-vs-speculation.md`
  §7.)

## 1. Null against the search's degrees of freedom, not against random keys

A search-based attack (annealed key/mapping search) overfits short ciphertext and will
"survive" a random-key null on pure noise (real / shuffled / random-length all hit
z≈20 at L=40). Gate on a matched null: rerun the *same search* on a
Fisher-Yates-shuffled ciphertext and require z ≥ 6 and a ≥ 1-nat margin. Keep a
random-key null too — it catches key-independent leaks (e.g. ciphertext-autokey
`p_i = c_i − c_{i−L}`) that shuffling hides. Demonstrated:
`data/practice-puzzles/KEYSTREAM-RESULTS.md`.

## 2. A positive control must exercise the gate end-to-end

Plant true plaintext → encrypt → run the *whole* attack → assert `survives == true`.
A control that only checks the optimizer (plant → assert recovered) passes while the
survival gate is silently miscalibrated, so it certifies nothing about your negatives.
Demonstrated by the held-out gate bug in `data/practice-puzzles/RAGBABY-RESULTS.md`.

## 3. Held-out scoring compares fold-vs-fold

Compare the candidate's held-out fold against the matched null's held-out fold, not
against the full-stream mean. Odd-index English is not contiguous English, so a
*perfectly* recovered decode fails a fold-vs-full check (a real false negative we hit).
Fixed by factoring a shared held-out-null helper. Write-up:
`findings/T1-heldout-gate-fix.md`.

## 4. Simulated annealing anneals the sum of log-probs, not the mean

With a mean objective, per-move deltas are ~0.01, so any temperature degenerates to a
random walk and even planted controls fail to recover. Use the sum of
log-quadgram probabilities, plus slide / reverse-segment moves and basin-hopping.
Demonstrated: `data/practice-puzzles/RAGBABY-RESULTS.md`.

## 5. Reduced-base alphabets must permute the real A..Z indices

When a cipher drops letters (Ragbaby base-25 folds J→I; base-24 also folds V→U),
permute and score in real-letter space. Relabeling the kept set to a contiguous
`0..base-1` range silently zeroes recovery. Demonstrated:
`data/practice-puzzles/RAGBABY-RESULTS.md`.

## 6. Calibrate power with a matched-base planted control

"Not cipher X" is only as strong as your ability to *recover* a planted cipher-X at the
same length and alphabet. Report that power (e.g. `five` Ragbaby ruled out at
planted-recovery 1.00 @274; `four`/121 near the information floor at ~0.70). A negative
below ~0.7 recovery power is "couldn't find it," not "isn't there." Demonstrated:
`data/practice-puzzles/RAGBABY-RESULTS.md`.

## 7. An exclusion binds only the model class that proved it — re-audit on model change

`one`'s "no bit-level fixed-width / ASCII codec" exclusion was proven against the raw
direction stream (a bit-complemented repeat is fatal there) and then silently
over-generalized to *every* bit-level reading. It never covered deterministic
orientation masks: under `b_i = i mod 2` polarity is meaningful again, the phrase
repeats become literal, and 7-bit ASCII read straight off — the solved plaintext had
been excluded only by scope creep, not by evidence. Two habits fix this cheaply:
(a) when hints or new structure change the model class, re-derive which recorded
exclusions still apply *from their proofs*, not from their headlines; and (b)
enumerate small closures — writing out all 16 one-bit update rules
`b' = f(b, p, o)` took minutes and exposed the one untested derived carrier.
Corollary: sweep **zero-parameter self-reading codecs first** (fixed codes + exact
re-encode round-trip) — at lengths where matched-null gates are measured-underpowered
(`codecpower`), a round-trip verdict is decisive in both directions and costs nothing.
Demonstrated: `data/practice-puzzles/CODEC-RESULTS.md` § "`one` — SOLVED".

## 8. Trim isomorph anchors before using them as hard filters

Equality-pattern isomorph detection overextends by 1–2 positions per boundary
(the surrounding pattern can agree by chance). Used raw as hard equality
constraints, the anchors excluded **the true key** (0 survivors over a 3.1M-key
space); trimming every hard anchor 2 positions per side recovered a truthful
survivor set. The failure is invisible to a planted positive control whose
anchor boundaries are clean — plant *dirty-boundary* anchors, or keep short
repeats as soft scores only. Demonstrated (independent agent, reconciled):
`handoff/two-cross-agent-recon.md`.

## 9. A group closed from observed evidence is a lower bound

Closing isomorph column-maps under composition reconstructs a subgroup of the
state group — but *sampling parity in the evidence* can trap the closure in a
proper subgroup (on `two`, all strong anchors had even gaps, so the closure
exposed only an index-2, order-48 shadow of the order-96 group). Before
trusting a reconstructed group's order, enumerate and test small-index
supergroups consistent with the same invariants. Demonstrated:
`handoff/two-cross-agent-recon.md`.

## 10. Quotient surfaces discard the algebra — keep a full-symbol attack in the ladder

A projection chosen for tractability (`two`'s deck-free 4-class eps-pair
stream) can delete exactly the structure that carries the solve: the raw
12-symbol isomorph alignments induce symbol bijections that reconstruct the
state group, and no 4-class attack could ever see them. Two scoped honest
negatives (Avenues A and G) were run on the quotient before an independent
solve showed the live information was upstream. Before concluding anything
family-level from quotient-surface negatives, ask what the projection
provably preserves — and schedule at least one attack on the unprojected
stream. Demonstrated: `handoff/two-cross-agent-recon.md`.

## 11. Re-encode acceptance is decisive only when the readout codec is fixed

Exact re-encode is vacuous when plaintext-to-symbol interpretation is co-searched
over a bijective table/permutation/order: decode any in-range symbol stream under
one such codec, then encode it back under the same fitted codec, and the original
symbol stream is recovered by construction. In that setting, round-trip is an
internal invariant for catching implementation bugs, not evidence that one
interpretation is plaintext. Acceptance needs an independent channel, such as a
powered language/null margin or an external anchor.

This is the opposite of `one`'s fixed `maskdecode` setting, where the readout
mapping was not fitted to the candidate and byte-for-byte re-encode was decisive.
For eyes/community GAK work, a "decode" that re-encodes to the ciphertext is not
verified if the readout codec was selected from the attack surface; it still needs
external anchoring or calibrated language power. Demonstrated:
`handoff/two-cross-agent-recon.md`.

## 12. A design caution is a hypothesis, not a measured negative — run the quadrant you're avoiding

We treated ns=3 known-plaintext swap recovery as a hard cost wall and built an
escalating *systematic* program around it: forward DFS → MRV + cross-message
forward-checking → a two-tier CDCL(T) target solver, then a pre-registered Phase-0
measurement gating an even finer CDCL(T) "Phase-2". Every failure we actually
*measured* was a failure of systematic search/learning. The handoff explicitly
cautioned against local search — "one wrong permutation desyncs all later state, so
the objective is avalanche-heavy and misleading" — and that **unmeasured caution** is
exactly what steered us away from the approach that trivially works. A plain
substitution-first coordinate-descent + basin-hopping local search recovers the ns=3
swaps for every letter that occurs in the corpus (24 of 26 — J and Z never appear in
the plaintext, so their swaps stay unconstrained) in ~14 s, verified byte-for-byte
against the vendor cipher (s=1 0.03 s, s=2 0.11 s, s=3 ~14 s; converged on the first
restart). The avalanche is defused by
settling the *substitution layer* first — perm[0] per letter, pinned by exact
message-start anchors and ranked with cheap single-swap representatives — so far-swap
noise cannot poison the score before the substitution is right.

Two habits fix this cheaply: (a) a caution against an approach is a hypothesis to
test, not a result to build around — before erecting an expensive escalation to avoid
a quadrant, spend the hours to run the cheap version of the avoided approach and record
it as a calibrated positive or negative; (b) beware a pre-registered gate that
adjudicates the *wrong* question. Our Phase-0 gate was built to score whether the ns=3
conflict structure is rich enough for the finer CDCL(T) solver; once we fixed its
observability and reran it, the wall-limited sample met both GO thresholds — a green
light on a question that no longer mattered, because the real question ("do we need a
systematic solver for ns=3 at all?") has answer *no*. Demonstrated:
`data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`.

## 13. Scope-match a verdict's confidence to what its proof actually covers

A verdict is only as strong as the model, key space, and substitution layer its proof
actually swept — not the adjective attached to it. Two exclusion proofs run over the
*same* chaining model can end up with inverted-looking confidence labels (one
"exhaustive," one "conditional") when the true relationship between them is
subsumption: if the narrower group is a literal subgroup of the wider one, excluding
the wider group within a model excludes the narrower group as a special case, for
free, within that same model. Before reporting relative confidence between two
results, check whether one's swept search space contains the other's and whether both
share the same relabeling-invariance assumptions — don't just compare their headline
adjectives. Case study: the AGL(1,83) vs D₁₆₆ exclusion-scope audit
(`research/findings/agl-exclusion.md` §8) — D₁₆₆ ≤ AGL(1,83) meant the "exhaustively
excluded" AGL sweep already covered the "conditional" dihedral case, and the doc had
been reporting the confidence the wrong way round.

## 14. Match optimizer moves to hard global constraints

A coordinate move can be locally impossible even when the corresponding global
change is valid. In hidden-base GAK recovery, first-symbol anchors make the
letter-to-top-source assignment injective. Changing one anchored letter's top
source therefore collides with the current owner, so ordinary one-letter
coordinate descent cannot traverse a valid permutation through its invalid
intermediate state. One favorable `n=7, s=2` fixture passed anyway, while the
registered default fixture remained at `SearchCapExceeded` after 512 restarts.

Factor the hard discrete layer out first, or move it jointly. A bounded CSP over
top sources, pruned with the exact second-symbol restart identity, followed by
coordinate descent only within each selected source bucket recovered five of
five registered `n=7, s=2` fixtures with exact replay and planted-base audit.
The lesson is narrower than "use a beam": identify invariants that make the
optimizer's neighborhood disconnected, then represent those invariants as a
separate search layer or add permutation-preserving joint moves. Demonstrated:
`handoff/gak-unknown-base-recovery/03-base-marginalized-local-search.md`.

## 15. Instrument which search layer lost the plant before widening every budget

A layered heuristic can miss because the correct coarse state was ranked out or
because refinement stalled inside the correct state. Those require different
fixes, and a wider global budget can obscure the distinction. In hidden-base GAK
recovery, raising the top-source beam/restart budget from 96 to 512 left the
registered `n=7, s=3` sample at `2/5`. An audit-only derivation
`top_source(L) = B^-1(c_0(L))` then showed that the planted coarse hypothesis had
already survived in all five fixtures (ranks `7..61`). The bottleneck was the
within-bucket neighborhood, not ranking.

Turn planted controls into provenance probes, while keeping their answers out of
the search itself. Report the plant's rank/retention at each lossy layer, then
ablate the proposed downstream move and account for its own work. Here, hard
second-symbol filtering alone reached only `1/5`; a capped two-letter sigma move
reached exact replay `5/5`, with its `22066..221255` replay evaluations reported
separately. This diagnoses the mechanism and exposes the cost instead of calling
a larger opaque budget an algorithmic gain. Demonstrated:
`handoff/gak-unknown-base-recovery/03-base-marginalized-local-search.md`.

## 16. A candidate cap is not a work bound — count the replayed evidence

Local-search candidates can have radically different evaluation costs, and a
cap scoped per restart can accumulate far beyond its headline value. In the
hidden-base `s=3, n=7` search, a `4096` joint-move cap still produced up to
`386298` joint candidate evaluations over one full run, and the landed evaluator
replayed all 384 events for every joint candidate. Candidate counts alone hid up
to 148 million event transitions.

Instrument the primitive work unit as well as the search-node count, and state
the scope of every cap. An exact objective lower bound can then stop a replay as
soon as mismatches plus fixed penalties cannot beat the incumbent, while final
acceptance still uses complete replay. On a pre-registered 24-run calibration,
this preserved all `18/24` exact outcomes and reduced the maximum joint replay
work by `7.7%..9.3%` across three corpus shapes. Halving the candidate cap cut
more work but reduced recovery to `17/24`, so it was recorded as a tradeoff and
not promoted. Demonstrated:
`handoff/gak-unknown-base-recovery/03-base-marginalized-local-search.md`.
