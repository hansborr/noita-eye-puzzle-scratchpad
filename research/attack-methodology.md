# Attack methodology — building trustworthy cipher attacks

Cross-cutting *process* lessons learned (usually the hard way) while building the
`solve` / `keystream` / `ragbaby` attacks in this workbench. They transfer to any new
attack even when the cipher math does not — each was paid for with a real false
negative or false positive, and the demonstrating write-up is cited.

The overarching rule (see also `AGENTS.md` and `NEXT-STEPS.md`): a high n-gram or
structure score is not a decode, and "ruled out" is meaningless without a *passing*
positive control and an adequate model/wordlist.

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
substitution-first coordinate-descent + basin-hopping local search recovers the full
ns=3 key in ~14 s, verified byte-for-byte against the vendor cipher (s=1 0.03 s,
s=2 0.11 s, s=3 ~14 s; converged on the first restart). The avalanche is defused by
settling the *substitution layer* first — perm[0] per letter, pinned by exact
message-start anchors and ranked with cheap single-swap representatives — so far-swap
noise cannot poison the score before the substitution is right.

Two habits fix this cheaply: (a) a caution against an approach is a hypothesis to
test, not a result to build around — before erecting an expensive escalation to avoid
a quadrant, spend the hours to run the cheap version of the avoided approach and record
it as a calibrated positive or negative; (b) beware a pre-registered gate that
adjudicates the *wrong* question. Our Phase-0 measurement faithfully returned GO ("the
ns=3 conflict structure is rich enough for the finer CDCL(T) solver") on its
wall-limited sample — a clean GO on a question that no longer mattered, because the
real question ("do we need a systematic solver for ns=3 at all?") had answer *no*.
Demonstrated: `data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`.
