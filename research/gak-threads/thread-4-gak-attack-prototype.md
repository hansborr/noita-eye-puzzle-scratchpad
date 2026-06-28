# Thread 4 — GAK attack prototype (the prize)

**Priority:** Medium to staff, but highest reward. **Effort:** High — a
time-boxed research spike, not a checklist. **Mapping-independent:** Yes in the
strongest sense — a working attack *produces* the symbol→permutation mapping
rather than needing it as input. **Game-data/Ghidra helps:** Only post-hoc (to
corroborate a recovered plaintext).

**One-line:** The community's stated open problem is a GAK attack — there is no
known way to "take deltas" in a GAK cipher with hidden states. Building even a
partial one is the single path that could break our long-standing "decode is
blocked on the unknown mapping" conclusion *by pure cryptanalysis*.

## Why this is the prize (and the reframe)

Classical chaining attacks recover the alphabet relationships in CTAK/Vigenère by
taking *additive* deltas between aligned positions. The repo already does this for
the cyclic case (`src/chaining.rs`, additive shifts only). GAK breaks it: the
"delta" between two cipher states is now a group element (a permutation), not a
scalar, and hidden state means you can't read the current state off the output.
The wiki:

> We currently do not have any known algorithm for finding the PT → group element
> mapping for GAK, and doing it with brute force is computationally infeasible due
> to the hidden states… Basically, we need a GAK attack, and any work on this would
> be much appreciated.

If such an attack existed, it would recover the plaintext→permutation mapping from
the isomorph structure alone — no in-game anchor, no developer statement. That
directly contradicts our standing memory claim that the mapping is recoverable only
from an external source. It is the reason that claim is *too strong*: the mapping
is unrecovered by the attacks tried so far, not unrecoverable in principle.

Wiki sources to read first (Lymm's eye-messages wiki,
github.com/Lymm37/eye-messages/wiki):
- pages `Group-Autokey-(GAK)`, `Alphabet-Chaining`, `Graph-Chaining`,
  `Hidden-State`
- pages `Chaining-Conflicts`, `Chaining-Conflict-Rates`, `Deck-Cipher`
- page `Explanation-of-Progress` (states what is
  already solvable: GCTAK fully; simple GAK partially, given enough isomorphs)

## Approach — validate on synthetic ground truth first, always

Never debug an attack on the eyes (no ground truth). The whole spike runs on
synthetic GAK/deck ciphers we generate, where we know the plaintext, the
per-letter permutations, and the initial state, so every intermediate claim is
checkable. Only at the very end do you point the matured attack at the eyes.

### Step 0 — general deck/GAK generator (prerequisite)

The existing `ciphers.rs` `DeckCipherKey` is a *fixed-schedule* Solitaire-style
simplification — not general GAK. Extend it (or add `GakKey`) so each plaintext
letter maps to an arbitrary permutation of `S_n` (or `A_n`), state updates
cumulatively, output is the top card / chosen coset. Make `n` a parameter so you
can work at `n = 5, 8, 12, …` before `83`. Generate ciphertexts from plaintext
containing repeated words/phrases (so the output has strong isomorphs, like the
eyes).

### Step 1 — reproduce the known-solvable baselines (calibration)

- Solve GCTAK puzzles end-to-end (the wiki says this is already doable with
  extended chaining). This is your positive control: if your harness can't solve
  GCTAK, it isn't ready for GAK.
- Partially solve small `S_n` GAK with few hidden states given many isomorphs —
  reproduce the wiki's "partially solve simple GAK examples" claim, then push it.

### Step 2 — the actual attack ideas (try several; this is research)

- **Generalized chaining graph.** Build the chain graph (Thread 5 produces this for
  the eyes; build the synthetic analogue here) where edges are symbol→symbol under
  a context, and contexts compose as permutations, not scalars. Recover
  contexts by constraint propagation: aligned isomorphs give equations
  `context · π(word) = context'`; solve for the unknown elements.
- **Exploit the small-support prior.** Thread 3 / the wiki's allomorph analysis
  give an upper bound of ~4 swaps per plaintext letter of decoherence — i.e.
  the per-letter permutations are *near-identity* (small-support), not arbitrary
  shuffles. That collapses the search from `S₈₃` (`83!`) to permutations expressible
  as ≤k transpositions, which is tractable. Make this prior a first-class
  constraint in the search.
- **Hidden-state marginalization.** Where brute force over hidden state is the
  blocker, try belief propagation / beam search over the hidden-state posterior
  conditioned on the observed isomorph constraints, rather than full enumeration.

### Step 3 — point it at the eyes (only after Step 1 passes)

Run the matured attack on the real corpus. Any candidate it produces is a
*hypothesis*, verified by: held-out isomorphs it was not trained on; the
perfect-isomorphism consistency from Thread 3; and only *then*, as a final
external check, plausibility of the recovered plaintext against in-game lore /
the relationships among the nine messages.

## Go / no-go milestones (to keep the spike bounded)

1. General `S_n` GAK generator + synthetic isomorph-rich corpora — week-1 gate;
   if this is shaky, stop.
2. GCTAK solved end-to-end (positive control) — decisive gate; no GCTAK solve,
   no GAK attempt.
3. Small `S_n` (n ≤ 8) GAK *partially* recovered with the small-support prior —
   the real result; reaching this reliably is already novel and is what the
   wiki asks for. Write it up even if `S₈₃` never falls.
4. (Stretch) scale toward `S₈₃` on the eyes. Treat anything here as a hypothesis to
   be killed, not a solution.

## Success / failure criteria

- **Win:** a reproducible attack that recovers per-letter permutations on synthetic
  GAK from isomorphs (at least small `n`), validated against ground truth. This is
  publishable progress on the community's open problem regardless of whether it
  cracks the eyes.
- **Honest partial:** GCTAK solved, GAK attacked but not solved at useful scale —
  still a contribution (negative bound on tractability + reusable harness).
- **The trap to avoid:** a "solution" on the eyes with no synthetic-ground-truth
  validation and no held-out check. Without ground truth, an unconstrained fit is
  almost certainly a coincidence. Do not report it as a decode.

## Pitfalls & honesty notes

- This is the one thread where the temptation to overclaim is highest, because a
  recovered plaintext *feels* like a solution. Hold the line: validate on
  synthetics, hold out data, and treat eye output as a hypothesis until it survives
  external corroboration.
- Effort is genuinely high and success is uncertain. Staff it only after Threads
  1/3/5 confirm the family is right and supply the chaining graph; otherwise you
  may be attacking the wrong cipher family.
- The small-support (~4-swaps/letter) prior is *tentative* (allomorph-derived).
  Treat it as a search heuristic to be validated, not a hard constraint.

## Reuse / build

- Reuse: `ciphers.rs` (generalize `DeckCipherKey`), `chaining.rs` (additive
  baseline + the calibration mindset), `cipher_attack.rs` (harness/null/positive-
  control pattern — including its honest "negative is the expected outcome" framing
  and shuffle-null contrast), Thread 5's chaining-graph module, `corpus.rs`.
- New: general GAK generator, the constraint-propagation / small-support / hidden-
  state-marginalization attack, and synthetic isomorph-rich test corpora with known
  ground truth.
