# Thread 2 — AGL stress-test (the soft link in the wiki's chain)

**Priority:** High — highest leverage if it breaks. **Effort:** Medium.
**Mapping-independent:** Yes for the feasibility test; the optional fit-to-data
sub-task searches a *small* space rather than needing the mapping as input.
**Game-data/Ghidra helps:** No.

**One-line:** The wiki rules out the two affine groups `C₈₃:C₄₁` and `C₈₃:C₈₂`
only tentatively. They are the one remaining candidate small enough to
brute-force (41 or 82 hidden states, vs. `83!` for the deck case). Make the
ruling-out rigorous — or break it, which would be a big deal.

## Why this matters

After Thread 1, the candidate set is `{C₈₃:C₄₁, C₈₃:C₈₂, A₈₃, S₈₃}`. The two
affine (AGL) options are qualitatively different from the symmetric ones: they
have only 41 or 82 hidden states, which the wiki itself notes is "the only
remaining candidate that could reasonably be brute-forced." The wiki excludes
them with a soft argument:

> The AGL options … are not generally able to produce shared sections after a
> differing first character, unless the initial states of all the messages are
> fine-tuned to allow for an immediate resync.

"Not generally able … unless …" is a tentative exclusion, not a proof. This is the
weakest link in the reduction to `S₈₃`/`A₈₃`. If the AGL cases are genuinely
excluded, we want a real argument. If they are *not* — if the eyes' specific
message-starts + shared-sections pattern is achievable in AGL more freely than the
wiki thinks — then the puzzle may be brute-forceable, and that reopens the
most tractable path to a solution.

Wiki sources to read first (Lymm's eye-messages wiki,
github.com/Lymm37/eye-messages/wiki):
- page `Affine-General-Linear-Group-(AGL)`
- pages `Message-Starts`, `Shared-Sections`,
  `The-Transitivity-Restriction-(6-Groups-for-83)`
- pages `Group-Autokey-(GAK)`, `Hidden-State`,
  `Isomorphic-Cipher-Hierarchy`

## Background: what an AGL GAK cipher is, concretely

`AGL(1,83)` acts on `Z₈₃` by `x ↦ a·x + b` (`a ∈ Z₈₃*`, `b ∈ Z₈₃`). As a GAK
state group of order `83·82`:
- The hidden subgroup is a point stabilizer (the maps fixing a chosen point),
  of order 82; its cosets ↔ the 83 points, and the ciphertext symbol is the
  image of a fixed reference point under the current state element.
- `C₈₃:C₄₁` is the index-2 subgroup using only the multiplicative subgroup of
  order 41; hidden subgroup size 41.
- Each plaintext letter maps to a fixed group element; the state updates
  cumulatively (`state ← state · π(letter)`); the output at each step is the
  current ciphertext symbol (the moved reference point).

The key behavioural question is about message starts: in the eyes, messages
begin with *different* first ciphertext symbols and then snap into long shared
sections (identical ciphertext) that, under the GAK reading, correspond to the
same plaintext. The wiki claims AGL can only do this if the per-message initial
states are fine-tuned to resync after exactly one character.

## Method

### Part A — feasibility test (decisive, mapping-independent)

Implement the AGL GAK cipher (both `C₈₃:C₈₂` and `C₈₃:C₄₁`) and determine, as a
constraint-satisfaction question, whether the eyes' message-start-then-shared
behaviour is reproducible:

1. Build the cipher as a primitive (suggested: extend `src/ciphers.rs` with an
   `AglGakKey`, mirroring the existing `DeckCipherKey` shape — `encrypt`/`decrypt`,
   documented, no panics).
2. Pose the question precisely: *do there exist initial states `s₁…s₉` (one per
   message) and a single plaintext-letter→group-element assignment such that two
   messages with a differing first symbol then share an identical run of length L
   (the observed shared-section lengths), under the same post-first-letter
   plaintext?* Treat L from the real corpus (messages 1–3 share long runs after
   the first symbol; see `perseus.rs` shared-run reconstruction for the anchors).
3. Characterize the solution set: is it empty? non-empty only when the initial
   states satisfy a one-character-resync constraint (confirming the wiki)? or
   broader (refuting it)? Because the hidden state space is only 41/82, this is
   enumerable — you can settle it exhaustively, not statistically.

Frame the output as: "AGL message-starts are achievable **iff** {precise
condition}", and then check whether that condition is consistent with the rest of
the eye data (all nine messages, their starts, the funny-looking obstacle, the
stutter section). Consistency required across the *whole* corpus, not one pair.

### Part B — optional: attempt an actual AGL fit to the eyes

Because the hidden-state count is tiny, a guided search for an AGL GAK that
*reproduces the real ciphertext* is feasible in a way it never is for `S₈₃`:

- Fix the hidden subgroup; the unknowns are the per-letter group elements and the
  per-message initial states. The isomorph structure heavily constrains these
  (repeated plaintext ⇒ repeated element products). Use the isomorphs as
  simultaneous equations / constraints and propagate.
- This still involves the unknown plaintext alphabet, but over a bounded space.
  Even a failed exhaustive search is a result: it converts the tentative
  exclusion into a real one ("no `AGL(1,83)` GAK reproduces the message-start +
  shared-section pattern"). A success would be a candidate structural solution
  — verify hard before believing it (a fit with no language constraint can be a
  coincidence; cross-check against held-out isomorphs).

## Success / failure criteria

- **Confirms the wiki (likely):** Part A shows AGL reproduces the eyes only under a
  resync condition that is inconsistent with the full nine-message start pattern →
  AGL is now *rigorously* excluded; candidate set is `{A₈₃, S₈₃}` for real.
  Deliverable: the precise condition + the inconsistency, with a null/positive
  control showing the test fires.
- **Breaks the wiki (high value):** Part A shows AGL reproduces the pattern without
  pathological fine-tuning, or Part B finds a consistent AGL fit. → AGL is back as
  a *brute-forceable* candidate; escalate immediately, because this is the most
  solvable branch of the whole tree.

## Pitfalls & honesty notes

- Get the GAK output function right: the ciphertext is the coset, i.e. the
  moved reference point, not the raw group element. Mis-modelling this is the easy
  way to get a wrong feasibility answer. Validate the cipher on a tiny synthetic
  AGL example with hand-checked output before trusting it on the eyes.
- The "fine-tuned initial states" exclusion is a statement about *all* messages
  simultaneously. A two-message demonstration neither confirms nor refutes it —
  carry all nine.
- Don't let Part B's fit, if found, be reported as a solution. A structural fit
  with no plaintext semantics is a hypothesis to be killed by held-out isomorphs
  and (later) by Thread 3's perfect-isomorphism check, not a decode.

## Reuse / build

- Reuse: `ciphers.rs` (the `DeckCipherKey` design is the template for `AglGakKey`),
  `corpus.rs`, `perseus.rs` (shared-run anchors / message-start alignment),
  `isomorph.rs` (constraint extraction for Part B).
- New: the `AglGakKey` primitive and the feasibility/enumeration logic.
