# Thread 1 — Dihedral impossibility + the 6-group transitivity restriction

**Priority:** High — start here. **Effort:** Low–Medium.
**Mapping-independent:** Yes (symbol equality + group theory only).
**Game-data/Ghidra helps:** No.

**One-line:** Independently verify the wiki's central narrowing — that a GAK cipher
on 83 symbols must use one of exactly 6 transitive groups, and that the dihedral
case `D₁₆₆` is provably excluded — by turning both arguments into checked
computations against our verified corpus.

## Why this matters

Everything downstream of the wiki (the reduction to `S₈₃`/`A₈₃`, the "deck cipher"
hypothesis, Thread 2's AGL work) rests on two claims:

1. **The transitivity restriction**: because 83 is prime, only 6 transitive
   permutation groups act on 83 points, so the GAK state group is one of
   `C₈₃, D₁₆₆, C₈₃:C₄₁, C₈₃:C₈₂, A₈₃, S₈₃`.
2. **The dihedral exclusion**: `D₁₆₆` is ruled out by an element-order /
   commutativity-conflict argument on the main isomorphs in messages 1–3.

These are exactly the kind of load-bearing claims our house style says to
"spot-read for correctness yourself." If either is wrong, the whole reduction
moves. If both are right, we can build on them with confidence.

Wiki sources to read first — Lymm's eye-messages wiki
(github.com/Lymm37/eye-messages/wiki):
- page `The-Transitivity-Restriction-(6-Groups-for-83)`
- page `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher`
- pages `Dihedral-Group`, `Cyclic-Group`, `Group-Autokey-(GAK)`, `Chaining-Conflicts`

## Part A — the transitivity restriction (verification, mostly on paper + a citation)

The claim is a known theorem, not a measurement. The agent should confirm it and
record the proof sketch so the repo doesn't take it on faith:

- **Burnside's theorem on groups of prime degree.** A transitive permutation group
  of prime degree `p` is either (a) solvable — hence a subgroup of `AGL(1,p) =
  C_p ⋊ C_{p−1}` that contains the regular `C_p` — or (b) 2-transitive.
- The solvable transitive groups are `C_p ⋊ C_d` for each divisor `d | (p−1)`
  (`C_{p−1}` is cyclic, one subgroup per divisor). For `p = 83`, `p−1 = 82 =
  2·41`, divisors `{1, 2, 41, 82}` → `C₈₃, D₁₆₆ (d=2), C₈₃:C₄₁, C₈₃:C₈₂ =
  AGL(1,83)`.
- The non-solvable transitive groups of prime degree are 2-transitive. For degree
  83 the only ones are `A₈₃` and `S₈₃` (83 is not a Mathieu degree, and `83` is
  not of the form `(qᵈ−1)/(q−1)`, so there are no exceptional affine-almost-simple
  2-transitive groups here). → exactly 6 groups.

**Deliverable for Part A:**
- A short proof note committed under `research/gak-threads/` (or appended to the
  thread doc) with the divisor argument worked out for 83.
- An independent cross-check against GAP's transitive-groups library if GAP is
  available: `NrTransitiveGroups(83)` should return 6, and their structure
  descriptions should match the list above. If GAP is not installed, state that
  the check was done by the Burnside argument only.
- Optionally a tiny Rust test asserting the *consequence* we will rely on (the six
  candidate group orders `{83, 166, 83·41, 83·82, 83!/2, 83!}` and their hidden
  subgroup sizes `{1, 2, 41, 82, …}`), so the assumption is encoded, not folkloric.

This part decodes nothing and changes no statistics; it is a correctness audit.

## Part B — the dihedral exclusion (turn the wiki proof into a checked computation)

This is the substantive coding task. The wiki proof works on this isomorph triple
(written in the ASCII+32 display form; only symbol *equality* matters):

```
OLPJ3P-O3QL
&-`=Q`_&Q?-
dN1D-15d-)N
```

The argument:
- In `D₁₆₆ = C₈₃ ⋊ C₂`, non-identity elements have order 83 (rotations) or 2
  (reflections). With hidden subgroup `C₂`, a group element's induced permutation
  on the 83 ciphertext symbols can only have cycle lengths dividing its order — so
  only 1-, 2-, or 83-cycles are possible.
- Therefore any observed chain longer than 2 forces its context element to
  have order 83, i.e. to live in the abelian `C₈₃` subgroup — and all such
  elements commute.
- Define contexts `a = msg1→msg2` and `b = msg1→msg3`. The triple yields a
  length-3 chain under `a` (`L → - → _`) and a length-3 chain under `b`
  (`3 → - → 5`), forcing both `a` and `b` to be order 83 ⇒ they commute.
- But the same letters exhibit a commutativity conflict: starting from `3`,
  `a` then `b` reaches one symbol while `b` then `a` reaches a different one
  (`3 →a Q →b )` versus `3 →b - →a _`). So `a` and `b` do not commute.
- Contradiction ⇒ the state group cannot be `D₁₆₆`.

**What to build:** a module (suggested `src/transitivity.rs` or extend
`src/pyry_conditions.rs`) that, working only from `corpus.rs` symbol equality:

1. Locates the cited isomorph occurrences in the real corpus and verifies the
   alignment the proof assumes (the `Q`/`-` correspondences, etc.). Fail loudly if
   the corpus does not actually contain them — that would itself be a finding.
2. Reconstructs the chain links under contexts `a` and `b` and confirms
   programmatically: (i) at least one chain of length > 2 exists under each
   context (the order-83 forcing), and (ii) the commutativity conflict holds
   (`a∘b ≠ b∘a` from a shared start symbol). The conjunction is the contradiction.
3. Reports the result as a structural verdict, not a decode.

Strengthen beyond the single example. The wiki notes this is "the most
convenient" conflict, not the only one. Have the tool search the full corpus
for *all* (context-pair, start-symbol) cases that simultaneously (a) force order
83 via a >2 chain and (b) exhibit a commutativity conflict. Count them. One clean
case already refutes `D₁₆₆`; a dozen independent ones make the refutation robust
to a single mis-transcription or "strategic typo" (the wiki's own stated escape
hatch).

## Success / failure criteria

- **Success (expected):** Part A reproduces the count of 6 with a recorded proof;
  Part B confirms ≥1 (ideally several) genuine order-83-forcing-plus-conflict
  cases, reproducing the contradiction. → The reduction to `{C₈₃:C₄₁, C₈₃:C₈₂,
  A₈₃, S₈₃}` stands; report it as audited.
- **Failure / surprise (high value):** the cited isomorphs don't align as claimed,
  or the only "conflict" depends on an unaligned/over-extended isomorph, or the
  >2-chain forcing is an artifact of including allomorphic positions. Any of these
  weakens the dihedral exclusion → write it up; it changes the candidate set.

## Pitfalls & honesty notes

- The proof assumes the cited isomorphs come from the same plaintext. Make
  that assumption explicit and, where possible, lean on the strongest (most
  internal repeats, multi-message, positionally-aligned) isomorphs so a single
  coincidental gap pattern can't be load-bearing. Cross-reference Thread 3's
  perfect-isomorphism scan for which isomorphs are safe to treat as repeated
  plaintext.
- Do not extend an isomorph past its allomorphic boundary when building chains
  — a chain link that crosses into differing plaintext is invalid. Bound chains by
  the isomorph extents Thread 3 produces (or reconstruct conservatively here).
- This thread is pure structure: no language scoring, no symbol→meaning mapping, no
  reading-order re-selection.

## Reuse / build

- Reuse: `corpus.rs` (data), `isomorph.rs` (`detect_isomorphs`, `PatternSignature`
  for locating/aligning the gap patterns), `pyry_conditions.rs` (pattern for a
  structural-predicate harness + CLI report).
- New: the chain-link / induced-cycle-length / commutativity-conflict logic.
  Thread 5 will generalize this into a full chaining graph; if Thread 5 is being
  done concurrently, coordinate so the chain-link primitive is shared, not
  duplicated.
