# Thread 5 — Chaining graph: conflict catalogue + transitivity coverage

**Priority:** Medium — foundational substrate for Threads 1 and 4.
**Effort:** Medium. **Mapping-independent:** Yes (symbol equality only).
**Game-data/Ghidra helps:** No.

**One-line:** Build the explicit chaining graph over the eye isomorphs and turn two
qualitative wiki assertions into measured numbers: (a) how much **non-commutativity
evidence** (chaining conflicts) there actually is, and (b) how much of the 83-symbol
alphabet the isomorph chaining graph **covers** — the empirical basis for assuming
the group action is *transitive*, which is what licenses the entire 6-group
restriction.

## Why this matters

Two pillars of the wiki's argument are stated qualitatively and never counted:

- **Non-commutativity.** "We see chaining conflicts indicating non-commutativity"
  is the reason `C₈₃` (and all commutative options) are ruled out. How many genuine
  conflicts are there? Where? Are any fragile (dependent on one over-extended
  isomorph)? Nobody has tabulated this.
- **Transitivity.** "The isomorphs cover nearly all ciphertext symbols" is the
  evidence offered for assuming a *transitive* group action — and transitivity is
  the precondition for "only 6 groups." "Nearly all" is never quantified.

This thread supplies both numbers, and in doing so builds the chain-link / chaining-
graph primitive that Thread 1 (dihedral proof) and Thread 4 (GAK attack) both need.
Doing it once, here, avoids three half-built versions.

Wiki sources to read first (Lymm's eye-messages wiki, github.com/Lymm37/eye-messages/wiki):
- pages `Graph-Chaining`,
  `Alphabet-Chaining`, `Chaining-Conflicts`, `Chaining-Conflict-Rates`
- page `The-Transitivity-Restriction-(6-Groups-for-83)`
- pages `Hidden-State`, `Groups`

## Concepts (precise definitions to implement)

- A **context** between two aligned isomorph occurrences is the transformation from
  one to the other — the cumulative product of the plaintext letters between them
  (same message) or the state change needed to align them (different messages). We
  never know the context's group element, but we observe its **action**: it maps
  some ciphertext symbols to others.
- A **chain link** is an observed `symbol → symbol` pair under a fixed context: at a
  position where two aligned occurrences both have a symbol, the pair `(x, y)` says
  "context maps `x ↦ y`."
- A **chaining conflict** is a witnessed non-commutativity: two contexts `a`, `b`
  and a start symbol `s` with `a` then `b` reaching a different symbol than `b` then
  `a`. (This is exactly the device Thread 1's dihedral proof uses.)

## Method

1. **Isomorph alignment → contexts.** Using Thread 3's safe (non-over-extended)
   isomorph list — or, if running first, a conservative in-thread extension — define
   contexts between aligned occurrences (within and across messages) and extract all
   chain links `(context, x, y)`. Reuse `isomorph.rs` for detection/alignment.

2. **Conflict catalogue.** Enumerate every `(a, b, s)` triple where the composed
   actions disagree (`a∘b ≠ b∘a` from `s`). Report: total count, how many are
   *independent* (don't share the same underlying isomorphs), and a fragility flag
   for any that depend on a single weak/long isomorph. This is the quantitative
   form of "we see chaining conflicts." A robust count of independent conflicts is
   strong support for non-commutativity; a count of ~1 fragile case would be a
   caution worth surfacing.

3. **Transitivity coverage.** Treat chain links as edges on the 83 ciphertext
   symbols and compute connected components. Report: number of symbols touched by
   *any* link, the size of the largest component, and the number of components. The
   wiki's transitivity assumption is well-supported iff (close to) all 83 symbols
   lie in one component. Quantify "nearly all" — e.g. "links touch 81/83 symbols in
   1 component" vs. "67/83 in 3 components" are very different evidential states.

4. **Null calibration.** As always, attach a null: under the within-message
   multiset shuffle (as in `isomorph_null.rs`), how many conflicts and how much
   coverage arise by chance? Real structure must exceed the shuffle null. A positive
   control: run the same pipeline on a *generated* non-commutative GAK fixture with
   known isomorphs and confirm the tool reports conflicts + high coverage there.

## Success / failure criteria

- **Expected:** many independent conflicts (non-commutativity confirmed,
  quantified) and near-total single-component coverage (transitivity assumption
  supported, quantified). → The 6-group restriction's two premises are now backed
  by numbers, not adjectives.
- **Surprise (valuable):** conflicts turn out fragile/few, or coverage is
  fragmented. Either would weaken a premise the whole reduction depends on — write
  it up; it feeds back into Threads 1 and 2.

## Deliverables

- A `chaining_graph` module (suggested `src/chaining_graph.rs`; keep the existing
  additive `chaining.rs` as-is — that one is Experiment 7B and is cyclic-only) that
  exposes: chain-link extraction, the conflict catalogue, and the
  connected-component coverage, all behind a CLI report in the `main.rs` style.
- A short results note: conflict count (total / independent / fragile), coverage
  fraction and component structure, the null comparison, and the positive-control
  result.
- A reusable chain-link primitive that Thread 1 and Thread 4 import.

## Pitfalls & honesty notes

- **Do not build chain links across allomorphic boundaries.** A link that crosses
  into differing plaintext is invalid and will manufacture spurious conflicts and
  coverage. Bound everything by Thread 3's isomorph extents; if Thread 3 hasn't run,
  extend conservatively and flag it.
- Coverage is evidence *for* transitivity, not proof of it; "nearly all symbols
  reachable in the observed isomorphs" is consistent with transitivity but doesn't
  establish the group action is transitive in the formal sense. State it at that
  strength.
- Pure structure: no language scoring, no mapping, no reading-order re-selection.

## Reuse / build

- Reuse: `isomorph.rs`, `isomorph_null.rs`, `perseus.rs` (alignment anchors),
  `corpus.rs`. Mirror `cipher_attack.rs` / `pyry_conditions.rs` for the
  report + null + positive-control structure.
- New: the chaining-graph module and its conflict/coverage analytics.
