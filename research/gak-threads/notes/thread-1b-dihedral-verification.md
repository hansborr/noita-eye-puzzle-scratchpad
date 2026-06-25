# Thread 1B — Adversarial logic verification of the dihedral-exclusion proof

**Scope:** soundness of the LOGIC only. A separate agent does the empirical
corpus reproduction (locating the cited isomorph triple in `corpus.rs` under the
correct reading order). This note checks whether the argument is valid
*independent of the data*, and maps its full assumption load.

**Sources read.**
- `research/gak-threads/thread-1-dihedral-and-transitivity.md` (Part B).
- `eye-messages.wiki/Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`.
- `eye-messages.wiki/Proof-that-semidirect-product-GAK-has-a-left-action-on-CT-symbols-when-the-hidden-state-is-fixed.md`.
- `eye-messages.wiki/{Hidden-State,Chaining-Conflicts,Dihedral-Group,Group-Autokey-(GAK),Alphabet-Chaining,Graph-Chaining,Proof-that-GAK-is-transitive,Proof-that-GAK-has-perfect-isomorphism,Isomorphs-(Gap-Patterns)}.md`.

Scratch scripts: `…/scratchpad/{cycle_check,general_proof,chain_logic,chain_provenance,cross_msg_context,robustness,all_conflicts,independence,order83_commute,final_checks,core_only,extension_dep}.py`.

---

## Verdict: the logic HOLDS. Two non-fatal holes in the *data dependency*.

Every inferential step is valid. The contradiction is real **conditional on the
cited 11-wide alignment being a single same-plaintext isomorph under one global
cipher**. The holes are not in the deduction; they are in how much transcription
the conclusion rests on, and the wiki already flags the chief one.

---

## Step (1) — "cycle lengths of the coset action divide the element order"

**Correct, and the right action is used.** Two subtleties had to be resolved.

1. **Which action?** The dihedral proof uses the *chaining-graph* action, which
   `Graph-Chaining.md` identifies as the Schreier coset graph and
   `Proof-that-GAK-is-transitive.md` derives explicitly as the **right**
   multiplication action of `G` on the right cosets `H\G`: a context between two
   isomorphs is right-multiplication by a fixed `t = a₁⁻¹b₁`, constant across all
   aligned columns. This is a genuine `G`-action on the 83 cosets for **every**
   group — it does **not** depend on `G` being a semidirect product.

2. **Is the cited "left action on CT symbols" proof what's needed?** No, and this
   is a trap worth stating: `Proof-that-semidirect-product-GAK-has-a-left-action-…`
   is about a *different* map `σ_{hV}(g)(c(hv)) = c(ghv)` (left multiplication,
   permutation only when `G = H ⋉ V` with the hidden state fixed to a coset of
   `V`). The dihedral proof does **not** rely on that left action. So the
   divides-order claim must be (and is) justified by the **right**-action lemma,
   not by the semidirect-product left-action proof. The cited supporting proof is
   adjacent, not load-bearing, for this step.

**The lemma itself is a textbook theorem of group actions, not a coset-specific
quirk:** for any action of `G` on a set, the permutation induced by `t` generates
a cyclic group that is a homomorphic image of `⟨t⟩`, so its order divides
`ord(t)`; cycles are the orbits of `⟨π_t⟩`, and by orbit–stabilizer each orbit
length divides `|⟨π_t⟩|`, hence divides `ord(t)`. Verified:
- Concrete `D₁₆₆` model `{x ↦ ±x + b mod 83}`, `H = {e, (x↦−x)}`: across **all**
  166 elements the right-coset permutation cycle lengths are exactly `{1, 2, 83}`,
  every one dividing the element's order (0 violations). Rotations (order 83) →
  one 83-cycle; reflections (order 2) → 41 two-cycles + 1 fixed point.
- Generic sanity (`S₅` on cosets of an order-2 subgroup): 0 violations.

So "only 1-, 2-, or 83-cycles are possible, and a length-`>2` chain forces order
83" is sound. Minor side-note: `Chaining-Conflicts.md` says reflections give "2
fixed points"; for odd `n = 83` the model gives **1** fixed point (an odd polygon
has one vertex-axis). This is a descriptive inaccuracy on a different page and is
irrelevant to the proof, which only uses "reflections have order 2 ⇒ cycles ⊆
{1,2}".

## Step (2) — does a length-3 chain truly require order 83?

**Yes, given the proof's isomorph assumption.** Adversarial concerns checked:

- **Could the 3-chain compose *different* context elements?** No — within one
  isomorph pair there is exactly one context element `t` (constant across
  columns, per the transitivity proof). The chain `L → - → _` (context `a`) is
  built by alphabet-chaining glue: link `L→-` from columns 1 & 10 and link
  `-→_` from column 6, sharing CT symbol `-`. All columns belong to the same
  `(msg1, msg2)` pair, so all are `π_{t_a}`. Three **distinct** CT symbols
  (`L,-,_`) on one orbit ⇒ cycle length ≥ 3 ⇒ (cycles ⊆ {1,2,83}) ⇒ 83.
  Distinctness of `{L,-,_}` and `{3,-,5}` verified; CT-symbol↔coset is a
  bijection so distinct symbols are distinct cosets.
- **Could it be an allomorph-boundary artifact?** Only if the glue column lies
  outside the true isomorph. The glue is column 6, which sits **inside** the
  twice-repeated 9-core `A.B.CB.AC`; the order-83 forcing for `a` survives on
  core columns `{1,6}` alone and for `b` on `{4,6}` alone (the duplicate columns
  10/8 are redundant). So the *order-forcing half* does not depend on the
  low-confidence 2-char extension. Good.

## Step (3) — robustness to a single mis-transcription ("strategic typo")

**This is HOLE 1 (the one the wiki itself admits).** The contradiction is the
conjunction of links spread over 10 `(column, cell)` entries. Redundancy exists
(the isomorph repeats twice per message: columns 0/7, 1/10, 2/5, 4/8 mutually
cross-check), **but two columns are single-source**: col6 `(-, _, 5)` and col9
`(Q, ?, ))`.

- Col6's `-` is the **only** occurrence of `-` as a `msg1` symbol, and **both**
  order-83 forcings glue through it. A single flipped symbol at col6 could
  simultaneously break the `a`-chain `>2` link and change the `b∘a` result.
- The within-triple "second conflict" `(a,c)` the wiki alludes to is **not
  independent** against a typo: it reuses the same `a`-context chain `L→-→_`
  (needs col6) and the same col9, so col6 and col9 remain shared single points of
  failure.

So a single strategic typo at col6 (or col9) does dissolve *this* triple's
contradiction. The proof is robust against a typo **only** if other isomorph
families independently reproduce a forcing-plus-conflict — which is exactly what
Thread 1B's empirical half is asked to enumerate. **On this triple alone, the
escape hatch is real.**

## Step (3b) — extra hole the wiki does NOT flag

**HOLE 2: the commutativity-conflict half lives entirely in the
over-extension.** Restricting to the high-confidence 9-core `A.B.CB.AC` (columns
0–8): all three contexts `a, b, c` still have length-3 chains (order-83 forcing
**holds on the core**), but **there is no commutativity conflict at all**. Every
conflict in the triple routes through `Q`'s image under `a`/`b`, which exists
only at **col9** — in the 2-trigram extension `QL / ?- / )N`, appended once and
not part of the twice-repeated core. `Chaining-Conflicts.md` and the thread doc
both warn that **overextending isomorphs manufactures spurious conflicts**. So
the two halves of the contradiction have asymmetric confidence:
- order-83 forcing: high confidence (twice-repeated core, internally redundant);
- commutativity conflict: lower confidence (single-source column outside the
  repeated core).

This does not make the *logic* unsound, but it means the empirical claim "and
they don't commute" rests on the weakest column in the alignment. A clean,
robust refutation needs a forcing-plus-conflict witnessed within repeated-core
columns of some isomorph family (again, the empirical agent's job).

## Step (4) — assumption load (the same-hidden-state question)

The proof **does** implicitly assume one global cipher across messages 1–3. Full
load:

- **A1 (same plaintext):** the three rows of the triple encode the same
  underlying word/phrase (stated, "reasonable assumption").
- **A2 (perfect isomorphism):** so a *single* context element `t` exists per
  pair (GAK has this — `Proof-that-GAK-has-perfect-isomorphism.md`).
- **A3 (no allomorph crossing):** the window stays same-plaintext for all used
  columns. Order-forcing uses core only (safe); the conflict uses col9 (the
  over-extended column) — the soft point.
- **A4 (right-coset action is the chaining action):** established above.
- **A5 (single global configuration):** messages 1/2/3 share **one** state group
  `D₁₆₆` **and one** hidden subgroup **and one** CT-symbol↔coset labeling. This
  is what lets "`a` and `b` are both order 83 ⇒ both in the **same** abelian
  `C₈₃` ⇒ they commute" be meaningful. If messages used different hidden
  reflections or different groups, `a` and `b` would not share a common `C₈₃` and
  the commute step would be unjustified. Reasonable for one puzzle, but it is an
  assumption, and the proof does not state it. (The wiki's parenthetical "a
  reflection subgroup, it does not matter which" only covers *which* reflection,
  assuming it is the **same** one throughout.)

**Core inference verified:** in `D₁₆₆` the 82 order-83 elements are exactly the
non-identity rotations, forming the unique (normal, Sylow-83) abelian `C₈₃`; all
`C(82,2)` pairs commute (0 non-commuting pairs in the model). So "order 83 ⇒
commute" is sound. And the conflict `3 →a Q →b )` vs `3 →b - →a _` is a genuine
non-commutation. The conjunction (both order 83 ⇒ commute) ∧ (don't commute) is a
true contradiction.

---

## Bottom line

- **Logic: sound.** Steps (1) coset-cycle-divides-order [right action, general
  theorem], (2) length-3 ⇒ order 83 [given single-isomorph context], (4)
  order-83 ⇒ commute in `D₁₆₆` [unique abelian `C₈₃`], and the final
  contradiction all check out. The cited semidirect-product left-action proof is
  **not** the support for step (1); the right-action transitivity proof is.
- **Holes are in the data dependency, not the deduction:**
  1. (wiki-acknowledged) single-typo escape hatch at col6/col9 on this one
     triple; the within-triple second conflict shares those columns and does not
     remove it.
  2. (not wiki-flagged) the commutativity conflict exists **only via the
     over-extended col9**; on the high-confidence repeated 9-core the order-83
     forcing fires but **no conflict appears**. The refutation's "they don't
     commute" half is its lowest-confidence claim.
- **Therefore:** `D₁₆₆` is excluded **if** the cited alignment (incl. the 2-char
  extension at col9) is a same-plaintext isomorph under one global cipher. The
  exclusion becomes typo-robust only once an independent isomorph family shows a
  forcing-plus-conflict inside repeated-core columns. House-style claim ceiling
  preserved: this constrains the candidate group set; it says nothing about
  recoverable plaintext.
