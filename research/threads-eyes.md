# Eyes & GAK threads — the community-facing work

*Self-contained brief covering the eyes themselves: GAK-disproof (Goal 2),
isomorph-leak quantification, GAK-attack rigor (Goal 1), and two near-free
contributions. All mapping-independent unless flagged. Background: `frontier.md`. Entry point:
`noita-eye gak-attack-eyes`; corpus `src/data/corpus.rs` (9 verified messages, 1036 trigrams,
83 symbols). Index: `NEXT-STEPS.md`.*

---

## Goal 2 — disprove GAK (was entirely unstaffed as forward work)

All our landed disproof work (D₁₆₆, AGL, the perfect-isomorphism scan) is *behind* us; the
community's whole Goal 2 had no forward thread. This is half the community problem.

### G2 — forward isomorph-falsification *(new · M · high community value, even if likely-negative)*
- **Serves:** Goal 2 (the only live whole-family falsifier). Mapping-independent.
- **Mechanism:** GAK is *proven* perfectly isomorphic (`c(ga)=c(a) ⇔ c(gb)=c(b)`). One robust
  same-plaintext isomorph that breaks where repeated plaintext predicts a match — *not* a word
  boundary — ejects the eyes from the entire perfectly-isomorphic family. The most decisive
  possible result.
- **Steps:**
  1. Push `src/analysis/perfect_isomorphism/mod.rs` (currently 0 robust violations,
     matched null) for a *single robust* internal violation: extend windows, properly null the
     loose bar, add an explicit word-boundary discount, and chase the one within-chance
     loose-bar candidate (Stutter east4@65 / west4@67).
  2. **Complement (the wiki's open ask):** construct a concrete imperfectly-isomorphic cipher
     family and test whether the eyes' borderline patterns (e.g. the `A.B..B.A` 7-instance
     pattern, ~13% coincidence chance) fit it *better* than GAK.
- **Validation:** any claimed violation must survive a hardened matched null *and* a word-boundary
  explanation; a clean negative (still perfect) is a legitimate, reportable strengthening of GAK.
- **Dependencies:** none (tooling exists). **Conflicts with:** other `perfect_isomorphism/mod.rs`/
  `isomorph.rs` edits.

---

## Isomorph-leak quantification & attack rigor (Goal 1, mapping-independent)

### G3 — quantify the isomorph leak's information-theoretic ceiling *(new · M · publishable)*
- **Serves:** Goal 1 feasibility (and the wiki's unanswered "is this even possible" question).
- **Mechanism:** the wiki states "it might be unrealistic to expect chaining to ever work for the
  eyes" given ~1036 trigrams vs a near-S₈₃ group — but never quantifies it. Compute, from the
  eyes' actual trigram count vs |S₈₃| / coset structure, an isomorph-mutual-information /
  coupon-collector bound on recoverable group elements — i.e. how many edges are extractable
  vs how many a candidate group needs to be pinned. Converting the soft pessimism into a stated
  feasibility/impossibility number is a disproof-side contribution that costs no new attack code.
- **Empirical anchor (from G1):** the GCTAK solver's clean failure on the known-answer hidden-state
  sample `two` pins the wall concretely — recovery dies because the visible readout is many-valued
  (out-degree 8 on all 12 symbols). That is the "delta-under-hidden-state" obstruction in the
  smallest real case; G3 should quantify how that many-valuedness scales toward the eyes' 83 symbols.
  The current `two` route reads through `research/handoff/two-cross-agent-recon.md`; the many-valued
  readout is a model-free measurement that survives its route reset (an order-48 observable shadow).
- **Files:** `src/analysis/isomorph.rs`, `src/analysis/chaining_graph/mod.rs`, `src/data/corpus.rs`.
- **Dependencies:** none.

### G4 — edge-overlap certification threshold vs transitivity degree *(new · M — fold into T6)*
- **Serves:** Goal 1 sub-problem (ii), mapping-independent.
- **Mechanism:** the wiki's stated half-solved problem — compute, per candidate `(group, hidden
  subgroup)`, the minimum number of identical chaining edges that forces "same transformation."
  Tied to the group's transitivity degree on cosets of `H` (S₈₃/S₈₂ worst case = all edges;
  dihedral ~2). This is exactly T6's substrate, generalized — implement them together.
- **Files:** `src/analysis/chaining_graph/mod.rs`, `src/attack/gak_attack/`.

### T6 — Schreier-composition-closure held-out gate for the eyes *(M · keep, raised)*
- **Serves:** GAK-attack rigor + the certification sub-problem (absorbs G4).
- A stricter held-out alternative: instead of the coverage-weighted
  held-out score, require recovered contexts to compose under Schreier-vector composition (the
  "correct" group-algebra check). Add as a variant gate in
  `src/attack/gak_attack/eyes/mod.rs::run_gak_attack_eyes` (chain-link infra in `chaining_graph/mod.rs`);
  reuse synthetic positive controls. Directly implements the wiki's "certify two partial graphs are
  the same transformation."
- **Dependencies:** Thread 4 + Thread 5 (landed). **Conflicts with:** T7 (both `gak_attack/`) — serialize.

### T7 — group-constrained `{A₈₃, S₈₃}` solver *(L · keep — cap effort)*
- **Serves:** Goal 1 recovery on the actual surviving family. Mapping-independent.
- With affine/dihedral ruled out, fix the family to A₈₃ or S₈₃ (without revealing the specific
  group) and ask whether the narrowed search improves recovery, exploiting the small-swap lead
  (≤~4 swaps/letter near-identity neighborhood). New variant, likely
  `src/attack/gak_attack/constrained_solver.rs`; reuse `generator.rs` for synthetic controls.
- **Caveat:** this is the "hard residue" the wiki itself doubts is tractable for the eyes — cap
  effort; a calibrated negative is a fine outcome.
- **Dependencies:** Thread 4. **Conflicts with:** T6 — serialize.

---

## Mapping-dependent long shot

### T8 — language-guided mapping search on the eyes *(L · keep, honesty-gated)*
- **Serves:** Goal 1 decode (key-dependent) — the one thread that could use
  language evidence after structural gates. Speculative; blocked on missing key
  material, a method disclosure, or known plaintext — not a fixed symbol→meaning
  mapping.
- Use a Finnish/English n-gram score as the search objective over the GAK
  letter→action key plus a candidate plaintext-letter reading (analogous in
  spirit to the Ragbaby keyed-alphabet search, but not a substitution solve).
  **Caveat (binding):** the eyes are a context-dependent deck-cipher autokey, so
  a naive substitution-style mapping search will not work — the GAK structure
  must be folded into the objective. Treat any readable output as a hypothesis
  and log per the candidate-logging directive (`research/gak-threads/candidates/`).
- **Dependencies:** T2 (Finnish quadgram, see `NEXT-STEPS.md` → Supporting). Builds on the
  Thread-4 solver. Don't gate the ladder on it; don't over-invest.

---

## Near-free contributions (cheap, directly contributable — *promoted onto the priority ladder*)

- **Publish the AGL exclusion.** The wiki holds AGL only "tentatively" ruled out; our
  `src/attack/agl_gak/mod.rs` excludes it exhaustively (0/6724, 0/3362). Package it + a write-up
  of the fixed-point lemma → converts a stated soft link to firm. Near-zero new work.
- **Base-5 first-trigram structure.** Tabulate the 9 first-trigram base-5 digit forms (already in
  `src/data/corpus.rs`); test index / checksum / last-char-moved-to-front and any base-5
  regularity. The wiki explicitly flags this as unsolved (Message-Starts). Hours, not weeks.

---

## Lower-priority eyes exploration

- **G5 — GAK tractability boundary sweep** (M, mapping-independent, analysis-only): map recovery
  over wider `n` (20→83) × hidden-subgroup size to state precisely where, between synthetic
  small-`n` successes and the `n=83` negative, recovery dies (`gak_attack/mod.rs` +
  `gak_attack/marginalization/mod.rs`). The quantitative claim that either justifies abandoning recovery or
  motivates a targeted attack — complements G3.
- Small-support prior (≤4 swaps/letter) sensitivity sweep — M.
- Deeper isomorph-family analysis of the broad chaining graph's ~5000 conflict pairs (benign
  collisions vs a second linguistic pattern?) — L; this is leak-exploitation, not lowest-priority
  busywork.
