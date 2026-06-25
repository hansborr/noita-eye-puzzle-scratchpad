# Thread 4 — GAK attack prototype: implementation / research spec

**Status:** spec only. Time-boxed research spike, gated by go/no-go milestones.
**Effort:** High. **Reward:** Highest — this is the one thread that could break the
standing "decode is blocked on the unknown symbol→meaning mapping" conclusion *by
pure cryptanalysis*, because a working GAK attack **produces** the
plaintext→permutation mapping rather than requiring it as input.

## The claim ceiling (non-negotiable, applies to every output of this thread)

The strongest defensible statement about the eyes remains: **"deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved; no
primary developer source confirms recoverable plaintext."** Nothing this thread
prints may be stronger. In particular:

- A candidate plaintext the attack emits for the eyes is a **hypothesis**, never a
  decode, until it survives held-out isomorph checks (Step 3). An unconstrained fit
  with no held-out data is almost certainly coincidence (see "The trap", §Gates).
- This is **mapping-independent** structural work: use only ciphertext symbol
  **equality** and group structure. Never invent a symbol→meaning mapping. (The
  attack may *recover* a plaintext→group-element map on **synthetic** ciphers where
  we hold the ground truth; that is a recovered key, not an assumed mapping.)
- Every structural negative needs a **matched null**; every positive control must
  **fire on known signal** (the `cipher_attack.rs` discipline).
- The small-support / ~≤4-swaps-per-letter prior is **TENTATIVE** (allomorph-derived,
  from `Deck-Cipher.md` "Shared Sections after a differing first character"). It is a
  **search heuristic to validate, not a hard constraint.** Label it as such in code,
  reports, and any write-up.

### Wiki sources this spec encodes (content current to 2026-01-16)

- `Group-Autokey-(GAK).md` — precise GAK definition (state group `G`, non-normal
  hidden subgroup `H`, PT map `p: P→G`, CT map `c: G→C` constant on right cosets
  `Hg`, cumulative left-multiplication update `g_{i+1}=p(a_i)∘g_i`, output
  `c_i=c(g_{i+1})`, `|C|=|G|/|H|`, injective `p`, one PT letter per coset).
- `Group-Ciphertext‐Autokey-(GCTAK).md` — GAK with **trivial** hidden subgroup
  (`c` bijective). The Step-1 positive control.
- `Deck-Cipher.md` / `Hidden-State.md` — the general `S_n` / `S_{n-1}` realization;
  top card visible, rest of deck is the hidden state; the small-support evidence.
- `Alphabet-Chaining.md`, `Graph-Chaining.md` — chaining: isomorph alignment →
  per-pair "contexts" → chain links `(context, x↦y)`; GCTAK = Cayley graph, GAK =
  Schreier coset graph; "geometric graph chaining" is the GAK generalization and is
  explicitly **a work in progress** that **may never scale to the eyes**.
- `Chaining-Conflicts.md`, `Chaining-Conflict-Rates.md` — non-commutativity is
  normal for GAK (a "conflict" is just a witnessed non-commuting context pair); GAK
  quirks: cycles of unequal length, edge overlap insufficient to prove equality
  (worst case `S_n`/`S_{n-1}` needs *all* edges identical), and the exact
  **TRUE-conflict** test (two arrows out of / into one symbol under one context ⇒
  not a permutation ⇒ bad isomorph assumption).
- `Explanation-of-Progress.md` — states what is already solvable: **GCTAK fully;
  simple GAK partially, given enough isomorphs**; and the open problem verbatim:
  *"we currently do not have any known algorithm for finding the PT → group element
  mapping for GAK … Basically, we need a GAK attack, and any work on this would be
  much appreciated."*
- `Smallest-GAK-Examples-with-Particular-Small-Hidden-Subgroups.md` — currently
  **`TBD`/empty** on the wiki; do not cite numbers from it. If it is filled in
  later it becomes a source of small ground-truth fixtures.

### Verified data and house rules

- Corpus: `src/corpus.rs`, the nine Experiment-0-verified messages, **1036**
  reading-layer trigrams over the **83-symbol** reading alphabet
  (`orders::READING_LAYER_ALPHABET_SIZE = ciphers::EYE_READING_ALPHABET_SIZE = 83`).
  Entry path: `orders::corpus_grids()` → `orders::accepted_honeycomb_order()` →
  `orders::read_corpus_message_values(&grids, order)` (per-message streams,
  boundaries kept; never concatenate across messages; never re-select a reading
  order). See `notes/api-analysis.md`.
- **Do not modify** `src/chaining.rs` (Experiment-7B, cyclic-only, additive). It is
  reusable as the additive baseline + calibration mindset only.
- Module/CLI/report wiring, lint rules, null+positive-control scaffold, and the
  exact-round-trip cipher-key test template: follow `notes/api-infra.md` verbatim
  (four-file touch: `src/<module>.rs`, `lib.rs`, `report.rs`, `main.rs`; new keys go
  in `ciphers.rs`). `unsafe` forbidden; no `unwrap`/`panic`/`indexing_slicing` in
  lib/CLI; every `pub` item documented; `--locked`; reuse `null.rs` PRNG only.

---

## Architecture overview

Three new compile units, plus reuse:

1. **`ciphers.rs` extension — `GakKey`** (Step 0 generator). General GAK over an
   abstract finite group with a chosen hidden subgroup, realized as a permutation
   group (deck) so `S_n`/`A_n`/`D_{2n}`/`AGL(1,p)` and the 6-group-for-83 cases all
   fit one type. Parametric `n`. This is *new cipher primitive* code and so lives in
   `ciphers.rs` beside `DeckCipherKey`, with the exact-round-trip test (§Step 0).

2. **`src/gak_attack.rs`** (Steps 1–3). The attack harness: GCTAK solver (positive
   control / decisive gate), the generalized graph-chaining + constraint-propagation
   + hidden-state-marginalization attack, synthetic-corpus drivers with ground truth,
   nulls, and the held-out evaluation. Mirrors `cipher_attack.rs` /
   `pyry_conditions.rs` shape (Config / Report / Error / `run_gak_attack`).

3. **Hard dependency on Thread 5's `chaining_graph` module** (`src/chaining_graph.rs`,
   **landed in commit 248fb32**). Thread 4 must import and reuse the shared
   chain-link primitive directly — it must never reimplement a second, divergent
   chaining-graph. The public items to consume are:
   `chaining_graph::ChainLink`, `chaining_graph::AlignedOccurrence`,
   `chaining_graph::chain_links_for_pair`, `chaining_graph::ConflictCatalogue`,
   and `chaining_graph::CoverageReport`. Thread 4 is staffed **only after Threads
   1/3/5** confirm the family and supply the graph (per the thread-4 brief), else
   we risk attacking the wrong cipher family.

The whole spike runs on **synthetic GAK we generate** (known plaintext, known
per-letter permutations, known initial state) so every intermediate claim is
checkable. The eyes are touched only at Step 3, only after Step 1's gate passes.

---

## Step 0 — general GAK / deck GENERATOR (`GakKey` in `ciphers.rs`)

**Goal.** A completely general GAK encipher/decipher where each plaintext letter maps
to an **arbitrary** permutation in `S_n` (or a constrained subgroup such as `A_n`),
state updates cumulatively, and the output is the hidden-subgroup **coset** (the deck
realization's "top card"). Parametric `n` so we work at `n = 5, 8, 12, …` long before
`83`.

**Type surface (mirror `DeckCipherKey`, `ciphers.rs:384`).**

```text
pub struct GakKey {
    ciphertext_alphabet_size: usize,   // |C| = |G|/|H|
    state_size: usize,                 // n: permutations act on 0..n (deck size)
    plaintext_letters: Vec<Permutation>,   // p(a) for each PT letter, each in S_n / A_n
    initial_state: Permutation,            // g_0, default identity
    coset_readout: CosetReadout,           // c: G -> C, constant on right cosets of H
}
```

- Represent `G` as a permutation group on `0..n` (`Deck-Cipher.md`: every group is a
  permutation group, so one representation covers all six 83-groups and all small
  test groups). A `Permutation` is a validated `Vec<usize>` (reuse the existing
  `validate_permutation` helper, `ciphers.rs:659`).
- Hidden subgroup `H` is encoded *via the readout*, not stored as a coset list: for
  the deck realization `H = S_{n-1}` (stabilizer of the top card) and
  `coset_readout(g) = g[top_index]` — i.e. "which card is on top", exactly the deck
  cipher. `|C| = n` here. For non-`S_n` groups the readout is the coset projection
  `c` that is **constant on right cosets `Hg`** (the `Group-Autokey-(GAK).md`
  requirement); provide a `CosetReadout::TopCard` variant (deck / `S_n`,`S_{n-1}`)
  and a `CosetReadout::CosetTable { coset_of: Vec<usize> }` variant for explicitly
  enumerated small groups.

**Construction validation (return `CipherError`, never panic).** Enforce the
`Group-Autokey-(GAK).md` well-formedness rules so generated fixtures are honest:
- each `p(a)` is a valid permutation of `0..n` (`validate_permutation`);
- **injective on cosets:** no two PT letters land in the same coset of `H` (else not
  reversible) — check `coset_readout(p(a)∘g_0)` distinct across letters from the
  identity state;
- **no-doubles option:** reject any `p(a)` that leaves the readout coset unchanged
  from identity (`Deck-Cipher.md`: don't pick from the identity coset) when
  `avoid_doubles` is set;
- if a subgroup constraint is requested (e.g. `A_n`), verify each `p(a)` parity.
- (Hidden-subgroup *irreducibility* — non-normal, no core subgroup — is a property of
  the chosen `H`, not of `p`. For the deck `S_n`/`S_{n-1}` it holds by construction;
  for hand-specified small `CosetTable` fixtures, document the `(G,H)` pair and its
  source rather than re-deriving irreducibility in code.)

**Encrypt / decrypt (free fns, `# Errors` doc each).**
- `gak_encrypt(&[Glyph], &GakKey) -> Result<Vec<Glyph>, CipherError>`: `g ← g_0`;
  per PT letter `a`: `g ← p(a) ∘ g`; emit `coset_readout(g)` as the CT symbol.
- `gak_decrypt(&[Glyph], &GakKey) -> Result<Vec<Glyph>, CipherError>`: replay the
  same cumulative state, inverting via the injective PT→coset map. Decrypt requires
  the key (this is the whole point: without the key the hidden state blocks
  brute-forcing — `Explanation-of-Progress.md`).

**Ground-truth fixtures + exact round-trip (mandatory, the `notes/api-infra.md`
template, `ciphers.rs:1224`).** In `#[cfg(test)]`:
- small alphabet and `EYE_READING_ALPHABET_SIZE`, random plaintexts via
  `SplitMix64`, `assert_eq!(gak_decrypt(gak_encrypt(p)), p)`;
- **GCTAK special case:** with `H` trivial (`coset_readout` bijective), assert the
  output equals an independent GCTAK reference encipher (cross-check that GAK reduces
  to GCTAK when `|H|=1`, per `Group-Autokey-(GAK).md`);
- **isomorph property:** encrypt a plaintext containing **repeated phrases**; assert
  the CT shows the *same* equality/gap pattern at the repeats (reuse
  `isomorph::PatternSignature::from_window`) — i.e. perfect isomorphism, the eye-like
  signal we need for the attack to have anything to bite on;
- **no-doubles fixture:** with `avoid_doubles`, assert no adjacent-equal CT symbols.

**Generator driver** (in `gak_attack.rs`, not `ciphers.rs`): given `(n, group_kind,
hidden_subgroup_kind, num_pt_letters, small_support_radius, seed)` and a
repeated-phrase plaintext template, produce `(plaintext, ciphertext, GakKey)` so the
attack always has held-back ground truth. The `small_support_radius` knob draws each
`p(a)` as a base permutation composed with ≤k random transpositions
(`Deck-Cipher.md`), so we can generate **both** the tentative small-support regime
and the unconstrained-`S_n` regime and measure where the attack works.

### Step 0 gate (week-1)

**General `S_n` GAK generator + synthetic isomorph-rich corpora exist, round-trip
exactly, and reproduce perfect isomorphs on repeated phrases.** If this is shaky,
**STOP** — there is no point attacking with a generator we don't trust.

---

## Step 1 — reproduce known-solvable baselines as POSITIVE CONTROLS

Calibration before attack. Both must fire on **known** signal (`cipher_attack.rs`
positive-control pattern, gated by a `MIN_MARGIN`-style threshold; a failure is a
`PositiveControlFailed` error variant — methodology suspect, not data).

1. **GCTAK solved end-to-end — the DECISIVE GATE.** `Explanation-of-Progress.md` says
   GCTAK is fully solvable by extended chaining. Implement that solver against
   generated GCTAK fixtures (trivial `H`, so the Cayley graph / `chaining_graph`
   applies directly): isomorph-align → build chain links → place the alphabet /
   recover the group structure → take group-element deltas → recover plaintext.
   Assert **exact** plaintext recovery on multiple seeds and group choices
   (cyclic and non-commutative GCTAK, e.g. a dihedral state group).
   **No GCTAK solve, no GAK attempt.** This is the harness's proof of life.

2. **Small `S_n` GAK *partially* recovered, given many isomorphs.** Reproduce the
   wiki's "partially solve simple GAK examples" claim on small `n` (start `n ≤ 8`),
   few hidden states, isomorph-rich CT. Success metric is **fraction of per-letter
   permutations / coset actions recovered**, scored against the held ground truth,
   with a **matched null**: the same recovery pipeline run on a within-message
   multiset shuffle (`null::fisher_yates` over `message_values.to_vec()`, exactly as
   `isomorph_null.rs`) must do **markedly worse** — the recovered fraction on real
   structure must exceed the shuffle-null band (add-one empirical p
   `(count+1)/(trials+1)`).

---

## Step 2 — the attack ideas (research; try several, validate each on ground truth)

All three operate on the **generalized chaining graph**, where (unlike
`chaining.rs`'s cyclic additive deltas) **contexts compose as PERMUTATIONS, not
scalars**.

1. **Generalized chaining graph + constraint propagation.** Build the chain graph
   (nodes = CT symbols; colored edges = `symbol↦symbol` under a fixed *context*),
   reusing Thread 5's `chaining_graph` chain-link primitive on the synthetic corpus.
   Aligned isomorphs give equations `context · π(word) = context'`; the unknowns are
   the per-letter group elements / context permutations. Solve by propagation over
   the **Schreier coset graph** (`Graph-Chaining.md`: GAK ⇒ Schreier graph of `G` on
   `H`-cosets). **Honor the GAK quirks** (`Chaining-Conflicts.md`): cycles of
   *unequal* length are normal (hidden state shortens some); edge overlap does **not**
   prove context equality (worst case `S_n`/`S_{n-1}` requires *all* edges identical
   before merging) — so a merge step needs a group-dependent overlap threshold, never
   "≥1 shared edge ⇒ equal". **TRUE conflicts** (two arrows out of / into one symbol
   under one context) abort: they prove a bad isomorph assumption, not a discovery.

2. **Small-support prior (TENTATIVE search heuristic).** `Deck-Cipher.md`'s shared-
   sections-after-differing-first-character evidence bounds per-letter permutations to
   **~≤4 transpositions from a shared base** (near-identity). This collapses the
   search from `S_83` (`83!`) to permutations expressible as ≤k transpositions —
   tractable. Make it a **first-class but soft** constraint: a prior/penalty in the
   search, **toggleable**, and **validated** by generating fixtures with and without
   it and measuring whether assuming it (a) speeds recovery when true and (b) *fails
   gracefully / is detectably wrong* when false. Never report a result that silently
   depends on it without the label.

3. **Hidden-state marginalization.** Where brute force over hidden state is the
   blocker (`Explanation-of-Progress.md`: infeasible "even … with only two hidden
   states per letter"), replace full enumeration with **belief propagation / beam
   search over the hidden-state posterior** conditioned on observed isomorph
   constraints. Score beams by constraint satisfaction against held-out chain links;
   prune by the small-support prior when enabled.

Each idea is scored on **synthetic ground truth** (recovered-permutation fraction,
recovered-plaintext exactness) with a matched shuffle null and a clean positive
control. "Negative is the expected outcome" framing (`cipher_attack.rs` module doc):
an idea that doesn't beat its null on synthetics is reported as such, not buried.

---

## Step 3 — point it at the eyes (ONLY after Step 1's gate passes)

Run the matured attack on `corpus.rs` (1036 trigrams, 83-symbol reading layer,
accepted honeycomb order, message boundaries kept). **Any candidate is a HYPOTHESIS,
killed — in this order — by:**

1. **Held-out isomorphs.** Recover on a subset of eye isomorphs; the candidate must
   correctly predict isomorphs / chain links it was **not** trained on. An
   unconstrained fit that can't predict held-out structure is coincidence.
2. **Thread 3 perfect-isomorphism consistency.** The candidate's implied state model
   must be consistent with Thread 3's perfect-iso scan (no manufactured TRUE
   conflicts, no crossing of allomorphic boundaries — `chaining` only within
   Thread 3's safe isomorph extents, never over-extended).
3. **(LAST) in-game lore / cross-message plausibility.** Only as a final external
   corroboration of a candidate that already survived (1) and (2) — never as the
   primary evidence, never to rescue a fit that failed the structural checks.

Expectation, stated honestly up front: given the group appears to be near `S_83` with
very little text (`Alphabet-Chaining.md`: "it might actually be unrealistic to expect
chaining to ever work for the eyes"), **Step 3 most plausibly does not yield a
surviving candidate.** That is an expected, reportable outcome — not a failure of the
thread.

---

## Go / no-go gates (verbatim, from the thread-4 brief) + the trap

1. **General `S_n` GAK generator + synthetic isomorph-rich corpora — week-1 gate; if
   this is shaky, stop.**
2. **GCTAK solved end-to-end (positive control) — decisive gate; no GCTAK solve, no
   GAK attempt.**
3. **Small `S_n` (n ≤ 8) GAK *partially* recovered with the small-support prior — the
   real result; reaching this reliably is already novel and is what the wiki asks
   for. Write it up even if `S_83` never falls.**
4. **(Stretch) scale toward `S_83` on the eyes. Treat anything here as a hypothesis to
   be killed, not a solution.**

**The trap to avoid (verbatim):** *a "solution" on the eyes with no
synthetic-ground-truth validation and no held-out check. Without ground truth, an
unconstrained fit is almost certainly a coincidence. Do not report it as a decode.*

---

## What counts as success — and why an honest partial IS a contribution

- **Win:** a reproducible attack that recovers per-letter permutations on synthetic
  GAK from isomorphs (at least small `n`), validated against ground truth.
  Publishable progress on the community's stated open problem **regardless of whether
  it cracks the eyes.**
- **Honest partial — itself a real contribution:** **GCTAK solved end-to-end; GAK
  attacked but not solved at useful scale.** This is not a non-result. It directly
  answers the wiki's explicit request ("we need a GAK attack, and any work on this
  would be much appreciated") with (a) a reusable, ground-truth-validated GAK
  generator + attack harness, (b) a **measured negative bound on tractability** (how
  far `n` / hidden-state count can go before recovery breaks, with and without the
  small-support prior), and (c) calibrated nulls and positive controls others can
  build on. The community problem is *open*; a rigorous, reproducible "here is how far
  it goes and where it stops" moves it forward.
- **The reframe (for memory / write-up):** if even a *partial* attack recovers the
  mapping from isomorph structure alone on synthetics, it shows the eye mapping is
  "unrecovered by attacks tried so far," **not** "recoverable only from an external
  source." That is a softening of the standing claim — but the standing claim about
  the **eyes** does not change until a candidate survives Step 3's held-out checks.

## Reuse map (do not reinvent)

- `ciphers.rs` — generalize `DeckCipherKey` → new `GakKey`; reuse `validate_*`
  helpers and the exact-round-trip test template (`ciphers.rs:1224`).
- `chaining.rs` — additive/cyclic baseline + calibration mindset **only; do not
  modify** (Experiment-7B, cyclic-only).
- `cipher_attack.rs` — harness/null/positive-control pattern, the
  `PositiveControlFailed`-as-error discipline, and the "negative is the expected
  outcome" + shuffle-null-contrast framing.
- Thread 5's `chaining_graph` module — chain-link extraction, conflict catalogue,
  connected-component coverage (hard dependency; build synthetic analogue if absent
  and flag it).
- `isomorph.rs` (`PatternSignature::from_window` — cross-message alignment primitive),
  `isomorph_null.rs` (within-message multiset shuffle null + add-one p),
  `perseus.rs` (alignment anchors), `null.rs` (PRNG — `SplitMix64`, `fisher_yates`,
  `shuffled_permutation`, `stateless_splitmix`, `random_index_below`; reuse only),
  `analysis.rs` (chi-square / IoC), `orders.rs`+`corpus.rs` (verified streams).
- Wiring: `notes/api-infra.md` four-file pattern (module + `lib.rs` + `report.rs` +
  `main.rs`), with a `gak-attack` CLI subcommand and a report whose `Interpretation:`
  paragraph states the claim ceiling, cites the GAK wiki pages, and preserves the
  "tentative" label on the small-support prior.

## New code to write

`GakKey` + `gak_encrypt`/`gak_decrypt` (in `ciphers.rs`); `src/gak_attack.rs` (GCTAK
solver, generalized graph-chaining + constraint propagation, small-support search,
hidden-state beam/BP, synthetic generator drivers, nulls, held-out eye evaluation);
the four-file CLI/report wiring; ground-truth fixtures and the matched nulls /
positive controls throughout.
