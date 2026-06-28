# Wave-2 summary — GAK threads land, and the GAK attack runs its course

**Date:** 2026-06-25. **Wave:** 2 (frozen wave-1 specs implemented under the build
gate; the Thread-4 GAK-attack spike taken end to end). Companion ledger:
[`PROGRESS.md`](../PROGRESS.md) §6. Eyes negative record:
[`candidates/eyes-seed-657965735f737470-trials-2000-beam-8.md`](../candidates/eyes-seed-657965735f737470-trials-2000-beam-8.md).

Claim ceiling (held verbatim throughout). The strongest defensible statement about
the eyes remains: *deterministic, engine-generated, strikingly structured data of
unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.*
Nothing in this note is stronger. Every wave-2 module is mapping-independent
(ciphertext symbol equality + group structure only); no symbol→meaning mapping is
invented or consumed. Each module is landed under `-D warnings` with `make verify`
green, and carries a matched within-message shuffle null plus a positive control that
fires on known signal.

---

## 1. What wave 2 did

Wave 1 produced verification notes, throwaway Python prototypes, and four frozen Rust
implementation specs — but nothing under `src/` had moved. Wave 2 closes that gap: it
moves the foundational structural work into the build gate, and then takes the one
remaining open thread, the GAK attack (Thread 4, the "prize"), as far as this workbench
can carry it. The headline: the structural pruning lands cleanly, the GAK attack
works on synthetic ciphers and breaks honestly on the eyes, and the standing
conclusion does not move.

## 2. The foundational structural modules (Threads 1B, 2, 3, 5)

Four landings turned the prototypes into gated Rust, with cross-model review on
each.

- **`248fb32` — Thread 5 `chaining_graph.rs` + Thread 1B `transitivity.rs`.** The shared
  chain-link primitive (the substrate every later thread reuses — no second chaining
  graph is ever reimplemented), the conflict catalogue, and connected-component coverage
  in broad + core-supported tiers, with a non-commutative GAK-stream positive control
  that clears its own null with margin (real 46 > null max 2). Thread 1B rides on top:
  `D₁₆₆` is conditionally excluded at medium confidence — order-83 forcing is robust
  on the 9-core but the commutativity conflict lives only in a col-9 over-extension, so
  the kill is single-witness-fragile. Hole 1 / hole 2, assumptions A1–A5, and the claim
  ceiling print verbatim; exactly one witness is pinned (`core_only=0`).

- **`47f0c51` — Thread 3 `perfect_isomorphism.rs`.** Tests whether the eyes are
  consistent with perfect isomorphism, the premise that keeps the whole
  CTAK..XGAK / GAK family viable. Result on the real corpus: 0 robust strong-bar
  internal violations over the full ≥3-repeat tier (matched null mean 0, max 0; add-one
  upper-tail p 1.0) ⇒ supports (does not prove) perfect isomorphism. It exports the
  16 safe-isomorph extents that Threads 1B/5/4 use to avoid chaining across
  allomorphic boundaries. Both main positive controls and the 3A/3B/3C regressions fire.
  Cross-model review caught two P0s — the headline counted violations only over the
  exported seeds while the null scanned the whole tier (a matched-null violation, now
  computed over the same population), and the far-run guard was too weak — both fixed
  before commit; the count stays 0, now for the *right* reason.

- **`a3413e7` — Thread 2 `agl_gak.rs` + `AglGakKey`.** The "soft link" in the
  candidate-group argument, killed rigorously. `AGL(1,83)`-GAK is exhaustively
  excluded — exhaustively, not statistically — for both affine variants. The
  mechanism: after a differing immediately-preceding symbol the inter-message
  discrepancy is a fixed non-identity affine map fixing ≤1 point, so any shared run must
  be a *constant* stutter; the eyes' shared runs vary. Confirmations: elements
  fixing ≥2 points = 0/6724 (`C83:C82`) and 0/3362 (`C83:C41`); agreement
  violations 0/40000; forward varying-shared-run sims 0/2,000,000. The verdict gates on
  the tightest clincher — the all-nine `(66,5)` length-2 varying prefix, AGL-impossible
  on its own. The report records that the *wiki over-conceded* (its message-start reason
  is weak; the varying-shared-run argument is the real kill).

- **`a31bc3a` — chore/review-fixups merge.** House-keeping that touched no scientific
  claim: centralized the `median` / `scaled_quantile_index` null helpers, enforced
  zero-trial guards in the library nulls (a zero-trial run is now rejected, not silently
  treated as a pass), and resolved doc drift.

Net effect on the candidate group set. Of the six transitive groups on 83 points —
`{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83)=C₈₃:C₈₂, A₈₃, S₈₃}` — `C₈₃` is out (commutative, no
non-commuting chaining); both AGL variants are exhaustively excluded (Thread 2);
`D₁₆₆` is conditionally excluded at medium (Thread 1B); and perfect isomorphism is
supported (Thread 3), keeping the family viable. That leaves the live candidates
`{A₈₃, S₈₃}`, with `D₁₆₆` conditional. All affine and dihedral exclusions are
conditional on the same shared-plaintext + single-global-config assumption the entire
transitivity analysis rests on; rejecting that assumption reopens the options *and*
weakens the 6-group restriction itself.

## 3. Thread 4 — the GAK attack, end to end

Thread 4 targets the wiki's explicit open problem ("we currently do not have any known
algorithm for finding the PT → group element mapping for GAK … we need a GAK attack").
It ran as a gated spike with hard go/no-go milestones. All six units landed. **Every
unit except the final eyes Step 3 is synthetic only:** the generator holds back the
ground-truth key, and the eyes corpus is not touched until unit 2c. The arc:

- **Step 0 (`e7b88f8`) — `GakKey`, the general GAK primitive.** A fully general
  Group-Autokey cipher, parametric in state size `n`, realized as a permutation group so
  `S_n`/`A_n` and all six 83-symbol candidate groups share one type: per-letter
  permutation, cumulative left-multiplication state update, and a hidden-subgroup coset
  readout. Exact round-trip, a GAK→GCTAK reduction cross-checked against an independent
  reference, and ciphertext-level perfect-isomorph reproduction on repeated phrases (the
  eye-like signal the attack needs to bite on). No claim about the eyes — a synthetic
  generator only. The week-1 gate ("generator round-trips exactly + reproduces perfect
  isomorphs, else STOP") passes.

- **Unit 1a (`d3b30fd`) — the GCTAK decisive gate. Passes (synthetic).** GCTAK is GAK
  with a trivial hidden subgroup (bijective readout), which the wiki states is fully
  solvable by extended chaining. This is the project's go/no-go gate — *no GCTAK solve,
  no GAK attempt.* The solver isomorph-aligns repeated phrases, clusters transitions into
  per-letter permutations, and reads off the plaintext, receiving only ciphertext + the
  observable coset readout — never the key, plaintext, or true permutations. The gate is
  rate-beats-null, not a lucky seed: across independent seeds the real recovery rate
  clears 0.8 *and* exceeds the matched within-message shuffle null (which recovers 0),
  including a non-commutative dihedral state group, with no ground-truth leak
  (confirmed adversarially). This reproduces the wiki's "GCTAK is fully
  solvable" as a synthetic positive control — a proof of life for the harness, not
  an eye result and not a decode.

- **Unit 1b (`aaa9e9a`) — CLI wiring + honesty lock.** The `gak-attack` subcommand and
  report (four-file pattern; solver logic untouched), with `tests/gak_attack_cli.rs`
  asserting the gate-independent claim-ceiling / synthetic-only / tentative / rate-vs-null
  / "exemplars are illustrations, not pass evidence" strings, so a quiet overclaim trips
  the gate.

- **Unit 2a (`1d928a2`) — the real-GAK deck attack. Partial, with a measured bound.**
  The generalized chaining attack on a non-trivial hidden subgroup — the community's
  actual open problem — on synthetic deck-stabilizer GAK (`H=S_{n-1}`, `|H|=(n-1)!>1`,
  hidden state = the rest of the deck), ground truth held. What it honestly establishes:
  only partial visible-coset action recovery — a fraction of per-letter visible-coset
  transitions, not a recovered key and not the plaintext→group-element mapping.
  The recoverable fraction stays small and roughly flat across `n` because it is bounded
  by a measured hidden-state obstruction: a letter's visible-coset action is ~0.8
  multi-valued across hidden states (this multi-valuedness is normal for GAK, not a
  conflict; it is measured, not aborted). That measured obstruction is precisely the
  contribution the wiki asks for, and it motivates idea 3.

- **Unit 2b (`8aa7c53`) — hidden-state marginalization (idea 3) + small-support prior
  (idea 2).** Idea 3 recovers more of the per-letter marginal with a bounded, truth-free
  beam: per aligned phrase column it splits occurrences into a train fold and a reserved
  held-out fold, builds support-ranked prefix hypotheses, and selects the one with the
  best held-out generalization — ground truth never enters selection, only post-recovery
  scoring. Measured (24 seeds, prior off, beam width enforced): idea 3 recovers
  several-fold more of the marginal than the 2a single-valued core at every swept `n`
  (≈5.9x / 3.9x / 4.9x / 2.8x for n=5..8) and beats its matched null everywhere,
  while degrading cleanly toward — never below — the baseline as `|H|=(n-1)!` grows
  (mean recovered fraction 0.407→0.156). That measured "marginalization helps, and here
  is where it breaks" is the contribution; it is partial visible-coset recovery on
  synthetic ground truth, not a recovered key and nothing about the eyes. The
  small-support prior (idea 2) is tentative: it fails gracefully (recall on ≤ off,
  never invents edges), holds/improves precision, but is only weakly discriminative
  (~0.44 vs ~0.41 retention) and is off in the headline, so no headline number
  depends on it.

- **Unit 2c (`44d4ec4`) — the eyes Step 3. Honest negative; decode blocked.** The one
  unit that touches the eyes. The matured chain-link / hidden-state attack is pointed at
  the real corpus (verified entry path only: `orders::corpus_grids()` →
  `accepted_honeycomb_order()` → `read_corpus_message_values`; 1036 reading-layer
  symbols, 83 distinct, boundaries kept, no concatenation or reorder), behind held-out +
  Thread-3 kill gates. A candidate is a hypothesis until it survives all gates.
  - **Gate 1 — held-out isomorphs vs matched within-message null.** The statistic is
    embargoed-consensus coverage-weighted excess correctness: a held-out edge scores only
    when ≥2 train contexts from distinct isomorph signature groups agree on it with no
    physical span overlap/adjacency (killing the nested-window leak a shuffle mimics).
    Chaining is enforced to stay within the Thread-3 safe isomorph extents, and the
    null is scored under the identical positional restriction. Real eyes: hits=0,
    misses=0, score=0; matched null over 2000 trials gives add-one p = 1.0000. The
    material-effect bar is population-relative and fair: the eyes' bar is 1722,
    *below* their own max-achievable score of 6888 — so the eyes *could* have passed
    with real signal — and a held-out positive control fires on a synthetic
    isomorph-rich fixture and clears its own population's bar, so the detector is trusted
    and the eyes' zero is a real negative, not a dead gate. Gate 1 verdict: false.
  - **Gate 2 — Thread-3 perfect-isomorphism consistency.** 0 robust internal violations;
    positive control fired; consistent.
  - **Gate 3 — speculative Finnish/English cleartext plausibility.** Correctly not
    run (Gate 1 failed); no candidate cleartext reported.
  - **Outcome: no surviving candidate.** No candidate cleartext, English or Finnish,
    arose. The run is logged for human review at
    `candidates/eyes-seed-657965735f737470-trials-2000-beam-8.md`.

## 4. The reframe — bounded — and the standing conclusion

The GAK attack is a measured tractability contribution to the community's open
problem: it shows *how far* chaining gets (synthetic GCTAK fully solved; real-GAK deck
partially recovered, several-fold improved by truth-free marginalization) and *exactly
where it stops* (the ~0.8 hidden-state multi-valuedness; the clean break as `(n-1)!`
grows). That is a real answer to "we need a GAK attack."

But the standing claim about the eyes does not change. The synthetic GCTAK gate and
the synthetic deck / idea-3 recoveries are positive results with ground truth held —
they are not eye results and not a decode. The eyes have abundant isomorph structure,
but it does not transfer across held-out contexts above a matched within-message
shuffle null (held-out score 0, p=1.0); the negative is clean and fair (the eyes could
have passed and did not). No candidate cleartext arose, and the speculative cleartext
gate was correctly never reached.

The eyes remain unsolved; the decode remains blocked on the unknown symbol→meaning
mapping. Claim ceiling, verbatim: *deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.*
