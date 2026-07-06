# ns=3 conflict-learning milestone — the two-tier CDCL(T) engine and its measured wall

> **STATUS: SUPERSEDED for vendored practice-puzzle recovery (2026-07-05).** The
> systematic CDCL(T) wall recorded here remains a valid measurement of that solver
> line, but it no longer describes the supported frontier of
> `gak-swap-recover`: substitution-first local search now recovers the ns=3
> observed-letter mapping for the vendored known-plaintext corpus with exact
> `2439/2439` re-encryption. Keep this file as provenance and implementation
> context; do not pick it up as the next task for solving `3_swap_ct.txt`.

Record of the ns=3 conflict-learning work in the gak-swap-recovery package: what
the engine delivers, the resolved two-tier architecture, the binding
soundness/honesty invariants, and the measured real-file wall. The
finer-vocabulary decision this milestone opened is **resolved** in
`05-ns3-finer-vocabulary-plan.md` (phased plan; that is the next-work package).

Read `research/handoff/gak-swap-recovery/README.md` first (framing, honesty
ceiling), then this, then
`research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md` for the
commands and measured numbers. House rules: `research/handoff/README.md`,
`AGENTS.md`. The binding invariants and the resolved architecture below are
load-bearing — do not regress them.

## Where this stands

- **ns=1 / ns=2: delivered.** Exact known-plaintext recovery, gated on planted
  controls + matched nulls, with byte-for-byte `2439/2439` re-encryption of all 8
  messages. Generalized generator sets (not just top-swaps), `--infer-swaps`,
  JSON + copy-pasteable Python `pt_mapping` shareable output, and a measured
  `(n, num_swaps)` frontier. Tasks 01/02/03 are done, reviewed, and merged;
  delivered against Lymm's community request.
- **ns=3 mechanism: proven on a planted key; the real `n=83` file is walled on
  COST, not soundness.** The two-tier conflict-learning engine recovers a
  *planted* ns=3 key exactly through the production path. The vendored
  `3_swap_ct.txt` does not recover — the wall is per-node cost at scale, not
  "algorithm wanders / is unsound" (the pre-Task-02 state). The CLI refuses
  `--num-swaps 3`; no exact `2439/2439` claim is made for ns=3 anywhere.
- **Finer-vocabulary decision: RESOLVED in `05-...md`.** The target layer is
  livelocked at the `(letter = target)` vocabulary — measured below, not
  conjectured. The resolved plan is phased: a Phase-0 short-conflict measurement
  gate → an implicit oracle regardless of the readout → conditional finer-literal
  CDCL(T); enumerate-and-filter is rejected as the *primary* engine (its oracle
  shape is adopted).
- **Phase-0 arc instrument: BUILT.** The `gak-swap-arc-phase0` subcommand
  (`src/cli/args_gak_swap.rs`, `commands/gak_swap_arc_phase0.rs`, wired through
  `dispatch.rs`) and its engine — `arc_phase0.rs`, `arc_phase0_tuple.rs`,
  `arc_phase0_types.rs`, `arc_phase0_controls.rs` under
  `src/attack/gak_attack/lymm_deck/recovery/` — measure whether the real `n=83`
  ns=3 instance admits short finer-than-`(letter = target)` conflicts, against the
  pre-registered Phase-0 decision rule in `05-...md`.

## The measured real-file wall (these numbers are load-bearing)

The engine is landed and adversarially reviewed in three increments — Stage 1
(deterministic target-rejection soundness: the `TargetUnsatCore` gap closed with
a broad-baseline recheck before learning, a dedicated `target_rejections`
counter, and production-path wrong-first target controls at `n=7/11/17`), Lever 1
(the deterministic `NoResidualCandidate` path tracks target-level implication
reasons and broad-replays every extracted reason before `learn_sat_clause`), and
Lever 1a (adaptive reason-replay order: controls stay quality-first and keep
singleton clauses, but once a multi-literal floor is demonstrated the real-file
path skips singleton probes and tries non-singleton tracked reasons first).
Anchored controls hold throughout at `4/15/18` target rejections (Lever 1a:
replay checks `5/22/25`, replay literals `4/15/18`), so the rejection-scaling
gate passes with no explosion.

The wall moved from "unsound" (pre-Task-02) to "cost", and the cost was then
re-characterized from an extraction-order artifact to a structural
target-vocabulary livelock. The load-bearing measurements:

- **cap-8 probe (Lever 1).** The real `n=83` cap-8 probe remains walled: `8`
  learned target rejections, `56` replay checks, `7.0` checks/rejection, about
  `216s` per learned rejection, no accepted target slice, and no exact
  `2439/2439` round trip.
- **cap-60 probes (Lever 1a).** The first cap-60 production probe learned `60`
  deterministic target clauses from `60` target rejections in `1856.190s` elapsed
  (`wall=1856.466s`), with `target_replay_checks=66` (`1.10` checks/rejection),
  `target_replay_literals=300`, and clause-length distribution `60 x len=5`. A
  follow-up adjudicating cap-60 probe instrumented the projected `E/H/S/T/Y` space
  and again learned `60` deterministic clauses with
  `target_floor_full_assignment_fallbacks=0`; it ran `2327.300s` elapsed
  (`wall=2327.536s`) and still accepted no target slice, reached no candidate-tier
  handoff, and made no exact `2439/2439` round trip. The projection measurement
  was decisive: all `60` rejected projected tuples were new, all stayed in the
  same `T=67` slab, and the static distinct projected space under that slab
  remained `34,234,200` with `34,234,140` still remaining at cap. Targeted
  residual sizes also showed no narrowing trend: `153896` entries on `55/60`
  assignments and `157136` on `5/60`, max domain `6562` throughout.

The projection probe supports the livelock read (Gemini-3.1-pro consult,
2026-07-04) over the earlier "stronger target reasons suffice" read: the
`(letter = target)` vocabulary learns only weak 5-literal nogoods and makes no
target-layer progress on the real `n=83` file, with the 5-literal floor most
likely structural/information-theoretic at `n=83`. Lever 1 and Lever 1a already
fixed the extraction-cost artifact (the real file now pays about one broad replay
per deterministic target rejection after floor discovery); the convergence side
is the wall, and chasing sub-5-literal target-only reasons is a dead burn. The
finer constraint vocabulary that this points to is designed in `05-...md`.

## The resolved architecture (two-tier CDCL(T)) — do not regress it

Recovery at ns≥3 is a target-level lazy-SMT / CDCL(T) loop over one-hot
`(letter = target)` literals, where `target = perm(L)[0]` (the forced top card).
It is **two-tier** — this is load-bearing and was the key design correction:

- **Rejection branch** — deterministic propagation rejects a target slice → learn a
  minimal negative *target-tuple* clause via greedy replay-minimization from a
  **fresh broad baseline** (unconditional `R-top`/`R-read` deductions + only the
  tested target subset; never reuse target-conditional narrowing). Code:
  `recovery/target_conflict.rs`, `recovery/ns3_cegar.rs`. Owner of learned target
  clauses: `recovery/target_solver.rs`.
- **Acceptance branch** — a target only fixes `perm(L)[0]`; the correct slice still
  leaves off-top *witness* freedom (measured on the scaled plant: `total=4, max=2`).
  So an accepted slice hands off to the **retained candidate SAT residual**
  (`recovery/residual.rs`, `build_residual_domains`), tests witnesses by exact
  re-encryption, and on failure learns a *candidate-level* clause. A target slice is
  banned in the outer solver **only** when its candidate space is genuinely
  exhausted (SAT UNSAT core) — never on a single witness failure.

**Why two-tier (don't collapse it back to target-only).** A target-only design
(the GPT lineage's first draft) is unsound on the acceptance branch: a target-tuple
clause cannot express "ban just this witness," so a single witness failure would
either livelock or ban a valid target slice — including, eventually, the truth. A
fresh-lineage (gemini-3.1-pro) design pressure-test caught this; the milestone's own
residual-freedom measurement then confirmed the acceptance branch has real work.

## Binding soundness/honesty invariants (a passing violation is a build-breaking bug)

- **Acceptance is ONLY exact byte-for-byte re-encryption.** Never a score, never
  perm-equality-to-plant. `report.round_trip.exact()` is the gate.
- **Per-clause truth-preservation.** Every learned clause (target AND candidate)
  passes `recovery/learning.rs::learn_sat_clause`, which asserts the planted truth
  falsifies ≥1 conjunct **before** insertion. Raw static-encoding inserts go
  through `add_static_encoding_clause` (renamed, with `debug_assert` + comment) so a
  future edit can't route a learned clause around the check. Keep that boundary.
- **A learned *target* clause must be valid against the *broad* baseline, restricted
  to only that clause's own literals** — not against a formula already narrowed to the
  other targets. Truth-preservation (above) is a no-op on the real (plant-free) file, so
  on the real file target-clause soundness rests *entirely* on this. The deterministic
  path earns it by construction: `target_conflict.rs::deterministic_rejects` re-runs
  broad propagation on exactly the candidate subset. The SAT `TargetUnsatCore` path
  (`residual.rs`) originally did **not**: its core was extracted from a formula whose
  domains were physically `restrict_to_targets`-narrowed to the *full* target assignment,
  so the channelling clauses baked in the off-core targets and an unsat core over a
  subset of target-assumption literals was not a proven broad-residual nogood. That
  landed gap is now closed by a one-shot broad-baseline recheck before
  `learn_sat_clause`; keep that recheck in place. Planted controls cannot catch this
  class by themselves because truth-preservation only fires when a bad core excludes
  *the* plant, and the controls have unique solutions — the exact
  "unsound-but-passing control" the process notes warn about.
- **Controls route through the production acceptance path** (`ns3_control.rs` calls
  `recover_known_plaintext_swaps`), truth tracking is observational/labeling only.
- **Measured frontier, never "scales arbitrarily."** A walled level is a reportable
  result with numbers, not a failure.

## Design rationale carried into `05-...md`

The finer-vocabulary lever was resolved by taking two explicit framings — pure
CDCL(T) finer-literal re-architecture vs. `shadow_search`-style
enumerate-and-filter per letter — to a cross-lineage design consult. The
resolution (05) keeps the learning core and enriches the vocabulary it learns
over, adopts the enumerate-and-filter *oracle shape* (per-letter MITM
projection/existence queries over generator words) without materializing the
per-letter candidate product, and gates the finer-literal build behind Phase 0.
The rationale that fed that resolution is preserved here.

### shadow_search relevance

`src/analysis/shadow_search` came from the `feat/two-hidden-state-key-search`
lineage. It is a `two`-side engine, not a deck-swap/eyes-side engine: different
puzzle, different threat model, full 12-symbol closure-group stream,
ciphertext-only, brute-force keyspace enumeration. It is not folded in wholesale.
What carries over:

- **Transfers: finer vocabulary evidence.** `shadow_search` expresses constraints
  as per-position domain-legality literals (`legal_lookup`) and per-position
  pairwise-equality literals over anchor spans. That is the same transition-arc
  scale the ns=3 fix needs. This is evidence, not a proof: `shadow_search`
  derives those literals statically as hard filters; it does not learn them.
- **Transfers partially: oracle shape.** `legal_lookup` is a clean per-position
  domain oracle and is the closest existing analog to the `LetterDomainOracle`
  seam. Caveat: it answers static membership. The CDCL(T) loop needs dynamic
  `image_mask`, `preimage_mask`, and `transition_possible` projections under a
  partial assignment.
- **Does not transfer: learning.** `shadow_search` has no conflict learning, no
  nogoods, and no partial-assignment propagation. Its early abort is a fully
  bound key streamed until failure, not a partial assignment reasoned about. The
  learning half of the CDCL(T) framing has no analog there.
- **Scope honesty.** `shadow_search` is itself at a documented `two` frontier. It
  enumerates down to a roughly `10^5` to `10^6` residual, but the crib-free finish
  failed; the known external solve required a 103-letter crib not held here. It
  is a sibling honest negative, not a shortcut to finishing `two`.

Scale caveat that framed the consult: `shadow_search`'s key space is about `3.1M`,
which is brute-forceable. ns=3 materializes about `541k` candidates per letter
over `83` letters, so the full product is astronomical. The adopted oracle-shape
path is not "materialize the product"; it lives or dies on whether the per-letter
MITM oracle can compose projected constraints without materializing that product.

### Deferred work (sequenced after a target slice is accepted)

- **Feature-level candidate CEGAR conflicts.** Candidate learning today is a
  whole-prefix no-good over the first-seen letters before the failed event
  (`residual.rs::add_prefix_conflict_clause`); a failed re-encryption should
  eventually learn local incompatible letter/candidate features where it can. It
  does not touch the current wall because the real file never reaches the
  candidate tier (`candidate_clauses=0`).
- **Incremental candidate solving.** The target solver is already incremental
  across the loop (`ns3_cegar.rs`); only the candidate `BasicSolver` is rebuilt
  per accepted slice. Payoff is on planted controls and post-target-wall stages,
  not the measured real-file wall.
- **ns=4 seam / implicit oracle.** ns=3 already materializes about `541k`
  candidates per letter; ns=4 over `n=83` cannot be built on
  `Vec<candidate_index>`. The move is an implicit `LetterDomainOracle` backed by
  the per-letter MITM over generator words (`lymm_deck/generators.rs`) answering
  projection/existence queries (`image_mask`, `preimage_mask`,
  `transition_possible`, `witness`) instead of returning full candidate sets,
  exposing finer-than-target literals so failures are explainable without
  discarding whole target assignments. This is the shared primitive `05-...md`
  builds regardless of the Phase-0 readout; it affects `propagation.rs`,
  `target_solver.rs`, `sat_encoding.rs`, and `residual.rs`, so do not churn every
  hot path outside that plan.

## Process notes (cheap, high-leverage — repeat them)

- **Cross-lineage design consult before a big implementation burn.** gemini-3.1-pro
  (outside the GPT/Claude lineages) caught a structural flaw both the GPT designer
  and the orchestrator missed, and later split the wall into its structural and
  artifact components. Get an off-lineage pressure-test of the approach, not just
  the diff.
- **Dedicated adversarial "re-derive from construction" review** on each landed
  lever — the full gate and a generic diff review do NOT catch an
  unsound-but-passing control or a learned clause that excludes a non-plant valid
  assignment.
- **Null classification is centralized** in `recovery/selftest.rs::classify_null_recovery`
  (shared by `reach.rs`). A null must fail by `CleanFailure` (proven infeasibility),
  never by solver cap/timeout. This bug reappeared 3× before centralizing — route
  every new null through the shared classifier.

## Validation entry points

- Planted ns=3 production-path control: `recovery/ns3_control.rs`.
- Real-file frontier probe (ignored, not gated): `lymm_deck/ns3_probe.rs`.
- Phase-0 finer-conflict instrument: `gak-swap-arc-phase0` subcommand +
  `recovery/arc_phase0*.rs` (self-calibrating controls via `--run-controls`).
- Full gate: `make verify` (do not regress ns=1/ns=2 or the planted ns=3 control).
- Rerunnable measurement commands + the residual-freedom finding: in
  `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`.
