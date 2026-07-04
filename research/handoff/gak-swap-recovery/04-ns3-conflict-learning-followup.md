# Handoff — ns=3/ns=4 conflict-learning follow-up (push the real-file wall)

Written 2026-07-04 after Tasks 01–03 landed and the first ns=3 conflict-learning
milestone was built + cross-lineage soundness-reviewed. Read
`research/handoff/gak-swap-recovery/README.md` first (framing, honesty ceiling),
then this. House rules: `research/handoff/README.md`, `AGENTS.md`.

## Start Here

1. Read `research/handoff/gak-swap-recovery/README.md`, then this file, then
   `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md` for the
   commands and measured numbers.
2. Treat the binding soundness/honesty invariants below as non-negotiable:
   acceptance only by exact byte-for-byte re-encryption; every learned clause
   routes through `learn_sat_clause`; nulls route through
   `recovery/selftest.rs::classify_null_recovery`.
3. Do a cross-lineage design consult before building the next lever. The measured
   decision point is no longer "make target-only reasons cheaper"; it is choosing
   how to move to a finer-than-`(letter = target)` vocabulary.

## Where this stands

- **Tasks 01/02/03: done, reviewed, merged.** Lymm-deck oracle + Python
  differential; exact ns≤2 KP recovery gated on planted controls + matched nulls;
  generalized generator sets (not just top-swaps); `--infer-swaps`; JSON +
  copy-pasteable Python `pt_mapping` shareable output; measured `(n, num_swaps)`
  frontier. Delivered against Lymm's community request.
- **ns=3 mechanism: proven on a planted key, real `n=83` file walled on COST, not
  soundness.** The two-tier conflict-learning engine recovers a *planted* ns=3 key
  exactly through the production path. The vendored `3_swap_ct.txt` did not
  recover: the first learned target clause alone took 25 broad-baseline replays and
  ~334.67s, then the one-node probe capped. The wall moved from "algorithm
  wanders / is unsound" (the pre-Task-02 state) to "per-node cost at scale."
- CLI still refuses `--num-swaps 3`; no exact `2439/2439` claim is made anywhere.

## Status update — 2026-07-04

This block supersedes the open-task state in the planning text below; the older
sections are retained for design rationale and guardrails.

- **Stage 1 is done and adversarially reviewed.** The `TargetUnsatCore`
  target-clause soundness gap was closed with a broad-baseline recheck before
  learning; a dedicated `target_rejections` counter was added; and the
  production-path wrong-first target controls now exercise deterministic
  rejection at `n=7/11/17`. Calibration measured `4/15/18` target rejections to
  convergence, so the rejection-scaling gate passed with no explosion.
- **Lever 1 landed and was adversarially reviewed.** The deterministic
  `NoResidualCandidate` path now tracks target-level implication reasons and
  broad-replays every extracted reason before it can reach `learn_sat_clause`.
  Anchored controls held at `4/15/18` target rejections. The real `n=83` cap-8
  probe remains walled: `8` learned target rejections, `56` replay checks,
  `7.0` checks/rejection, about `216s` per learned rejection, no accepted target
  slice, and no exact `2439/2439` round trip.
- **Pre-lever-1a review read.** Lever 2, feature-level candidate CEGAR
  conflicts, is premature until the search accepts at least one target slice.
  The recommended emphasis is stronger target reasons: smaller broad-valid
  deterministic clauses for the real-file rejection family. Per the process note
  below, this read was intentionally tested before spending a larger
  implementation burn; the later projection probe supersedes it for the current
  next decision.
- **Gemini-3.1-pro consult, 2026-07-04.** The consult split the wall into a
  structural and an artifact component: the real-file 5-literal target floor is
  likely structural/information-theoretic at `n=83`, while the `7.0`
  checks/rejection cost was an extraction-order artifact from testing doomed
  singleton/focused candidates before the full tracked core. Its ranked levers
  were: first, fix replay ordering; second, pull finer-than-target/partial
  transition literals forward; third, partial-slice DPLL(T) so deterministic
  propagation rejects target prefixes before full assignments are proposed; and
  fourth, candidate-feature conflicts only after target slices start being
  accepted. Its warning was that chasing smaller target-only reasons may livelock
  the solver in a huge 5-target tuple space because the `(letter = target)`
  vocabulary is too coarse.
- **Lever 1a landed after the consult.** The deterministic reason replay order is
  now adaptive: controls stay quality-first and keep singleton clauses, but once
  a run has demonstrated a multi-literal floor the real-file path skips singleton
  probes and tries non-singleton tracked reasons first. Anchored controls still
  hold at `4/15/18` target rejections with replay checks `5/22/25` and replay
  literals `4/15/18`.
- **Lever 1a real-file probes measured the livelock risk.** The first cap-60
  production probe learned `60` deterministic target clauses from `60` target
  rejections in `1856.190s` elapsed (`wall=1856.466s`), with
  `target_replay_checks=66` (`1.10` checks/rejection), `target_replay_literals=300`,
  and clause-length distribution `60 x len=5`. A follow-up adjudicating cap-60
  probe instrumented the projected `E/H/S/T/Y` space and again learned `60`
  deterministic clauses with `target_floor_full_assignment_fallbacks=0`; it ran
  `2327.300s` elapsed (`wall=2327.536s`) and still accepted no target slice,
  reached no candidate-tier handoff, and made no exact `2439/2439` round trip.
  The projection measurement was decisive: all `60` rejected projected tuples
  were new, all stayed in the same `T=67` slab, and the static distinct projected
  space under that slab remained `34,234,200` with `34,234,140` still remaining
  at cap. Targeted residual sizes also showed no narrowing trend:
  `153896` entries on `55/60` assignments and `157136` on `5/60`, max domain
  `6562` throughout. This supports the Gemini livelock warning over the earlier
  "stronger target reasons suffice" read; next design work should pressure-test
  finer-than-target or partial-slice theory propagation, not spend a blind
  implementation burn searching for sub-5 target-only clauses.
- **Current decision point for the next agent.** The target layer is livelocked
  at the `(letter = target)` vocabulary. This is measured, not conjectured: the
  adjudicating cap-60 probe rejected `60` fresh projected `E/H/S/T/Y` tuples,
  consumed only `60` of `34,234,200` projected tuples under `T=67`, never changed
  `T`, and kept max domain `6562`. The next serious lever is a finer constraint
  vocabulary. Before building, resolve two competing framings with a
  cross-lineage design consult: pure CDCL(T) re-architecture that learns finer
  literals, versus a `shadow_search`-style enumerate-and-filter-per-letter path
  that uses per-letter MITM oracle projections and reserves learning for
  cross-letter glue.

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

## The Next Lever

Lever 1 and lever 1a changed the cost side of the equation: the real file now
pays about one broad replay per deterministic target rejection after floor
discovery. The convergence side is the wall. The measured cap-60 projection says
the `(letter = target)` vocabulary learns only weak 5-literal nogoods and does
not make target-layer progress on the real `n=83` file. Do not spend another
burn chasing sub-5-literal target-only reasons. The Gemini consult read the
5-literal floor as structural to `n=83`; the projection probe is consistent with
that read. The extraction-cost artifact was already fixed in lever 1a.

Before building, take these two explicit framings to a cross-lineage design
consult. They both target finer-than-`(letter = target)` granularity; they differ
on how to search it.

1. **Pure CDCL(T) re-architecture.** Enrich the solver so it can learn finer
   literals: transition arcs, `(letter,input_pos)=output_pos` features, or
   partial-slice theory-propagation facts. A rejection should become explainable
   without discarding a whole target assignment. This is the existing
   `LetterDomainOracle` / ns=4-seam direction below: keep the learning core, but
   change the vocabulary it learns over. Scope is high because it affects every
   consumer of materialized candidate domains: `propagation.rs`,
   `target_solver.rs`, `sat_encoding.rs`, and `residual.rs`.
2. **Enumerate-and-filter per letter.** Instead of teaching the loop to learn
   finer literals, brute-force the finer structure directly in the spirit of
   `src/analysis/shadow_search`: enumerate per-letter candidates with the
   existing per-letter MITM over generator words (`lymm_deck/generators.rs`),
   compose through oracle projection/existence queries instead of materializing
   full candidate `Vec`s, deduplicate by canonical class, and reserve learning
   for cross-letter glue if learning is needed at all. This framing is viable
   only if an enumerable finer substructure exists at `n=83`; it is on the table
   because `shadow_search` shows that an exhaustive, finer-vocabulary sibling
   GAK engine can be real.

State this scale caveat to the consult: `shadow_search`'s key space is about
`3.1M`, which is brute-forceable. ns=3 materializes about `541k`
candidates per letter over `83` letters, so the full product is astronomical.
Framing 2 is not "materialize the product"; it lives or dies on whether the
per-letter MITM oracle can compose projected constraints without materializing
that product. Do not assume framing 1 is the only path just because this doc
sketched it first.

### shadow_search Relevance

`src/analysis/shadow_search` came from the `feat/two-hidden-state-key-search`
lineage. It is a `two`-side engine, not a deck-swap/eyes-side engine: different
puzzle, different threat model, full 12-symbol closure-group stream,
ciphertext-only, brute-force keyspace enumeration. Do not fold it in wholesale.
What carries over:

- **Transfers: finer vocabulary evidence.** `shadow_search` expresses constraints
  as per-position domain-legality literals (`legal_lookup`) and per-position
  pairwise-equality literals over anchor spans. That is the same transition-arc
  scale the ns=3 fix likely needs. This is evidence, not a proof: `shadow_search`
  derives those literals statically as hard filters; it does not learn them.
- **Transfers partially: oracle shape.** `legal_lookup` is a clean per-position
  domain oracle and is the closest existing analog to the `LetterDomainOracle`
  seam. Caveat: it answers static membership. The CDCL(T) loop would need dynamic
  `image_mask`, `preimage_mask`, and `transition_possible` projections under a
  partial assignment.
- **Does not transfer: learning.** `shadow_search` has no conflict learning, no
  nogoods, and no partial-assignment propagation. Its early abort is a fully
  bound key streamed until failure, not a partial assignment reasoned about. The
  learning half of framing 1 has no analog there.
- **Scope honesty.** `shadow_search` is itself at a documented `two` frontier. It
  enumerates down to a roughly `10^5` to `10^6` residual, but the crib-free finish
  failed; the known external solve required a 103-letter crib not held here. It
  is a sibling honest negative, not a shortcut to finishing `two`.

### Deferred Work

- **Feature-level candidate CEGAR conflicts** are still sequenced after a target
  slice is accepted. Candidate learning today is a whole-prefix no-good over the
  first-seen letters before the failed event
  (`residual.rs::add_prefix_conflict_clause`); a failed re-encryption should
  eventually learn local incompatible letter/candidate features where it can.
  It does not touch the current wall because the real file still never reaches
  the candidate tier (`candidate_clauses=0`).
- **Incremental candidate solving** is also later-stage. The target solver is
  already incremental across the loop (`ns3_cegar.rs`); only the candidate
  `BasicSolver` is rebuilt per accepted slice. Payoff is on planted controls and
  post-target-wall stages, not the measured real-file wall.
- **ns=4 seam / implicit oracle.** ns=3 already materializes about `541k`
  candidates per letter; ns=4 over `n=83` cannot be built on
  `Vec<candidate_index>`. The eventual move is an implicit `LetterDomainOracle`
  backed by the per-letter MITM over generator words (`lymm_deck/generators.rs`)
  answering projection/existence queries (`image_mask`, `preimage_mask`,
  `transition_possible`, `witness`) instead of returning full candidate sets,
  exposing finer-than-target literals so failures are explainable without
  discarding whole target assignments. Write down the required oracle operations
  before a rewrite, but do not churn every hot path until the consult resolves
  which framing is being built.

## Process notes (cheap, high-leverage — repeat them)

- **Cross-lineage design consult before a big implementation burn.** gemini-3.1-pro
  (outside the GPT/Claude lineages) caught a structural flaw both the GPT designer
  and the orchestrator missed. For the next lever, get an off-lineage pressure-test
  of the approach, not just the diff.
- **Dedicated adversarial "re-derive from construction" review** on the landed lever
  — the full gate and a generic diff review do NOT catch an unsound-but-passing
  control or a learned clause that excludes a non-plant valid assignment.
- **Null classification is centralized** in `recovery/selftest.rs::classify_null_recovery`
  (shared by `reach.rs`). A null must fail by `CleanFailure` (proven infeasibility),
  never by solver cap/timeout. This bug reappeared 3× before centralizing — route
  every new null through the shared classifier.

## Validation entry points

- Planted ns=3 production-path control: `recovery/ns3_control.rs`.
- Real-file frontier probe (ignored, not gated): `lymm_deck/ns3_probe.rs`.
- Full gate: `make verify` (do not regress ns=1/ns=2 or the planted ns=3 control).
- Rerunnable measurement commands + the residual-freedom finding: in
  `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`.
