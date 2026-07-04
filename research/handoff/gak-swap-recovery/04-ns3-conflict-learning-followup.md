# Handoff — ns=3/ns=4 conflict-learning follow-up (push the real-file wall)

Written 2026-07-04 after Tasks 01–03 landed and the first ns=3 conflict-learning
milestone was built + cross-lineage soundness-reviewed. Read
`research/handoff/gak-swap-recovery/README.md` first (framing, honesty ceiling),
then this. House rules: `research/handoff/README.md`, `AGENTS.md`.

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
- **Next-lever read from review.** Lever 2, feature-level candidate CEGAR
  conflicts, is premature until the search accepts at least one target slice.
  The recommended emphasis is stronger target reasons: smaller broad-valid
  deterministic clauses for the real-file rejection family. Per the process note
  below, get a cross-lineage design consult before spending that implementation
  burn.
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

## The next lever (ranked; full list in the results note)

Primary target: make the real `n=83` ns=3 node cost tractable — but "cost" is two
numbers, not one. **Convergence = (target rejections to close) × (cost per rejection).**
The measured 334s is only the *second* factor; the first is unmeasured. Optimize both,
and gate the burn on the first.

1. **Instrumented target-level implication tracking** (results-note lever 1, high
   confidence / high cost) — the primary. Replace the 25-replay greedy minimization
   with a compact *reason* returned directly from the propagation step that found the
   contradiction (implication graph / 1-UIP-style core). Three binding conditions:
   - **Verify every extracted reason** with one broad-baseline `deterministic_rejects`
     replay before learning it (1 replay vs 25). This is empirical self-consistency —
     cheap insurance against buggy reason extraction, not a proof the propagator itself
     is sound — and it keeps the broad-baseline soundness property the greedy path had
     for free (see the target-clause invariant above), which truth-preservation cannot
     provide on the plant-free real file.
   - **Watch clause quality, not just clause speed.** The greedy path yields a tight
     4-literal core; a reason read off one pass can be larger/weaker, which *grows* the
     rejection count even as per-rejection cost falls. A cheaper-but-weaker clause can be
     a net loss — the whole point of factor one above.
   - **Scope precisely.** Only the `NoResidualCandidate` (deterministic-rejection) path
     is the 334s path. The `TargetUnsatCore` path already returns a core cheaply — but
     that core is *not* currently a sound broad-residual nogood (target-clause invariant
     above), so it needs the same recheck. The design fork — instrument the strong
     deterministic propagator vs. make the target SAT strong enough to surface these
     contradictions as sound assumption-guarded cores — resolves toward instrumenting
     the propagator (a witness-level target SAT would explode the encoding). But
     assumption-guarding the *restriction* alone (not the witness dynamics) is the
     cheaper half and independently closes the existing core-soundness gap.

   **Gate the burn on a calibration first.** Measure target rejections-to-convergence as
   a function of `n` on *new* mid-size top-swap ns=3 planted controls (an n=11/17
   analogue of the n=7 `ns3_control`). The existing n∈{11,17} stress plants do **not**
   exercise the CEGAR loop — they run explicit rotation generators through the word/MITM
   path (`reach.rs`), not `recover_ns3_with_target_cegar`. And `stats.nodes` is overloaded
   (residual nodes; ns=3 also folds target assignments in on success, `ns3_cegar.rs`), so
   add a dedicated target-rejection counter before drawing the curve. If rejection count
   scales badly, the lever is *stronger* clauses, not cheaper ones — stop and re-plan
   rather than build cheap-and-weak.

2. **Feature-level candidate CEGAR conflicts** (results-note lever 2, medium/high) —
   sequenced after lever 1 produces accepted slices. Candidate learning today is a
   whole-prefix no-good over the first-seen letters before the failed event
   (`residual.rs::add_prefix_conflict_clause`); a failed re-encryption should learn the
   local incompatible letter/candidate features where it can. It does not touch the first
   deterministic wall, but once slices are accepted it is more direct firepower than
   solver reuse — and the results note ranks it above lever 3.

3. **Incremental solving with reusable learned clauses across target slices**
   (results-note lever 3, medium) — strictly later-stage, gated behind lever 1. Today the
   candidate `BasicSolver` is rebuilt per accepted slice and its learned clauses are
   discarded between outer iterations. But on the measured real file the run dies in
   *deterministic target rejection* before the candidate tier ever fires
   (`candidate_clauses=0`), so this optimizes a path the current wall prevents reaching.
   The target solver is *already* incremental across the loop (`ns3_cegar.rs`); only the
   candidate solver is rebuilt. Payoff is on the planted control and post-lever-1 stages,
   not the current n=83 wall.

**ns=4 direction (deferred until ns=3 real-file closes — design the seam now, defer the
rewrite).** ns=3 already materializes ~541k candidates/letter; ns=4 over `n=83` cannot be
built on `Vec<candidate_index>`. The eventual move is an implicit `LetterDomainOracle`
backed by the per-letter MITM over generator words (`lymm_deck/generators.rs`, already
built) answering projection/existence queries (`image_mask` / `preimage_mask` /
`transition_possible` / `witness`) instead of returning full candidate sets, exposing
**finer-than-target literals** (transition arcs / `(letter,input_pos)=output_pos`) so
failures are explainable without discarding the whole target assignment. This is a
*re-architecture of every consumer*, not a one-function swap: `propagation.rs`,
`target_solver.rs`, `sat_encoding.rs`, and `residual.rs` all index the materialized
candidate `Vec`s pervasively. **Write down the required oracle operations now; defer the
rewrite** — landing the trait boundary concurrently with lever 1's propagation
instrumentation would churn every hot path before ns=3 is even closed.

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
