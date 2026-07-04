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
- **Controls route through the production acceptance path** (`ns3_control.rs` calls
  `recover_known_plaintext_swaps`), truth tracking is observational/labeling only.
- **Measured frontier, never "scales arbitrarily."** A walled level is a reportable
  result with numbers, not a failure.

## The next lever (ranked; full list in the results note)

Primary target: make the real `n=83` ns=3 node cost tractable. Two paired moves,
both in `SWAP-RECOVERY-RESULTS.md` → "Likely next levers":

1. **Instrumented target-level implication tracking** (results-note lever 1, high
   confidence / high cost). Replace the 25-replay greedy minimization with a compact
   *reason* returned directly from the propagation step that found the contradiction
   (implication-graph / unsat-core), preserving the per-clause truth invariant. This
   attacks the 334s/clause cost head-on.
2. **Incremental solving with reusable learned clauses across target slices**
   (results-note lever 3, medium). Today the candidate `BasicSolver` is rebuilt per
   accepted slice and its learned clauses are discarded between outer iterations, so
   identical candidate collisions are re-learned repeatedly — a flagged cost driver.
   Persist candidate learning across slices (assumptions-based incremental solving).

**ns=4 direction (deferred until ns=3 real-file closes).** ns=3 already materializes
~541k candidates/letter; ns=4 over `n=83` cannot be built on `Vec<candidate_index>`.
Replace `build_residual_domains` with an implicit `LetterDomainOracle` backed by the
per-letter MITM over generator words (`lymm_deck/generators.rs`, already built)
reshaped to answer projection/existence queries (`image_mask` / `preimage_mask` /
`transition_possible` / `witness`) instead of returning full candidate sets, and
expose **finer-than-target literals** (transition arcs / `(letter,input_pos)=output_pos`)
so failures are explainable without discarding the whole target assignment.

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
