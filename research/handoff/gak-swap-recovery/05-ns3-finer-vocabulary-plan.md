# Plan — ns=3 finer-vocabulary lever: the resolved framing

Written 2026-07-04. This resolves the open decision point at the end of
`04-ns3-conflict-learning-followup.md` ("Current decision point for the next
agent" / "The Next Lever"): choosing between **(i) pure CDCL(T) finer-literal
re-architecture** and **(ii) `shadow_search`-style enumerate-and-filter per
letter**, before any build. Read `04-...md` first (measured wall, honesty ceiling,
soundness invariants) and `../../data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`
(every number). House rules: `../README.md`, `AGENTS.md`.

This is a **pre-build** plan produced by a cross-lineage design consult
(orchestrator Opus-4.8 design; gemini-3.1-pro and codex/GPT pressure-tests),
hardened by a post-consult review pass (Fable 5) that tightened the Phase-0
measurement into a pre-registered, self-calibrating instrument. It
does not relax the honesty ceiling. ns=1/ns=2 are delivered (`2439/2439` exact).
ns=3-real (`3_swap_ct.txt`) stays walled, measured, not claimed.

## Decision (what to build, in order)

A **phased plan**, not a single framing. Framing (i) is the eventual engine, gated
behind a cheap measurement and preceded by a shared primitive justified on its own
merits. Framing (ii) as the *primary* engine is rejected; its oracle *shape* is
adopted.

1. **Phase 0 — adjudicating measurement (do FIRST, budgeted).** Measure
   whether the real `n=83` ns=3 instance admits **short (≤3-literal) conflicts in a
   finer-than-`(letter = target)` vocabulary** with real pruning power. Go/no-go
   follows the **pre-registered decision rule** in the Phase-0 spec (context bins,
   kill-count metric, budget) — not adjudicated after the run. Go ⇒ Phase 2. No-go
   (a ~5+ arc-literal floor, or any readout outside the go rule) ⇒ **do not build a
   bigger solver**; land Phase 1 as the generality deliverable and write ns=3-real
   up as a measured, likely-structural/information-theoretic frontier.
2. **Phase 1 — the implicit `LetterDomainOracle` (build regardless of Phase 0).**
   Replace the materialized `Vec<CandidateRuntime>` with an implicit per-letter
   oracle (`image_mask`/`preimage_mask`/`transition_possible`/`witness`). Justified
   independently of ns=3: it is the ns=4 unblocker and *is* the community mandate
   ("a more general GAK attack for larger groups"). Not wasted under either Phase-0
   outcome. Lands only behind the differential-equivalence gate (§ Phase 1 below).
3. **Phase 2 — finer-literal CDCL(T) (framing i), CONDITIONAL on Phase 0.** Arc /
   partial-transition literals in the SAT vocabulary; oracle as an SMT
   theory-propagator with lazy arc-nogood generation; partial-slice DPLL(T); the
   existing sound learning core kept and extended to arc literals.

## Why this shape — two grounding facts about the current code

Read for this plan: `recovery/{ns3_cegar,target_solver,target_conflict,target_reason,propagation,residual,learning}.rs`
and `lymm_deck/{generators,domain,domain_build}.rs`.

**Fact A — propagation is fine-grained; reason *provenance* is only
letter-granular; the learned clause is coarse.** `propagation.rs` keeps
`state_domains: Vec<Vec<Vec<u128>>>` (message × walk-index × card-value → position
bitmask) and runs per-position transition-arc reasoning (`DomainRelation`
`post_to_pre`/`pre_to_post`, `narrow_transition_state`, all-different, two-step
arcs). **But** `TargetReasonTracker` attributes conflicts with a `u128` bitmask
over *letters*, not positions/arcs (`target_reason.rs:11,80`), and the SAT layer's
only literals are `(char, target)` (`target_solver.rs:15`). The solver *propagates*
finely and *learns* coarsely — which is exactly why each rejection kills one tuple
of the 34,234,200-tuple `T=67` slab. Consequence for Phase 0: the arc-granular
conflict is **not already computed** and cannot merely be "read out" — Phase 0 must
add arc/position provenance to the tracker.

**Fact B — candidates are materialized full-perm Vecs; the oracle needs two
backends.** `ResidualDomains.candidates: Vec<CandidateRuntime{perm}>` +
`by_letter: BTreeMap<char, Vec<usize>>` (`residual.rs:22,27`); ns=3 materializes
~541k/letter, and ns=4 over `n=83` cannot live on Vecs at all. The real vendored
file is a **top-swap** cipher whose default path is `enumerate_top_swap_domains`
(`domain.rs:164`) — **not** the `generators.rs` MITM (that serves explicit
generator sets). So the oracle needs a **top-swap backend** (the one that matters
for ns=3-real; queries answerable combinatorially from `{0,k}`-chain support) *and*
an **explicit-generator MITM backend** reusing the hash-join
`enumerate_generator_words_mitm_entry_target` (`generators.rs:378`) intercepted
before materialization.

**The reframe.** (i) and (ii) are not "fine theory vs brute force" — the theory is
already fine. Both framings need the *same* missing primitive (the implicit
per-letter oracle). The real axis is *where learning lives and over what
vocabulary* — and that is decided by one unknown.

## The decisive unknown (what Phase 0 measures)

> Does the real `n=83` ns=3 instance admit SHORT (≤2–3 literal) conflicts in ANY
> richer-than-`(letter=target)` vocabulary (transition arcs / partial slices)?

- **Yes** ⇒ a finer literal (e.g. `letter_E maps post_pos 4 → pre_pos 9`)
  implicitly covers many targets, so one short arc-nogood prunes a whole slab of
  the 34M space. Framing (i) converges.
- **No** (conflicts irreducibly ~5+ even at arc granularity) ⇒ **no clause-learning
  scheme converges** (long weak clauses do not drive unit propagation; the livelock
  "changes shape but the wall remains"), and enumerate-filter only helps if the
  per-letter substructure is small — measured *large* (34M flat `T=67` slab,
  per-letter max domain 6,562). Then the honest move is to report the wall.

Both prior large probes (cap-8, cap-60) taught the coarse lesson. The process note
that has paid off twice — measure the decisive thing cheaply before a big burn —
says measure this first.

## Phase 0 — instrument spec (the concrete next step)

Add **arc/position provenance** to `TargetReasonTracker` so each real-file
rejection emits the set of transition-arc literals deterministic propagation used
to reach `NoResidualCandidate`; minimize each arc reason under broad replay (as
target reasons already are, `target_conflict.rs`); measure the size distribution on
`3_swap_ct.txt`. This is a real instrument, not a read-out (Fact A).

**Load-bearing requirement (gemini [P0]):** an arc reason must carry the
**generator/domain-restriction context** it depended on. The original rejection
happens inside a context where the *target assignments* implicitly restrict other
positions' domains via generator constraints. If the arc reason does not carry that
context, asserting only the arc literals against the broad baseline **fails to
reproduce the conflict**, so the validation gate rejects a legitimate arc nogood
and the engine silently falls back to the coarse clause. That is not unsoundness
(the gate fails safe) — it is a **silent under-count of short conflicts** that would
mis-adjudicate the entire decision toward a false "no short conflicts." The Phase-0
readout must record arc literals *with* their generator/domain context, or the
measurement is biased.

**The same trap, mirrored (review [P0]): context can also fake a "go."** If a
≤3-arc-literal conflict reproduces only *with* a target-conditional
domain-restriction context, the reusable nogood is really `context ⇒ ¬(arcs)` —
and unless that context is expressible as literals in the Phase-2 vocabulary, the
short conflict yields no short *learnable clause*. The readout must therefore bin
every short conflict:

- **(a) context-free** — the arc literals alone survive broad replay;
- **(b) context-expressible** — reproducible with a context that reduces to
  additional vocabulary literals (arc or target), which **count toward the
  clause length**;
- **(c) context-opaque** — reproducible only under a domain restriction the
  vocabulary cannot express.

Only (a) and (b) support the Phase-2 premise. Counting (c) as "short"
mis-adjudicates toward a false "go" — the exact mirror of the gemini under-count.

**Instrument controls (house rule: planted positive + matched null).** The
solver invariants below do not calibrate the *measurement itself*; the Phase-0
instrument gets its own controls before any real-file run:

- **Positive control** — a synthetic instance constructed to admit a known short
  arc conflict; the instrument must extract it, minimize to it, and the result
  must survive broad replay.
- **Matched null** — an instance whose minimal conflict is known to be long (the
  planted ns=3 control is a source of ground-truth cases); the instrument must
  NOT report a spurious short conflict. A replay bug that accepts too easily
  fakes a "go" and triggers the expensive Phase-2 build; this control is what
  catches it.

**Pruning power is the decision metric; literal count is the proxy.** The
convergence argument for Phase 2 is that one short nogood prunes a slab — so
measure that, not just lengths. For each minimized (a)/(b) reason, record an
**estimate of how many of the `34,234,200` projected `T=67` tuples it excludes**,
with the estimate's construction stated (per-letter mask arithmetic where arc
literals are letter-local, spot-checked by sampled propagation on a few hundred
tuples), and label it an estimate. Grounding: a coarse 5-target clause kills
exactly `1` tuple — the measured livelock; at `10^4` tuples/nogood, covering the
slab takes ~`3.4k` rejections at ~1 replay each, which is plausible-convergence
territory.

**Budget (pre-registered).** Sample cap: the first `60` real-file rejections or
`3600s` wall, whichever comes first (cap-60 precedent: `60` coarse rejections ≈
`2330s`; arc-granular minimization is strictly more work per rejection).
Minimizer cap: at most `32` broad replays per rejection; when capped, report the
unminimized bound as "size ≤ k" (still adjudicating data when `k ≤ 3`). Hitting
the budget without adjudication is itself a reportable outcome (§ soundness).

**Decision rule (pre-registered — amend only in writing, BEFORE the real-file
run).** GO to Phase 2 iff, on the sampled rejections, **both**:

1. **≥25%** minimize to **≤3 literals** in bins (a)/(b) (context literals
   included in the count), and
2. the **median tuple-kill estimate** of those short nogoods is **≥10^4**.

Anything else — a floor at 4, a bimodal split, short-but-weak nogoods, a
(c)-dominated readout, or budget exhaustion — is a NO-GO: land Phase 1 and write
the wall up as measured. These defaults are written down now precisely so the
run cannot be rationalized post hoc. Numbers land in
`../../data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md` per the doc-set
convention.

## Phase 1 — oracle acceptance gate

Phase 0 runs entirely on the existing materialized path — it needs no oracle
code — so Phases 0 and 1 can proceed independently, and the adjudicating
measurement never depends on new oracle code. The oracle itself lands only
behind a **differential-equivalence gate**: on every configuration where the
materialized `Vec<CandidateRuntime>` path is feasible (ns≤2 at all `n`, small-`n`
ns=3, the planted ns=3 control), `image_mask`/`preimage_mask`/
`transition_possible`/`witness` must match what materialization produces
bit-for-bit, and the ns=1/ns=2 `2439/2439` regressions and null classifications
must be unchanged. Both backends (top-swap and explicit-generator MITM) go
through the same gate.

## Phase 2 — finer-literal CDCL(T) (only if Phase 0 says go)

- Introduce arc / partial-transition literals alongside `(letter,target)` (which is
  the `post_pos=0` special case). **Hybrid encoding** (codex): eager clauses for
  target/top and possibly hot observed arcs; **lazy** oracle nogoods for the rest —
  because the hard part is exact channeling back to "reachable by ≤ns generator
  word," which is exactly what the oracle answers.
- Oracle as SMT theory-propagator: on a partial assignment it lazily generates
  arc-level nogoods so one short nogood prunes a slab.
- Partial-slice DPLL(T): branch targets incrementally, propagate after each partial
  assignment, reject doomed *prefixes* before ~20 irrelevant targets are fixed.
- Keep the sound learning core: every learned clause (arc-level too) through
  `learn_sat_clause` (truth-preservation) and validated by broad-baseline replay
  **restricted to its own literals** — the target-clause rule, extended.

Scope is high (the `04` warning stands): `target_solver.rs`, `propagation.rs` /
`target_reason.rs`, `residual.rs`, `sat_encoding.rs`, `domain_build.rs`.

## Why NOT framing (ii) as primary

1. It discards the hard-won sound CDCL machinery (`learn_sat_clause`, broad replay,
   truth-preservation, two-tier acceptance), re-opening the "unsound-but-passing
   control" class.
2. It is gated on a small enumerable per-letter substructure the data says is
   large (34M slab, max domain 6,562 after restriction).
3. `shadow_search` is a sibling honest-negative, not a shortcut, and transfers less
   than `04` implies: its `legal_lookup` is a **static** `Vec<Option<usize>>`
   membership table (`engine.rs:362`), not the *dynamic-under-partial-assignment*
   projection the ns=3 loop needs; it has no learning, no nogoods, no partial-
   assignment propagation (`engine.rs:175,415`). The genuinely reusable asset is the
   MITM join in Subsystem B, not `legal_lookup`.

So: **take the MITM join; treat shadow_search as precedent-only; keep the CDCL
learning core.** Both consult lineages independently agreed no reason
enumerate-filter converges on this data.

## Soundness / honesty invariants (unchanged, extended to arcs)

- Acceptance = exact byte-for-byte re-encryption (`report.round_trip.exact()`).
- Every learned clause (target, arc, candidate) through `learn_sat_clause` with
  truth-preservation asserted before insertion.
- Every learned nogood valid against the **broad** baseline restricted to its own
  literals — extended from target tuples to arc literals (and see the Phase-0
  generator-context requirement above, which is the same obligation surfacing early).
- Truth-preservation only bites on plants; **real-file soundness rests entirely on
  broad replay.** Treat oracle `false` answers as learnable facts; treat `true`
  projections as non-witnesses until exact re-encryption accepts.
- Nulls via `recovery/selftest.rs::classify_null_recovery`; a null fails by
  `CleanFailure`, never cap/timeout.
- Report the measured frontier. A Phase-0 "stop and report" is a legitimate,
  honest outcome, not a failure — including hitting the Phase-0 budget without
  adjudication, which reports as "unmeasured at budget," never as evidence in
  either direction.

## Consult provenance

- **Orchestrator (Opus-4.8):** grounded the (i)/(ii) choice in the source, produced
  the phased plan and the "decisive unknown" framing.
- **gemini-3.1-pro (copilot consult):** "proceed exactly as proposed"; contributed
  the [P0] arc-literal broad-replay under-count trap (folded into Phase 0 + §
  soundness) and confirmed the livelock escapes iff arc-nogoods are short.
- **codex/GPT (exec consult):** "keep the Phase 0 gate ... not over-cautious";
  corrected Fact A (reason tracker is letter-granular, not arc-granular →
  Phase 0 is an instrument, not a read-out), corrected the oracle to need a
  top-swap backend (real file is top-swaps, not the `generators.rs` MITM), and
  refined Phase 2 to a hybrid eager/lazy encoding.
- **Fable 5 (post-consult review, 2026-07-04):** verified every line-cited code
  claim in this doc against source; contributed the mirrored context trap
  (bins (a)/(b)/(c) — context can fake a "go," not only a "no-go"), the
  pre-registered decision rule + budgets, the tuple-kill pruning metric, the
  Phase-0 instrument's own planted positive / matched-null controls, and the
  Phase-1 differential-equivalence gate.

Both lineages converged: keep the Phase-0 gate; build the oracle regardless; build
full finer-literal CDCL(T) only if Phase 0 finds short arc conflicts; reject
enumerate-filter as primary. The consult [P0]s and the review [P0] are
complementary and together specify the Phase-0 instrument: **build arc/position
provenance that carries its generator/domain-restriction context so broad replay
can re-derive the conflict — then bin each short conflict by whether that context
is expressible in the clause vocabulary, and score it by tuples killed, under a
decision rule fixed before the run.**
