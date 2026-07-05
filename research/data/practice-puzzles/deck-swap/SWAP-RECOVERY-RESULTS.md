# GAK swap-recovery Task-02 results

Recorded 2026-07-03 on branch `feat/community-request`.

This note is model-conditional: it reports what the current Lymm top-swap
known-plaintext recovery engine can verify by exact re-encryption, and where the
systematic propagation/SAT encoding stopped. It is not a claim that larger swap
budgets are impossible.

## 2026-07-05 correction: ns=3 known-plaintext observed-letter recovery

The earlier `ns=3` "wall" framing below is corrected for the vendored
known-plaintext practice puzzles. The wall was a limitation of the systematic
propagation/CDCL(T) line, not of the practice-puzzle key-recovery problem.

A substitution-first coordinate-descent local search recovers the top-swap
mapping for the 24 plaintext letters that occur in the vendored corpus and
accepts only by exact byte-for-byte re-encryption. `J` and `Z` never appear in
the plaintext, so their swaps are unconstrained and are not reported as
recovered:

| level | result | exact re-encryption | reference local-search timing |
| --- | --- | --- | --- |
| `ns=1` | observed letters recovered | residual `0`, `2439/2439` | about `0.03s` |
| `ns=2` | observed letters recovered | residual `0`, `2439/2439` | about `0.11s` |
| `ns=3` | observed letters recovered | residual `0`, `2439/2439` | about `14s`; `541406` candidate permutations enumerated |

Independent verification used a fresh pure-Python re-encryption implementation of
Lymm's vendored cipher formula, not the reference driver. The recovered
observed-letter mapping re-encrypts all 8 messages byte-for-byte to the
ciphertext, decrypt-from-scratch reproduces the plaintext, and every recovered
observed-letter permutation is reachable by exactly `s` top-card `(0,k)` swaps
from the public base. Exact re-encryption does not identify the absent-letter
swaps for `J` or `Z`. The `ns=3` solve converged on attempt `0`; no basin-hop
restart was needed.

Current Rust wiring keeps the complete systematic engine as the default path for
`ns=1/2` and routes `ns=3` top-swap recovery through the local-search backend
under `--strategy auto`. Direct reproduction command:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/3_swap_ct.txt \
  --num-swaps 3 \
  --strategy local-search
```

The vendored `ns=3` Rust regression is kept ignored because the debug-profile
test measured about `132s` in this worktree, above the default pre-commit gate
budget. Reproduce it explicitly with:

```sh
cargo test --locked ns3_recovery_recovers_vendored_key_and_reencrypts_exactly -- --ignored --nocapture
```

Scope: this is known-plaintext key recovery for Lymm's practice-puzzle files. It
answers the community request on that surface for observed plaintext letters. It
does not break the real Noita eye glyphs, which remain ciphertext-only with no
known plaintext crib, and it does not change the eye-puzzle unsolved state.
Historical Phase-0/Phase-2 CDCL(T) measurements and decision entries below are
preserved as measurements of that systematic line; they are superseded only for
practice-puzzle recovery by the exact-verified local-search path above.

## Verified frontier

Inputs: `plaintexts.txt` paired with `1_swap_ct.txt`, `2_swap_ct.txt`, and
`3_swap_ct.txt` under the default Lymm spec (`n=83`, `pt=A..Z`,
`ct=chr(33+i)`, `base=affine:shift=26,decimation=3`, identity restarts).

| level | status | exact re-encryption | solver stats |
| --- | --- | --- | --- |
| `ns=1` | observed letters recovered | `2439/2439` | `candidates=83`, `pruned=0`, `deductions=24`, `nodes=0`, `sat_decisions=0`, `sat_conflicts=0` |
| `ns=2` | observed letters recovered | `2439/2439` | `candidates=6725`, `pruned=134804`, `deductions=925549`, `nodes=1`, `sat_decisions=0`, `sat_conflicts=0` |
| `ns=3` | observed letters recovered by local search | `2439/2439` | `candidates=541406`; exact-verified candidate, not a uniqueness proof |

Support-size summary for the recovered levels:

- `ns=1`: all 24 appearing letters recover as singleton domains with canonical
  two-position support `{0,k}`; `J` and `Z` do not appear.
- `ns=2`: exact round-trip is recovered after propagation collapses the residual
  to one SAT model check. Reported observed-letter supports are within the
  `<=3` top-swap bound; most are three-position supports, with rare/degenerate
  letters shorter. The CLI emits the per-letter target/support/swap word.
- `ns=3`: exact round-trip is recovered by the complementary local-search path
  for the 24 observed letters. The emitted mapping is accepted only by
  byte-for-byte re-encryption; the local-search report marks it as a candidate
  rather than claiming exhaustive uniqueness. `J` and `Z` remain
  `UNRECOVERED`/unconstrained and are not serialized as recovered swaps.

Validation controls:

- Current self-test controls use a small deterministic planted corpus (`n=11`,
  `pt=ABCD`) so they are cheap enough for the default gate.
- Planted `ns=1`: exact; `4/4` observed letters matched the planted unique
  permutation.
- Planted `ns=2`: exact; `4/4` observed letters matched the planted unique
  permutation.
- Planted `ns=3` through local search: exact; `4/4` observed letters matched
  the planted candidate permutation.
- Matched nulls all concluded with `CleanFailure` under the default
  `max_nodes=50000` cap: random full-permutation mapping at the `ns=2` bound,
  over-budget `ns=2` encrypted text attacked at `ns=1` (while recovering at
  `ns=2`), ciphertext-symbol label shuffle at the `ns=2` bound, and an
  anchor-consistent ciphertext perturbation at the `ns=3` local-search bound.
  The self-test does not count `SearchCapExceeded` or `SearchTimeExceeded` as a
  genuine null failure.

The `gak-swap-recover` CLI exposes the same library path used by the tests for
the supported frontier. `--strategy auto` keeps the systematic path for `ns=1/2`
and routes `ns=3` top-swap recovery through local search.

## Rerun commands

Stable supported-frontier checks:

```sh
cargo test --locked ns1_recovery_recovers_vendored_key_and_reencrypts_exactly -- --nocapture
cargo test --locked ns2_recovery_recovers_vendored_key_and_reencrypts_exactly -- --nocapture
cargo test --locked ns3_top_swap_candidate_count_matches_verified_frontier -- --nocapture
cargo test --locked local_search_ns3_planted_control_recovers_exact_candidate -- --nocapture
cargo test --locked infer_swaps_reaches_ns3_local_search_frontier -- --nocapture
cargo test --locked swap_recovery_self_test_passes_supported_frontier_controls -- --nocapture
cargo test --locked ns3_planted_truth_survives_target_cegar_pruning -- --nocapture
cargo test --locked ns3_planted_control_recovers_through_production_path -- --nocapture
cargo test --locked ns3_recovery_recovers_vendored_key_and_reencrypts_exactly -- --ignored --nocapture
NOITA_SWAP_CEGAR_TRACE=1 NOITA_SWAP_TRACE_PASSES=1 NOITA_SWAP_TRACE_MAX_PASSES=2 \
  NOITA_SWAP_NS3_PROBE_MAX_NODES=1 \
  cargo test --locked ns3_real_file_production_path_frontier_probe -- --ignored --nocapture
```

Stable CLI checks:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/1_swap_ct.txt \
  --num-swaps 1

cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/3_swap_ct.txt \
  --num-swaps 3 \
  --strategy local-search
```

Task-03 item 1 adds supported-budget inference. It runs increasing budgets only
through the measured frontier and reports the maximum final-permutation support
size, not canonical swap-word length:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/2_swap_ct.txt \
  --infer-swaps 1..3
```

For the vendored `2_swap_ct.txt` file, this rejects `s=1` and reports `s=2`
with exact `2439/2439` re-encryption and maximum observed support size `3`.
Ranges that extend past the current supported frontier, for example
`--infer-swaps 1..4`, cap at `ns=3`; ranges that start past it fail with the
shared frontier message.

Task-03 item 4 adds shareable output:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/1_swap_ct.txt \
  --num-swaps 1 \
  --output json
```

The JSON report includes the recovered observed-letter `pt_mapping`, per-letter
`support`/`support_size`/canonical `swap_word`, aggregate and per-letter verdicts,
and `round_trip.exact`. Unobserved plaintext letters are omitted from
`pt_mapping` and reported as unrecovered/unconstrained. It also includes
`python_pt_mapping`, the same
copy-pasteable `pt_mapping = {...}` dict printed by text output for direct use in
Lymm's `noita_test_cipher.py`. The reference-Python side remains the existing
thin `generate_reference_vectors.py` oracle/generator; no Python attack logic was
added.

Task-03 item 2 adds explicit generator sets:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file plaintexts.txt \
  --ciphertext-file ciphertexts.txt \
  --generator-file generators.txt \
  --max-swaps 1
```

The generator file is one full permutation per non-comment line, optionally
prefixed with `label:`. The recovery model is `perm(L) = base o word(G)` with
word length `<= max-swaps`; reported `swap_word` entries are generator row indexes
for explicit files. The engine keeps the built-in top-swap support enumerator
unchanged for `--generator-set top-swaps`, uses a sparse transposition-support
path when every explicit generator is a small-support transposition, and uses a
word meet-in-the-middle path otherwise. The word path applies the forced-top prune
when all observed letters are pinned by identity restarts.

Validation added for this surface:

- Planted explicit small-transposition control at `n=7`, `max-swaps=1`, exact
  recovery, plus a matched null whose generator surface lacks enough distinct
  nonzero targets.
- Planted full-support rotation control at `n=7`, `max-swaps=1`, exact recovery
  through the word/MITM branch, plus a ciphertext-label null.
- A CLI integration test that writes plaintext, ciphertext, base, and generator
  files and recovers through `--generator-file`.

Bounded-search note: built-in top-swap `ns=3` now routes through exact-accepted
local search under `--strategy auto`; budgets above `3` still use the shared
frontier guard. The generator-set generality does not claim larger reach by
itself; higher budgets and larger-group stress frontiers are Task-03 item 3. The
distinct nonzero target/no-doubles assumption remains load-bearing for
generalized generator sets, and violating it is reported as a model rejection
rather than a candidate recovery.

The `ns=3` planted test is a soundness control, not a real-file recovery claim:
it exercises the same `ns=3` broad propagation, target pre-solver, targeted
deterministic propagation, and exact planted-assignment verification that could
otherwise prune the truth invisibly.

Task-03 item 5 wires compose direction and emission index:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file plaintexts.txt \
  --ciphertext-file ciphertexts.txt \
  --generator-file generators.txt \
  --max-swaps 1 \
  --compose-direction right \
  --emit-index 1
```

The default vendored top-swap behavior remains the same (`left`, `emit-index 0`,
identity restarts). Generalized runs use the configured forced entry:
left-compose constrains `perm(L)[emit_index]`, while right-compose constrains
`perm(L)[state_prev[emit_index]]` and therefore matches `perm(L)[emit_index]`
under identity restarts. Explicit non-identity `--initial-state` values are used
by both the domain bootstrap and partial-state initialization; unknown/secret
initial states are not modeled.

Validation added for this surface:

- Planted full-support rotation control at `n=7`, `max-swaps=1`, left compose,
  `emit-index=1`, and a non-identity initial state, exact recovery plus a
  ciphertext-label null.
- Planted full-support rotation control at `n=7`, `max-swaps=1`, right compose
  and `emit-index=1`, exact recovery plus a ciphertext-label null.
- A CLI integration test that writes plaintext, ciphertext, base, and generator
  files and recovers through `--compose-direction right --emit-index 1`.

Bounded-search note: this item does not extend the built-in top-swap
local-search result to every configured surface. Built-in left-compose top-swaps
at `ns=3` recover the observed-letter mapping by exact-accepted local search;
right-compose residual recovery bypasses the left-compose transition-pruning
clauses rather than claiming those deductions are symmetric.
The distinct nonzero target/no-doubles assumption remains documented and enforced
at `perm(L)[emit_index]`; when the configured direction/start forces a different
first-read entry, that bootstrap entry is checked as well. Violating surfaces are
model rejections, not candidate recoveries.

Task-03 item 3 adds the first measured reach rung for explicit full-support
generator sets. The domain builder now uses per-letter meet-in-the-middle
enumeration when a restart pins a forced `(entry, target)`: for word-based
generators, prefix states are indexed by the input that maps to the target source,
and suffix states join only against that input. This keeps the old top-swap path
unchanged while narrowing explicit-generator residual domains before they reach
the SAT layer.

Validation added for this surface:

- A larger-group stress self-test plants full-support rotation-generator mappings
  and recovers exactly for `n in {11,17}` and `max-swaps in {1,2,3}`.
- Every stress case includes a matched null using the same ciphertexts but a
  generator surface that cannot realize the planted targets. The null outcome is
  classified; only a clean model failure counts as a passing null, not a solver
  cap, timeout, or plumbing error.
- The test asserts the measured passing boundary `(n=17, max-swaps=3)` and records
  per-case candidate counts/nodes in the `GakSwapReachStressReport`.

Bounded-search note: this does not generalize the public top-swap `ns=3`
local-search result to arbitrary generator surfaces or larger budgets. Built-in
top-swaps at `ns=3` now recover the observed-letter mapping by exact-accepted
local search; the new stress boundary is model-conditional on the explicit
rotation-generator surface and planted controls.

Phase-1 oracle primitive (2026-07-05): residual recovery now uses an implicit
`LetterDomainOracle` instead of a materialized `Vec<CandidateRuntime>`. The
landed backends are:

- top-swap support oracle for the vendored `{0,k}` generator family;
- explicit-generator sparse/MITM oracle for word-generator domains, including the
  forced `(entry,target)` MITM path.

The differential gate materializes reference permutations only inside tests and
checks `image_mask`, `preimage_mask`, `transition_possible`, and `witness`
bit-for-bit against those references. Coverage: top-swaps at `ns=1` and `ns=2`
for `n=2..17` plus `n=83`; small top-swap `ns=3` for `n=3..9`; the planted
small `ns=3` control residual; and an explicit noncommuting generator control at
`max_swaps=2` that takes the `WordMitm { split: 1 }` branch,
checks the full MITM surface, and checks forced `(entry,target)` pruned domains.
The vendored ns=1/ns=2 regressions now assert the concrete `2439/2439` exact
round-trip counts. Oracle performance characterization: the win is memory and
the ns=4 unblock; per-replay CPU on ns=3 is comparable to possibly slower because
queries scan per-position support. This did not rerun or change the Phase-0
real-file budget or decision rule.

## Superseded systematic ns=3 wall

Before the local-search correction, the systematic `ns=2` success did not scale
automatically to `ns=3`. The structural break is that R-top/R-read deductions
become much weaker once each letter domain has hundreds of thousands of possible
three-swap candidates. At `ns=2`, the traced residual reached `6725` candidates,
`18863` total domain entries, max domain `6643`, then propagation collapsed the
SAT-ready residual to `24` total entries with max domain `1`. At `ns=3`,
equivalent propagation leaves multi-million-entry residuals, so the systematic
SAT model had too little eager structure to learn from.

Measured attempts before landing the bounded frontier:

| attempt | propagation / encoding idea | measured size / time | failure mode |
| --- | --- | --- | --- |
| Straight exact `ns=3` lift | Enumerate all up-to-3 top-swap candidates, apply the same partial-state R-top/R-read propagation and residual handoff used for `ns=2`. | `541406` candidates; `10854368` total domain entries; max domain `541406`; only the identity-restart-heavy letters (`D/N/T/U`) dropped to about `6562`; no useful SAT-ready collapse after about `2.5-3 min`. | Too large. The true solution was not intentionally dropped, but the residual stayed too broad to encode/use. |
| Target/no-zero propagation | Add eager target/no-doubles-style filtering before residual construction. | `10723128` total entries; max domain `534844`; after propagation about `10722804` entries remained, with only a few letters near `6400`. | Too large. The filter removes obvious impossibilities but does not touch most off-top ambiguity. |
| Sparse per-letter prefilters | Derive sparse per-letter constraints from observed reads and prefilter candidate domains before SAT. | Example `A`: `726` constraints, `183` singleton, `183` negative, `0` positive; domain still `534844`. | Too large. The sparse constraints mostly became weak negative facts and did not isolate the true off-top chain. |
| Large-domain defer / exact-small | Fully solve only small propagated domains and defer large domains. | Still about `10.72M` residual entries after propagation. | Too large. Deferring large letters leaves the same coupled state-walk gap. |
| Shadow target seeding, top-16 | Seed domains by intersecting with top shadow targets before exact residual. | Initial domain surface about `1932632` entries; max domain `104992`. | Too large and heuristic. It reduces the surface but does not make exact SAT practical. |
| Shadow target seeding, top-4 | More aggressive top shadow intersection. | Initial domain surface about `531604`; max domain `26248`; some letters collapsed strongly (`A/E/R/S` to `16`, `L` to `96`), many remained at `26248`; still ran past `120s` without closing. | Too large and heuristic. Still no exact proof, and many letters retain broad domains. |
| Shadow target seeding, top-1 | Force the single best shadow target per letter. | About `62s`, then `NoResidualCandidate`. | Unsound. The simplification globally fixed each letter to one shadow target; at least one true `ns=3` target was outside that top-1 set, so the true solution was dropped. |

The table above is a scratch-trace diagnosis from development runs, not a stable
golden fixture. The real-file `ns=3` CEGAR traces used temporary library entry
points and internal env flags such as `NOITA_SWAP_TRACE_ONLY=1`,
`NOITA_SWAP_TRACE_PHASE=target`, `NOITA_SWAP_TRACE_PASSES=1`, and
`NOITA_SWAP_CEGAR_TRACE=1` before the landed CLI guard was restored. The stable
rerunnable commands are the supported-frontier tests, the CLI checks, and the
scaled `ns=3` truth-preservation control listed above.

The original `ns=3` wall diagnosis was that the candidate SAT model had too
little eager structure. The landed residual SAT model is now stronger than that:
it has per-letter exactly-one constraints, top-image channelling, and
all-consecutive adjacent transition clauses over propagated partial states. The
separate `ns=3` target pre-solver also enforces one distinct nonzero target per
observed letter and adds adjacent plus bounded two-step target clauses. The
remaining gap is not missing first-order adjacency; it is that deterministic
target-restricted propagation can reject a wrong full target assignment without
returning a small learned target-level reason. Whole-assignment target nogoods are
still combinatorially weak when `ns=3` leaves hundreds of thousands of candidates
per hard letter.

Follow-up ns=3 attack pass, 2026-07-03:

- Added complete local permutation-domain propagation inside each partial state
  (singleton value positions remove that position from other values, and positions
  with one supporting value become singleton assignments). This increased state
  deductions on the real `3_swap_ct.txt` broad pass from about `8,367` to
  `257,083`, but did not by itself reduce broad candidate-domain entries.
- Added all-consecutive adjacent channelling plus a sound two-step R-read arc
  (`L M N`: constrain `perm(L)[perm(M)[target_N]]` against the propagated
  pre-state domain). On the broad ns=3 residual this leaves `10,194,676` total
  domain entries, max domain `508,596`, with `659,692` entries pruned. The two-step
  rule only removes two additional broad entries because target domains are still
  wide.
- On a target-restricted CEGAR slice, the same rules are much stronger: the first
  traced slice started at `153,896` entries, then pass 1 reduced it to about
  `94,929` entries (`58,967` pruned) before later deterministic transition
  propagation rejected the wrong target slice. That is a real residual reduction,
  but it does not solve target assignment.
- Exhaustive broad candidate-arc pruning was re-tested with the stronger state
  domains and still failed the cost test: no first-pass trace line after more than
  `210s`, so it was dropped.
- A guarded-assumption target-core CEGAR experiment was tried. With only one
  deterministic pass, the first wrong target slice hit the residual node cap after
  `20` candidate models rather than producing a useful SAT unsat core; with the
  stronger deterministic pass, wrong slices fail before SAT can return a core.
- A bounded four-event target clause pass for identity-start windows was tried
  because the first wrong slices consistently contradicted at message 1's `THE`
  prefix (`E` transition). It added about `75s` of target-solver construction time
  and left the first target model unchanged, so it was dropped.

These follow-up measurements are likewise scratch trace observations unless they
are covered by the stable commands above.

Systematic-line diagnosis at the time: the new propagation bought useful
target-restricted pruning but did not close the target-assignment problem. The
wall was specifically that deterministic propagation can reject wrong full target
assignments, but the engine did not learn a small sound target-level reason from
that rejection. Whole-assignment nogoods continued to enumerate nearby target
permutations too slowly. The all-consecutive channelling and stronger
deterministic R-read levers were therefore implemented and spent as standalone
closing hypotheses.

First target-level conflict-learning milestone, 2026-07-04:

- Landed the two-tiered production path. Deterministic target-slice rejections
  learn target-tuple clauses through the same `learn_sat_clause` truth-preserving
  path as candidate witness failures. Accepted target slices still run the
  candidate residual; exact re-encryption remains the only success oracle, and a
  bad witness learns a candidate-level clause rather than banning the target
  slice.
- The planted `ns=3` positive control now exercises the production `max_swaps=3`
  library path with planted-truth tracking. It recovers exactly, and every learned
  clause would fail immediately if it excluded the planted truth. With the
  ns=3-targeted deterministic tier (`R-top`/generalized `R-read`/state-domain,
  no exhaustive candidate arc), the correct planted target slice leaves residual
  candidate freedom: `total=4`, `max=2`, per-letter `A:1,B:2,C:1`. This is the
  pivotal measurement for the scaled plant: the candidate witness tier has real
  work after target acceptance, not merely a confirm. It does not prove that
  learned candidate clauses fired. The vendored `3_swap_ct.txt` key is not
  recorded, so the same correct-target residual-freedom measurement cannot be
  made for the real file unless the solver first recovers the real exact key.
- The first real `3_swap_ct.txt` production-path probe used the ignored rerunnable
  command listed above. It used `max_nodes=1` to bound the attempt after one
  target assignment. The first target model had `153896` target-restricted
  candidate entries, max domain `6562`; deterministic replay minimization learned
  one target clause with a minimal core of `4` target literals after `25` fresh
  replay checks. The run stopped at `SearchCapExceeded { nodes: 1 }` after
  `334.67s`, with outer stats `candidates=541406`, broad `pruned=659692`,
  broad `deductions=257081`, `target_clauses=1`,
  `target_replay_checks=25`, `target_replay_literals=4`,
  `candidate_clauses=0`, `truth_checks=0`.
- A prior unbounded version of the same probe, before the ns=3-targeted no-arc
  split, reached the first target model and then spent more than ten minutes
  inside the exhaustive candidate-arc propagation for that single slice before
  being interrupted. That arc is now deliberately excluded from the target tier;
  the retained candidate SAT residual is the witness tier.
- This did not earn the real `ns=3` systematic recovery rung at the time. This
  pre-local-search probe had no exact `2439/2439` re-encryption for
  `3_swap_ct.txt`, and `--num-swaps 3` was still capped by design.

Stage-1 planted ns=3 calibration controls, 2026-07-04:

- Closed the SAT `TargetUnsatCore` target-clause soundness gap before running this:
  a core returned from a physically target-restricted residual is now replayed
  once from the broad residual with only that core's literals before it can reach
  `learn_sat_clause`. If the core is not a broad residual nogood, the engine falls
  back to the full target assignment only after the same broad replay.
- Hardened the deterministic `NoResidualCandidate` fallback as well: if future
  code reaches the full-assignment fallback, that target clause is learned only
  after broad residual replay proves the full assignment is a broad nogood.
- Added `SwapRecoveryStats::target_rejections` so target assignments rejected by
  ns=3 CEGAR are counted separately from residual candidate-model `nodes`.
- Added ignored mid-size top-swap planted controls for `n=11` and `n=17`. These
  call `recover_known_plaintext_swaps` with `max_swaps=3`, so they route through
  `recover_ns3_with_target_cegar`; they are not the `reach.rs` word/MITM stress
  plants. The mid-size controls use exhaustive width-4 `ABC` context rows and
  planted seeds `0x5a17_0200_0000_1133` / `0x5a17_0200_0000_1733`.

Initial smoke-test commands (Bash `time`; `/usr/bin/time` was unavailable in this
environment):

```sh
TIMEFORMAT='wall=%3R s'; time env NOITA_SWAP_CEGAR_TRACE=1 \
  cargo test --locked ns3_planted_control_recovers_through_production_path -- --nocapture

TIMEFORMAT='wall=%3R s'; time \
  cargo test --locked ns3_top_swap_planted_control_n11_recovers_through_target_cegar -- --ignored --nocapture

TIMEFORMAT='wall=%3R s'; time \
  cargo test --locked ns3_top_swap_planted_control_n17_recovers_through_target_cegar -- --ignored --nocapture
```

Initial warm-run measurements from this worktree:

| control | production path | target rejections | target clauses | candidate clauses | wall-clock | notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `n=7`, `ABC`, original small control | `recover_ns3_with_target_cegar` | `0` | `0` | `0` | `0.080s` command wall | First target assignment accepted; targeted residual `total=4`, max domain `2`. |
| `n=11`, `ABC`, ignored mid-size control | `recover_ns3_with_target_cegar` | `0` | `0` | `0` | `60.542ms` test body / `0.224s` command wall | Targeted planted residual collapsed to `total=3`, max domain `1`; residual `nodes=2`. |
| `n=17`, `ABC`, ignored mid-size control | `recover_ns3_with_target_cegar` | `0` | `0` | `345` | `223.281ms` test body / `0.303s` command wall | First target assignment accepted; candidate witness tier did the work (`nodes=347`, target residual `total=137`, max domain `125`). |

Interpretation of the initial smoke tests: these numbers are **not** a pass of
the handoff's rejection-scaling gate. They are useful as production-path and
counter smoke tests, but every target-rejection count is `0`, so the deterministic
target-rejection branch that walled the real `n=83` file was never exercised.

Actual target-rejection calibration controls:

- Added planted top-swap ns=3 controls using anchored width-4 `ABC` rows. Each
  message starts with `A` and then appends an exhaustive width-4 `ABC` suffix.
  This deliberately avoids pinning every letter's target from an identity restart:
  the earlier rows started independent messages with `A`, `B`, and `C`, so broad
  R-top propagation pinned all three target literals before the target solver
  could propose a wrong slice.
- Fixture discovery: scan SplitMix64 planted seeds from
  `0x5a17_0200_0100_0000` upward under the anchored width-4 rows, keeping the
  first production-path recovery with exact planted `pt_mapping`, exact
  re-encryption, `target_rejections > 0`, `target_clauses_learned > 0`, and
  `target_replay_checks > 0`. First hits were `n=7` and `n=11` at offset `2`
  (`0x5a17_0200_0100_0002`), and `n=17` at offset `0`
  (`0x5a17_0200_0100_0000`).

Rerunnable commands:

```sh
TIMEFORMAT='wall=%3R s'; time \
  cargo test --locked ns3_top_swap_rejection_control_n7_recovers_after_target_rejections -- --nocapture

TIMEFORMAT='wall=%3R s'; time \
  cargo test --locked ns3_top_swap_rejection_control_n11_recovers_after_target_rejections -- --ignored --nocapture

TIMEFORMAT='wall=%3R s'; time \
  cargo test --locked ns3_top_swap_rejection_control_n17_recovers_after_target_rejections -- --ignored --nocapture
```

Warm-run measurements from this worktree:

| control | production path | target rejections | target clauses | replay checks | candidate clauses | wall-clock | notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `n=7`, anchored width-4 `ABC` | `recover_ns3_with_target_cegar` | `4` | `4` | `13` | `0` | `370.205ms` test body / `0.450s` command wall | Exact planted mapping recovered; residual `nodes=6`, target residual `total=5`, max domain `3`. |
| `n=11`, anchored width-4 `ABC` | `recover_ns3_with_target_cegar` | `15` | `15` | `52` | `129` | `3.190s` test body / `3.265s` command wall | Exact planted mapping recovered; residual `nodes=146`, target residual `total=37`, max domain `30`. |
| `n=17`, anchored width-4 `ABC` | `recover_ns3_with_target_cegar` | `18` | `18` | `61` | `106` | `1.393s` test body / `1.472s` command wall | Exact planted mapping recovered; residual `nodes=126`, target residual `total=160`, max domain `147`. |

Interpretation of the actual gate data: these controls now exercise the
deterministic target-rejection branch, and the count rises from `4` at `n=7` to
`15`/`18` at `n=11`/`n=17`. That is a real increase, but not an observed
explosion on this three-letter planted family; the handoff's "stronger clauses,
stop and re-plan" trigger is not tripped by this calibration. The caveat remains
load-bearing: this does not make `n=83` cheap. The real-file wall still includes
large per-rejection broad replay cost, which is exactly why lever 1 targets
reason extraction / cheaper sound target reasons.

Lever-1 target-reason extraction, 2026-07-04:

- Replaced the deterministic `NoResidualCandidate` path's full target-assignment
  greedy minimization with target-level reason tracking inside deterministic
  propagation. The learned reason is still replayed from the broad residual
  before it can reach `learn_sat_clause`.
- Ambiguous tracked reasons are validated only over literals present in the
  extracted implication reason, not over the whole target assignment. On the
  planted controls this preserves the greedy rejection counts exactly while
  cutting replay checks.

Control quality gate, greedy baseline vs. implication-tracked reasons:

| control | greedy target rejections | reason target rejections | greedy replay checks | reason replay checks | checks/rejection before | checks/rejection after | result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `n=7`, anchored width-4 `ABC` | `4` | `4` | `13` | `5` | `3.25` | `1.25` | Holds. |
| `n=11`, anchored width-4 `ABC` | `15` | `15` | `52` | `22` | `3.47` | `1.47` | Holds. |
| `n=17`, anchored width-4 `ABC` | `18` | `18` | `61` | `25` | `3.39` | `1.39` | Holds. |

Latest warm-run control command:

```sh
cargo test --locked ns3_top_swap_rejection_control -- --include-ignored --nocapture
```

Latest reason-tracked control measurements:

| control | target rejections | target clauses | replay checks | replay literals | candidate clauses | test body |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `n=7`, anchored width-4 `ABC` | `4` | `4` | `5` | `4` | `0` | `621.085ms` |
| `n=11`, anchored width-4 `ABC` | `15` | `15` | `22` | `15` | `129` | `3.498s` |
| `n=17`, anchored width-4 `ABC` | `18` | `18` | `25` | `18` | `106` | `1.411s` |

Real `3_swap_ct.txt` probe after lever 1:

```sh
TIMEFORMAT='wall=%3R s'; { time env NOITA_SWAP_CEGAR_TRACE=1 \
  NOITA_SWAP_NS3_PROBE_SECONDS=1800 \
  NOITA_SWAP_NS3_PROBE_MAX_NODES=8 \
  cargo test --locked ns3_real_file_production_path_frontier_probe -- --ignored --nocapture; } 2>&1 \
  | tee /tmp/ns3-probe-after-cap8.log
```

Result: still no recovery claim. The probe stopped cleanly at
`SearchCapExceeded { nodes: 8 }` after `1729.216s` test elapsed
(`wall=1729.461s`). It learned `8` deterministic target clauses from `8`
target rejections, with `target_replay_checks=56`, `target_replay_literals=40`,
`candidate_clauses=0`, `truth_checks=0`, `candidates=541406`,
`pruned=659692`, and `deductions=257083`. No target slice was accepted, no
candidate witness tier fired, and there is no exact `2439/2439` re-encryption.

Real-file cost comparison: the previous greedy probe spent `25` broad replay
checks and `334.67s` on its first learned rejection (`25.0` checks/rejection).
The reason-tracked cap-8 probe spent `56` replay checks across `8` learned
rejections (`7.0` checks/rejection, about `216.15s` elapsed per learned
rejection). That is a material cost reduction, but the real file remains walled:
the learned reasons are consistently 5-literal clauses. The `7.0`
checks/rejection figure means the singleton/focused sub-reason candidates are
failing broad verification on the real file, and each rejection runs until the
full 5-literal tracked core verifies. The target solver was still rejecting
deterministic slices when the cap was reached.

Lever-1a adaptive reason replay ordering, 2026-07-04:

- Added run-adaptive candidate ordering for deterministic target reasons. The
  extractor keeps the quality-first singleton ordering until learned target
  clauses demonstrate a multi-literal floor, then tries non-singleton tracked
  cores first and skips singleton probes. Every learned clause still passes the
  same broad-baseline replay before `learn_sat_clause`.
- Control quality held after the change: the anchored rejection controls remain
  at `4/15/18` target rejections for `n=7/11/17`, with replay checks
  `5/22/25` and replay literals `4/15/18`. The controls still learn singleton
  target clauses.

Real `3_swap_ct.txt` cap-60 probe after lever 1a:

```sh
TIMEFORMAT='wall=%3R s'; { time env NOITA_SWAP_CEGAR_TRACE=1 \
  NOITA_SWAP_NS3_PROBE_SECONDS=2700 \
  NOITA_SWAP_NS3_PROBE_MAX_NODES=60 \
  cargo test --locked ns3_real_file_production_path_frontier_probe -- --ignored --nocapture; } 2>&1 \
  | tee /tmp/ns3-probe-lever1a-final-cap60.log
```

Result: still no recovery claim and no accepted target slice. The probe stopped
cleanly at `SearchCapExceeded { nodes: 60 }` after `1856.190s` test elapsed
(`wall=1856.466s`). It learned `60` deterministic target clauses from `60`
target rejections, with `target_replay_checks=66`,
`target_replay_literals=300`, `candidate_clauses=0`, `truth_checks=0`,
`candidates=541406`, `pruned=659692`, and `deductions=257083`. Clause-length
distribution was `60 x len=5`; all learned target reasons were the recurring
`E/H/S/T/Y` family, with `T=67` throughout and the other values swept.

Cost comparison: lever 1a cuts the real-file deterministic rejection cost from
`7.0` to `1.10` broad replay checks/rejection. Wall-clock cost drops from about
`216.15s`/rejection at cap 8 to about `30.94s`/rejection at cap 60. The extra
six replay checks are the first rejection's floor-discovery cost; after that the
probe mostly pays one broad replay per learned 5-literal clause.

Livelock read: the cap-60 probe shows no visible convergence pressure, but by
itself does not distinguish true target-layer livelock from slow local
convergence inside the recurring `E/H/S/T/Y` subspace. There was no accepted
slice, no candidate-tier handoff, and no exact `2439/2439` round trip. The
targeted residual-size trace stayed broad: `targeted entries=153896,
max_domain=6562` on `55/60` assignments and `targeted entries=157136,
max_domain=6562` on `5/60`; it oscillated between broad regions rather than
shrinking. One reading is true livelock in a too-coarse target vocabulary;
another is finite but slow enumeration of a local projected pocket. A projected
`E/H/S/T/Y` measurement is needed before committing to the next major lever.

Projected `E/H/S/T/Y` adjudication probe, 2026-07-04:

```sh
TIMEFORMAT='wall=%3R s'; { time env NOITA_SWAP_CEGAR_TRACE=1 \
  NOITA_SWAP_NS3_PROBE_MAX_NODES=60 \
  cargo test --locked ns3_real_file_production_path_frontier_probe -- --ignored --nocapture; } 2>&1 \
  | tee /tmp/ns3-projection-cap60.log
```

Result: still no recovery claim, no accepted target slice, no candidate-tier
handoff, and no exact `2439/2439` round trip. The probe stopped cleanly at
`SearchCapExceeded { nodes: 60 }` after `2327.300s` test elapsed
(`wall=2327.536s`). It learned `60` deterministic target clauses from `60`
target rejections, with `target_replay_checks=66` (`1.10` checks/rejection),
`target_replay_literals=300`, and `target_floor_full_assignment_fallbacks=0`.
Clause-length distribution was `60 x len=5`; all learned clauses were the
tracked `E/H/S/T/Y` reason family. Cap-wide wall cost was `38.79s` per learned
rejection and `35.27s` per broad replay; the first rejection still pays the
floor-discovery sequence, while subsequent rejections mostly pay one broad
replay each.

Projection-space measurement: every rejected projected tuple was new
(`unique_projected=60`), every one remained in the same `T=67` slab
(`t_change=initial` once, then `same` `59` times), and the static distinct
projected space under `T=67` stayed `34,234,200` throughout. The final line was
`unique_for_t=60`, `projected_remaining_for_t=34,234,140`: only `60` of
`34,234,200` projected tuples were eliminated. Targeted residual entries again
showed no narrowing trend: `153896` entries on `55/60` rejections and `157136`
on `5/60`, with `targeted_max_domain=6562` throughout. The run touched
`7` distinct `E` values, `6` distinct `H` values, `13` distinct `S` values, and
`8` distinct `Y` values, but did not move `T`.

Verdict: this adjudicates the livelock question toward true target-layer
livelock at the current `(letter = target)` vocabulary. The solver is not
measurably exhausting a finite local projected pocket; it is enumerating fresh
5-target tuples inside a huge flat `T=67` slab. The next major lever should not
be more target-only singleton chasing. It should bring finer-than-target /
partial-transition literals or partial-slice theory propagation forward.

Phase-0 arc-provenance adjudicating measurement, 2026-07-05:

```sh
cargo run --locked --bin noita-eye -- gak-swap-arc-phase0 \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/3_swap_ct.txt \
  --output json
```

Result: unmeasured at budget. The command was run with the pre-registered
defaults baked into the instrument (`max_rejections=60`, `wall=3600s`,
`replay_cap=32`, controls enabled). It exceeded the `3600s` wall budget before
emitting an instrument JSON report. The process was still CPU-bound at the last
check (`01:01:41` elapsed) and was interrupted to avoid extending the registered
budget. Captured stdout was `0` bytes; captured stderr contained only Cargo's
startup lines. Therefore there is no emitted sampled-rejection readout to score.

Mechanical decision-rule application:

- Sampled rejections emitted by the Phase-0 report: not available; no report was
  emitted before the wall budget.
- Stop/cap: wall-budget exhaustion without adjudicating output.
- Bin distribution: not available (`context-free=0`, `context-expressible=0`,
  `context-opaque=0` are not claimed; the instrument emitted no rows).
- Literal-count distribution: not available; no capped `size <= k` rows were
  emitted.
- Short `(a)/(b)` conflicts (`<=3` literals, context literals included):
  not measurable from this run.
- Median tuple-kill estimate over short `(a)/(b)` nogoods in the pinned `T=67`
  slab: not measurable from this run.
- Slab anomalies: not available; no tuple-kill estimates were emitted.
- Verdict: **unmeasured at budget**. Per the pre-registered rule, budget
  exhaustion without adjudication is not evidence for either GO or NO-GO, and the
  budget was not extended to force a verdict.

Post-observability registered rerun, 2026-07-05 (**SUPERSEDED and MOOT**):

After the observability fixes in commits `a0bff33`, `fefa733`, and `6524eb8`,
the registered Phase-0 measurement was rerun. This supersedes only the
post-fix measurement record; it does not alter the original entry above, the
pre-registered decision rule, or the pre-registered budgets. It is historical
and moot for practice-puzzle recovery because substitution-first local search
already recovers the `ns=3` observed-letter mapping by exact `2439/2439`
re-encryption, so Phase-2 is unnecessary regardless of this GO readout.

- Input: `3_swap_ct.txt`, 8 known-plaintext pairs, `ns=3`.
- Config: `max-rejections=60`, `wall=3600s` (actual wall `3624s`),
  `replay-cap=32`, `spot-check-samples=256`.
- Controls passed: planted-positive, matched-null, matched-null-context.
- Broad stats: `candidates=541406`, `domains_pruned=659692`,
  `deductions=257083`.
- Stop/caps: `stop=time-budget`, `target_nodes=4`,
  `short_go_conflicts=4`, `tuple_kill_slab_anomalies=0`.

Sampled rejections from the post-fix report:

| node | class | literal count | tuple-kill estimate |
| ---: | --- | ---: | ---: |
| 1 | context-expressible | 3 | 438900 |
| 2 | context-free | 3 | 33795300 |
| 3 | context-free | 3 | 33795300 |
| 4 | context-free | 3 | not measured; wall aborted the spot-check |

All four literal counts are exact `literal_count=3`, not upper bounds.
`median_short_tuple_kill_estimate = 33795300`.

Mechanical decision-rule application for the rerun: by the letter of the
pre-registered rule, both GO conditions are met on this wall-limited four-sample:
100 percent of sampled rejections are at most three literals in bins `(a)/(b)`,
and the median tuple-kill estimate far exceeds `10^4`. The historical Phase-0
rerun verdict is therefore **GO**, but it is **SUPERSEDED and MOOT** because no
Phase-2 systematic solver is needed for the known-plaintext practice-puzzle
`ns=3` recovery.

## Historical systematic next levers

The ranked list below was the systematic-line planning snapshot before the
local-search correction. It is retained as historical context, not as a live
Phase-2 plan.

Ranked hypotheses for closing `ns=3` systematically:

1. Finer-than-target deterministic clauses / partial transition literals.
   Confidence: medium/high. Cost: high. Lever 1a made 5-literal target clauses
   cheap, but cap 60 still stayed in deterministic target rejection. The next
   useful vocabulary likely has to explain transition or candidate features
   below `(letter = target)`, with the same broad-replay soundness rule.
2. Partial-slice target DPLL(T). Confidence: medium/high. Cost: medium/high.
   The cap-60 probe shows the target solver proposing full assignments that are
   rejected by small repeated target families. Driving deterministic propagation
   on partial target assignments could reject these before 20+ irrelevant target
   choices are fixed.
3. Feature-level candidate CEGAR conflicts instead of whole-prefix nogoods.
   Confidence: medium/high after an accepted slice, low for the current wall.
   Failed exact re-encryptions should learn local incompatible letter/candidate
   features where possible, but the real file still has not reached the
   candidate tier.
4. Incremental solving with assumptions and reusable learned clauses across
   target slices. Confidence: medium. Cost: medium. This pairs naturally with
   target-level cores and avoids rebuilding similar candidate residuals.
5. Dependency-tracked longer n-gram target/candidate clauses. Confidence: medium.
   Cost: medium/high. The spent bounded four-event target experiment was too
   blunt, but a compact encoding that can explain failures may still help.
6. Per-letter meet-in-the-middle for hard residual domains. Confidence: medium.
   Cost: medium/high. Useful where one letter is the bottleneck, but it does not
   by itself encode cross-letter state coupling.
7. Crib equalities from shared identity prefixes and repeated spans. Confidence:
   medium. Cost: low/medium. These should reduce residual domains but are unlikely
   to close `ns=3` alone.
8. More aggressive shadow seeding. Confidence: low. Cost: low. The top-1 run was
   unsound, and top-4/top-16 remained too large; use only as a diagnostic, not as
   a recovery proof.
