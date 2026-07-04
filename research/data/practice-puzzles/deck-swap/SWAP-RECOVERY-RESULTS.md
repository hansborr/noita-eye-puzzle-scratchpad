# GAK swap-recovery Task-02 results

Recorded 2026-07-03 on branch `feat/community-request`.

This note is model-conditional: it reports what the current Lymm top-swap
known-plaintext recovery engine can verify by exact re-encryption, and where the
current propagation/SAT encoding stops. It is not a claim that larger swap budgets
are impossible.

## Verified frontier

Inputs: `plaintexts.txt` paired with `1_swap_ct.txt`, `2_swap_ct.txt`, and
`3_swap_ct.txt` under the default Lymm spec (`n=83`, `pt=A..Z`,
`ct=chr(33+i)`, `base=affine:shift=26,decimation=3`, identity restarts).

| level | status | exact re-encryption | solver stats |
| --- | --- | --- | --- |
| `ns=1` | recovered | `2439/2439` | `candidates=83`, `pruned=0`, `deductions=24`, `nodes=0`, `sat_decisions=0`, `sat_conflicts=0` |
| `ns=2` | recovered | `2439/2439` | `candidates=6725`, `pruned=134804`, `deductions=925549`, `nodes=1`, `sat_decisions=0`, `sat_conflicts=0` |
| `ns=3` | not recovered by current engine | not claimed | unsupported in landed CLI; strengthened propagation frontier below |

Support-size summary for the recovered levels:

- `ns=1`: all 24 appearing letters recover as singleton domains with canonical
  two-position support `{0,k}`; `J` and `Z` do not appear.
- `ns=2`: exact round-trip is recovered after propagation collapses the residual
  to one SAT model check. Reported observed-letter supports are within the
  `<=3` top-swap bound; most are three-position supports, with rare/degenerate
  letters shorter. The CLI emits the per-letter target/support/swap word.

Validation controls:

- Planted `ns=1`: exact; `24/24` observed letters matched the planted unique
  permutation, `0` ambiguous, `0` mismatched unique.
- Planted `ns=2`: exact; `23/24` observed letters matched the planted unique
  permutation, `1` observed letter remained ambiguous under exact re-encryption
  with the planted permutation present in that letter's reported candidate set,
  `0` ambiguous letters missing the plant, and `0` mismatched unique.
- Matched nulls all concluded with `CleanFailure` under the default
  `max_nodes=50000` cap: random full-permutation mapping at the `ns=2` bound,
  over-budget `ns=2` encrypted text attacked at `ns=1` (while recovering at
  `ns=2`), and ciphertext-symbol label shuffle at the `ns=2` bound. The
  self-test does not count `SearchCapExceeded` or `SearchTimeExceeded` as a
  genuine null failure.

The `gak-swap-recover` CLI exposes the same library path used by the tests for
the supported frontier. A request for `--num-swaps 3` currently fails with an
explicit measured-frontier message rather than emitting a candidate.

## Rerun commands

Stable supported-frontier checks:

```sh
cargo test --locked ns1_recovery_recovers_vendored_key_and_reencrypts_exactly -- --nocapture
cargo test --locked ns2_recovery_recovers_vendored_key_and_reencrypts_exactly -- --nocapture
cargo test --locked swap_recovery_self_test_passes_supported_frontier_controls -- --nocapture
cargo test --locked ns3_planted_truth_survives_target_cegar_pruning -- --nocapture
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
  --num-swaps 3
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

For the vendored `2_swap_ct.txt` file, this caps the requested `1..3` range to
the supported `1..2` range, rejects `s=1`, and reports `s=2` with exact
`2439/2439` re-encryption and maximum observed support size `3`. A range that
starts at `3` (for example `--infer-swaps 3..4`) fails with the same measured
frontier message as `--num-swaps 3`.

Task-03 item 4 adds shareable output:

```sh
cargo run --locked --bin noita-eye -- gak-swap-recover \
  --plaintext-file research/data/practice-puzzles/deck-swap/plaintexts.txt \
  --ciphertext-file research/data/practice-puzzles/deck-swap/1_swap_ct.txt \
  --num-swaps 1 \
  --output json
```

The JSON report includes the full recovered `pt_mapping`, per-letter
`support`/`support_size`/canonical `swap_word`, aggregate and per-letter verdicts,
and `round_trip.exact`. It also includes `python_pt_mapping`, the same
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

Bounded-search note: direct CLI recovery still rejects `--num-swaps` /
`--max-swaps >= 3` with the measured-frontier message. The generator-set
generality does not claim larger reach by itself; higher budgets and larger-group
stress frontiers are Task-03 item 3. The distinct nonzero target/no-doubles
assumption remains load-bearing for generalized generator sets, and violating it
is reported as a model rejection rather than a candidate recovery.

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

Bounded-search note: this item does not extend the real-file frontier. The CLI
still rejects `--num-swaps` / `--max-swaps >= 3` with the measured-frontier
message, and right-compose residual recovery bypasses the left-compose
transition-pruning clauses rather than claiming those deductions are symmetric.
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

Bounded-search note: this does not change the public real-file frontier. The
CLI still rejects direct `--num-swaps` / `--max-swaps >= 3` requests with the
measured-frontier message, and the vendored S83 `ns=3` ciphertext remains in the
wall section below. The new stress boundary is model-conditional on the explicit
rotation-generator surface and planted controls.

## ns=3 wall

The current ns=2 success does not scale automatically to ns=3. The structural
break is that R-top/R-read deductions become much weaker once each letter domain
has hundreds of thousands of possible three-swap candidates. At `ns=2`, the traced
residual reached `6725` candidates, `18863` total domain entries, max domain
`6643`, then propagation collapsed the SAT-ready residual to `24` total entries
with max domain `1`. At `ns=3`, equivalent propagation leaves multi-million-entry
residuals, so the current SAT model has too little eager structure to learn from.

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

Current diagnosis: the new propagation buys useful target-restricted pruning but
does not close the target-assignment problem. The wall is now specifically that
deterministic propagation can reject wrong full target assignments, but the engine
does not yet learn a small sound target-level reason from that rejection. Whole
assignment nogoods continue to enumerate nearby target permutations too slowly.
The all-consecutive channelling and stronger deterministic R-read levers have
therefore been implemented and spent as standalone closing hypotheses.

## Likely next levers

Ranked hypotheses for closing `ns=3`:

1. Target-level conflict learning from deterministic propagation failures.
   Confidence: high. Cost: medium/high. The current engine can reject wrong target
   slices, but it needs dependency tracking or a replayable explanation to learn a
   small incompatible subset instead of banning one full target assignment.
2. Feature-level candidate CEGAR conflicts instead of whole-prefix nogoods.
   Confidence: medium/high. Cost: medium. Failed exact re-encryptions should learn
   local incompatible letter/candidate features where possible, not only a full
   prefix assignment.
3. Incremental solving with assumptions and reusable learned clauses across
   target slices. Confidence: medium. Cost: medium. This pairs naturally with
   target-level cores and avoids rebuilding similar candidate residuals.
4. Dependency-tracked longer n-gram target/candidate clauses. Confidence: medium.
   Cost: medium/high. The spent bounded four-event target experiment was too
   blunt, but a compact encoding that can explain failures may still help.
5. Per-letter meet-in-the-middle for hard residual domains. Confidence: medium.
   Cost: medium/high. Useful where one letter is the bottleneck, but it does not
   by itself encode cross-letter state coupling.
6. Crib equalities from shared identity prefixes and repeated spans. Confidence:
   medium. Cost: low/medium. These should reduce residual domains but are unlikely
   to close `ns=3` alone.
7. More aggressive shadow seeding. Confidence: low. Cost: low. The top-1 run was
   unsound, and top-4/top-16 remained too large; use only as a diagnostic, not as
   a recovery proof.
