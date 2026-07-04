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

The independent read of the landed SAT model matches the measurements: the eager
SAT clauses are essentially the per-letter exactly-one constraints plus
start-bigram links for each message's first two events. The remaining state walk is
enforced lazily through whole-prefix nogoods from failed exact re-encryptions. That
is enough after `ns=2` propagation has collapsed every observed letter, but it is
combinatorially weak when `ns=3` leaves hundreds of thousands of candidates per
hard letter.

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

Current diagnosis: the new propagation buys useful target-restricted pruning but
does not close the target-assignment problem. The wall is now specifically that
deterministic propagation can reject wrong full target assignments, but the engine
does not yet learn a small sound target-level reason from that rejection. Whole
assignment nogoods continue to enumerate nearby target permutations too slowly.

## Likely next levers

Ranked hypotheses for closing `ns=3`:

1. Generalize start-bigram channelling to all consecutive events over propagated
   partial states. Confidence: high. Cost: medium/high. This gives CDCL real unit
   propagation across the corpus instead of waiting for whole-prefix failures.
2. Strengthen deterministic R-read beyond message starts, including longer
   n-gram reads and partial-state entry domains. Confidence: high. Cost: medium.
   The ns=2 result says deductions are decisive when they fire.
3. Feature-level CEGAR conflicts instead of whole-prefix nogoods. Confidence:
   medium. Cost: medium. Failed re-encryptions should learn a local incompatible
   subset of letter/candidate choices rather than banning a full prefix assignment.
4. Per-letter meet-in-the-middle for hard residual domains. Confidence: medium.
   Cost: medium/high. Useful where one letter is the bottleneck, but it does not
   by itself encode cross-letter state coupling.
5. Crib equalities from shared identity prefixes and repeated spans. Confidence:
   medium. Cost: low/medium. These should reduce residual domains but are unlikely
   to close `ns=3` alone.
6. More aggressive shadow seeding. Confidence: low. Cost: low. The top-1 run was
   unsound, and top-4/top-16 remained too large; use only as a diagnostic, not as
   a recovery proof.
