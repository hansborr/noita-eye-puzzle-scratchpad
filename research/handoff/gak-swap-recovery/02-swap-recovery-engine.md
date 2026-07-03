# Task 02 — swap-recovery engine + `gak-swap-recover` CLI + controls

**Mission (one pass, one agent).** Build the known-plaintext recovery engine on
top of Task 01's oracle: recover the per-letter permutations (the "swaps") from
`(pt, ct)` pairs, expose it as a `gak-swap-recover` CLI subcommand, and gate it on
a planted positive control + three matched nulls. **Acceptance = recover the
vendored ns=1/2/3 challenge keys exactly (re-encryption byte-for-byte).**

Depends on **Task 01** (oracle, plant, candidate enumerator, KP parser). Read
`research/handoff/gak-swap-recovery/README.md` first (algorithm consensus, measured
feasibility, risks). House rules: `research/handoff/README.md`.

## Algorithm (primary — do not substitute a search-first design)

Exact **forward-propagation CSP** over 26 variables (one `σ_L` each), domain = the
small-support reachable set, coupled through the deterministic state walk of **all
messages jointly**:

1. **Propagate before branching.** Simulate every message from `initial_state`.
   At each step: if `perm(L)` is known, advance + check ct (conflict ⇒ backtrack);
   if unknown and the pre-state is fully known, record the forced top
   `perm(L)[0] = state_prev⁻¹[ct]` and intersect `L`'s domain. Apply:
   - **R-between:** two consecutive fully-known states pin the letter exactly
     (`perm(L) = state_prev⁻¹ ∘ state_next`); one perm known once ⇒ known for all
     its occurrences (shared key);
   - **consecutive-pair off-top leak:** once the next letter's `perm[0]=q` is
     known (q≠0), `perm(L)[q] = state_prev⁻¹[ct_next]` — a *deduced* off-top entry;
   - **no-doubles prune:** `perm[0] != 0` and all-different `perm[0]` across letters;
   - unit-propagate any letter whose domain collapses to one candidate.
2. **Branch by MRV** — when propagation stalls, pick the *unresolved letter with
   the smallest candidate domain* (never simply the first letter in message order;
   that ordering is what blows up — measured 2M-node exhaustion). Order candidates
   by lookahead (how much replay/domain reduction each unlocks).
3. **Forward-check across ALL messages.** A candidate must keep every
   already-fully-determined step in every message consistent; messages restart at
   identity so a later message often closes while message 1 is still open, giving
   early cheap contradictions. Anchor propagation on the identity restarts and on
   repeated-plaintext-span cribs (the messages are variations on one paragraph).
4. **Best-first / iterative-deepening with a hard node/time budget.** On
   exhaustion, report the bound and what was dropped (`AGENTS.md`: a bounded search
   states its limits). **Accept only on exact re-encryption of every message** —
   never on a score.

Fallbacks (wire as options, not the default path): per-letter meet-in-the-middle
over generator words for a bottleneck letter; leave a SAT/CP-SAT hook for Task 03.
Do **not** implement per-letter local search as primary (avalanche objective).

## Deliverables

- **`recover_known_plaintext_swaps(spec, pairs, search_cfg) -> RecoveryReport`** —
  ingests all pairs jointly. `RecoveryReport`: per letter `target=perm[0]`,
  support, final `perm(L)`, canonical minimal swap-word + equivalent-count/flag,
  no-doubles status, search stats (candidates, domains pruned, nodes, beam drops),
  per-message and total re-encryption `matched/total`, and a verdict enum
  `RecoveredUnique | RecoveredAmbiguous | Candidate | NoCandidate`.
- **`round_trip_check(spec, report, pairs)`** — re-encrypt with the recovered
  mapping, exact-match bool + first-divergence index.
- **`gak-swap-recover` CLI subcommand** (thin `clap` over the library, via
  `cli::shared`): `--plaintext-file`, `--ciphertext-file`,
  `--pair-format labels|blank-lines|jsonl`, `--pt-alphabet`, `--ct-alphabet`,
  `--n`, `--base-permutation affine:shift=,decimation= | --base-file`,
  `--num-swaps <hint>` / `--max-swaps <bound>`, `--beam`/`--max-nodes`/
  `--time-budget`, `--initial-state`, `--run-controls`, `--seed`,
  `--output text|json`. (Leave `--compose-direction`, `--emit-index`,
  `--generator-set`, `--infer-swaps` as Task-03 knobs but reserve the flag names.)
- **`gak_swap_self_test(cfg) -> SelfTestReport`** — the planted control + nulls,
  callable from `--run-controls` and from tests.

## Validation (binding)

- **Positive control:** plant a mapping (seeded `SplitMix64`) at ns ∈ {1,2,3},
  encrypt known plaintext, recover, assert (a) recovered `perm(L)` == planted
  `perm(L)` for every appearing letter, and (b) exact re-encryption. **Assert on
  `perm(L)` and re-encryption, NOT on the swap-word** (non-unique factorization).
- **Matched nulls (must genuinely fail):** (1) replace each `perm(L)` with a full
  *random* permutation (not small-support) → attack at the same bound returns no
  consistent small-support solution (clean failure, not a fabricated mapping);
  (2) over-budget — encrypt at `b+1`, run bounded at `b` → must fail, and `b+1`
  must recover; (3) label-shuffle the ct → must fail. **A passing null is a
  build-breaking bug, not a warning.**
- The CLI runs the control + a null before trusting real-file output and labels
  output a **candidate** unless re-encryption matches exactly.

## Acceptance criteria

- `make verify` green.
- **Recovers the vendored `1_/2_/3_swap_ct.txt` keys and re-encrypts all 8
  messages of each byte-for-byte** (this is the real-data proof the oracle +
  engine are correct). ns=1 should be effectively instant (closed form); ns=2/ns=3
  should close under a modest node budget with the propagation+MRV design.
- Positive control passes and all three nulls fail, as tests calling the same
  library fns the CLI uses.
- A results note under `research/data/practice-puzzles/deck-swap/` (and/or a
  `research/gak-threads/` entry) recording the recovered support sizes per level,
  the node/branch counts, and the measured ns frontier — labeled model-conditional.

## Notes

- The prototype confirms ns=1 is closed form and that naive DFS explodes at ns≥2 —
  ship the propagation-first engine, not the naive DFS. If ns=3 does not close
  under budget, that is a signal the MRV ordering / cross-message forward-checking
  is under-exploited (the problem is over-determined — ~90 occurrences per letter),
  not that more search is needed.
- Keep the engine oracle-agnostic: it consumes `LymmDeckSpec` so Task 03 can flip
  compose-direction / emission-index / generator-set without touching recovery.
