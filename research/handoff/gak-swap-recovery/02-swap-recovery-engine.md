# Task 02 — swap-recovery engine + `gak-swap-recover` CLI + controls

**Mission (one pass, one agent).** Build the known-plaintext recovery engine on
top of Task 01's oracle: recover the per-letter permutations (the "swaps") from
`(pt, ct)` pairs, expose it as a `gak-swap-recover` CLI subcommand, and gate it on
a planted positive control + three matched nulls. **Acceptance = recover the
vendored ns=1/2/3 challenge keys exactly (re-encryption byte-for-byte).**

Depends on **Task 01** (oracle, plant, candidate enumerator, KP parser). Read
`research/handoff/gak-swap-recovery/README.md` first (algorithm consensus, measured
feasibility, risks). House rules: `research/handoff/README.md`.

## Algorithm — propagation-first deduction + CP-SAT residual (MEASURED)

**Load-bearing measurement — read before you design anything.** The obvious
"forward-simulate from identity, branch on each new letter" engine **does not
work** at ns≥2, and this was measured on two independent prototypes — including a
*planted* case where the answer is provably in the search space:

| case | result | budget |
|---|---|---|
| real ns=1 (8 msgs) | SOLVED, exact, re-encrypts all 8 | closed-form sweep |
| planted ns=1 | SOLVED, exact match | 23 nodes |
| **planted ns=2** (truth in space) | **CAP, no solution found** | 2,000,000 nodes |
| real ns=2 (8 msgs), MRV + cross-message forward-check | **CAP** | 3,000,000 nodes |
| real ns=3 (8 msgs), MRV + cross-message forward-check | **CAP** | 3,000,000 nodes |

Root cause: off-top entries are constrained only through *delayed, coupled* effects,
so a local ct-check passes for wrong off-tops as long as they conspire; chronological
backtracking can't isolate the wrong variable and explores ≈`n^{#distinct-letters}`
before a displaced card surfaces. **More nodes / Rust speed will not fix this** — it
is an algorithm problem. Do **not** build the ns≥2 primary as forward left-to-right
DFS (naive *or* MRV). Retain forward DFS only as the ns=1 closed-form fast path and
as a control/verifier.

### The design to build

Exact **propagation-first CSP** over 26 variables (one `σ_L` each, domain = the
small-support reachable set), coupled through the deterministic state walk of **all
messages jointly**, with the residual coupling handed to a real conflict-learning
solver.

1. **Deduce to a fixpoint (no branching), anchored at the 8 identity restarts.**
   Two exact rules turn off-tops from *guess* into *read*:
   - **R-top:** known pre-state `S` + emission ⇒ `perm(L)[0] = S⁻¹[ct]` (the letter's
     *target*).
   - **R-read (the crucial one):** known pre-state `S` at an occurrence of `L`,
     immediately followed by letter `M` whose target is known, reads a specific
     off-top entry: `perm(L)[target_M] = S⁻¹[ct_at_M]`. Generalises to n-grams: a
     known chain of following targets exposes deeper entries. Because English
     bigrams follow each `L` by many different `M`, a handful of reads pins each
     `perm(L)`'s ≤`num_swaps+1` support positions.
   - Supporting: **R-between** (two consecutive fully-known states ⇒
     `perm(L)=S_prev⁻¹∘S_next`, and a perm known once is known everywhere); the
     `perm(L)=base` off-support prior; the no-doubles/distinct-target filter
     (`perm[0]≠0`, all-different targets); unit-propagate collapsed domains.

   **Partial states are the normal case at ns≥2.** Past the first occurrence of
   a letter with unpinned off-tops, the walk's states are only partially known
   (each unresolved support entry blanks one state position, and the blanks move
   with the walk). Implement the rules over per-position known/unknown (or
   domain) state entries: R-top fires whenever the ct value's position in the
   pre-state is among the *known* entries, not only on fully-known states. ns=1
   is closed-form precisely because its states never degrade; a literal
   "known pre-state" implementation stalls at the first ambiguous letter and
   makes propagation look uselessly weak.
2. **Residual coupling → CP-SAT / SAT** (primary for ns≥2, *not* a hand-rolled
   backtracker). Variables = `perm(L)[i]` one-hot; constraints = permutation
   all-different, small-support (`≤num_swaps+1` indicators with a cardinality bound
   vs `base`), and the emission/state-walk equalities as channelling constraints
   across the whole corpus. Seed it with the R-top/R-read/R-between deductions as
   unit facts to shrink domains first. A conflict-learning (CDCL) core supplies
   the non-chronological backjumping the coupling needs and that forward DFS
   lacks; see Notes for the realistic Rust backend options. (Codex's caution
   stands: the encoding is heavy, so lead with the deductions and keep the
   solver behind a clean interface.)
3. **Accelerators regardless of backend:** anchor on the identity restarts. Two
   distinct crib classes — do not conflate them: (a) *identity-restart shared
   prefixes* give literal state equality (msgs 1&4 share exactly `THE` → 3 equal
   leading ct chars, verified in all three files); (b) *interior repeated spans*
   give only a relative constraint — the same net permutation across both spans,
   NOT equal states (the pre-states differ). The messages are variations on one
   paragraph, so both classes are plentiful. Note pt 5 ≡ pt 8 byte-for-byte, so
   msg 8 adds zero information (ct 5 ≡ ct 8 in every file — verified): it is a
   free corpus-integrity check, and the effective corpus is 7 distinct messages.
4. **Accept only on exact re-encryption of every message** — never on a score. On a
   solver timeout, report the bound and what was dropped (`AGENTS.md`).

Fallback: per-letter **meet-in-the-middle** over generator words when a single
letter's domain is the bottleneck (`O(|G|^⌈m/2⌉)` vs `O(|G|^m)`). Do **not**
implement per-letter local search as primary (avalanche objective).

> Honesty: ns=1 is verified solved. The ns≥2 propagation+CP-SAT path is the
> recommended design but is **not yet verified end-to-end** — see Acceptance: the
> first milestone is to *earn* ns=2 on the real file before building the full CLI.

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
  encrypt known plaintext, recover, assert (a) exact re-encryption, and (b) per
  appearing letter: `RecoveredUnique` ⇒ recovered `perm(L)` == planted `perm(L)`;
  `RecoveredAmbiguous` ⇒ the planted perm is in the reported candidate set. Do
  NOT assert blanket perm equality — rare letters (K appears 2× in the vendored
  plaintexts) can be legitimately undetermined off-top even when re-encryption
  is exact, and a correct engine must be allowed to say so. **Never assert on
  the swap-word** (non-unique factorization).
- **Matched nulls (must genuinely fail):** (1) replace each `perm(L)` with a full
  *random* permutation (not small-support) → attack at the same bound returns no
  consistent small-support solution (clean failure, not a fabricated mapping);
  (2) over-budget — encrypt at `b+1`, run bounded at `b` → must fail, and `b+1`
  must recover; (3) label-shuffle the ct → must fail. **A passing null is a
  build-breaking bug, not a warning.**
- The CLI runs the control + a null before trusting real-file output and labels
  output a **candidate** unless re-encryption matches exactly.

## Acceptance criteria

Do this as a ladder, in order — **each rung is a gate; don't build the next until
the current one is earned:**

1. `make verify` green throughout.
2. **ns=1 (should be closed-form-instant):** recover the vendored `1_swap_ct.txt`
   key and re-encrypt all 8 messages byte-for-byte. (The prototype already does
   this — it is the warm-up that proves the oracle wiring.)
3. **ns=2 (the real milestone — EARN it before building the full CLI):** get the
   propagation (R-top/R-read) + CP-SAT residual to recover the vendored
   `2_swap_ct.txt` key with exact re-encryption of all 8 messages (ambiguity, if
   any, confined to explicitly flagged undetermined entries). This is the step
   that validates the *chosen algorithm* (forward search is measured to fail here).
   If it does not close, the fix is stronger deduction / a better SAT encoding —
   **not** more forward-search nodes.
4. **ns=3:** same on `3_swap_ct.txt`.
5. Positive control passes and all three nulls fail, as tests calling the same
   library fns the CLI uses.
6. A results note under `research/data/practice-puzzles/deck-swap/` (and/or a
   `research/gak-threads/` entry) recording recovered support sizes per level,
   solver stats (deductions made before the residual, SAT conflicts/decisions), and
   the measured ns frontier — labeled model-conditional.

## Notes

- The prototype confirms ns=1 is closed form **and measured that forward search
  (naive and MRV + cross-message forward-checking) wanders at ns≥2, including a
  planted ns=2 with the truth in the search space** — so ship the propagation +
  CP-SAT engine, not a forward backtracker. The problem is over-determined (~90
  occurrences per letter): if the residual solver struggles, the deduction stage
  (R-read n-gram probes, crib equalities) is under-exploited — feed it more before
  reaching for search.
- Keep the engine oracle-agnostic: it consumes `LymmDeckSpec` so Task 03 can flip
  compose-direction / emission-index / generator-set without touching recovery.
- Pick the SAT/CP-SAT backend deliberately (a vetted crate; justify it per
  `AGENTS.md` "minimal dependency surface"). Reality check: there is no
  OR-tools-class pure-Rust CP-SAT crate. The expected path is a pure-Rust CDCL
  SAT solver — candidates: `varisat` or `batsat` (MIT/Apache) or `splr`
  (MPL-2.0); all three licenses pass the current `deny.toml` allowlist — plus
  hand-rolled one-hot / all-different / channelling encodings. The conflict
  learning comes from the SAT core; the CP-style propagation is the deduction
  stage you are already building. Native bindings (kissat, OR-tools) are a
  supply-chain event out of proportion to this instrument — do not add them
  without explicit sign-off. Keep the backend behind a small trait so a future
  pure-propagation solver or MITM path can replace it without touching the CLI
  or the deduction stage.
