# Handoff — general GAK / deck-cipher known-plaintext swap-recovery instrument

Written 2026-07-03 after a four-way design consult (Sonnet-5 repo+wiki inventory,
Opus-4.8 design, Codex/GPT design, gemini-3.1-pro fresh-angle) plus a working
Python prototype run against the real challenge files. This folder is a scoped,
delegatable proposal package: build a *trustworthy, general* GAK deck-cipher
attack that recovers the per-letter permutations ("swaps") from known plaintext.

## Why this exists (the community request)

Lymm — author of `../../../eye-messages.wiki` and of the practice puzzles — asked:

> "All I really want is a more general GAK attack that can work on larger groups
> than these small examples."

A community member supplied Lymm's reference generator and clarified the concrete
task: *given known plaintext, the group (S₈₃), the CT alphabet, and the base
permutation, reverse what the swaps are*, at increasing `num_swaps` difficulty.

**Framing (binding).** The eyes match no known cipher; **GAK is the framework the
community built while trying to solve them**, and these deck-cipher practice
puzzles are how they build and validate GAK attack tooling. This instrument is
community infrastructure — a general, self-validated KP attack Lymm can point at
larger groups. It is **not** a claim about the eyes, and nothing here relaxes the
repo's honesty ceiling (`AGENTS.md` → Golden rules).

## The cipher (from the vendored reference generator)

Corpus vendored at `research/data/practice-puzzles/deck-swap/`
(`noita_test_cipher.py` = Lymm's generator; `1_/2_/3_swap_ct.txt` = ciphertexts at
`num_swaps` 1/2/3; `plaintexts.txt` = the labeled known plaintexts extracted from
the generator's `encrypt()` calls; `README.md` = provenance).

Deck of `n=83`, state starts at identity. Per plaintext letter `L`:

```
state = compose(perm(L), state)      # compose(p1,p2)=p2[p1]; new[i]=state[perm(L)[i]]
emit    ct_alphabet[ state[0] ]      # = state_prev[ perm(L)[0] ]
```

Non-alphabet chars (`\n`, spaces) pass through verbatim and **do not advance the
state**. Each `encrypt()` restarts from identity, so each challenge file is 8
independent messages under **one shared 26-letter key**.

**The exploitable structure:** `perm(L) = base ∘ σ_L`, where `σ_L` is a chain of
`num_swaps` top-transpositions `(0 k)`. So `perm(L)` differs from the *public*
`base` in at most `num_swaps+1` positions, always chained through position 0, and
`perm(L)[0] = base[σ_L(0)]` is forced whenever the pre-state is known. Recovery is
recovering *which few positions moved and where* — a few `log n`-bit choices per
letter against ~100 occurrences each on average (2,439 letters over 24 used
letters; J and Z never appear). It is **over-determined in aggregate**; the
difficulty is search *ordering*, not information. One honest caveat: the tail is
skewed (K appears 2×, X 8×, Q 15×), so the rarest letters may stay legitimately
ambiguous off-top even under exact re-encryption — that is `RecoveredAmbiguous`,
not a bug.

## Q1 — What existing tooling is appropriate (reuse, don't rebuild)

| Asset | File(s) | Use for this attack |
| --- | --- | --- |
| Permutation mechanics | `src/ciphers/validation.rs` (`compose_permutations`, `validate_permutation`, `identity_gak_permutation`) | Core S_n composition/validation. |
| General GAK types | `src/ciphers/keys_gak.rs` (`GakKey`, `GakKeyOptions`, `CosetReadout`), `src/ciphers/mechanics.rs` | Encoder scaffolding. **Caveat:** the repo GAK uses left-mult + inverse-position readout — *not* Lymm's `state[perm[0]]` emission. Sonnet verified you can reproduce Lymm exactly by feeding each letter's **inverted** perm to `GakKey::deck`, but the clean move is to implement Lymm's convention directly (see Task 01). |
| Hidden-state attack home | `src/attack/gak_attack/` (`hidden_state`, `known_answer`, `render`, `error`) | This attack *is* hidden-state recovery; `hidden_state` is the natural module, `known_answer` the natural home for the planted positive control. |
| Small-support precedent | `gak_attack/marginalization/beam.rs` (`SmallSupportPrior`), `gak_attack/.../deck_fixture.rs` (`SmallSupport`) | Prior art for base+perturbation modelling (note: it swaps arbitrary `(i,j)`, not `(0,k)` top-swaps). |
| File-driven self-validating instrument pattern | `gak_attack/hidden_state_solver/instrument.rs`, `src/cli/commands/gak.rs`, `src/attack/maskdecode/selftest.rs` (plant+null+verify) | The instrument shape to mirror. |
| CLI input plumbing | `src/cli/shared.rs` (`resolve_input_text`, `parse_cli_sequence`, `split_blank_line_messages`, `parse_seed`) | `--input-file/--stdin + --alphabet`, multi-message split, seed parsing. |
| Reproducible nulls | `src/nulls/null` (in-crate `SplitMix64`, `fisher_yates`) | Matched-null generation (do not add a crates.io RNG — `AGENTS.md`). |
| English/n-gram scoring | `src/attack/language/mod.rs`, `src/attack/quadgram.rs` | **Only** if a ciphertext-only mode is ever attempted — not needed for KP (exact re-encryption is the oracle). Including it in the KP path invites the "high score = recovery" fallacy. |

**Gap:** no module anywhere does *known-plaintext permutation recovery*. Every
existing GAK module is deliberately ciphertext-only / mapping-independent because
the real eye corpus has no known plaintext. There is no Lymm-exact oracle, no
top-swap candidate enumerator, no KP pair parser, no domain-propagation engine, no
CLI surface, and no `num_swaps` inference. That is what this package builds.

## Q2 — What to build (the proposal, three delegatable tasks)

A new Rust instrument `gak-swap-recover` (do **not** overload `gak solve`), built
as a dependency ladder so each task is one coherent, independently-verifiable
mission. **Rust core, decisively** (performance + the repo's self-validated
instrument convention + null discipline); community shareability comes from a thin
reference-Python oracle differential-tested against the Rust oracle on the
vendored plaintexts, plus a
copy-pasteable Python `pt_mapping` dict in the output — Python is never the engine.

1. **[01] Lymm deck oracle + KP corpus plumbing + differential test.** The
   foundation that retires the #1 risk (orientation) *before* any recovery: an
   exact, parameterized `encrypt_lymm_deck`, a seeded mapping generator (plant),
   the labeled multi-message KP pair parser, and a **byte-for-byte differential
   test against the reference Python generator under planted mappings**. (The
   vendored ct keys are unrecorded, so reproducing `1_/2_/3_swap_ct.txt` itself
   requires key recovery — that is Task 02's acceptance, not an oracle test.)
   Also the top-swap candidate enumerator. → `01-lymm-deck-oracle.md`
2. **[02] Recovery engine + CLI + controls.** The exact forward-propagation CSP
   over per-letter small-support domains (MRV branching, cross-message joint
   forward-checking, accept only on exact re-encryption), the report type, the
   `gak-swap-recover` subcommand, and the planted positive-control + three matched
   nulls. Acceptance ladder: recover the ns=1/2/3 challenge keys exactly.
   → `02-swap-recovery-engine.md`
3. **[03] Generality + shareability + reach.** `num_swaps` inference, arbitrary
   generator sets / larger `n` / compose-direction / emission-index knobs,
   MITM/beam (and optional SAT) fallbacks for higher `num_swaps`, JSON + Python-dict
   output, and a larger-group stress/self-test. → `03-generality-and-followups.md`

## The recommended algorithm (consensus + a measured course-correction)

Primary: **propagation-first deduction, run jointly over all messages, with a real
CP-SAT/SAT solver for the residual coupling.** Two exact deduction rules do most of
the work (anchored at the 8 identity restarts):
- **R-top** — a known pre-state pins the letter's top: `perm(L)[0]=state_prev⁻¹[ct]`.
- **R-read** — a known pre-state at `L` followed by a letter `M` whose top is known
  *reads* an off-top entry: `perm(L)[target_M]=state_prev⁻¹[ct_at_M]`. English
  bigrams follow each `L` by many different `M`, so a handful of reads pins each
  `perm(L)`'s ≤`num_swaps+1` support positions — **deduction, not guessing.**
  (At ns≥2, states past the first unpinned letter are only *partially* known —
  the rules run over per-position known/unknown state entries, not full states;
  see Task 02.)
Whatever propagation can't deduce (the residual coupling) goes to a **CP-SAT/SAT
encoding** (variables `perm(L)[i]` one-hot; all-different + small-support
cardinality + the state-walk emission equalities as channelling constraints), seeded
with the R-deductions as unit facts. Per-letter meet-in-the-middle over generator
words is a targeted fallback when one letter's domain is the bottleneck. Acceptance
is **exact re-encryption**, never a score.

**Do NOT build the ns≥2 engine as forward left-to-right search** (simulate from
identity, branch on each new letter) — that is *measured* to fail (below). It is
retained only as the ns=1 closed-form fast path and as a verifier. Also do **not**
use per-letter local search as primary: one wrong permutation desyncs all later
state, so the objective is avalanche-heavy and misleading.

**Measured feasibility (two independent prototypes, on the real files):**
- `num_swaps=1`: **closed form, no search — SOLVED.** A single forward sweep
  recovered all 24 used letters, consistent across all 8 messages, exact
  re-encryption. Verified independently by two agents. `perm(L)[0]` alone
  determines the whole perm.
- `num_swaps≥2`: an emission pins only `perm(L)[0]`; off-top entries are constrained
  only through *delayed, coupled* effects on future emissions. **Forward search
  wanders — measured, and this is the load-bearing correction:** not just naive DFS
  but MRV + full cross-message forward-checking capped without a solution (real ns=2
  at 3M nodes; real ns=3 at 3M nodes; **and a *planted* ns=2 with the truth in the
  search space capped at 2M nodes**). A local ct-check passes for wrong off-tops as
  long as they conspire, and chronological backtracking can't isolate the wrong
  variable. **More nodes / Rust speed do not fix this — it is an algorithm problem.**
  Hence propagation-first + CP-SAT (conflict learning + non-chronological
  backjumping), not forward DFS.
- Frontier: **ns=1 is delivered/verified; ns≥2 is a validation ladder to *earn* via
  the propagation + CP-SAT path, not a solved given** — do not assume ns=2/3 are
  cheap just because ns=1 is. ns≥4 leans harder on MITM/CP-SAT; ns≥5 research-grade.
  **Report the measured frontier; never claim "scales arbitrarily."**

## Validation (binding, `AGENTS.md`)

Planted positive control: assert on exact re-encryption plus, per letter,
`RecoveredUnique` ⇒ equals the planted `perm(L)` and `RecoveredAmbiguous` ⇒ the
planted perm is in the reported candidate set — **never on the swap-word**
(factorization is non-unique). Blanket perm-equality is too strong: rare letters
(K appears twice in the whole corpus) can be legitimately undetermined off-top
even when re-encryption is exact. Three matched nulls that must
genuinely fail: (1) random *full* permutation mapping → no small-support solution;
(2) over-budget — encrypt at `b+1`, attack bounded at `b` must fail and `b+1` must
succeed; (3) label-shuffle the ct → fail. A passing null is a build-breaking bug.
The CLI runs the control + a null before trusting any real-file output and labels
its result a **candidate** unless re-encryption matches exactly.

## Top risks (all consults flagged #1)

1. **Orientation** — `compose` direction, left-vs-right mult, emission index,
   `base∘σ` vs `σ∘base` are all easy to invert. Gate *everything* on the Task-01
   byte-for-byte differential test against the Python reference generator
   (planted mappings) before trusting any recovery.
2. **Non-unique swap factorization** — assert on `perm(L)` + re-encryption; emit
   swaps only as a flagged canonical minimal word.
3. **State desync / over-claiming** — require exact round-trip + positive control +
   matched null + explicit ambiguity reporting (`RecoveredUnique` /
   `RecoveredAmbiguous` / `Candidate` / `NoCandidate`).
4. **Non-alphabet passthrough** does not advance state — mirror on both sides or
   pt/ct de-aligns silently.
5. **Single-message weakness** — the shared-key, 8-identity-restart structure is
   load-bearing; ingest all pairs jointly by construction.

## Consult provenance

Full working notes: this was cross-checked by Sonnet-5 (repo+wiki inventory),
Opus-4.8 (design, independently reproduced the ns=1 solve and *measured* the ns≥2
forward-search failure, incl. a planted ns=2), Codex/GPT (design + concrete repo
symbols), and gemini-3.1-pro (fresh angle). They converged on propagation-first as
the foundation. The one place the measurement overturned an initial recommendation:
Codex favored a "direct domain solver" with MRV branching over SAT, and an early
draft of this handoff followed that — but Opus then *measured* MRV + cross-message
forward-checking wandering even on a planted ns=2, so the residual solver is now a
CP-SAT/SAT backend, not hand-rolled MRV-DFS. Codex's caution that the SAT encoding
is heavy still stands: feed it the R-top/R-read deductions as unit facts first, and
keep it behind a clean interface so MITM or a stronger propagator can swap in. Net
honesty note: **ns=1 is verified solved; the ns≥2 propagation+CP-SAT path is
recommended but not yet verified end-to-end — Task 02's first milestone is to earn
it on the real ns=2 file before building the full CLI.**
