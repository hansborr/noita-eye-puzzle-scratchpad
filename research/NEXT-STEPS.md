# NEXT-STEPS — work plan & hand-off briefs (2026-06-26)

A prioritized, parallelizable backlog for the Noita eye-puzzle workbench, written so
a fresh agent can pick a thread off the shelf and run it. Each thread is
self-contained: what, why/expected outcome, effort, files (with line numbers),
steps, validation, and dependencies.

> Honesty ceiling (binding, project-wide): a high n-gram/structure score on
> gibberish is **not** a decode. Every "ruled out" claim needs a PASSING positive
> control and an adequate model/wordlist. Label model-conditional results as such.
> See `AGENTS.md`.

## Strategic snapshot (read before picking a thread)

- **Eyes / GAK: mature, largely exhausted, most likely a permanent honest-negative.**
  Live groups narrowed to `{A₈₃, S₈₃}` (+ `D₁₆₆` conditional); affine groups
  exhaustively excluded; perfect-isomorphism supported. The GAK attack
  (`noita-eye gak-attack-eyes`) runs end-to-end but returns an honest negative on
  the real eyes (Gate 1 held-out score 0, p=1.0). The decode is **blocked on the
  unknown symbol→meaning mapping with no external anchor**. Remaining eyes moves are
  narrow and *likely-negative* — worth doing for rigor, not because a decode is
  probable. (Source: gak-threads survey, `research/gak-threads/PROGRESS.md`.)
- **Sample puzzles are where a decode is actually achievable** — English is
  maintainer-confirmed. 3 concrete attacks remain untried-in-engine.
- **A correctness bug spans two shipped deliverables** (T1 below). Fix it first.
- **Refactor backlog is small**: only Brief 08 (CLI registry) is unstarted; the
  rest of the engine-spine / maintainability campaign is done.

## Priority ladder (recommended order)

1. **T1** (correctness, S) — fix the held-out gate bug in keystream + solve.
2. **T2** (tooling, M) — Finnish quadgram scorer (enables T8; unblocks Finnish work).
3. **T3 / T4 / T5** (sample-puzzle attacks, M each) — the real decode upside.
4. **T6 / T7 / T8** (eyes, M–L) — rigorous, likely-negative; T8 is the one long shot.
5. **R1–R3** (refactors) — schedule in gaps; R1 (Brief 08) ideally before the C-stream.

---

## CATEGORY: Code improvements / bug-fix

### T1 — Fix the held-out gate bug in `keystream.rs` + `solve/mod.rs` (shared null module)
- **Category:** bug-fix · **Effort:** S · **Expected outcome:** corrected gate;
  re-confirm (or flip) existing negatives.
- **Context:** The survival gate's held-out check compares the *odd-index fold* of
  the decrypt (`heldout_score`) against the **full-stream** matched-null mean. But
  every-other-letter of English is not contiguous English, so the fold scores low
  and a *true decode* can falsely fail the gate. This was found and fixed in
  `ragbaby.rs` (compare the candidate fold vs the **matched null's fold** —
  apples-to-apples). The same bug is still live in two places:
  - `src/attack/keystream.rs:703` — `heldout_ok = … && heldout_score > matched_mean`
    (`matched_null` at `:564` returns only `(mean, std)`).
  - `src/attack/solve/mod.rs:242` — `candidate_survives`:
    `candidate.heldout_mapping_score > candidate.null_mean`.
- **Reference fix:** `src/attack/ragbaby.rs` — `matched_null` returns
  `(full_mean, full_std, heldout_mean)` (~`:900`); `heldout_ok = heldout_score >
  matched_heldout_mean` (~`:1001`), with rationale comment.
- **Steps:**
  1. Factor a shared helper in `src/nulls/` (e.g. `matched_null_heldout.rs` or a
     method on the existing null harness) that returns the matched-null **held-out
     fold mean** alongside the full mean/std. Have ragbaby, keystream, and solve all
     use it (de-duplicate; ragbaby currently has its own copy).
  2. Fix the keystream and solve gates to compare fold-vs-fold.
  3. Re-run the keystream battery (`KEYSTREAM-RESULTS.md` reproduce block) and the
     solve corpus tests; confirm whether any prior negative flips. (They likely hold
     — those negatives also rest on `beats_null`/`matched_z` — but the audit is the
     point.)
  4. Add a `planted_decode_survives_full_gate`-style regression test to keystream
     and solve (mirror `ragbaby.rs`).
- **Validation:** a planted true decode must SURVIVE the corrected gate in each
  module; `make check` green; golden-master fixtures updated if gate output changed.
- **Dependencies:** none. **Conflicts with:** anything else touching
  `nulls/`/`keystream.rs`/`solve/mod.rs` — run it before T3/T4 if those reuse the
  null harness.

### R1 — Brief 08: CLI registry + args dedup
- **Category:** refactor · **Effort:** M.
- `src/main.rs` is 2107 lines with ~20 uniform `run_*` dispatchers. Brief 08
  (`docs/refactor/08-*.md`, spec'd, **not started**) collapses them into a registry.
- **Why schedule early:** every new sample-puzzle attack (T3/T4/T5) adds a CLI
  subcommand → edits `main.rs`. Doing R1 first (or having one integrator own the
  `main.rs` stubs) avoids merge thrash across the C-stream.

### R2 — Split `ciphers/mod.rs` (3673 lines) one-file-per-family · refactor · L
Pure maintainability; biggest god-file. `docs/refactor/` brief-02 extension. Low urgency.

### R3 — Finish Brief 06: extract colocated report renderers from `experiments/*` · refactor · L
The ~27 hand-written `print_*_report` fns still live inside experiment modules
(`conditional_structure.rs`, `periodicity.rs`, …). Low urgency.

---

## CATEGORY: New tools

### T2 — Finnish quadgram scorer
- **Category:** new-tool · **Effort:** M · **Expected outcome:** language-flexible
  quadgram scoring; enabler for T8.
- **Context:** `src/attack/language.rs` already has English + Finnish **bigram**
  models (`finnish_model()`, alphabet `A–Z + ÅÄÖ`). But `src/attack/quadgram.rs` is
  **English-only**, and the keystream/ragbaby/solve searches hardcode the English
  quadgram model. Noita is a Finnish game, so a Finnish cipher hypothesis deserves a
  Finnish quadgram scorer.
- **Steps:** add a Finnish quadgram training corpus to `research/data/lang/`
  (current `finnish.txt` is only ~2 KB — too small; source a larger public-domain
  Finnish corpus, record provenance in `README-corpus.md`); generalize
  `quadgram.rs` to a language-parameterized model (handle the 29-letter alphabet);
  thread a `--language en|fi` choice through the `ragbaby`/`keystream` (and solve)
  search entry points.
- **Validation:** held-out calibration — Finnish text scores higher under the
  Finnish model than English, and vice-versa (mirror `language.rs:584`).
- **Dependencies:** none. **Conflicts with:** T1 if both touch the scoring plumbing.

---

## CATEGORY: Attempts on the sample puzzles (best decode upside; English confirmed)

Context for all three: see `research/data/practice-puzzles/KEYSTREAM-RESULTS.md`
and `RAGBABY-RESULTS.md`. The four letter puzzles are aperiodic polyalphabetic,
word-boundary-preserving, flat-IoC; mono/periodic/keyword-Ragbaby/general-Ragbaby
are ruled out. Use the matched-null discipline (gate against the SEARCH's DoF) and
a passing positive control for every negative.

### T3 — Engine running-key two-stream beam on `five` (the z≈2.4 lead)
- **Category:** attempt · **Effort:** M · **Expected outcome:** the most promising
  decode lead; or a calibrated negative.
- **Context:** A Python two-stream running-key beam on `five` reached a weak,
  non-surviving z≈2.43 (the lone non-zero signal across the whole battery). It was
  never engine-ified or pushed with a stronger beam + crib constraints.
- **Steps:** implement a running-key (two-stream joint-quadgram) beam as an engine
  subcommand mirroring `keystream.rs`; widen the beam; add crib/word constraints;
  gate with the matched null. Validate the optimizer on a *planted* running-key
  first (positive control), then run on `five`.
- **Dependencies:** benefits from T2 if testing Finnish; adds a CLI subcommand (see R1).

### T4 — Plaintext long-autokey (recurrence form)
- **Category:** attempt · **Effort:** M.
- The *ciphertext* autokey key-independence leak (`p_i = c_i − c_{i−L}`) is already
  exhaustively negative (L=1..60). The **plaintext** autokey recurrence
  `p_i = c_i − p_{i−L}` is a genuine search (the key is the L-length primer) and is
  **untried**. Implement + planted positive control + matched-null gate.
- **Dependencies:** adds a CLI subcommand (R1).

### T5 — `seven`'s `#` as an Alberti rotation index
- **Category:** attempt · **Effort:** M.
- Ragbaby with `#` as a deletable null or word-break is already negative
  (`RAGBABY-RESULTS.md`). The remaining interpretation: `#` marks an **Alberti disk
  rotation** (`KB#K`, `B#TV`, `OG#PJ`, standalone `#`). Implement an Alberti
  attack that treats `#` as a re-key/rotation marker; positive control + gate.
- **Dependencies:** adds a CLI subcommand (R1).

---

## CATEGORY: Research / attempts on the eyes (rigorous, likely-negative)

All mapping-independent unless noted. Entry point: `noita-eye gak-attack-eyes`;
spec at `research/gak-threads/specs/thread-4-spec.md`. Corpus: `src/data/corpus.rs`
(9 verified messages, 1036 trigrams, 83 symbols).

### T6 — Schreier-composition-closure held-out gate for the eyes
- **Category:** research · **Effort:** M · **Mapping-independent.** · **Expected:**
  likely-negative but tighter than the current gate.
- A codex review proposed a stricter held-out alternative: instead of the current
  coverage-weighted held-out score, require recovered contexts to **compose under
  Schreier-vector composition** (the "correct" group-algebra check). Add as a
  variant gate in `src/attack/gak_attack/eyes.rs::run_gak_attack_eyes` (chain-link
  infra in `chaining_graph.rs`). Reuse synthetic positive controls.
- **Dependencies:** Thread 4 + Thread 5 (landed).

### T7 — Group-constrained `{A₈₃, S₈₃}` solver
- **Category:** research · **Effort:** L · **Mapping-independent.**
- With affine/dihedral ruled out, fix the group family to `A₈₃` or `S₈₃` (without
  revealing the specific group) and ask whether the narrowed search improves
  recovery on the eyes. New solver variant, likely `src/attack/gak_attack/
  constrained_solver.rs`. Reuse `generator.rs` for synthetic controls.
- **Dependencies:** Thread 4. **Conflicts with:** T6 (both touch `gak_attack/`) —
  serialize.

### T8 — Language-guided mapping search on the eyes (the long shot)
- **Category:** research · **Effort:** L · **Mapping-DEPENDENT** · **Expected:**
  speculative; the one thread with genuine fresh-insight potential.
- Gate 3 (language plausibility) was never *run* (Gate 1 failed first), and it was
  only ever a post-hoc check. Different idea: use a Finnish/English n-gram score as
  the **search objective** over the GAK key / symbol→meaning mapping (the analog of
  the Ragbaby keyed-alphabet search). Caveat: the eyes are a context-dependent
  deck-cipher autokey, so a naive substitution-style mapping search will not work —
  this needs the GAK structure folded into the objective. Treat any readable output
  as a HYPOTHESIS and log per the candidate-logging directive.
- **Dependencies:** **T2** (Finnish quadgram). Builds on Thread 4 solver.

### Lower-priority eyes exploration
- GAK tractability sweep over wider `n` (20→83) and hidden-subgroup size to map the
  recovery boundary precisely (`gak_attack/mod.rs` + `marginalization.rs`) — M,
  mapping-independent, analysis-only.
- Small-support prior (≤4 swaps/letter) sensitivity sweep — M.
- Deeper isomorph-family analysis of the broad chaining graph's ~5000 conflict pairs
  (benign collisions vs a second linguistic pattern?) — L.

---

## Parallelization map

Four independent streams (different subsystems → run concurrently, ideally in
separate git worktrees):

- **Stream A — correctness:** T1 → re-run keystream/solve batteries.
  *(touches `nulls/`, `keystream.rs`, `solve/mod.rs`)*
- **Stream B — tooling:** T2 (Finnish quadgram). *(touches `quadgram.rs`,
  `research/data/lang/`)* → unblocks T8.
- **Stream C — sample attacks:** T3 ∥ T4 ∥ T5. *(each a new module + one `main.rs`
  subcommand)*
- **Stream D — eyes:** T6 → T7 (serialize; both `gak_attack/`); T8 after B.

**Coordination hazards**
- **`main.rs`** is the one shared file across Stream C (and any new subcommand).
  Mitigation: do **R1 (Brief 08)** first, or have a single integrator own the
  subcommand stubs. Don't run two `main.rs`-editing threads in parallel without it.
- **Refactors R2/R3** rewrite `ciphers.rs`/`experiments/*` — conflict with feature
  work on those files; schedule in gaps, not concurrently.
- **T1 vs T3/T4** — if the sample attacks reuse the null harness, land T1's shared
  module first so they build on the corrected gate.

**Suggested first iteration (cleanly parallel, highest value):**
T1 (Stream A) + T2 (Stream B) + one of T3/T5 (Stream C) — a correctness fix, an
enabler, and the most promising sample-puzzle decode attempt.

## Sources
- Eyes/GAK survey → `research/gak-threads/{README,PROGRESS,MORNING-SUMMARY}.md`,
  thread briefs, and `src/attack/gak_attack/`, `src/analysis/{transitivity,
  perfect_isomorphism,chaining_graph}.rs`, `src/attack/agl_gak.rs`.
- Sample-puzzle state → `research/data/practice-puzzles/{KEYSTREAM,RAGBABY}-RESULTS.md`.
- Refactor briefs → `docs/refactor/` (all complete except 08).
- Memory: `practice-puzzle-keystream-state`, `noita-eye-puzzle-state`,
  `noita-eye-wiki-gak-convergence` (the GAK convergence + mapping-independent threads).
