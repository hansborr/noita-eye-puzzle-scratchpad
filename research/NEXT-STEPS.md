# NEXT-STEPS — work plan (index) · revised 2026-06-26

A prioritized, parallelizable backlog for the Noita eye-puzzle workbench, **re-weighted
after a full read of the community wiki** (Lymm's eye-messages wiki at
`github.com/Lymm37/eye-messages/wiki` — the most up-to-date community work). This file is the index: the
strategic snapshot, the priority ladder, and the parallelization map. The full thread
briefs live in three companion docs, each readable on its own:

- **`frontier.md`** — what the #silmä-cryptography effort is actually trying to do, and
  what each goal needs. *Read this first if you're new.*
- **`threads-proving-ground.md`** — the community sample puzzles: which are GAK vs
  classical, plus G1 (validate GAK tooling on the GAK samples), T1 (gate fix), and the
  demoted classical decodes T3/T4/T5.
- **`threads-eyes.md`** — the eyes themselves: GAK-**disproof** (G2), isomorph-leak
  quantification (G3/G4), GAK-**attack** rigor (T6/T7/T8), and two near-free
  contributions (publish the AGL exclusion; the base-5 first-trigram question).

> **Honesty ceiling (binding, project-wide):** a high n-gram/structure score on
> gibberish is **not** a decode, and a high score on the *wrong* structure is not a
> recovery. Every "ruled out" claim needs a PASSING positive control and an adequate
> model. Label model-conditional results as such. See `AGENTS.md`.

---

## The answer: does the wiki change the plan?

**Yes — materially in emphasis, not in correctness.** The prior plan was technically
sound and honest, but it was **attack/recovery-heavy and proving-ground-misaligned**:

1. The community frontier is **two goals, both driven by the isomorph leak**: *find a
   GAK attack* (recover information) **or** *disprove the eyes are GAK* (find a property
   the eyes have that GAK cannot produce, or vice-versa). See `frontier.md`.
2. Our near-term energy (T3/T4/T5) was spent on **classical sample-puzzle decodes whose
   *attack code does not transfer* to the eyes** — a different mathematical object
   (a non-abelian, hidden-state, 83-symbol group-autokey with no symbol→meaning map).
   What transfers from the proving ground is the **methodology** (matched-null
   discipline, firing positive controls, held-out gating), not the cipher math.
3. **The proving ground was aimed at the wrong machine.** Of the seven sample puzzles,
   `one` and `two` are the **GAK-family** ones (a structural hypothesis from provenance +
   observed structure, not a repo-proven generator) — but they were only ever run through
   the **classical** `solve` pipeline, which cannot represent a GCTAK keystream. So our GAK
   tooling had **never been validated on a known-answer GAK instance**. **G1 fixed that
   (@b681c35)** for the cyclic case: `one` recovers cleanly — the first known-answer positive
   control for the **GCTAK gate** (not yet the *hidden-state* machinery). `two` (hidden-state)
   dies precisely at the wall that blocks the eyes — making it the standing first-class target
   (**G1b**), not a closed follow-on.
4. **GAK-disproof — half the community's problem — had zero forward thread.** The wiki
   names one live whole-family falsifier (**isomorph imperfection**); we own the tooling
   but weren't pushing it. Added as **G2**.

---

## Priority ladder (recommended order)

Full briefs in the linked docs; one line each here.

1. **G1** (proving-ground, S) — **DONE (@b681c35):** drove the GAK samples `one`/`two` through
   `solve_gctak`. `one` (cyclic) recovered cleanly — first known-answer positive control for the
   **GCTAK gate**; `two` (hidden-state) honest-negative at the wall that blocks the eyes.
   → `threads-proving-ground.md`. *(also informs G3/G4)*
2. **Near-free wins** (S each, HIGHEST value-per-effort) — publish our **exhaustive AGL exclusion**
   (the wiki rules AGL out only "tentatively") and tabulate the **base-5 first-trigram** structure
   (open wiki question; needs only the 9 values in `corpus.rs`). → `threads-eyes.md` (near-free section).
3. **T1** (correctness, S) — fix the held-out gate bug shared by `keystream.rs` + `solve/`;
   it hardens the matched-null/held-out helper the **eyes** Gate-1 also relies on.
   → `threads-proving-ground.md`.
4. **G1b** (proving-ground, M — *biggest-underweight catch*) — hidden-state attack on the
   **known-answer** sample `two` (+ codec layer): the closest *verifiable* miniature of the eyes'
   blocker. Run before eyes-scale T6/T7, in parallel with G2. → `threads-proving-ground.md`.
5. **G2** (disproof, M) — forward isomorph-falsification: push `perfect_isomorphism.rs`
   for a robust violation + construct a concrete *imperfectly*-isomorphic candidate family.
   → `threads-eyes.md`.
6. **G3 / G4** (leak quantification, M) — quantify the isomorph leak's information ceiling;
   compute the edge-overlap certification threshold (fold G4 into **T6**). Mapping-
   independent, publishable, answer wiki-open questions. → `threads-eyes.md`.
7. **T6 → T7** (eyes GAK-attack rigor, M→L, serialized in `gak_attack/`). → `threads-eyes.md`.
8. **T8** (mapping-DEPENDENT long shot, L) — honesty-gated, HYPOTHESIS-only. → `threads-eyes.md`.
9. **T3 / T4 / T5** (classical sample decodes, M each) — **demoted to opportunistic.** Keep
   the proving ground running in parallel but bias it toward the *transferable* GAK samples
   (G1/G1b), not the non-transferable classical letter puzzles. → `threads-proving-ground.md`.
10. **R1** (refactor, M) in gaps; **R2 / R3** deferred (see Supporting/internal below).

---

## Parallelization map

Independent streams (different subsystems → run concurrently, ideally separate worktrees):

- **Stream A — proving ground / correctness:** G1 (done) → **G1b** (hidden-state attack on `two`
  + codec) ∥ T1 (gate fix) → (opportunistic) T3/T4/T5. The two near-free outputs (publish AGL
  exclusion; base-5 first-trigram) ship anytime, independently.
  *(touches `gak_attack/`, `chaining_graph.rs`, `nulls/`, `keystream.rs`, `solve/mod.rs`)*
- **Stream B — disproof:** G2 (isomorph-imperfection falsifier + imperfect-isomorph family).
  *(touches `perfect_isomorphism.rs`, `isomorph.rs`)*
- **Stream C — leak quantification & attack rigor:** G3 ∥ (G4→T6) → T7. *(touches
  `chaining_graph.rs`, `gak_attack/`, `marginalization.rs`)* — serialize G4/T6/T7.
- **Stream D — tooling/long-shot:** T2 → T8 (mapping-dependent; lowest community priority).

**Coordination hazards**
- **`gak_attack/`** is shared by G1, T7, G5 and (indirectly) G4/T6 — don't run two
  `gak_attack/`-editing threads in parallel without coordinating; serialize T6/T7.
- **`main.rs`** is the shared chokepoint for any new CLI subcommand (G1, T3/T4/T5, T8).
  Do **R1 (CLI registry)** first, or have one integrator own the subcommand stubs.
- **T1 vs the sample attacks** — land T1's shared null helper before any sample attack that
  reuses the gate, so they build on the corrected version.

---

## Supporting / internal (low community priority)

These serve no direct community goal; schedule in gaps.

- **T2 — Finnish quadgram scorer** (new-tool, M). Generalize `quadgram.rs` (English-only)
  to a language-parameterized model; add a larger public-domain Finnish corpus to
  `research/data/lang/` (record provenance); thread `--language en|fi` through the search
  entry points. Calibrate held-out (mirror `language.rs:584`). **Only matters as the
  enabler for T8** — defer until a mapping-independent result motivates a language objective.
- **R1 — CLI registry + args dedup** (refactor, M). `main.rs` is ~2107 lines with
  ~20 uniform `run_*` dispatchers; collapse into a registry. Schedule early — every new
  subcommand (G1, T3/T4/T5, T8) edits `main.rs`. (Not started.)
- **R2 — Split `ciphers/mod.rs`** (~3673 lines) one-file-per-family (refactor, L). Pure
  maintainability; biggest god-file. Low urgency.
- **R3 — extract colocated `print_*_report` renderers** from `experiments/*`
  (`conditional_structure.rs`, `periodicity.rs`, …) (refactor, L). Low urgency.

---

## Sources
- Wiki review (this revision): the 55-page community wiki
  (Lymm's eye-messages wiki, `github.com/Lymm37/eye-messages/wiki`), read against the two
  community goals + the isomorph leak. Condensed in `frontier.md`.
- Eyes/GAK state → `research/gak-threads/{README,PROGRESS}.md`, `src/attack/gak_attack/`,
  `src/analysis/{isomorph,perfect_isomorphism,chaining_graph,transitivity}.rs`,
  `src/attack/agl_gak.rs`.
- Sample-puzzle state → `research/data/practice-puzzles/{KEYSTREAM,RAGBABY}-RESULTS.md`,
  `research/gak-threads/G1-RESULTS.md` (G1 output, pending).
- Memory: `noita-eye-puzzle-state`, `noita-eye-wiki-gak-convergence`,
  `practice-puzzle-keystream-state`, `gak-cipher-example-sample`.
