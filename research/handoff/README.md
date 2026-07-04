# Handoff backlog — Noita eye-puzzle workbench

A series of small, single-pass tasks for an implementing agent (and the
sub-agents it delegates to). Each `TNN-*.md` is scoped to one agent, one pass.
Work the priority ladder below top-down; stop when the marginal value drops
(it is explicitly fine to stop after Tier 1).

This backlog was written 2026-06-26 after a full state read + two codex passes (a
direction second-opinion and a review of this folder). It supersedes the (stale)
ranking in `research/NEXT-STEPS.md` — fixing that file is task T00.

## The one-paragraph situation

The mapping-independent *structural attack* program is essentially exhausted. The
eyes' transitive group family is pinned to {A₈₃, S₈₃} (D₁₆₆ conditional); AGL
is exhaustively excluded; perfect-isomorphism is *supported* (so GAK is not
falsified); the Thread-4 attack gives a clean, fair honest-negative; and G3
quantified a calibrated no on chaining recovery at this data budget. The
decode is blocked on the unknown symbol→meaning mapping, with no external
anchor. So the honest next move is harden-and-publish, not "find the next
solver." The remaining code work is transcription-robustness certification +
(low-value, mostly-exhausted) proving-ground decodes.

## House rules (read before any task)

- **Branch off `main`.** Use one feature branch per task (or per small batch).
  Commit completed work with a clear message — don't wait to be asked (`AGENTS.md`).
- **The gate is `make verify`** (fmt-check + clippy `-D` + filesize + tests +
  rustdoc `-D` + cargo-deny); the pre-commit hook runs it, so a commit that lands
  *is* gate-green. Run `make check` before a PR. Doc-only tasks still trip
  codespell — keep prose clean.
- **Honesty ceiling (binding, every task).** Never exceed: *the eye data is
  deterministic, engine-generated, strikingly structured data of unknown meaning;
  unsolved; no primary developer source confirms recoverable plaintext.* A high
  n-gram score on the wrong structure is not a recovery. Label model-conditional
  and assumed choices as such. See `AGENTS.md` → Golden rules.
- **Every new negative needs a matched null and a positive control that fires** on
  known signal — otherwise it is not a finding. Reuse `src/nulls/` helpers.
- **Any candidate cleartext (English or Finnish) → log it** as a hypothesis under
  `research/gak-threads/candidates/` per that folder's README. Never a decode.
- **`src/main.rs` is the CLI chokepoint.** Any task adding a subcommand edits it;
  if two code tasks run in parallel, have one agent own the subcommand stubs.

## Keeping `docs/deslop-audit` merged in (read carefully — it touches code)

A separate agent is doing a maintainability pass on `docs/deslop-audit`. This
is not prose-only — it refactors code (e.g. the commit on it now extracts
`*_tests.rs` siblings out of `chaining_graph.rs`, `gak_attack/mod.rs`,
`solve/mod.rs`, `ciphers/mod.rs`; more file-decomposition/dedup is coming per
`docs/deslop/02-*`/`03-*`/`04-*`). It is a local branch — there is no
`origin/docs/deslop-audit`, so do not `git fetch` it.

- **Cadence:** at the start of each task and again before you commit, run
  `git merge docs/deslop-audit` (local branch name, no `origin/`). First run
  `git log main..docs/deslop-audit --stat` to see what it is currently touching.
- **Expect real code conflicts** if your task edits a file it is refactoring.
  Because it moves/splits code (inline tests → a sibling `*_tests.rs`, files
  decomposed), resolve on substance — never blindly take one side for code,
  and run `make verify` after every merge. For pure prose/doc conflicts, prefer
  the deslop agent's wording.
- **Low overlap right now:** the Tier-1 code tasks touch a *new* file (T01),
  `agl_gak.rs` (T02), `analysis/isomorph_imperfection.rs` (T03), and
  `experiments/transitivity.rs` (T04) — none of which are in the current deslop
  refactor set. Re-check at task start; the set grows.
- **Stray artifacts:** an earlier deslop commit accidentally carried
  `verify-solve.log` at the repo root (since removed at the deslop tip). As a general
  rule, don't propagate stray build logs/artifacts that show up in a merge — drop
  them and `.gitignore` if needed, and flag to the maintainer.

## Priority ladder

**Tier 0 — tooling (maintainer-requested 2026-06-29; a different shape than the publish tasks).**
- `T12` — turn the analysis/attack capability into **file-driven CLI instruments** (un-hardwire the
  structural battery from the eye corpus; promote the GAK hidden-state solver + discriminator out of
  `#[cfg(test)]` into a `gak` subcommand with a self-test). High value for every future agent: the
  toolbox becomes runnable on arbitrary ciphertext, not frozen to fixtures. Intended for a fresh-context
  agent; independently committable in pieces.
- `gak-swap-recovery/` — **general GAK deck-cipher known-plaintext swap-recovery instrument**
  (community-requested 2026-07-03 by Lymm: "a more general GAK attack that can work on larger groups").
  A 3-task dependency ladder (oracle+differential-test → propagation recovery engine+CLI+controls →
  generality/shareability/reach) with a vendored challenge corpus at
  `research/data/practice-puzzles/deck-swap/`. Design is settled (four-way consult + working prototype:
  ns=1 closed-form-solved, ns≥2 needs the propagation engine). See the folder's `README.md`.

**Tier 1 — harden & publish the eyes frontier (do these first; highest value/effort).**
- `T00` — refresh `NEXT-STEPS.md` (doc hygiene; unblocks anyone reading the stale ladder).
- `T01` — transcription-perturbation harness (shared primitive; enables T02–T04).
- `T02` — AGL-exclusion transcription robustness.
- `T03` — perfect-iso / G2 Stutter-region transcription *sensitivity* (the audit itself is done).
- `T05` — community-facing structural summary (the publish artifact).

**Tier 2 — the standing unblocker + optional formalization.**
- `T11` — external-anchor hunt (the only real decode-unblocker; mostly non-computational).
- `T04` — D₁₆₆ dihedral-exclusion robustness (optional; only sharpens an already-hedged verdict).
- `T06` — G3 certification-degree appendix (formalization; numbers already exist in G3).

**Tier 3 — proving ground (low transfer, mostly exhausted; opportunistic only).**
- `T07` — proving-ground status + remaining low-value classical leads. Note: `one`/`six`/`two`
  codec runs are already logged honest-negatives; the rest is low-value, non-transferring,
  and must be split before starting. This is a menu, not a must-do.
- `two-post-avenue-a-handoff.md` — **pickup point for practice puzzle `two`**
  after Avenue A closed (scoped honest negative, 2026-07-03). Carries the open
  route decision (run Avenue G / pivot eyes-side / stop) and the ruling that the
  merged `gak-swap-recovery` engine does not supersede the `two` route. Start
  here if continuing `two` or deciding its priority.
- `two-cross-agent-recon.md` — **2026-07-04 route reset for `two`**: a
  spoiler-firewalled reconciliation with an independent agent's crib-assisted
  solve. The live surface is the full 12-symbol stream (isomorph column-maps →
  group closure, order-48 shadow of a reported order-96 group); the `C3 × S4`
  reading and the 4-class coloring framing are superseded. Read this before
  any further `two` work; new methodology lessons #8–10 in
  `../attack-methodology.md`.

> Optional confirmatory one-off (no task file): if GAP becomes available, run
> `NrTransitiveGroups(83)` to machine-cross-check the 6-group count — the one
> residual gap in Thread 1A (`PROGRESS.md` §1). Tiny; skip unless GAP is installed.

## Dependency / conflict map

```
T00  (doc)            — independent
T01  (code) ──┬─> T02 (code+doc)   [AGL: src/attack/agl_gak.rs]
              ├─> T03 (code+doc)   [Stutter: src/analysis/isomorph_imperfection.rs]
              └─> T04 (code+doc)   [D166: src/experiments/transitivity.rs]
T02,T03 ─────────> T05 (doc)       [summary cites the certificates]
T06, T11 (doc)       — independent
T07  (doc/menu)      — independent; opportunistic only
```

## What "done" looks like for the whole backlog

Tier 1 landed = the eyes' structural conclusions are transcription-certified and
packaged into one postable summary, with the stale ladder fixed. That is a
publishable, honest close of the computational frontier. Tiers 2–3 are upside —
T11 is the only thing that could change the decode outcome, and it is external.
