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
- **Adding a subcommand lives in `src/cli/`, not `main.rs`.** `src/main.rs` is a
  13-line shim (`mod cli; fn main() -> ExitCode { cli::run() }`). A new subcommand
  adds an argument struct in `src/cli/args_*.rs`, a `Command` variant in
  `src/cli/args.rs`, and a handler in `src/cli/commands/`, all wired through the
  uniform run loop in `src/cli/dispatch.rs` (shared helpers in `src/cli/shared.rs`).
  `main.rs` is untouched, so parallel code tasks no longer contend on one file.

## Priority ladder

**Tier 0 — tooling (maintainer-requested 2026-06-29; both items now DELIVERED — kept as a pointer to the landed instruments).**
- `T12` — **DONE.** The analysis/attack capability is now **file-driven CLI instruments**: the
  structural battery is un-hardwired from the eye corpus (each analysis keeps its verified-corpus
  default but accepts an `--input-file`/`--stdin` stream under `--alphabet`, via the `structural` and
  `groupscan` subcommands), and the GAK hidden-state solver + discriminator are promoted out of
  `#[cfg(test)]` into a `gak` subcommand with a self-test. The toolbox runs on arbitrary ciphertext,
  not frozen to fixtures.
- `gak-swap-recovery/` — **BUILT + MERGED.** The general GAK deck-cipher known-plaintext swap-recovery
  instrument (community-requested 2026-07-03 by Lymm: "a more general GAK attack that can work on larger
  groups"). Tasks 01/02/03 are done/reviewed/merged; the `gak-swap-recover` subcommand is live
  (`src/cli/args.rs` + `src/cli/commands/gak_swap*.rs`). The engine recovers observed-letter mappings for
  `num_swaps=1`, `2`, and `3` exactly (byte-for-byte 2439/2439 re-encryption of all 8 messages; J/Z are
  unconstrained because they do not occur in the plaintext). The earlier ns=3 CDCL(T) cost-wall and
  Phase-0/Phase-2 escalation are superseded for the vendored practice-puzzle recovery by the
  substitution-first local-search backend. Vendored challenge corpus + results at
  `research/data/practice-puzzles/deck-swap/`.

**Tier 1 — harden & publish the eyes frontier (do these first; highest value/effort).**
- `next-cycle-2026-07-06.md` — **coordinator handoff for the next natural cycle**:
  after practice `two` confirmation, stop broad proving-ground search and execute
  the Tier-1 publishability path: T00 → T01 → T02/T03 → T05, with T11 as an
  optional doc/research sidecar.
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
  legacy codec-family runs are already logged as scoped negatives, and `two` now
  has a separate `shadowfinish`/`substfinish` candidate record. The rest is
  low-value, non-transferring, and must be split before starting. This is a menu,
  not a must-do.
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
- `two-crib-free-finish-plan.md` — **solved / maintainer-confirmed (2026-07-06)**:
  the plan was driven through fixed `shadowfinish` and produced the plaintext
  hypothesis, then maintainer confirmation against withheld ground truth confirmed
  the solution. See `../findings/two-shadowfinish-substitution-candidate.md`
  before doing more search. Remaining work is optional punctuation-recovery
  measurement / original-generator verifier / broader null, not another broad
  route reset.

> Optional confirmatory one-off (no task file): if GAP becomes available, run
> `NrTransitiveGroups(83)` to machine-cross-check the 6-group count — the one
> residual gap in Thread 1A (`PROGRESS.md` §1). Tiny; skip unless GAP is installed.

## Dependency / conflict map

```
T00  (doc)            — independent
T01  (code) ──┬─> T02 (code+doc)   [AGL: src/attack/agl_gak/mod.rs]
              ├─> T03 (code+doc)   [Stutter: src/analysis/isomorph_imperfection/mod.rs]
              └─> T04 (code+doc)   [D166: src/experiments/transitivity/mod.rs]
T02,T03 ─────────> T05 (doc)       [summary cites the certificates]
T06, T11 (doc)       — independent
T07  (doc/menu)      — independent; opportunistic only
```

## What "done" looks like for the whole backlog

Tier 1 landed = the eyes' structural conclusions are transcription-certified and
packaged into one postable summary, with the stale ladder fixed. That is a
publishable, honest close of the computational frontier. Tiers 2–3 are upside —
T11 is the only thing that could change the decode outcome, and it is external.
