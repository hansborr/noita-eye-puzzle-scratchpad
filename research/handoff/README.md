# Handoff backlog — Noita eye-puzzle workbench

A series of small, single-pass tasks for an implementing agent (and the
sub-agents it delegates to). Each `TNN-*.md` is scoped to one agent, one pass.
Work the priority ladder below top-down; stop when the marginal value drops
(it is explicitly fine to stop after Tier 1).

This backlog was written 2026-06-26 after a full state read + two codex passes (a
direction second-opinion and a review of this folder). Update 2026-07-06:
Tier 1 has landed through the structural summary. If the goal is the eyes decode
itself, the active remaining queue is Tier 2, starting with `T11`. If the goal is
to help Lymm's stated GAK-attack interests, start with
`gak-unknown-base-recovery/`.

## The one-paragraph situation

The mapping-independent *structural attack* program is essentially exhausted. The
eyes' transitive group family is pinned to {A₈₃, S₈₃}; AGL is exhaustively
excluded, and D₁₆₆ is excluded within-model by subsumption in the Full AGL sweep
[Lymm, verified]. Perfect-isomorphism is *supported* (so GAK is not falsified);
the Thread-4 attack gives a clean, fair honest-negative; and G3 quantified a
calibrated no on chaining recovery at this data budget. The decode is blocked on
missing key material, method disclosure, or known plaintext, with no external
anchor. The harden-and-publish cycle is now complete: the transcription
robustness certificates landed, and the publishable structural summary is in
`research/findings/eyes-structural-summary.md`. The remaining useful work is
mostly external-anchor documentation plus optional formalization; broad decode
search is not the next move. The separate smaller-GAK/deck proving ground
removed the public-base assumption at `n=7`, exposed a scaling cliff, and then
replicated the diagnosed unresolved-base completion fix at `n=8,9`. Every
retained plant now recovers on the measured development and holdout batches;
top-source ranking still drops over half the larger-deck plants. This remains
known-plaintext community tooling, not an eyes decode bridge.

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
- `gak-unknown-base-recovery/` — **BUILT + CALIBRATED.** The public-base solver
  conditioned on a base permutation the eyes would not provide, so this track
  added hidden-base fixtures, identifiability audit, exact `s=1` recovery, and
  bounded `s=2..3` base marginalization. Exact state SAT over retained
  top-source hypotheses improved both development and a sealed holdout. An
  optional wider beam closed the open misses but did not improve a fresh
  holdout. It is community GAK tooling, not an eye decode.

**Tier 1 — harden & publish the eyes frontier (DONE; kept as provenance).**
- `next-cycle-2026-07-06.md` — **EXECUTED.** It sent the repo through
  T00 → T01 → T02/T03 → T05 after practice `two` confirmation.
- `T00` — **DONE** (`9c60769`). `NEXT-STEPS.md` was refreshed into a
  navigation/status index.
- `T01` — **DONE** (`3290d84`). The source-layer transcription-perturbation
  harness is live in `src/analysis/perturbation.rs`.
- `T02` — **DONE** (`5052f10`). AGL exclusion robustness is recorded in
  `research/findings/agl-exclusion.md`.
- `T03` — **DONE** (`68fcca9`). Perfect-iso / G2 Stutter sensitivity is recorded
  in `research/gak-threads/G2-isomorph-imperfection.md`.
- `T05` — **DONE** (`a314f42`). The structural summary is published at
  `research/findings/eyes-structural-summary.md`.

**Tier 2A — active community-infrastructure frontier: Lymm's general-GAK interest.**
- `gak-unknown-base-recovery/` — unknown-base known-plaintext GAK/deck recovery
  on small planted instances is built, scaled through `n=9`, and
  holdout-calibrated. Complete small base-completion sets recover every retained
  plant on the measured `n=8,9` batches. An opt-in route-relaxation rank improved
  a fresh `n=9` row from `5/16` to `7/16` but tied `8/16` at `n=8`, failing its
  two-size promotion gate; top-source ranking remains the measured bottleneck.
  Do not repeat `n=7` refinement or scaling. A further ranker would need another
  distinct preregistered algebraic feature and fresh holdout;
  generator-family breadth remains a separate optional direction.

**Tier 2B — eyes-specific remaining work: the standing unblocker + optional formalization.**
- `T11` — external-anchor hunt (the only real decode-unblocker; mostly
  non-computational). Do this next when the priority is the eyes decode itself.
- `T04` — D₁₆₆ dihedral-exclusion robustness (optional; D₁₆₆ is already excluded
  within-model by AGL subsumption, same conditions as the AGL verdict — this only
  sharpens the Thread-1B single-witness corroboration, which stays hedged on its own).
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

> Count cross-check note: direct GAP `NrTransitiveGroups(83)` is unavailable
> (`fail`, per maintainer-run GAP) [Lymm]. The count cross-check is closed by the
> prime-degree transitive=primitive reduction plus OEIS A000019 `a(83)=6`
> [verified 2026-07-06]; `NrPrimitiveGroups(83)` would only be an extra machine
> check.

## Dependency / conflict map

```
T00, T01, T02, T03, T05 — DONE
gak-unknown-base-recovery — active next for Lymm/general-GAK work; independent
T11  (doc)              — active next for eyes-decode work; independent
T04  (code+doc)         — optional; depends on landed T01 harness
T06  (doc)              — optional; independent
T07  (doc/menu)         — independent; opportunistic only
```

## What "done" looks like for the whole backlog

Tier 1 has landed: the eyes' structural conclusions are transcription-certified
and packaged into one postable summary, with the stale ladder fixed. That is a
publishable, honest close of the computational frontier. Tiers 2–3 are upside;
T11 is the only remaining item that could change the eyes decode outcome, and it
is external. The unknown-base GAK track is separate: it can help the community's
general attack tooling without implying a new eye-corpus result.
