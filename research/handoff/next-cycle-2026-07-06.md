# Next cycle handoff — publishable eyes frontier

**Date:** 2026-07-06  
**Status:** executed; retained as provenance after Tier 1 landed
**Audience:** an implementation/exploration agent picking up the repo cold

Execution update: this cycle landed on `main` as `T00` (`9c60769`), `T01`
(`3290d84`), `T02` (`5052f10`), `T03` (`68fcca9`), and `T05` (`a314f42`).
Current new work should start from `research/NEXT-STEPS.md` and
`research/handoff/README.md`; the next recommended item is `T11`, not another
pass through the phases below.

## Executive summary

The natural next cycle is **not another broad decode search**. Practice puzzle
`two` is now maintainer-confirmed at the plaintext level, and the remaining
practice-puzzle work is either optional measurement or blocked on external
generator/key artifacts. The eyes themselves remain unsolved because no external
anchor — key material, a method disclosure, or known plaintext — has surfaced.

The highest-value next cycle is therefore:

1. clean the planning surface so new agents stop reading stale priorities;
2. build the transcription-perturbation harness;
3. use it to harden the two load-bearing eyes claims;
4. publish a single structural-summary document.

This is the "harden and publish the computational frontier" cycle from
`research/handoff/README.md` Tier 1.

## Current state to preserve

- Practice `two` is **solved / maintainer-confirmed** at the plaintext level.
  See `research/findings/two-shadowfinish-substitution-candidate.md`.
- The pure computational recovery for `two` is still letter-level:
  `shadowfinish` produced the candidate, and `substfinish` recovered the
  monoalphabetic plaintext hypothesis with spaces.
- The polished punctuation/hyphenation/quote form of `two` came from
  source/syntax alignment over that result, not from the Rust finisher and not
  from a recovered punctuation alphabet.
- `two` still lacks an original-generator round-trip. See
  `research/findings/two-original-generator-roundtrip-blocker.md`.
- The frozen candidate record should remain frozen. Do not edit
  `research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`
  unless a maintainer explicitly asks to supersede the confirmation packet.

## Recommended cycle

### Phase 0 — planning hygiene

Do `T00` first unless the user explicitly wants code first.

Task file: `research/handoff/T00-refresh-next-steps.md`

Goal: bring `research/NEXT-STEPS.md` up to date and point readers at
`research/handoff/` as the active backlog. It is currently stale relative to the
merged GAK threads, deck-swap work, and the confirmed practice `two` solve.

Why first: every future agent is likely to read `NEXT-STEPS.md`; stale strategy
causes wasted work.

Expected output:

- `research/NEXT-STEPS.md` says the active backlog is `research/handoff/`.
- done items are marked done with commit/file references;
- practice `two` is no longer described as an open hidden-state target;
- no cryptanalytic claim is upgraded beyond the docs already in `findings/`.

### Phase 1 — shared perturbation primitive

Task file: `research/handoff/T01-perturbation-harness.md`

Goal: add the small source-layer transcription-perturbation harness. It should
enumerate tiny windows of one- and optionally two-orientation-digit
counterfactuals, rebuild the reading-layer values through the accepted honeycomb
order, and run a caller-supplied verdict.

Why this is the right code next: both publish-blocking robustness tasks depend on
it. It turns "this result depends on a small region of the transcription" into a
measured sensitivity certificate.

Keep this small:

- perturb rendered orientation digits `0..=4`, never reading-layer values;
- skip delimiter `5`;
- rebuild through `GlyphGrid` / `orders::accepted_honeycomb_order`;
- refuse combinatorial explosion for double changes;
- include tests pinning variant counts and first-break reporting.

Expected output:

- new reusable primitive, likely `src/analysis/perturbation.rs`;
- rustdoc and focused unit tests;
- no new dependency;
- committed with the full gate passing.

### Phase 2 — robustness certificates

After `T01` lands, `T02` and `T03` can run in parallel in separate branches or
worktrees.

Task files:

- `research/handoff/T02-agl-robustness.md`
- `research/handoff/T03-perfectiso-stutter-robustness.md`

`T02` hardens the AGL exclusion:

- use the perturbation harness on the load-bearing prefix / `[66, 5]` region;
- report how many one- and bounded two-digit perturbations preserve exclusion;
- name any perturbations that dissolve the exclusion;
- update `research/findings/agl-exclusion.md`.

`T03` hardens the G2 perfect-isomorphism negative:

- use the perturbation harness around the Stutter-region candidates;
- report whether one- or bounded two-digit perturbations promote a robust
  internal violation;
- update `research/gak-threads/G2-isomorph-imperfection.md`.

Important wording:

- These are counterfactual sensitivity checks, not alternative transcriptions.
- The verified corpus remains the verified corpus.
- A fragility result does not mean the eyes are not GAK; it tells us which
  verified glyphs carry the conclusion.

Expected output:

- certification counts asserted in tests;
- exact dissolving/flipping perturbations named if any exist;
- findings docs updated with an honest "given the verified transcription" claim;
- committed with `make verify`.

### Phase 3 — publishable structural summary

Task file: `research/handoff/T05-structural-summary-publish.md`

Goal: write `research/findings/eyes-structural-summary.md`, a single postable
summary of the eyes computational frontier.

Do this only after `T02` and `T03` land, because the summary should cite their
certificates.

It should synthesize, not re-derive:

- transitivity restriction and surviving group family;
- AGL exclusion plus robustness;
- perfect-isomorphism supported / GAK not falsified plus Stutter sensitivity;
- G3 leak ceiling;
- Thread-4 attack honest-negative;
- the bottom line: GAK survives as a model, recovery is not supported at the
  current data budget, and decode remains blocked on missing key material, a
  method disclosure, or known plaintext — not a symbol-to-meaning mapping.

Expected output:

- `research/findings/eyes-structural-summary.md`;
- all numbers cited to existing docs;
- no new uncited computation;
- `make check` before handoff if time permits, because this is the publish
  artifact.

## Optional sidecar

If the next agent is more research/doc-oriented than code-oriented, `T11` is a
good bounded sidecar:

- `research/handoff/T11-external-anchor-hunt.md`
- output: `research/external-anchor-hunt.md`

This does not solve the eyes. It records what would count as a primary/verifiable
external anchor (key material, a method disclosure, or known plaintext) and where
to periodically look. Treat the actual search as standing human work, not
something to exhaust in one agent pass.

## Explicit non-goals for this cycle

- Do not restart broad practice-puzzle `two` search. It is confirmed.
- Do not treat the `two` punctuation restoration as a pure code result.
- Do not build a punctuation-capable `substfinish` unless the user specifically
  wants to measure punctuation recoverability without source alignment.
- Do not build an original-generator verifier for `two` unless new external
  generator/key/codec artifacts are supplied.
- Do not start `T07` classical proving-ground leads unless the user explicitly
  prioritizes sample-suite progress over eyes publishability.
- Do not change the eye claim ceiling: intentional structured data, unsolved,
  no primary developer source confirming recoverable plaintext.

## Suggested branch / commit shape

Use one branch per logical task:

```sh
git switch main
git pull --ff-only
git switch -c docs/refresh-next-steps      # T00
git switch -c feat/transcription-perturb   # T01
git switch -c feat/agl-robustness          # T02, after T01
git switch -c feat/stutter-sensitivity     # T03, after T01
git switch -c docs/eyes-structural-summary # T05, after T02/T03
```

Parallelism:

- `T00` and `T11` can run immediately and independently.
- `T01` gates `T02` and `T03`.
- `T02` and `T03` can run in parallel once `T01` is merged.
- `T05` should wait for `T02` and `T03`.

Commit every completed task. The repo policy is to commit completed work without
waiting to be asked.

## Verification expectations

For code tasks:

- run `make verify`;
- if the task is broad or publish-facing, run `make check` before final handoff;
- keep positive controls and matched nulls intact.

For doc-only tasks:

- run `git diff --check`;
- run `codespell` on changed docs;
- rely on the commit hook for blob-size and other cheap checks;
- run `make check` for `T05` if feasible.

## Files the next agent should read first

1. `AGENTS.md`
2. `research/handoff/README.md`
3. this file
4. `research/handoff/T00-refresh-next-steps.md`
5. `research/handoff/T01-perturbation-harness.md`
6. `research/handoff/T02-agl-robustness.md`
7. `research/handoff/T03-perfectiso-stutter-robustness.md`
8. `research/handoff/T05-structural-summary-publish.md`

For context, also read:

- `research/findings/two-shadowfinish-substitution-candidate.md`
- `research/findings/two-original-generator-roundtrip-blocker.md`
- `research/frontier.md`
- `research/03-confirmed-vs-speculation.md`

## One-sentence instruction for the next agent

Start with `T00`, then implement `T01`; after `T01` is merged, use it to complete
`T02` and `T03`, and only then write the `T05` structural summary.
