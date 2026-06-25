# Morning summary — GAK-threads wave-2 overnight run

**Written:** 2026-06-25 (end of the autonomous overnight session). **Branch:**
`gak-threads-wave-1`. **Mode:** ultracode, delegation-heavy (Claude subagents implement,
codex adversarially reviews), orchestrator kept its own context clean. **Gate:** `make
check` (full local CI) is **green**.

## Bottom line

**Thread 4 — the GAK attack, the last planned and highest-reward thread — is COMPLETE.**
The standing scientific conclusion is **unchanged and now more strongly grounded**: the
eyes are *deterministic, engine-generated, strikingly structured data of unknown meaning;
unsolved; the decode remains blocked on the unknown symbol→meaning mapping.* **No
candidate cleartext — English or Finnish — surfaced.**

## What landed (7 commits this session, all gate-green)

| Commit | Unit | Result |
|---|---|---|
| `e7b88f8` | Step 0 | `GakKey` — general parametric-`n` GAK cipher primitive (round-trips, GCTAK reduction, isomorph reproduction) |
| `d3b30fd` | 1a | **GCTAK decisive gate PASSES** — the wiki's "GCTAK is fully solvable" reproduced as a synthetic positive control (rate-beats-null, non-commutative dihedral witness, no ground-truth leak) |
| `aaa9e9a` | 1b | `gak-attack` CLI wiring + honesty-lock test |
| `1d928a2` | 2a | Real-GAK (non-trivial-H deck) attack — **partial** visible-coset action recovery, bounded by a **measured ~0.8 hidden-state multi-valuedness obstruction** |
| `8aa7c53` | 2b | **Hidden-state marginalization** (idea 3) — a *truth-free* held-out beam recovers several-fold more than the 2a baseline (~5.9× at n=5) and beats its matched null, **breaking cleanly as \|H\|=(n−1)! grows**. Small-support prior (idea 2): TENTATIVE, fails-gracefully, OFF in the headline |
| `44d4ec4` | 2c | **EYES Step 3 — clean fair NEGATIVE: no surviving candidate; decode blocked** |
| `c170835` | docs | PROGRESS ledger current + `notes/wave-2-summary.md` |

## The eyes result (the headline), honestly

The matured attack was pointed at the real corpus (1036 trigrams, 83 symbols, per-message,
boundaries kept) behind the spec's kill gates:

- **Gate 1 (held-out isomorphs vs matched within-message null):** FAILS. The eyes have
  abundant isomorph structure (zero TRUE-conflict aborts, Thread-3 consistent) but it does
  **not transfer** across held-out contexts above a shuffle null — held-out score **0**,
  p=**1.0**. Crucially the gate is **fair**: a held-out positive control *fires* on
  synthetic signal, and the material-effect bar is population-relative so the eyes *could*
  have passed with real signal (bar 1722 < their max-achievable 6888). Gate-1 chaining is
  enforced to stay within Thread-3 safe extents.
- **Gate 2 (Thread-3 perfect-iso consistency):** consistent (0 robust internal violations).
- **Gate 3 (speculative Finnish/English cleartext):** correctly **NOT RUN** (Gate 1 failed).

The run is logged at `research/gak-threads/candidates/` (a README protocol + a
clock-free-labelled record) as a HYPOTHESIS-free negative for your review.

## Why this is a real contribution, not just a null

It directly answers the wiki's stated open problem ("we need a GAK attack"): a reusable,
ground-truth-validated GAK generator + attack harness, a GCTAK solve, and a **measured
tractability bound** (how far hidden-state marginalization gets and exactly where it breaks)
— all on synthetic ciphers we hold the key to. The reframe is bounded: this is synthetic
progress on the *attack*; the standing claim about the *eyes* does not move because no
candidate survived held-out.

## Honesty highlights (the cross-model review earned its keep)

Every unit ran Claude-implement → **codex adversarial review** → fix → commit. Codex caught
real would-be-dishonest moments, each fixed before commit:
- 2a: a "recovered key / Schreier-propagation" overclaim (it only recovers partial
  visible-coset *actions*; the chain links were made genuinely load-bearing) and a
  mis-scoped TRUE-conflict (normal hidden-state multi-valuedness was being called a conflict).
- 2b: confirmed the idea-3 beam selection is **truth-free** (the ~9× was not a ground-truth
  peek); fixed beam-width overclaim + ambiguous labels.
- 2c: **a material-effect bar the eyes could never have cleared** — a rigged-to-fail
  "negative" — recalibrated to a fair population-relative bar; and an unenforced Thread-3
  safe-extent claim, now genuinely enforced.

## State / housekeeping

- `make check` green; working tree clean; everything committed on `gak-threads-wave-1`.
- Memory updated (`noita-eye-puzzle-state`, `candidate-cleartext-logging`).
- **One collateral loss:** during a 2c codex review run, an interim (uncommitted) draft of
  the synthesis docs was deleted; they were recreated from the committed state (no
  information lost — just rework).

## Suggested next steps (NOT auto-run — your call)

1. **Review** the eyes candidate record + `notes/wave-2-summary.md`, and the 2c held-out
   statistic (the most novel/subtle piece — embargoed-consensus coverage-weighted excess).
2. **Merge** `gak-threads-wave-1` → `main` if you're satisfied (it's a large, self-contained,
   gate-green body of work).
3. **Optional deeper exploration** (handoff backlog, not yet done): drive the synthetic
   attack to wider regimes (vary group/hidden-subgroup/`n`); run the other landed modules on
   the corpus for cross-thread signal; or the Schreier-composition-closure predictor codex
   flagged as a stricter (but heavier) held-out alternative for the eyes.
