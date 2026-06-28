# T00 — Refresh `NEXT-STEPS.md` (mark merged threads, record re-ranking)

**Tier:** 1 · **Size:** XS · **Type:** doc · **Status:** Todo
**Depends on:** none · **Conflicts with:** none · **Touches:** `research/NEXT-STEPS.md`

## Goal
Bring `research/NEXT-STEPS.md` in line with reality: several items it lists as
pending are merged, and its priority ranking is superseded by this handoff folder.

## Why
The file is the first thing a new contributor reads; right now it points them at
already-done work (G2/G3 as "M, pending") and over-ranks G4/T6. Cheap correctness.

## Steps
1. Confirm against `git log --oneline -40` what is merged. As of `5667bfe`:
   G1, G1b, T1, G2, G3 are all merged; the Thread-4 GAK-attack arc is complete;
   the two "near-free wins" (AGL exclusion write-up, base-5 first-trigram) are
   landed as `research/findings/`.
2. Mark those done in the ladder (one line each, with commit refs) and move them
   out of the "recommended order".
3. Add a short note at the top: *"Re-ranked 2026-06-26 — see `research/handoff/`
   for the active backlog. `git log` is the source of truth for what's merged."*
4. Record the re-ranking rationale in one paragraph: G4/T6 demoted to a
   formalization (G3 already computed `t=N−1=82` and the 332.2 coupon demand);
   T7/G5 confirmatory; T8/T2 triage-only; highest-value remaining work is the
   transcription-robustness certificate + publish.

## Definition of done
- [ ] `NEXT-STEPS.md` marks G1/G1b/T1/G2/G3 + the near-free wins as merged.
- [ ] Top-of-file pointer to `research/handoff/`.
- [ ] No invented status — every "DONE" cites a commit or a `findings/` file.
- [ ] `docs/deslop-audit` merged in; `make verify` green; committed.

## Honesty guardrails
Do not upgrade any verdict while editing. D₁₆₆ stays "conditional / MEDIUM";
perfect-iso stays "SUPPORTED (not proven)"; the decode stays blocked.

## Pointers
- `research/NEXT-STEPS.md` (the file)
- `research/gak-threads/PROGRESS.md` §6 (wave-2 landings + commit table)
- `git log --oneline -40`
