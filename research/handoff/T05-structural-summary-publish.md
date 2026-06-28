# T05 — Community-facing structural summary (the publish artifact)

**Tier:** 1 · **Size:** S · **Type:** doc · **Status:** Todo
**Depends on:** T02, T03 (cites their certificates) · **Conflicts with:** none
**Touches:** new `research/findings/eyes-structural-summary.md`

## Goal
One self-contained, postable document that consolidates the eyes' structural
conclusions into a single honest narrative a community reader can absorb without
spelunking the thread docs.

## Why
The structural attack program is essentially done; its results are scattered across
`gak-threads/` + `findings/`. A single synthesis is the actual deliverable of
"publish-and-close the computational frontier." Highest-value doc task.

## Steps
1. Open with the claim ceiling verbatim and a one-paragraph "what this is."
2. Summarize, each in a short section with the headline number and a pointer to its
   full write-up (do not re-derive):
   - Transitivity restriction → 6 groups; family pinned to {A₈₃, S₈₃}, D₁₆₆ conditional.
   - **AGL exhaustively excluded** (0/6724, 0/3362) + its transcription-robustness certificate (T02).
   - **Perfect-isomorphism supported** → GAK not falsified; + Stutter robustness (T03).
   - **G3 leak ceiling:** recovery is a calibrated no at this data budget (supply 26
     vs demand 332.2; 98.6–99.9% transitions undecidable).
   - **Thread-4 attack:** clean, *fair* eyes honest-negative (the eyes could have
     passed; they scored 0).
3. State the bottom line: GAK survives as a model; recovery not supported under
   stated assumptions; decode blocked on the symbol→meaning mapping (no anchor).
4. A short "what would change this" section → external anchor (see T11).
5. Keep it mapping-independent; flag every model-conditional assumption (shared
   plaintext + single global config) once, clearly.

## Definition of done
- [ ] `eyes-structural-summary.md` reads standalone; every number cites its source doc.
- [ ] No claim exceeds the ceiling; assumptions labelled; T02/T03 certificates referenced.
- [ ] `make check` green (codespell clean — this is prose-heavy).
- [ ] `docs/deslop-audit` merged in; committed.

## Honesty guardrails
This is a *synthesis*, not new results — do not introduce a number that isn't
already proven in a cited doc. "Pinned to {A₈₃,S₈₃}" and all affine/dihedral
exclusions are conditional on the shared-plaintext + single-global-config
assumption; say so. The eyes remain unsolved.

## Pointers
- `research/findings/agl-exclusion.md`, `research/findings/base5-first-trigram.md`
- `research/gak-threads/{PROGRESS.md, G2-isomorph-imperfection.md, G3-leak-ceiling.md}`
- `research/frontier.md` (the two community goals — frame against them)
- `research/03-confirmed-vs-speculation.md` (the skeptic's scorecard — stay consistent)
