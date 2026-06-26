# Handoff — continue the Noita eye-puzzle wave after T1 (2026-06-26)

*Paste the "PROMPT" section below to the next agent. The rest is context for a human.*

---

## Status at handoff

- **Branch `exploration`, HEAD = `34cac21` ("T1: fold-vs-fold held-out survival gate").
  Working tree clean. `make verify` green. NOT pushed.**
- `origin/main` is far behind: it lacks the entire recent wave (G1, G1b, AGL exclusion,
  base-5 first-trigram, **and T1**). **Any new work must branch off `exploration` HEAD,
  not `main`/`origin/main`.**
- **T1 DONE** (this session): the held-out survival gate now compares fold-vs-fold
  (shared `src/nulls/heldout.rs`), fixed in `keystream.rs` + `solve/` (all three null
  paths), ragbaby de-duped onto the helper. Write-up: `research/findings/T1-heldout-gate-fix.md`.
  Side-finding: the corrected gate flips Gate 2 for the eyes' top searched candidate to a
  marginal pass; the eyes' honest negative now rests on Gate 3 (`beats_null=false`). Eyes
  still UNSOLVED; claim ceiling intact.
- **Open (this is the handoff): the parallel wave G3 ∥ G2.** Neither started.

---

## PROMPT (give this to the next agent)

You are continuing the Noita eye-puzzle workbench (`/home/node/persist/noita-eye-puzzle-ghidra`,
branch `exploration`, HEAD `34cac21`). The eyes are UNSOLVED; keep the claim ceiling.

Read these first, in order:
- `research/NEXT-STEPS.md` (priority ladder + parallelization map)
- `research/threads-eyes.md` (the G2 / G3 / G4 briefs — your main spec)
- `research/frontier.md` (the two community goals + the isomorph leak)
- `research/gak-threads/G1b-RESULTS.md` (empirical anchor for G3)
- `research/findings/T1-heldout-gate-fix.md` (what just landed; the survival gate is now
  trustworthy fold-vs-fold — reuse `src/nulls/heldout.rs` if you need held-out gating)

TASK — run the parallel wave **G3 ∥ G2** in separate worktrees off `exploration` HEAD,
then review (Claude multi-lens + a codex SECOND opinion), fix, merge to `exploration`,
`make verify` green, remove worktrees. Do NOT push unless asked. Do NOT jump to the
L-effort eyes-scale attacks (T6/T7) — gate them on G3's feasibility number first.

**G3 — quantify the isomorph leak's information ceiling** (mapping-independent, publishable).
Anchor on G1b's measured coverage collapse / readout many-valuedness (on practice puzzle
`two`: out-degree 8 on all 12 symbols; 76–83% of transitions undecidable). Compute, from
the eyes' ~1036 trigrams vs |S₈₃| / coset structure, an isomorph-MI / coupon-collector
bound on recoverable vs needed group elements, and how it scales toward 83 symbols.
Answers the wiki's unquantified "is recovery even realistic." Files to consume (mostly
read-only): `src/analysis/{isomorph,chaining_graph}.rs`, `src/data/corpus.rs`. Implement
as a **greenfield analysis module + test-only entry point** (the god-files are at their
file-size cap). Write-up → `research/findings/` or `research/gak-threads/`.

**G2 — forward isomorph-imperfection disproof** (Goal 2, still unstaffed). Push
`src/analysis/perfect_isomorphism.rs` (currently 0 robust violations) for ONE robust
non-word-boundary same-plaintext break: extend windows, null the loose bar, add a
word-boundary discount, chase the Stutter east4@65 / west4@67 candidate. Complement:
construct a concrete imperfectly-isomorphic cipher family and test whether the eyes'
borderline patterns (e.g. the `A.B..B.A` 7-instance pattern, ~13% coincidence) fit it
better than GAK. A clean negative is a legitimate, reportable GAK-strengthening result.
Write-up → `research/findings/` or `research/gak-threads/`.

PROCESS (binding):
- **Worktrees:** create them yourself off `exploration` HEAD, e.g.
  `git worktree add -b g3-isomorph-leak .claude/worktrees/g3 exploration` (and likewise
  `g2`). **Do NOT use the Agent tool's `isolation:'worktree'` default** — it branches from
  `origin/main` (baseRef `fresh`), which is missing the whole recent wave including T1. If
  you delegate to subagents, point each at its absolute worktree path and have it run
  `cd <worktree> && make verify` there.
- **Conflict hazard:** G2 and G3 both can touch `isomorph.rs`. Keep G3 additive (greenfield
  file, read-only on `isomorph.rs`) so it doesn't conflict with G2; serialize the merges
  and resolve any `isomorph.rs` overlap by hand.
- **File-size ratchet:** `scripts/check-file-size.sh` pins god-files at their current size
  (they may only shrink). Prefer greenfield files + `#[cfg(test)]` entry points. If you
  MUST grow a pinned file, bump its line in `scripts/file-size-allowlist.txt` with a
  `# bumped X->Y: <reason>` in the SAME commit (sanctioned pattern). Ratchet the pin DOWN
  when you remove lines.
- **Committing:** the pre-commit hook reruns the FULL test suite (~3–4 min). The default
  Bash timeout is 2 min and will KILL the commit mid-hook (it won't land). Commit with a
  long timeout (≥420000 ms). Confirm with `git log --oneline -1` afterward.
- **Delegation:** Claude does ALL implementation (subagents / Workflow). codex is a
  review-only SECOND opinion, never primary impl/review. (`/home/node/.claude` memory:
  `alternate-codex-and-claude-subagents`, `delegate-in-ultracode`.) Ultracode is ON:
  author workflows for substantive work; token cost is not a constraint.
- End git commit messages with the two trailers the harness requires (Co-Authored-By +
  Claude-Session). End PR bodies with the Claude Code generator line.

HONESTY (binding): every "recovered/ruled-out" claim needs a PASSING positive control and
an adequate model; null against the SEARCH's degrees of freedom, not random keys; label
model-conditional results; a clean negative is a valid result; any candidate cleartext →
`research/gak-threads/candidates/` as a HYPOTHESIS (claim ceiling holds). `make verify`
must stay green (unsafe forbidden; no unwrap/panic/indexing/unused_results in non-test
code; doc all public items; `--locked`; SplitMix64 for nulls).

Deliver: each thread's result (write-ups under `research/`), merged to `exploration`,
`make verify` green, worktrees removed. Don't push unless asked.

---

## Extra context the prompt compresses

- **Auto-memory** to trust-but-verify: `noita-eye-wiki-gak-convergence` (updated with the
  T1 entry), `noita-eye-puzzle-state`, `practice-puzzle-keystream-state`.
- **Why G3 before T6/T7:** G1b empirically pinned the "deltas-under-hidden-state" wall —
  recovery needs a dominant repeated phrase for coverage; the eyes don't have one. G3
  converts that into a stated feasibility/impossibility number; the eyes-scale attacks
  should be gated on it.
- **Task tracker:** tasks #2 (G3) and #3 (G2) are already created (pending). #1 (T1) is
  completed.
- **The T1 helper** (`src/nulls/heldout.rs`) is the canonical place for any held-out-fold
  gating either thread reuses — don't re-roll a fourth copy.
