# Handoff — `two` after Avenue A, and the route decision

> **STATUS (2026-07-04): SEMI-ARCHIVAL — the open decision is closed and the
> coloring surface is superseded. Read this for the Avenue-A record and the
> `gak-swap-recovery` ruling, which remain accurate; do not act on "THE OPEN
> DECISION" below.**
>
> - **Avenue G was RUN — closed, not a live choice.** The "run Avenue G next"
>   option (option (a) below) is done: `pairclass --pattern-crib-scan` (Round 9,
>   commit `0b05f78`) planted-positive-fired and null-quiet on all three
>   committed corpora, then returned **0 surviving spans** on real `two` — a
>   scoped honest negative, not a decode. Record: `two-fresh-avenues.md`
>   §"Avenue G" and `research/data/practice-puzzles/CODEC-RESULTS.md` §Round 9.
> - **The 26→4 coloring surface here is SUPERSEDED.** On 2026-07-04 the `two`
>   campaign was route-reset (`research/handoff/two-cross-agent-recon.md`) to the
>   **full 12-symbol ciphertext stream**: raw-symbol isomorph column-maps close
>   to an order-48 observable shadow of a reported order-96 group. The
>   direct-product `C3 × S4` (order-72) reading that the deck-free eps-pair
>   4-class quotient — the surface Avenues A and G both attack — presumes is
>   *superseded*; that quotient is now understood as a **lossy** projection of
>   the stream that carried the crib-assisted solve. So the coloring/quotient
>   framing of Avenues A/G/F below no longer describes the live surface, even
>   though each avenue stands as an honest negative on the surface it ran on.

Written 2026-07-03 at the close of the Avenue-A campaign on practice puzzle
`two`. Self-contained: an incoming agent should be able to pick up from here
without replaying the session. Load-bearing detail lives in-repo (pointers
below), not in this note.

## TL;DR

Avenue A (structured-coloring enumeration on `two`) is **done — scoped honest
negative**. The next planned lever is **Avenue G** (repeated-span pattern-crib
scan). A `main` merge just landed the `gak-swap-recovery` community engine;
it does **not** supersede the `two` route (different threat model). There is
**one open decision the maintainer left for you** (below). Nothing is in
flight; branch tree is clean.

## Branch / tree state

- Branch `feat/lm-free-window-harvest`, clean, `main` already merged in
  (merge commit `8c8b460`). Do not re-merge blindly; `git log main..HEAD` to
  see what is branch-local.
- Round-8 record commits: `3cfbafd..53b1975` (two-tier decode, strict truth
  gate, relabel band, null-normalized controls redesign + fixes, recovery-gate
  relax, and the two result-record commits).
- Housekeeping: `.no-stop-uncommitted` (the stop-nudge marker) was added to the
  **shared** `.git/info/exclude` so it stays untracked. Harmless; just don't be
  surprised it isn't in `git status`.

## What just finished — Avenue A (full record: `CODEC-RESULTS.md` §Round 8)

Built as `pairclass --coloring-family {core,core-curated,toy}`: enumerate
deterministic 26→4 colorings, oracle-decode every candidate, controls-first.
Verdict on both tiers: **`LowPowerNoExclusion` — no candidate.** The real `two`
eps-pair stream is null-typical→null-inferior (curated p_emp 0.840 = 41/49
matched Markov nulls beat it; broad p_emp 1.000 = 20/20) while the same
instrument retains planted truths at top-3 rank on 6/6 plants and renders them
at 0.52–0.65 recovery. Honest ceiling: *these deterministic coloring families,
under this scoring surface, produced no candidate* — **not** "deterministic
coloring excluded" (anomaly-gate power measured only 2/6; the relabel filter
dropped a bounded set). Evidence leans against a simple deterministic coloring
for `two`, but does not close the family space.

Three instrument findings were forced out along the way and are recorded as
durable lessons (they will bite any future decode-scored family attack):
1. **Absolute LM scores never compare across streams** — each stream has its own
   junk-fit level; a cross-stream score floor is unsound by construction.
2. **Junk-max swamping** — at ~23k-candidate family breadth the max over junk
   colorings outscores planted truth within-stream ~50% of the time.
3. **Marginal-L1 relabel selection is noise-dominated at N=348** — needs a
   guaranteed near-best relabel band, not best-L1-per-base.

The controls were redesigned around **per-stream matched-null p-values** after a
two-model consult (codex `gpt-5.5` + Gemini-3.1-pro converged); that machinery
is reusable for any future decode-scored attack on `two`.

## The merge, and the ruling: does `gak-swap-recovery` supersede G/F? **No.**

The merge brought in a general GAK **known-plaintext** deck-cipher swap-recovery
engine (`src/attack/gak_attack/lymm_deck/`, CLI `gak-swap-recover`, dossier
`research/handoff/gak-swap-recovery/`, corpus `deck-swap/`). It answers Lymm's
community request ("a general GAK attack for larger groups") and is real and
working: **ns=1 and ns=2 solved** (exact re-encryption, controls pass, nulls
fail), ns=3 is its current frontier.

It does not apply to `two`:

| | swap-recovery engine | `two` / Avenue G/F |
|---|---|---|
| Input | **known plaintext** | ciphertext only (we do not hold `two`'s plaintext; do **not** ask) |
| Base perm | public/known | unknown |
| Deck | known n=83 top-swap corpus | genuine hidden-state wall (already an honest negative) |
| Target | recover per-letter top-swaps vs base | recover a 26→4 coloring of a deck-free channel |

Its SAT/propagation machinery is reusable only as engineering pattern; a SAT
reformulation of `two` is already demoted in `two-fresh-avenues.md` (pure SAT
feasibility yields junk). The "few-swaps-from-a-base" evidence is about the
**real eyes**, not `two`. What the merge *does* change is **priority**: it
advances exactly the eyes-relevant direction (small-support deck recovery), so
it raises the value of eyes-side work relative to grinding the `two` ladder.

## THE OPEN DECISION (maintainer left this for the next agent)

Pick one before doing work:

- **(a) Run Avenue G next** (recommended), then reassess. Cheap on **both** axes
  — a few hours of orchestrated build, and **minutes** of runtime (it is an
  isomorph crib scan, not a beam decode of thousands of colorings, so it does
  *not* repeat Avenue A's multi-hour grind). Independent of A's failure mode;
  pins ~40% of the classes on a hit → could crack `two` outright. If G misses,
  **do not** grind Avenue F next — pivot eyes-side.
- **(b) Skip G, pivot straight to eyes-side** small-support work leveraging the
  new engine. Higher ceiling (the eyes are the real target), larger effort.
- **(c) Stop `two`/eyes solve work here** and hand back to the publish ladder
  (`research/handoff/README.md` Tier 1).

**Defer Avenue F regardless.** It is the larger build (soft-EM/forward-backward
with its own controls) *and* has unmeasured runtime, spent on a surface where
the leading hypothesis was just excluded. Only worth it if G yields partial
pins to seed it, or if the goal is specifically to finish `two`.

Estimate note (so you don't misread the above): "hours/days" throughout refers
to **build effort**, and in this delegation model that compresses to hours of
Codex dispatch + review, not calendar days (Avenue A's whole instrument arc was
~7 commits in one session). **Runtime is the separate axis that made A long** —
and G is cheap on it, F is unmeasured.

## If you run Avenue G — where to start

Design + rationale: `research/handoff/two-fresh-avenues.md` §"Avenue G". The
idea: attack the doubly-occurring ~34-token repeated span directly with the
**isomorph constraint** (same plaintext letter ⇒ same observed 4-class token;
different classes ⇒ different letters), no dictionary DP (so it dodges the
occ1 explosion that closed Round 7). A surviving span induces a partial
coloring pinning ~40% of the text's classes.

- **Reuse**: `isoscan`'s translate-isomorph machinery over the 4-class token
  stream on the anchor span. Vehicle: a new `pairclass` mode or subcommand.
- **Data**: embedded `two` tokens via `embedded_two()` / `PairTokens::tokens`
  (`src/attack/pairclass/mod.rs`); the tie is the len-33 phase-0 repeat at token
  116 == 176. Corpus/phrase list from `research/data/lang/`.
- **Controls-first (binding)**: a structured planted positive must fire and a
  matched null / random negative must stay quiet before real `two` is scanned; a
  surviving span is a **candidate**, never a decode, until an exact re-encode
  round-trip (Avenue E verifier) or a withheld-truth check. Log any candidate
  cleartext to `research/gak-threads/candidates/` as a hypothesis.

## Working mechanics (so you match the established workflow)

- **Delegation**: implementation and diff-review go to Codex via the `codex-cli`
  skill (reread it each session — it is the source of truth); dispatch from this
  worktree, backgrounded, read the `-o` last-message file, inspect the real diff
  before trusting "done". Reserve inline edits for small correctness-sensitive
  changes. Cross-model second opinions via the `copilot-cli` skill
  (Gemini-3.1-pro for a heavyweight fresh angle). Pre-start sccache
  (`sccache --start-server`) to avoid a known lock-inheritance hang.
- **Binary name** is `noita-eye` (not `noita-eye-puzzle`); `/usr/bin/time` is
  absent in this container (use epoch markers for timing).
- **Wordlist** (if you reuse the decode path) is regenerated deterministically
  from the committed corpus — recipe is in `CODEC-RESULTS.md` §Round 8.
- **Gate**: the pre-commit hook runs `make verify`; a commit that lands is
  gate-green. Commit completed work without waiting to be asked (`AGENTS.md`).
- **Honesty ceiling**: candidate never decode; controls-first; Inconclusive when
  anything was dropped near threshold; a high score is not a recovery.

## Pointers

- `research/data/practice-puzzles/CODEC-RESULTS.md` §Round 8 — the Avenue-A
  record (instrument arc + both definitive runs + claim ceilings).
- `research/handoff/two-fresh-avenues.md` — the ranked avenue backlog (A done,
  G next, F deferred, E verifier); Avenue A status banner updated.
- `research/handoff/gak-swap-recovery/README.md` — the merged community engine.
- Memory: `practice-puzzles-one-two-analysis.md` (project state), and the
  working-style feedback memories (delegation, context-lean orchestration).
