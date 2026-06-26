# Report 01 — Publish blockers (do these first)

Legal, privacy, and staleness gates that must clear before the repo is shared
publicly. All citations verified first-hand on 2026-06-26. None of these touch
code behavior — they are deletions, edits, file additions, and doc moves.

The scientific rigor in the docs is a **strength** — this report removes
*AI-orchestration scaffolding, leaked local state, and stale "target-state"
framing*, not the research discipline. Keep `honest-negative`, claim-ceiling, and
HYPOTHESIS language verbatim everywhere.

---

## P0 — Blocking (must clear before any public push)

### P0.1 — Add the missing LICENSE files
`Cargo.toml:7` declares `license = "MIT OR Apache-2.0"` and `README.md:287`
repeats it, but **no `LICENSE`, `LICENSE-MIT`, or `LICENSE-APACHE` file is
tracked** (`git ls-files` confirms none). This is a blocking legal gap for a
public dual-licensed Rust crate.
- **Fix:** add `LICENSE-MIT` and `LICENSE-APACHE` at repo root (standard Rust
  convention) with the maintainer's name + year. Optionally add the conventional
  `## License` + contribution-licensing paragraph to the README footer.

### P0.2 — Remove the leaked Claude session URL
`research/gak-threads/OVERNIGHT-HANDOFF.md:129` contains a concrete personal
session link:
```
Claude-Session: https://claude.ai/code/session_01NPAWVsyBWgPQqqyEU5n4m7
```
- **Fix:** delete the line. (The whole file is recommended for removal in P0.5;
  this is called out separately because the URL is the sharpest single leak.)
  Also sanitize the generic mention at `research/HANDOFF-2026-06-26-post-T1.md:84`.

### P0.3 — Scrub maintainer local paths
Local absolute paths leak the maintainer's machine layout and private sibling
repos. **14 files** under `research/`+`docs/` contain `/home/node/persist/...`,
plus:
- `/home/node/persist/eye-messages.wiki` in ~11 research files
  (`research/frontier.md:4`, `research/NEXT-STEPS.md:4,130`,
  `research/gak-threads/thread-{3,4,5}-*.md`, `…/specs/thread-{2,3}-spec.md`).
- `/home/node/persist/Noita/data/data.wak` at
  `research/gak-threads/notes/thread-6-datawak-scan.md:15`.
- `/workspace` **private monorepo** references at `deny.toml:2`
  ("Right-sized from the /workspace monorepo's policy") and four times in
  `docs/refactor/09-file-size-ratchet.md` (`:23,108,382,389`).
- **Fix:** replace wiki paths with the public wiki URL; drop the `data.wak`
  local path or generalize it; remove every `/workspace` reference (they mean
  nothing to a public reader and name an internal repo). For `deny.toml:2`,
  reword to a neutral "tuned for a single crate."

### P0.4 — Fix the stale README "Layout" section (dead links for newcomers)
The role-directory refactor moved every source file, but the docs still cite the
old flat paths. A newcomer following the README lands nowhere.
- `README.md:37` cites `src/corpus.rs` → now `src/data/corpus.rs`.
- `README.md:59-81` ("Layout") lists `src/glyph.rs`, `src/corpus.rs`,
  `src/generator.rs`, `src/null.rs`, `src/ciphers.rs`, … — all moved under
  `core/ data/ nulls/ ciphers/` etc.
- `HANDOFF.md` has ~13 more stale `src/*.rs` references (`:56,63,74,89,302,310,
  458-464`) — mooted if `HANDOFF.md` is archived (P0.5).
- **Fix:** regenerate the README layout block from the actual `src/` tree; update
  the `src/corpus.rs` mention. Also `AGENTS.md:39` references `corpus.rs` (now
  `src/data/corpus.rs`) — trivial path drift, fix while here.

### P0.5 — Move the AI-orchestration docs out of the public tree
Three doc clusters read as an autonomous-AI-agent operating manual and, worse,
are **stale** in a way that makes shipped work look unstarted. Move them to a
private branch or an `archive/` tag (not the public default branch):

1. **`HANDOFF.md`** (root, 36 KB) — the single most over-exposing file. It opens
   "You will run for a long time with no human available … delegating the
   implementation heavily to codex" (`:1-11`), embeds `codex exec`/`review`
   recipes including `\codex -c sandbox_mode=danger-full-access` (`:197-223`), and
   is itself stale (old flat module list `:186-189`, `"on master"` at `:53`).
   `README.md:284` links to it — **update that link** when you move it.
2. **`docs/refactor/`** (13 files, ~350 KB) — completed planning briefs, but
   **every one is headed `Status: not started`** (verified on all of 00–10) with
   AI hand-off framing ("handing individual refactors to other agents", "the
   implementing agent", `00-OVERVIEW.md:4,5,11`) and stale `file:line` citations
   (`cipher_attack.rs:13`, `report.rs:5694`). A public reader would conclude the
   project is an *unstarted plan* — the opposite of the truth.
3. **`research/` handoff logs** — pure inter-agent ops, no research value:
   `research/gak-threads/OVERNIGHT-HANDOFF.md`,
   `research/gak-threads/MORNING-SUMMARY.md`,
   `research/gak-threads/notes/codex-second-opinion.md`,
   `research/HANDOFF-2026-06-26-post-T1.md`,
   `research/data/practice-puzzles/HANDOFF-keystream-letter-puzzles.md`.

- **Fix:** `git rm` them from the public branch (preserve in an `archive/` branch
  or tag). Then add the two replacements in P1.1/P1.2 so the *real* architecture
  and history survive in public form.

---

## P1 — Should clear before publishing (visible, not blocking)

### P1.1 — Add a hand-written `ARCHITECTURE.md`
Replace the archived `docs/refactor/` briefs with one present-tense doc
describing the **as-built** `src/{core,data,analysis,nulls,ciphers,attack,
experiments,report}` design, with correct paths. Preserve the claim-ceiling /
honest-negative discipline verbatim. This keeps the (genuinely good) architecture
knowledge without the "unstarted plan" framing.

### P1.2 — Distill a public `CHANGELOG.md` / README "History"
The experiment-by-experiment record buried in `HANDOFF.md` §9 is real provenance.
Distill it into a short public changelog so the rigor story survives the archive.

### P1.3 — Strip AI-attribution from shipping source comments
Two shipped doc-comments name the review tool (the statistics are good — delete
only the attribution):
- `src/attack/gak_attack/eyes.rs:654` — "the leak-proof, **codex-validated**
  embargoed-consensus statistic" → drop "codex-validated".
- `src/attack/gak_attack/eyes.rs:776` — "**codex's** 'effect size, not just
  p-value'" → reword to "effect size, not just p-value".
- (See report 03 for the broader `brief NN` chatter in source — same theme.)

### P1.4 — Fix "placeholder corpus" framing that is now false
`research/07-workbench-bridge.md:33,69,140-150` and `research/README.md:74-81`
describe `corpus.rs` as "placeholder data only" and Experiments 0/1/11 as future
first commits. The corpus is now the verified Experiment-0 corpus. Re-label as
"original plan, since implemented" or update to present tense.

### P1.5 — Neutralize reviewer/branch archaeology in surviving docs/config
- `scripts/file-size-allowlist.txt:28,41` narrate "(codex P2)", "codex review
  P1/P2" in a shipped config — reword to "(review finding)". (The long
  `bumped X->Y` histories are also archaeology; see report 04 P2.)
- `HANDOFF.md:53` "on master" — repo default is `main` (mooted if archived).
- `docs/refactor/02-cipher-trait.md:43` "since 71d25fe's E1 dedup",
  `04a-codec-transduction.md:10` "codex review point #1" — mooted if archived.

---

## P2 — Polish (nice-to-have for public)

- **P2.1 — README CLI list is incomplete** (`README.md:85-111`): omits shipping
  subcommands `solve`, `keystream`, `ragbaby`, `profile`, `gak-attack`,
  `gak-attack-eyes`, `agl-gak`, `perfectiso` (all in `src/main.rs:45-129`). Add
  them or note "see `--help` for the full set."
- **P2.2 — README newcomer intro** is solid but could add one plain sentence on
  *what Noita is / where the eye glyphs appear in-game* for a total stranger
  (`README.md:1-10`).
- **P2.3 — Generated candidate records** under
  `research/gak-threads/candidates/*.md` are committed machine-generated
  gibberish-as-HYPOTHESIS. They are *correctly* labelled (every one carries a "NO
  surviving candidate" verdict — keep the format spec and the labelling), but
  consider moving the run artifacts to a release asset or ignored output dir so
  mainline isn't carrying generated text. Trim two phrases in
  `research/gak-threads/candidates/README.md:64,79` that reference "the harness
  cannot call the clock" / "committed by the orchestrator".
- **P2.4 — `.claude/settings.json` is tracked** and will ship. It is a harmless
  git-safety deny-list (no secrets) and even demonstrates safety hygiene, but it
  advertises the repo as Claude-driven. Judgment call: keep, or `git rm --cached`
  + add to `.gitignore` if the owner wants to de-emphasize AI authorship. No
  security reason to remove.
- **P2.5 — Relocate dev-scaffolding notes** `research/gak-threads/notes/
  api-analysis.md` and `api-infra.md` ("Files to touch in order", stale `lib.rs`
  line numbers) to `docs/` or remove — they are not research-dossier material.
- **P2.6 — Sanitize residual `codex`/"second-opinion"/"session" mentions** in any
  research summary files kept rather than removed: `research/gak-threads/
  PROGRESS.md`, `notes/wave-2-summary.md`, `NEXT-STEPS.md:67`, `threads-eyes.md`,
  `threads-proving-ground.md`, `RAGBABY-RESULTS.md:53-55`.

---

## What to explicitly KEEP (do not "sanitize" these)

- The claim-ceiling section `README.md:21-33`, Experiment-0 provenance
  `README.md:35-51`, and the `[confirmed]/[likely]/[speculative]` scorecard in
  `research/README.md:13-56` and `research/03-confirmed-vs-speculation.md`.
- The candidate-cleartext kill-order discipline
  (`research/gak-threads/candidates/README.md:9-53`).
- `research/findings/agl-exclusion.md` and `base5-first-trigram.md` (clean,
  wiki-postable results).
- `CONTRIBUTING.md` (works from a clean clone, not AI-specific).
- The whole `Makefile` / `.github/workflows/ci.yml` / `scripts/check-file-size.sh`
  tooling — professional and reviewer-friendly.
