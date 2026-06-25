# Overnight handoff — GAK-threads wave-2 continuation

**Written:** 2026-06-24, end of a long orchestration session. **For:** the next agent
(fresh context). **Branch:** `gak-threads-wave-1` (HEAD `a31bc3a`). **Mode:** ultracode,
delegation-heavy, autonomous overnight.

You are continuing a multi-thread cryptanalysis build on the Noita eye-glyph puzzle. Read
`AGENTS.md` (house rules) and the memory index first, then this doc, then
`research/gak-threads/specs/thread-4-spec.md`. Everything below is current as of `a31bc3a`.

---

## 0. Your mandate (the user set these explicitly, then cleared context)

1. **Finish Thread 4** (`gak_attack` spike) — the last planned module. Then keep going.
2. **Go big — loop till morning.** Run a self-sustaining autonomous loop. Spend generously
   (codex runs + Workflows are fine). Checkpoint-commit gate-green on this branch as you go.
3. **You may invent NEW exploration directions** beyond the 6 planned threads — novel
   mapping-independent analyses/attacks you devise — as long as you hold the claim ceiling and
   label every assumption/hypothesis.
4. **Be delegation-heavy.** Use BOTH dynamic **Workflows** (the `Workflow` tool) and the
   **codex-cli** skill. ALTERNATE between them across tasks; pair an implementer of one model
   with a reviewer of the other. You orchestrate, verify, and commit — you do NOT hand-implement
   modules yourself (reserve inline edits for tiny correctness-sensitive fixes).

### The claim ceiling (NON-NEGOTIABLE, holds for every output, especially unattended)

> The strongest defensible statement about the eyes: **"deterministic, engine-generated,
> strikingly structured data of unknown meaning; unsolved; no primary developer source confirms
> recoverable plaintext."** Nothing you print/commit may be stronger.

- Every candidate plaintext is a **hypothesis**, never a decode, until it survives **held-out**
  isomorph checks. An unconstrained fit with no held-out data is almost certainly coincidence.
- Mapping-independent only: ciphertext symbol **equality** + group structure. Never invent a
  symbol→meaning map. (You MAY *recover* a map on **synthetic** ciphers where you hold ground
  truth — that's a recovered key, not an assumed mapping.)
- Every structural **negative** carries a **matched null**; every **positive control** must
  **fire on known signal**. No "result" is recorded without a **cross-model adversarial verify**.

---

## 1. Where things stand (all committed, all gate-green)

Branch `gak-threads-wave-1`, in order:
- `4594cfd` wave-1 (notes + Python prototypes + frozen specs) — pre-existing.
- `248fb32` **Thread 5 + 1B foundational pair**: `chaining_graph.rs` (shared chain-link
  primitive, ConflictCatalogue, CoverageReport broad+core tiers, matched shuffle null, stream
  positive control) + `transitivity.rs` (conditional D166 exclusion, MEDIUM, HOLE 1/2).
- `672d4f0` PROGRESS: marked 1B/5 landed.
- `2abee08` **Spec hardening** (thread-2/3/4 specs vs empirical — fixed drift before impl).
- `ca8b2e5` **F5**: centralized `add_one_p_value` + `mix_seed` into `null.rs`.
- `47f0c51` **Thread 3** `perfect_isomorphism.rs` (allomorph scan; 0 robust internal violations
  over the full strong tier → SUPPORTS perfect isomorphism; 16 safe-isomorph extents).
- `a3413e7` **Thread 2** `agl_gak.rs` + `AglGakKey` (AGL(1,83)-GAK **exhaustively excluded**,
  both C83:C82 and C83:C41).
- `a31bc3a` **Merge** of `chore/review-fixups` (more null.rs helper centralization:
  `median_*`/`scaled_quantile_index`; zero-trial guards; doc-drift fixes).

**Scientific state (the candidate transitive group set for the 83-symbol GAK):** the 6 transitive
groups on 83 points are `{C83, D166, C83:C41, AGL(1,83)=C83:C82, A83, S83}`. So far: C83 is
commutative (out for non-commuting chaining); **both AGL variants exhaustively excluded** (Thread
2); **D166 conditionally excluded** at MEDIUM (Thread 1B, single-witness-fragile). Perfect
isomorphism is **SUPPORTED** (Thread 3). ⇒ the live candidates are **{A83, S83}** (with D166
conditional). Thread 4's GAK attack builds on this.

### Threads status
| Thread | Module | Status |
|---|---|---|
| 1A transitivity restriction | (test constant in `transitivity.rs`) | done |
| 1B dihedral exclusion | `transitivity.rs` | landed `248fb32` |
| 5 chaining graph | `chaining_graph.rs` | landed `248fb32` |
| 3 perfect isomorphism | `perfect_isomorphism.rs` | landed `47f0c51` |
| 2 AGL exclusion | `agl_gak.rs` + `AglGakKey` | landed `a3413e7` |
| **4 GAK attack spike** | `gak_attack.rs` + `GakKey` | **NOT STARTED — your first task** |
| 6 binary re-exam | (closed dead-end) | n/a |

---

## 2. Immediate task: Thread 4 — `gak_attack` spike (the "prize")

**Spec:** `research/gak-threads/specs/thread-4-spec.md` (already hardened — F6 made it
hard-depend on the landed `chaining_graph`, no synthetic-stub hatch). Read it in full.

**Shape (from the spec):**
- **Step 0 — `GakKey` in `ciphers.rs`** (beside `DeckCipherKey`): a general GAK encipher/decipher,
  each PT letter → a permutation in `S_n`/`A_n`, cumulative left-mult state update, output = the
  hidden-subgroup coset. Parametric `n` (work at n=5,8,12 long before 83). Exact round-trip test.
- **Step 1 — GCTAK solver in `gak_attack.rs`** = the **decisive go/no-go gate** + positive
  control. GCTAK = GAK with trivial hidden subgroup (bijective `c`). It is **fully solvable**;
  if your solver can't recover a synthetic GCTAK key, stop and report.
- **Steps 2–3** — the generalized graph-chaining + constraint-propagation + hidden-state-
  marginalization attack on synthetic GAK with ground truth; nulls; then **eyes only at Step 3**,
  behind **held-out isomorph checks**. The ≤4-swaps-per-letter small-support prior is **TENTATIVE**
  — a search heuristic to validate, label it as such.
- **HARD dependency:** import and reuse `chaining_graph::{ChainLink, AlignedOccurrence,
  chain_links_for_pair, ConflictCatalogue, CoverageReport}`. Never reimplement a second graph.
- The whole spike runs on **synthetic GAK you generate** (known PT/perms/state). The eyes are
  touched only at Step 3, only after Step 1's gate passes.

**Honesty risk is highest here** — this is the thread that could "break" the decode-blocked
conclusion. A Step-3 eyes candidate is a hypothesis until held-out checks pass. Do not let any
delegate (or yourself) print a decode claim.

**Wiring (four-file pattern, see `research/gak-threads/notes/api-infra.md`):** `src/gak_attack.rs`
+ `pub mod` in `src/lib.rs` (alphabetical) + `format_*_error`/`print_*_report` in `src/report.rs`
+ Command/Args/From/run_*/match-arm in `src/main.rs` + a `tests/gak_attack_cli.rs` integration
test asserting the report's honesty strings (every other thread has one — keep parity).

---

## 3. The working loop (proven this session — follow it)

For each module/task:
1. **Delegate the implementation** to codex OR a Claude subagent/Workflow (ALTERNATE; see §4).
   Point it at the hardened spec + `notes/api-infra.md` + the honesty constraints + "make verify
   green, do NOT commit."
2. **Verify yourself:** read the delegate's summary tail; run `make verify` (the gate); spot-check
   the highest-risk code (don't re-read everything — that pollutes context).
3. **Cross-model review BEFORE commit** (the opposite model from the implementer): a `Workflow`
   with one agent per dimension → **adversarial verify** each P0/P1 finding (refute-or-confirm)
   before acting. OR a codex `exec` review told to use subagents per dimension. This caught real
   bugs this session (a matched-null P0 in Thread 3; the Thread 2 verify dropped a false-positive).
4. **Apply confirmed P0/P1** (delegate the fix, alternating model) + worthwhile P2s.
5. **`make verify` green → commit** on `gak-threads-wave-1` (the pre-commit hook re-runs the gate).

**Commit trailers** (every commit):
```
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01NPAWVsyBWgPQqqyEU5n4m7
```
(Use your own session URL.)

---

## 4. Delegation cheat-sheet

### codex-cli (skill: `codex-cli`)
- Holds the **workspace write-lock** for its whole run. NEVER run 2 codex on this workspace at
  once; do not edit files / run formatters while codex runs (read-only inspection is fine).
- Invocation (bypass the broken sandbox; close stdin; redirect to a log):
  ```bash
  \codex -c sandbox_mode=danger-full-access -a never exec \
    < /path/to/prompt.txt > /path/to/codex-<task>.log 2>&1
  ```
  Run it backgrounded (Claude Bash `run_in_background=true`); you get a completion notification.
- Codex reads `AGENTS.md`/`CLAUDE.md` itself — don't restate house rules. To make codex use
  subagents, **say so in the prompt** ("USE SUBAGENTS — one per dimension"). It's prompt-driven,
  not a flag.
- After it returns: read the **log tail** for its summary; don't re-read full diffs.

### Dynamic Workflows (the `Workflow` tool)
- Best for fan-out: dimension-review → adversarial-verify pipelines, parallel analyses. Returns a
  structured result; read it from the task `.output` file (the return value is under the
  `result` key — `python3 -c "import json; json.load(open(path))['result']"`).
- Use `schema:` for structured agent output. Use `pipeline()` by default (no barrier);
  `parallel()` only when you need all results together. Use `isolation:'worktree'` only when
  agents mutate files concurrently.
- A working review-Workflow script from this session lives at
  `~/.claude/projects/<proj>/<session>/workflows/scripts/review-thread2-agl-gak-*.js` — but
  that path is session-scoped; just re-author from the pattern (review dimensions → per-finding
  verify → return confirmed/refuted). The canonical pattern is in the `Workflow` tool docs.

### Claude subagents (the `Agent` tool)
- For a single coherent implementation (alternating off codex) or a focused fix. They edit the
  main worktree + run `make verify`. Use `model:'opus'` for correctness-critical work.

### Alternation log so far (so you can keep rotating)
- Thread 5/1B impl+review+fix: **codex**. F5: **codex**. Spec hardening: **3 Claude subagents**.
- Thread 3 impl+review+fix: **codex**. Thread 2 impl: **codex**; review: **Claude Workflow**;
  P2 fixes: **Claude subagent**.
- ⇒ **Thread 4 implementation should be Claude** (subagent or Workflow); **review it with codex**.

---

## 5. Autonomy — how to NOT idle overnight

The harness re-invokes you when a background task (codex/subagent/Workflow) completes. So the loop
self-sustains **as long as you always have either a background task running or a scheduled
wake-up** before you yield. Discipline:
- After launching a delegate, end your turn — you'll be re-invoked on completion.
- If you ever finish a step with nothing queued (e.g., between phases), either immediately launch
  the next delegate, or `ScheduleWakeup` (long fallback, 1200s+) so you're not stuck.
- Keep a running **task list** (`TaskCreate`/`TaskUpdate`) as the backlog; always pull the next
  item. When the planned backlog empties, generate the next exploration item (you're authorized).
- **Checkpoint-commit** gate-green after each landed unit so progress survives.

### Suggested backlog after Thread 4 (you may reorder / extend)
1. **Synthesis + PROGRESS update.** Update `research/gak-threads/PROGRESS.md` to mark Threads
   2/3/4 landed (only 1B/5 are marked). Write a wave-2 summary note: candidate set now `{A83,S83}`
   + D166 conditional; perfect-iso supported; AGL excluded; what the GAK attack established.
2. **Drive the GAK attack** to its limits on synthetic (vary group/hidden-subgroup/`n`), then the
   eyes Step-3 held-out checks — report honestly whether anything survives (almost certainly not;
   that's a fine result).
3. **Run the landed modules on the real corpus** and cross-check for any cross-thread signal;
   matched nulls + adversarial verify on anything interesting.
4. **Novel analyses** you devise (authorized) — e.g. deeper Schreier-coset graph chaining,
   GCTAK-style recovery attempts conditioned on `{A83,S83}`, alternative isomorph families. Hold
   the ceiling; label everything; null-calibrate; cross-model verify.
5. **Final hardening:** `make check` (full local CI: verify + machete + codespell + shellcheck +
   release build), update memory, write a morning summary note for the user.

---

## 6. House rules / gates (from `AGENTS.md` — enforce on every delegate)

- **`make verify` must be green before every commit** (fmt-check + clippy `-D` + tests + rustdoc
  `-D` + cargo-deny). The pre-commit hook runs it. `make check` = verify + machete + codespell +
  shellcheck + release build (the full CI gate).
- `unsafe` is **forbidden** crate-wide. No `unwrap`/`panic`/`indexing_slicing`/`string_slice` in
  lib/CLI (relaxed in `#[cfg(test)]`). `missing_docs` on — doc every `pub` item incl. fields/
  variants. `#[allow(..., reason="...")]` not bare. `--locked` everywhere. Bind dropped
  `#[must_use]`.
- **Do NOT modify** `src/chaining.rs` (Experiment-7B, cyclic additive), `Cargo.toml`, `Makefile`,
  CI — unless a task explicitly requires it.
- Reuse `null.rs` helpers (PRNG `SplitMix64`/`stateless_splitmix`/`mix_seed`, `random_index_below`,
  `add_one_p_value`, `median_f64`/`median_usize`/`scaled_quantile_index`) — do NOT add private
  copies. Reuse `isomorph::PatternSignature`, `orders`/`corpus` loaders, perseus shared-run prims.

---

## 7. Gotchas / lessons from this session (save yourself the pain)

- **Stale `dead_code` diagnostics.** The harness sometimes reports `dead_code` for items that ARE
  used (mid-edit LSP snapshot). Don't trust it — confirm with `make verify`. Seen twice
  (`MAIN_ISOMORPH_W11`, the AGL helpers) — both were false alarms.
- **Matched-null discipline is the #1 bug source.** Thread 3's first cut computed the real
  violation count over a *different* population than the null scanned ("0 violations" was an
  artifact). Real and null MUST run the same pipeline over the same population. Reviewers should
  hammer this.
- **`in_repeated_core` ≠ same-plaintext genuine tier.** In `chaining_graph`, the core-supported
  coverage figure is a provenance filter, NOT wave-1's literal same-plaintext tier (28/83). The
  report says so; keep that distinction in any new coverage reporting.
- **Adversarial verify earns its keep.** The Thread 2 review's one P1 ("verdict rests on the
  sampled Monte Carlo") was REFUTED on verify — the verdict actually gates on the *exhaustive*
  fixed-point enumeration. Always refute P0/P1 before acting.
- **Verify exhaustive/algebraic claims independently.** For AGL, a subagent brute-forced the
  fixed-point counts (0/6724, 0/3362) and re-derived the n=5 example ([2,0]→[0,2]) rather than
  trusting the impl. Do this for any "exhaustive" or "0/N" headline.
- **CLI tests lock the honesty surface.** Every module has a `tests/<mod>_cli.rs` asserting the
  report prints its claim-ceiling/caveat strings. Keep parity — it catches honesty regressions.
- A worktree review of `4594c` (the wave-1 commit) found spec/empirical drift (F1–F7), all
  addressed in `2abee08` + `ca8b2e5`. The thread-3 fix also caught a wrong regression string the
  review missed (re-derive from the empirical, don't trust review numbers blindly).

---

## 8. Pointers

- **Specs:** `research/gak-threads/specs/thread-{1b-5,2,3,4}-spec.md` (all hardened).
- **Notes:** `research/gak-threads/notes/` — `api-infra.md` (wiring), `api-analysis.md` (analysis
  API map), `reading-streams.md` (the 0..82 stream + the isomorph oracle), `thread-*-empirical.md`
  (the numbers to reproduce), `thread-*-verification.md` (the logic), `codex-second-opinion.md`.
- **PROGRESS:** `research/gak-threads/PROGRESS.md` (the canonical per-thread ledger — UPDATE for
  Threads 2/3/4 + the merge; currently only 1B/5 are marked landed).
- **Memory** (`~/.claude/projects/.../memory/MEMORY.md` index): `noita-eye-puzzle-state`,
  `noita-eye-binary-confirmation`, `noita-eye-wiki-gak-convergence`, `codex-delegation-via-forks`,
  `codex-multi-angle-reviews`, `delegate-in-ultracode`, `alternate-codex-and-claude-subagents`.
- **Corpus entry:** `orders::corpus_grids()` → `orders::accepted_honeycomb_order()` →
  `orders::read_corpus_message_values(&grids, order)`. 9 messages, 1036 trigrams, 83 symbols,
  order `standard36-u012-d012`. Never concatenate across messages; never re-select reading order.
- **Run the CLI:** `make run ARGS="<subcommand> --seed 123 ..."` or `cargo run --locked -- <sub>`.
  Existing subcommands incl. `chaining-graph`, `transitivity`/`dihedral`, `perfectiso`, `agl-gak`.

---

## 9. First actions for you (the next agent)

1. `git status` (expect clean), `git log --oneline -8`, confirm branch `gak-threads-wave-1`.
2. Read `AGENTS.md`, the memory index, and `research/gak-threads/specs/thread-4-spec.md`.
3. Seed your task list from §5 (Thread 4 first).
4. **Delegate Thread 4 implementation to a Claude subagent/Workflow** (alternating off codex),
   against the hardened spec, with the claim ceiling + reuse-`chaining_graph` constraints. While
   it runs, prep the codex review prompt. Then verify → codex review (adversarial) → fix → commit.
5. Keep the loop alive per §5. Hold the claim ceiling. Checkpoint-commit. Go till morning.
