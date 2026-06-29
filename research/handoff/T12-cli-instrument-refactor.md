# T12 — Turn the analysis/attack capability into runnable CLI instruments

**Priority:** High (maintainer-requested, 2026-06-29). **Effort:** L (one big
principle, several independently-committable pieces). **Status:** open / not
started. **Owner:** unassigned — written to be picked up cold by a fresh agent.

> **One-line:** Stop shipping cryptanalysis capability as `#[cfg(test)]`-only
> validations or as analyses hardwired to the eye corpus. Make every analysis and
> attack a **file-driven CLI instrument** — arbitrary ciphertext in, honest
> candidate out, self-validated by a positive control + matched null — so future
> agents can actually *run* the toolbox on new inputs.

---

## 1. The problem (why this task exists)

The repo has two CLI "shapes":

- **Runnable instruments** — `stats`, `solve`, `keystream`, `ragbaby`, `profile`
  take `--input-file` / `--stdin` / a positional sequence + `--alphabet`, and
  self-validate with a planted positive control + matched null. These are useful:
  a future agent can point them at anything.
- **Frozen / hardwired** — (a) the structural battery (`chaining`,
  `chaining-graph`, `isomorphnull`, `perfectiso`, plus the un-exposed
  `isomorph_imperfection` and `leak_ceiling`) **ignores its input and loads the
  eye corpus** via `orders::corpus_grids()` / `CorpusContext::load()`; (b) recent
  capability (e.g. the GAK hidden-state solver, commit `ca64f13`, and the G1
  `known_answer.rs`) lives in `#[cfg(test)]` modules validated only against a
  hardcoded synthetic fixture.

The maintainer's verdict (2026-06-29): the frozen/hardwired shape is **not a
tool**. A `#[cfg(test)]` module is a regression test; an eye-corpus-hardwired
analysis can't be run on a new puzzle, a synthetic stress case, or the eyes'
own reading-layer streams under a different reading order. **Everything we build
should be runnable on arbitrary input from the CLI, self-validated by controls —
not frozen to a fixture.**

This task makes that real.

---

## 2. Desired end state

1. **The GAK hidden-state tools become a file-driven CLI subcommand + library.**
   The discriminator and solver currently in `#[cfg(test)] mod hidden_state_solver`
   (commit `ca64f13`) become documented library functions plus a `gak`
   subcommand with `discriminate`, `solve`, and `self-test` modes.
2. **The structural battery accepts file input.** Each analysis runs on an
   arbitrary `--input-file --alphabet …` stream *in addition to* its current
   eye-corpus default (don't break the eye path; add a file path).
3. **Tests call the same library functions the CLI uses.** Keep the synthetic
   positive-control + matched-null as tests, but have them exercise the *library*
   API the CLI calls — so the instrument and its regression can't drift. Promote
   the needed functions out of `#[cfg(test)]`.

Non-goal: solving puzzle `two` or the eyes. The solver remains an honest
**candidate generator** on real data (see §6).

---

## 3. Background a fresh agent needs

- **What the GAK tools do (commit `ca64f13`,
  `src/attack/gak_attack/hidden_state_solver/`).** Practice puzzle
  `research/data/practice-puzzles/two` (698 symbols `A..L`) was re-diagnosed as a
  **C3 × S4 hidden-state GAK** (group order 72, hidden subgroup S3; visible
  symbol `s = 3·top + r`, where `r` is a ±1 walk on C3 and `top` is the visible
  top card of a hidden 4-card deck). Two instruments came out of that:
  - `markov_excess(symbols, alphabet)` = `H(s_t|s_{t-1}) − H(s_t|s_{t-2},s_{t-1})`.
    Large drop ⇒ hidden-state GAK; small ⇒ visible-state GCTAK. Pure structural,
    **no language model** — runs on any symbol stream. (`two` ≈ 0.80 vs a
    visible-state synthetic ≈ 0.27.)
  - `solve_hidden_state_gak(ciphertext, lm, population, generations, seed)` — a
    Viterbi-over-24-deck-states (collapses to a deterministic forward walk because
    the next top card is forced by the observed top) + a held-out-LM-scored
    genetic search over the hidden per-coset permutations. Recovers a synthetic
    known-answer plaintext at ~100%. **On real `two` it is an honest negative**
    (the codec/exact-convention is unknown) — see the module's `two` test.
  - Module doc is the current truth on `two`'s structure. NOTE: older in-repo docs
    (`research/data/practice-puzzles/CODEC-RESULTS.md`, the README, and a memory)
    predate this and still describe `two` as a "transition-law artifact"; they are
    stale on the C3×S4 diagnosis. Not your job to fix here, but don't trust them
    over the module.

- **The file-driven plumbing already exists.** `src/cli/shared.rs`
  `resolve_input_text(sequence, input_file, stdin)` and the `--alphabet` →
  `parse_cli_sequence` path are reused by `solve`/`keystream`/`ragbaby`/`profile`.
  Copy that pattern; don't reinvent it. `--alphabet ABCDEFGHIJKL` declares a
  12-symbol alphabet, `--alphabet 01234` a 5-symbol one, etc.

- **Where the hardwiring lives.** The analysis `run_*` functions are under
  `src/cli/commands/` (e.g. `src/cli/commands/misc.rs:108` calls
  `orders::corpus_grids()`); the command/arg wiring is in `src/cli/args.rs`
  (the `Command` enum), `src/cli/args_attack.rs` (the file-driven arg structs),
  and `src/cli/dispatch.rs`.

- **Two primitives are already generic over an arbitrary stream** (the easy wins):
  - `src/analysis/isomorph.rs:212` `pub fn detect_isomorphs<T: Eq + Copy>(seq, window, min_period, max_period)`.
  - `src/analysis/chaining/engine.rs:37` `pub fn chaining_signature(message_values, period, alphabet_size)`.
  The report layers (`chaining_graph::compute_graph` is `pub(crate)`;
  `perfect_isomorphism`'s per-stream entry is private; `leak_ceiling` /
  `isomorph_imperfection` have no `Command` at all) need a small public per-stream
  entry point added.

---

## 4. Workstream A — GAK discriminator + solver as a CLI instrument

This is the cohesive first piece; it also *demonstrates* the pattern for B.

1. **Fold in the codex P2 fix first** (it's a precondition for honest CLI use). In
   `src/attack/gak_attack/hidden_state_solver/solver.rs` around the `eps`
   computation (`eps = (b + CLASS_MOD − a) % CLASS_MOD`, ~line 115): a same-class
   adjacency yields `eps == 0`, which the cipher model forbids (shifts are only
   1 or 2), and the later `saturating_sub(1)` aliases it into the eps=1 cosets —
   so a malformed/shuffled stream is silently decoded instead of rejected. **Fix:**
   validate the no-same-class precondition up front and return a `GakAttackError`
   when violated. `two` satisfies the law (passes); a Fisher-Yates shuffle does
   not (now correctly *rejected*). Update the matched-null test to expect the
   shuffled null to be rejected (Err) or, if a rare valid shuffle slips through,
   to not recover.
2. **Promote out of `#[cfg(test)]`.** Move `markov_excess`,
   `solve_hidden_state_gak`, `decode_with_key`, `draw_key`, `encrypt`,
   `BigramLm`, `DeckTables`, `DeckConvention` (and the result types) into
   non-test library code. They now compile in release ⇒ **every public item needs
   rustdoc** (gate is `rustdoc -D`), clippy `-D`, and the file-size ratchet
   (`scripts/file-size-allowlist.txt`, 600-line cap) applies.
3. **Add a `gak` subcommand** (mirror `KeystreamArgs`/`SolveArgs` in
   `src/cli/args_attack.rs`, wire in `src/cli/args.rs` + dispatch + a
   `src/cli/commands/` handler) with modes:
   - `gak discriminate --input-file <ct> --alphabet <chars>` → print the
     `markov_excess` drop and a hidden/visible verdict, with matched
     same-length synthetic references for calibration.
   - `gak solve --input-file <ct> --alphabet <chars> --lm-corpus <file>
     [--population N --generations N --seed N]` → run the solver, print the best
     **candidate** with its held-out score and a matched-null comparison.
     **Label it a candidate, not a decode** (honesty discipline, §6).
   - `gak self-test` → run the synthetic positive control + matched null in-process
     and print PASS/FAIL (so a user can trust the instrument fires on a known
     answer before believing it on real data).
4. **Keep the four tests**, but have them call the now-public library functions
   (the same ones the CLI handler calls).

**Acceptance (A):** `make run ARGS='gak discriminate --input-file
research/data/practice-puzzles/two --alphabet ABCDEFGHIJKL'` prints a hidden-state
verdict for `two`; `gak self-test` prints PASS; `gak solve …` on `two` prints an
honest non-English candidate (not a decode); `make check` green.

---

## 5. Workstream B — un-hardwire the structural battery

For each analysis below, add a file-driven path (`--input-file`/`--stdin` +
`--alphabet`, reusing `cli::shared`), keep the eye-corpus default, and add a
positive control / self-test where one doesn't already exist. Do **one analysis
per commit** (they're independent; small, reviewable diffs).

Order by ease (reuse-first):

1. **`chaining`** — `chaining_signature(message_values, period, alphabet_size)` is
   already public + generic. Mostly arg plumbing + alphabet-size from `--alphabet`.
2. **`isomorph` / `isomorphnull`** — `detect_isomorphs<T>` is already public +
   generic. Add a file-driven entry; the within-message-shuffle matched null
   already exists in `src/nulls/`.
3. **`chaining-graph`** — `chaining_graph::compute_graph` is `pub(crate)`; add a
   public per-stream entry that takes `&[Vec<SymbolValue>]` + alphabet size.
4. **`perfectiso`** — expose `perfect_isomorphism`'s per-stream
   `report_from_message_values` (currently private) as a public, alphabet-size-
   parameterized entry.
5. **`leak_ceiling`** and **`isomorph_imperfection`** — currently have *no*
   `Command` at all (test-only). Add a `Command` variant + file-driven entry for
   each. `leak_ceiling` already hardcodes `two`'s measured constants
   (`TWO_COSETS` etc.) — generalize it to compute those from the input stream.

**Exclude** `honeycomb` and `grouping`: they are specific to the 2-D 83-symbol
eye trigram lattice and are not meaningful on a linear ciphertext. If you touch
them at all, only to document why they stay eye-specific.

**Watch:** these analyses currently assume the eye alphabet size (83). Thread the
alphabet size from `--alphabet` everywhere; don't leave an 83 hardcoded.

**Acceptance (B):** each migrated analysis runs on
`research/data/practice-puzzles/{one,two}` and on a synthetic, with its positive
control firing; the eye-corpus default still works unchanged; `make check` green.

---

## 6. Honesty discipline (binding — see `AGENTS.md`)

- Every file-driven *attack* emits a **candidate**, never a "decode," and is gated
  by a **matched null** + a **self-test positive control**. A high n-gram score
  or "survives the gate" is not a recovery. Label model-conditional results
  (e.g. the solver depends on an assumed codec/convention) as such.
- The solver on real `two`/eyes is an **honest negative / candidate generator**.
  The 6-fold deck slack lets a Viterbi decode manufacture English-looking text for
  a wrong key — so held-out scoring + the matched no-English control are
  load-bearing, not decoration. Don't let the CLI imply a decode.
- Don't silently truncate: if a search is bounded (top-N, seed budget), print what
  was dropped.

---

## 7. Gates & process

- `make verify` (fmt-check + clippy `-D` + filesize + tests + rustdoc `-D` +
  cargo-deny) must stay green; `make check` adds machete + codespell + shellcheck
  + release build. The pre-commit hook runs the gate — note the full test suite
  can exceed a 2-minute shell timeout; budget a longer timeout when committing.
- Promoting code out of `#[cfg(test)]` newly subjects it to rustdoc `-D` and the
  file-size ratchet — keep new/moved files under 600 lines (split modules as the
  existing `hidden_state_solver/` already does).
- Commit each piece on a branch off `main` (or the current working branch);
  conventional-commit messages; the two trailers required by this repo's tooling.

---

## 8. Suggested sequencing

A (GAK tool, with the P2 fix) first — it's self-contained and establishes the
file-driven-instrument + self-test pattern the rest of B copies. Then B in the
ease order above, one analysis per commit. Each step is independently valuable;
none blocks the others except that A's `cli::shared` usage is the reference.

---

## 9. Pointers

- Capability to promote: `src/attack/gak_attack/hidden_state_solver/` (commit
  `ca64f13`); wired at `src/attack/gak_attack/mod.rs` (`#[cfg(test)] mod …`).
- CLI precedent: `src/cli/{args.rs,args_attack.rs,shared.rs,dispatch.rs,commands/}`;
  copy `keystream`/`solve`/`profile`.
- Generic primitives to reuse: `src/analysis/isomorph.rs:212`,
  `src/analysis/chaining/engine.rs:37`.
- Discipline: `AGENTS.md`, `research/attack-methodology.md`.
- Test fixtures: `research/data/practice-puzzles/`.
