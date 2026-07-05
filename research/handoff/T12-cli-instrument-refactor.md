# T12 — Turn the analysis/attack capability into runnable CLI instruments

**Priority:** High (maintainer-requested, 2026-06-29). **Effort:** L (one big
principle, several independently-committable pieces). **Status:** Workstream A
**DONE** (2026-06-29); Workstream B **DONE** (2026-06-29) — see the completion
record below. **Owner:** complete.

> **One-line:** Stop shipping cryptanalysis capability as `#[cfg(test)]`-only
> validations or as analyses hardwired to the eye corpus. Make every analysis and
> attack a **file-driven CLI instrument** — arbitrary ciphertext in, honest
> candidate out, self-validated by a positive control + matched null — so future
> agents can actually *run* the toolbox on new inputs.

---

## Status & what to do next (updated 2026-06-29)

**Workstream A — the GAK discriminator + solver instrument — is COMPLETE.** Three
commits on `exploration`, full `make verify` green each time, codex-reviewed clean:

- `61db12e` — **P2 fix:** the convention-B decode now rejects a same-class
  adjacency (`eps == 0`) up front in `DeckProblem::from_ciphertext` via the new
  `GakAttackError::SameClassAdjacency`, instead of silently aliasing it into the
  `eps == 1` cosets (the old `saturating_sub(1)` bug).
- `e1dd966` — **instrument + promotion:** promoted `hidden_state_solver` out of
  `#[cfg(test)]` to `pub mod` (namespaced so its consts don't collide with the
  gate's `DEFAULT_SEED`), added `hidden_state_solver/instrument.rs` (the library
  layer: `discriminate`, `solve_candidate`, `run_self_test`), added the `gak`
  subcommand (`discriminate`/`solve`/`self-test`), and rewired the four tests to
  call the instrument functions.
- `80d0cfe` — codex nits (1-based `position`; `Ambiguous` wording).

  Verified live: `gak discriminate --input-file research/data/practice-puzzles/two
  --alphabet ABCDEFGHIJKL` → HIDDEN-STATE; `gak self-test` → PASS; `gak solve` on
  `two` → honest "NO ENGLISH RECOVERED" candidate.

## Workstream B — COMPLETE (2026-06-29)

Seven commits on `exploration`, full `make verify` green each, each primary-reviewed;
the entangled-three + multi-message work also got a codex second-opinion sweep (one
P1 + three P2 found and fixed in `bd8eeab`, re-reviewed). Every analysis keeps its
verified eye-corpus default **byte-for-byte unchanged** and gains a file-driven path.

**Clean three (§5.2), one commit each:**

- `395e870` **chaining** — file-driven; calibration null matched to input
  lengths/alphabet; `ChainingConfig.alphabet_size` now CLI-reachable.
- `edab982` **isomorphnull** — file-driven; within-message multiset-shuffle null;
  equality-based, alphabet-agnostic.
- `abdc7f9` **chaining-graph** — file-driven; `compute_graph` threaded with
  `alphabet_size` (the 83 hardcode removed); synthetic stream-independent positive
  control.
- `cd7a881` — dropped false eye-corpus/wiki/wave-1 provenance from the three stream
  reports (codex P2).

**Entangled three (§5.3) — maintainer decision (2026-06-29): rebuild all three with
synthetic per-input controls, gating the eye-calibrated controls off the stream
path.**

- `b97b1c9` **perfectiso** — cross-message: a single stream → empty cross-message
  catalog *by construction* (`STRONG_MIN_OCCURRENCES = 2`), so the stream report
  honestly states "the cross-message test does not apply" and self-validates only the
  synthetic internal-violation control. Eye path untouched.
- `55bcbfa` **isomorphimperf** — same cross-message degeneracy pattern; **new
  `isomorphimperf` Command** (it had none); family generator split into `family.rs`
  for the 600-line cap.
- `30072ef` **leakceiling — option 2 (maintainer's choice):** the headline
  "undecidable fraction" is a *fitted* analytic prediction (free constant `G = 2`,
  reverse-fit to puzzle two's band, no non-circular control). A sound synthetic
  positive control was investigated and found **not buildable** (any ground truth is
  either circular — re-deriving the coupon formula it validates — or requires
  generalizing the test-only, C3×S4-bound G1b marginalization oracle, a research
  subproject). So the stream path **gates the fitted prediction + `calibration_control`
  + `scaling_sweep` OFF** (via a separate `LeakCeilingStreamReport` type) and exposes
  ONLY transparent per-input measurements + textbook bounds (Part A measured supply,
  Part B coupon-collector demand, Part C shortfall-ratio / MI-upper-bound /
  underdetermination bounds — control-free by construction). The fitted prediction is
  deliberately withheld. **New `leakceiling` Command.**

**Multi-message extension — maintainer-approved (2026-06-29).** The two cross-message
instruments could only ever see a single `"input"` message from the CLI, so their
detectors never ran on user data. Added a blank-line-separated multi-message input
format so they actually test user corpora:

- `d612e51` + `ba7fd5d` — `cli::shared::split_blank_line_messages` +
  `resolve_stream_multi` (backward-compatible: no blank line → one `"input"` message);
  rewired perfectiso/isomorphimperf to consume all messages; planted-positive-on-user-
  input + matched-null tests. They now emit an honest "structural candidate … not a
  recovery" when a supplied corpus has a genuine cross-message repeat.
- `cefc227` — disclose that the within-message shuffle null is a structure-destroying
  **trivial floor** for the cross-message statistic (degenerates to ~0), so the reports
  defer to the synthetic family control as the binding positive control.
- `bd8eeab` — codex-sweep fixes: **(P1)** the perfectiso stream headline could affirm
  `supports (does not prove) perfect isomorphism` off-corpus for a multi-message stream
  with repeats but zero robust violations → now a 4-case analysis keyed to message
  count never affirms off-corpus (the affirmation is gated to the eye path);
  **(P2a)** degeneracy wording keyed to message count, not empty results; **(P2b)** the
  three public `*_for_stream` fns reject mismatched `keys`/`messages` lengths;
  **(P2c)** the perfectiso planted test frames the trivial-floor p as a sanity floor.

**Honeycomb / grouping** left eye-specific (§5.4) — they are 2-D glyph-geometry, not
1-D streams.

**Known cosmetic nit (pre-existing, not fixed):** isomorphimperf's stream section
header prints `single-stream applicability` even for a multi-message stream; the body
correctly says "N messages supplied."

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

> **Items 1–3 are DONE (Workstream A, 2026-06-29) — see the Status section at the
> top.** Kept for context; the remaining work is Workstream B (§5).

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
  - **Superseded 2026-07-04** (`research/handoff/two-cross-agent-recon.md`): the
    C3 × S4 hidden-state diagnosis recorded here was itself later superseded. The
    live surface is the full 12-symbol stream — isomorph column-maps close to an
    order-48 observable shadow of a reported order-96 group, neither containing nor
    contained in C3 × S4 (order 72). Treat the C3 × S4 reading as a historical step,
    not the current truth on `two`'s structure. The `markov_excess` instrument and
    the honest-negative result stand; only the group framing moved on.

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

## 4. Workstream A — GAK discriminator + solver as a CLI instrument ✅ DONE

> **DONE (2026-06-29), commits `61db12e` / `e1dd966` / `80d0cfe`.** Kept here as
> the worked reference the structural-battery migration (§5) copies. All sub-steps
> below were completed; the P2 fix landed as its own commit first, and the four
> tests now assert on the `instrument.rs` functions the CLI calls.

This was the cohesive first piece; it also *demonstrates* the pattern for B.

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

**Goal (unchanged):** each analysis keeps its verified eye-corpus default (no input
flags) and gains a file-driven path (`--input-file`/`--stdin` + `--alphabet`,
reusing `cli::shared`) that runs the same computation on an arbitrary symbol
stream, with a working positive control. **One analysis per commit.** The map
below is from a fresh read of the code (2026-06-29) and supersedes the original
ease-ordered sketch.

### 5.0 The migration pattern (established by Workstream A — copy it)

All four CLI-exposed battery analyses are dispatched through the *uniform*
`emit(dispatch("… error", a.into(), lib::run_*))` registry in
`src/cli/dispatch.rs`, which calls a config-only library entry that **loads the
eye corpus and ignores CLI input**. The file-driven migration for each is the same
shape:

1. **Add input args.** Give the `*Args` struct in `src/cli/args_analysis.rs` a
   positional `sequence: Option<String>` + `--input-file` + `--stdin` +
   `--alphabet` (mirror `StatsArgs`, args_analysis.rs:17-36). Make the fields
   `pub(crate)` (the handler reads them). Adding `Option<String>` means the struct
   can no longer derive `Copy`; the old `From<…Args> for …Config` impl becomes
   unused — delete it (the handler builds the config).
2. **Add a `pub fn *_for_stream(config, message_values: &[Vec<TrigramValue>])`**
   library entry next to the existing `run_*`, wrapping the private per-stream seam
   (`report_from_message_values`) with a neutral `ReadingOrder::RawRows` and a
   single generated key `&["input"]` (the `order`/`keys` are report labels only —
   no eye traversal is claimed for arbitrary input). Re-export it from the analysis
   module. Thread `alphabet_size` through from `--alphabet`.
3. **Move the analysis to a bespoke handler** in `src/cli/commands/structural.rs`
   (new file; `src/cli/commands/gak.rs` from Workstream A is the template): read
   input via `cli::shared::resolve_input_text` + `parse_cli_sequence`, convert
   `parsed.glyphs` (`Glyph(u16)`, value = alphabet index) to `Vec<TrigramValue>`
   via `TrigramValue::new(u8::try_from(g.0))`, build the config with the derived
   alphabet size, and call `*_for_stream`; with **no** input flags, fall back to
   the existing eye-corpus `run_*`. Print `report.render()` (`use
   noita_eye_puzzle::report::Report`).
4. **Re-wire dispatch.** Remove the analysis's arm from the uniform block in
   `dispatch.rs`, add a bespoke arm `Command::X(args) => run_x(&args)`, register the
   handler in `commands/mod.rs`, and drop the now-unused name from the
   `analysis::{…}` import in dispatch.rs.
5. **Test the file-driven entry** on a synthetic stream (its positive control must
   fire) and confirm the eye-corpus default still works unchanged.

### 5.1 Shared facts (apply to all six)

- **Alphabet-size hardcode root:** `pub const READING_LAYER_ALPHABET_SIZE: usize =
  83;` at `src/analysis/orders/mod.rs:39`. Every battery "83" flows from it. Thread
  `alphabet_size` from `--alphabet`; don't leave an 83 hardcoded. `TrigramValue`
  holds `0..=124` (`core/trigram.rs:51`), so alphabets up to 125 work.
- **Two eye loaders, both eye-hardwired:** `orders::corpus_grids()` +
  `accepted_honeycomb_order()` + `read_corpus_message_values(...)` (chaining,
  chaining-graph, perfectiso), and the no-arg `CorpusContext::load()`
  (`orders/context.rs:37`) (isomorphnull, leak_ceiling, isomorph_imperfection).
- **A per-stream seam already exists for 3 of 6** — `chaining`, `isomorphnull`,
  `perfectiso` each split into a thin `run_*` (loads the corpus) + a private
  `report_from_message_values(config, order, keys, message_values)`. That is your
  seam. All three take `keys: &[&'static str]` (fine for the single file stream —
  pass `&["input"]`) and `order: ReadingOrder` (an eye concept used only as a
  report label — pass `RawRows`).

### 5.2 The clean three — DO THESE FIRST, one commit each

Their calibration controls are already matched to the input (lengths/alphabet) or
synthetic and stream-independent, so a file-driven path keeps a valid positive
control. No honesty judgment call.

1. **`chaining`** — easiest. `chaining_signature(message_values, period,
   alphabet_size)` is already `pub` + generic (`chaining/engine.rs:37`);
   `ChainingConfig.alphabet_size` already exists (`chaining/mod.rs:71`) but is not
   CLI-reachable; the calibration null is built from per-message lengths + alphabet
   (input-matched). `ChainingArgs` at `args_analysis.rs:122`; uniform dispatch at
   `dispatch.rs:130`; seam `report_from_message_values` at `engine.rs:94`;
   `validate_alphabet` accepts `1..=125`.
2. **`isomorphnull`** — `detect_isomorphs<T>` is `pub` + generic
   (`isomorph.rs:212`); the math is equality-based and alphabet-agnostic (no 83).
   Seam `report_from_message_values` at `isomorph_null.rs:306` (its own tests
   already call it with synthetic fixtures — proven). `IsomorphNullArgs` at
   `args_analysis.rs:104`; uniform dispatch at `dispatch.rs:125`. The within-message
   shuffle matched null already exists.
3. **`chaining-graph`** — more plumbing, but **no eye-control problem**
   (`run_positive_control` is synthetic and stream-independent). `compute_graph`
   (`chaining_graph/graph.rs:19`) is `pub(crate)` and **hardcodes 83 at graph.rs:27**
   (`coverage_from_links(&links, READING_LAYER_ALPHABET_SIZE)`) —
   `coverage_from_links`/`coverage_counts_from_links` already take `alphabet_size`,
   so only the call site needs it. There is no single `report_from_message_values`
   seam; the trio `compute_graph` → `run_shuffle_null` → `run_positive_control` is
   inlined in `run_chaining_graph` (`chaining_graph/mod.rs:502-504`) — wrap it in a
   new `pub fn …_for_stream(config, message_values, alphabet_size)`. Bump
   `compute_graph` (and `GraphComputation`/`ContextMetadata`, graph.rs:205/213) to
   `pub` and add the `alphabet_size` parameter. `ChainingGraphArgs` at
   `args_analysis.rs:146`; uniform dispatch at `dispatch.rs:131`.

### 5.3 The entangled three — STOP, get a maintainer decision first (see §6)

> **RESOLVED (2026-06-29) — see the Workstream B completion record above.** The
> maintainer chose to rebuild all three with synthetic per-input controls; `leakceiling`
> was narrowed to transparent measurements/bounds with its fitted prediction withheld.
> The text below is the original pre-decision analysis, kept for provenance.

These fuse eye-corpus-calibrated validation into the per-stream path. Making them
file-driven means **gating that off or rebuilding it as a per-input synthetic
control** — an honesty call, not a mechanical change. Do not guess; raise it.

4. **`perfectiso`** — seam `report_from_message_values`
   (`perfect_isomorphism/mod.rs:379`, private) **runs pinned wiki-regression checks
   + a positive control keyed to eye message names** (`run_regression_checks` /
   `ensure_all_regressions_reproduced` / `run_positive_control`, mod.rs:403-405;
   benign-region enums `east1`/`west1`/`east4`, mod.rs:223-230) — these fail on
   arbitrary input. Its signature also takes `keys: &[&'static str]` (no `'static`
   keys for arbitrary input → change to owned/generated labels). `ALPHABET_SIZE`
   const at mod.rs:43. `PerfectIsomorphismArgs` at `args_analysis.rs:204`; uniform
   dispatch at `dispatch.rs:146`.
5. **`leak_ceiling`** — **no `Command` at all** (test-only; `run_leak_ceiling` at
   `leak_ceiling/mod.rs:354`, loads `CorpusContext::load()`). Hardcodes `two`'s
   G1b-measured constants at `mod.rs:70-80` (`TWO_COSETS=12`, `TWO_STREAM_LEN=698`,
   `TWO_DOMINANT_OCCURRENCES=76`, `TWO_OUT_DEGREE=8`, `TWO_UNDECIDABLE_LOW=0.76`,
   `TWO_UNDECIDABLE_HIGH=0.83`, `CALIBRATED_GEOMETRY=2.0`) consumed by
   `analytic_demand`/`calibration_control`. The original handoff said "compute those
   from the input stream," but the Part-D calibration is a *measured reference* —
   decide with the maintainer whether to generalize it or gate it off for file
   input. Also depends on chaining-graph's 83 fix (it calls `compute_graph` via
   `math::chaining_supply`). Needs a new `Command` + arg struct + file-driven entry.
6. **`isomorph_imperfection`** — **no `Command` at all** (test-only;
   `run_isomorph_imperfection` at `isomorph_imperfection/mod.rs:321`, loads
   `CorpusContext::load()`). No numeric alphabet hardcode (works on `u32` class
   labels), but has eye-specific controls (`locate_stutter_candidate` keyed to
   `east4`/`west4`, mod.rs:343; synthetic positive control `ensure_positive_control`,
   mod.rs:347) and window bounds (`EXTENDED_WINDOWS` up to 17, validated against the
   shortest message, mod.rs:336) that reject short arbitrary inputs. Needs a new
   `Command` + arg struct + file-driven entry, with the eye controls gated/rebuilt.

### 5.4 Exclude `honeycomb` and `grouping`

Both are specific to the 2-D eye glyph geometry, not a 1-D stream: `honeycomb`
(`honeycomb/mod.rs:314`) tests a fixed 2-D lattice over physical row-pair
coordinates of the reconstructed grids; `grouping` (`grouping/mod.rs`, bespoke
handler `misc.rs:57`) does base-N state-count calibration of the eye reading-layer
stream. Leave them eye-specific; if you touch them, only to document why.

**Watch:** thread the alphabet size from `--alphabet` everywhere; don't leave an 83
hardcoded (root: `orders/mod.rs:39`).

**Acceptance (B), per analysis:** runs on
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

**A is DONE** (commits `61db12e` / `e1dd966` / `80d0cfe`) — it established the
file-driven-instrument + self-test pattern and the `cli::shared` usage the rest of
B copies. **Do B in this order:** the clean three (§5.2) `chaining` →
`isomorphnull` → `chaining-graph`, one commit each; then **pause for a maintainer
decision** on the entangled three (§5.3) before touching their eye-calibrated
controls. The steps are independently valuable and don't logically block each
other, but they all touch the shared CLI files (`args.rs`, `dispatch.rs`,
`commands/mod.rs`), so do them sequentially, not in parallel worktrees.

---

## 9. Pointers

- **Reference instrument (Workstream A, DONE):** the `gak` subcommand —
  `src/cli/commands/gak.rs` (handler), `src/cli/args_attack.rs`
  (`GakArgs`/`GakMode` + the three mode arg structs),
  `src/attack/gak_attack/hidden_state_solver/instrument.rs` (the
  `discriminate`/`solve_candidate`/`run_self_test` library layer). Copy this shape
  for the bespoke battery handlers.
- CLI precedent for bespoke handlers: `src/cli/commands/{gak,solve,keystream}.rs`;
  shared input plumbing in `src/cli/shared.rs`
  (`resolve_input_text`/`parse_cli_sequence`). New battery handlers go in a new
  `src/cli/commands/structural.rs`.
- Generic primitives to reuse: `src/analysis/isomorph.rs:212` (`detect_isomorphs`),
  `src/analysis/chaining/engine.rs:37` (`chaining_signature`).
- Glyph→symbol conversion: `Glyph(pub u16)` (`core/glyph.rs:165`), value = alphabet
  index; `TrigramValue::new(value: u8)` accepts `0..=124` (`core/trigram.rs:51`).
- Discipline: `AGENTS.md`, `research/attack-methodology.md`.
- Test fixtures: `research/data/practice-puzzles/`.
