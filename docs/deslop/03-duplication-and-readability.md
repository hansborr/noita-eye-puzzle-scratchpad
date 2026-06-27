# Report 03 — Duplication & code-level readability

Within-code smells (independent of file size, which report 02 owns). The
codebase is clean on the usual rot axes — **0** commented-out code, **0**
`dead_code` allows, **0** `TODO`/`FIXME`, **2** non-test `unwrap`s, **306** named
constants. So this report is about *structural duplication* and *readability*,
and it deliberately separates "genuinely smelly" from "large but fine."

Quantified scope: **6** functions ≥100 lines, **28** ≥80, **46** ≥70 (of ~2300).
Most long ones are flat `match`/`writeln!` builders that are large-but-fine — only
the high-*nesting* ones below are worth touching.

---

## The 5 highest-ROI fixes

### 1. P1 — Cipher trait-impl boilerplate + a comment duplicated 14× → a macro
`src/ciphers/mod.rs:1553-1760`. Nine cipher families each get a zero-sized marker
struct + a `Cipher` impl that only delegates to the free `*_encrypt`/`*_decrypt`
fns and returns a `name()` literal (~20 lines each, ~180 total). The comment
`// Free functions take (sequence, key); trait methods take (key, sequence).` is
copy-pasted **14 times verbatim**.
- **Fix:** an `impl_cipher!(Caesar, CaesarKey, caesar_encrypt, caesar_decrypt,
  "Caesar")` declarative macro collapses all nine impls and states the arg-order
  note once. (The free-fn `(sequence, key)` vs trait `(key, sequence)` swap is the
  root cause of the repeated comment — consider aligning the signatures instead.)

### 2. P1 — Null-driver preamble duplicated verbatim across 6 modules → a helper
`src/nulls/isomorph_null.rs:294`, `perseus.rs:567`, `tree_residual.rs:488`,
`zero_adjacency_null.rs:442`. Each `run_*` opens with the identical 6-line ritual:
`validate_config` → `orders::corpus_grids()?` → map `GlyphGrid::message_key` →
`accepted_honeycomb_order()` → `read_corpus_message_values` →
`report_from_message_values(...)`. Cosmetic drift only (`Vec<&'static str>`
annotation vs `.collect::<Vec<_>>()` turbofish — itself an inconsistency).
- **Two more members from the `exploration` merge:**
  `src/analysis/isomorph_imperfection.rs:608` is a **full** member — same ritual,
  and it carries the `Vec<&'static str>` annotation variant of the drift.
  `src/analysis/leak_ceiling.rs:561` shares the `corpus_grids()?` →
  `accepted_honeycomb_order()` → `read_corpus_message_values` *triple* but stops
  before the `report_from_message_values` tail (it's a pure-analytic driver, not a
  matched-null one), so it would consume the front half of the same helper.
- **Good sign (no new debt):** `isomorph_imperfection.rs` correctly imports
  `mix_seed`/`usize_band`/`fisher_yates` from `crate::null` instead of re-defining
  them — i.e. the newest code already follows the consolidation precedent below.
- **Fix:** a shared `CorpusContext::load() -> (grids, keys, order, message_values)`
  helper. The `nulls/heldout.rs` helper (commit T1) shows the team is already
  consolidating this way — follow that precedent.

### 3. P1 — `keystream.rs` ↔ `ragbaby.rs` are near-clone cracker modules
`src/attack/keystream.rs` (1360) and `src/attack/ragbaby.rs` (1736) share the same
skeleton function-for-function: `render_plaintext`, `matched_null`,
`crack_with_model`, `render_record`, even mirrored test names
(`matched_null_rejects_overfitting_*`). `crack_with_model` is the same pipeline in
both (search → recompute best decrypt → score → held-out fold → random-key null →
matched null → z-scores → round-trip), and `render_record` emits the same report
scaffold differing only in cipher-specific key fields.
- **Fix:** a generic "search + null + render" harness parameterized over the
  cipher primitive, or at minimum a shared `render_record` header/verdict builder.
  Coordinate with report 02 (split both into `cipher`/`search`/`record` together).

### 4. P1 — Two deeply-nested loop pyramids (extract the inner arms)
- `run_codec_search` `src/attack/solve/mod.rs:128` nests
  `for family { for language { for codec { match mappings { Fixed => for mapping {
  for cipher { … }}}}}}` — candidate pushed ~7 levels deep in 70 lines.
- `eyes_message_evidence` `src/attack/gak_attack/eyes.rs:1223` (106 lines) nests
  `for window_len { … for (sig, starts) { for left { for lower { … }}}}` (5 deep).
- **Fix:** extract the `Fixed`/`Search` match arms and the inner pair-comparison
  loop into named helpers; the outer fn then reads as the algorithm outline.

### 5. P1 — AI-agent / review chatter in shipped source comments
(P1 *specifically because the goal is "public without embarrassment."*)
- `src/attack/gak_attack/eyes.rs:654` ("the leak-proof, **codex-validated**
  embargoed-consensus statistic") and `:776` ("**codex's** 'effect size…'") name
  the review tool. (Also tracked in report 01 P1.3.)
- **20** `brief NN` references point at internal task docs the public won't have
  — concentrated in `src/attack/solve/mod.rs` (5×), `lib.rs` (3×),
  `attack/codec.rs:600` ("brief 04a step 3"), `core/ingest.rs`, `solve/types.rs`.
  Plus `solve/mod.rs:324` ("Step 10(b)"), `main.rs:1456` ("defect D2"),
  `solver.rs:22` ("review finding F4").
- **Fix:** strip tool names; rewrite `brief NN`/`step`/`defect`/`review finding`
  labels into durable technical rationale. **Keep** the ~30 `honest negative`
  mentions — that is a legitimate *domain term* (the expected attack outcome), not
  chatter.

---

## More duplication (P2)

- **`report_from_message_values` header re-emission** — the title/alphabet/seed/
  trials lines are re-emitted in each `fn render(&self) -> String` across
  `isomorph_null.rs:308`, `perseus.rs:579`, `tree_residual.rs:502`,
  `zero_adjacency_null.rs:465`, `periodicity.rs:679`, and (from the `exploration`
  merge) `leak_ceiling.rs:781`'s `append_header` (title/order variant). Consistent
  naming (good) but a shared report-header trait would remove the repetition.
- **Duplicate utility functions that already exist in `crate::null`:**
  - `src/experiments/modular_diff.rs:1466` defines a local `fn mix_seed` despite
    `crate::null::mix_seed` (`src/nulls/null.rs:105`). Delete the local, use the
    shared one.
  - `src/analysis/honeycomb.rs:1024` and `src/analysis/chaining_graph.rs:1288`
    each define their own `fn null_band`; `chaining_graph` also keeps local
    shuffle/band/quantile plumbing (`:1197`). Migrate to the shared
    `run_null_test` / `WithinMessageShuffle` / `usize_band`/`f64_band` harness.
- **`too_many_arguments` proliferation in the solve pipeline** — `evaluate_cipher`
  `solve/eval.rs:62`, `evaluate_cipher_search` `solve/search.rs:67`,
  `best_family_search_score` `solve/search.rs:196`, `log_solve_run`
  `solve/record.rs:259` each thread 8+ positional params and carry the allow. A
  `CipherEval { … }` params struct removes the allows and the positional confusion.

---

## Magic numbers — the smell is *inconsistency*, not absence (P2)

306 consts exist, but the same domain quantities are open-coded or differently
named across modules:
- The base-5 trigram decomposition `value / 25, (value / 5) % 5, value % 5` is
  open-coded with bare `5`/`25` in `first_trigram.rs:93`, `orders.rs:744`,
  `grouping.rs:886`, `solve/mod.rs:2091/2122/2163` — even though
  `ORIENTATION_BASE = 5` already exists (`dof_null.rs:43`, `grouping.rs:25`). The
  `25` (=5²) place value is never named. **Fix:** a shared `to_base5_digits()`
  helper; reuse `ORIENTATION_BASE`.
- Same quantity, different const names across modules: base-5 is
  `ORIENTATION_BASE` (dof_null, grouping) vs `ORIENTATION_BUCKETS`
  (`orientation_homogeneity.rs:26`); 125 is `TRIGRAM_VALUE_COUNT`
  (`honeycomb.rs:27`) vs `STORAGE_MODULUS` (`first_trigram.rs:33`) vs
  `SECONDARY_MODULUS` (`modular_diff.rs:43`); base-7 is `STORAGE_BASE` vs
  `ENGINE_STORAGE_BASE`. **Fix:** hoist canonical `ORIENTATION_BASE`/
  `STORAGE_BASE`/`TRIGRAM_VALUE_COUNT` into `core` and reuse.
- Bare `83` (reading-layer alphabet size) appears 73× inline despite
  `HEADLINE_ALPHABET_SIZE`/`EYE_READING_ALPHABET_SIZE` existing
  (e.g. `transitivity.rs:482-485`, `periodicity.rs:1237`). Lower priority — many
  are in report strings/fixtures where inline is fine.

---

## Naming (P2)

- Cryptic crypto locals in `src/attack/keystream.rs` (mirrored in `ragbaby.rs`):
  `let n = alphabet_size.max(1)`, `let l = key_len.max(1)` (`:667-668`), and
  `k`/`p` for key-value/plaintext-byte (`:286-287`). Conventional-ish for cipher
  code and partly comment-explained, but inconsistent with the codebase's
  otherwise descriptive style — `alphabet_size`/`key_len` read better.
- Otherwise naming is a **strength**: the `run_*` / `report_from_message_values`
  / `render` parallelism across modules is consistent and intentional.

---

## Comment quality & dead code

- Dense algorithms are generally *well*-commented (the `(a)/(b)/(c)/(d)` step
  comments in `recover_letter_permutations` `solver.rs:494`, the null-aggregation
  rationale in `run_codec_search:137-145`) — a strength. The only comment smell is
  the AI/brief chatter in fix #5.
- **Effectively no dead code or scaffolding.** The one
  `#[allow(unused_imports, reason="referenced only by intra-doc links")]` at
  `codec_search.rs:1` is legitimate. `solve/types.rs:268`'s "Retained for API
  stability" field is a deliberate, documented retention, not rot. No action.

---

## What NOT to touch

- The long flat `Display`/`match` error formatters (`controls.rs:279` 121 ln,
  `ciphers/mod.rs:218`, `gak_attack/error.rs:132`) and the linear `append_*`/
  `writeln!` report builders — long but low-complexity. Leave them (report 02 may
  move them into `*_report.rs`, which is the right lever, not rewriting them).
- `main()` `src/main.rs:1013` (108 ln) — flat subcommand `match` over the
  dispatch registry. Idiomatic; keep.
- All claim-ceiling / `honest negative` domain language.
