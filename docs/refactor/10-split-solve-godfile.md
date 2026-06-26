# 10 — Split the `solve.rs` god-file into `attack/solve/`

> One-line: split the 4,016-line `src/attack/solve.rs` into a cohesive
> `src/attack/solve/` module directory (one file per natural seam) — a pure,
> behavior-preserving move-refactor that changes no fn body and no reported
> number, completing the `attack/ … solve/` *directory* the overview's target
> layout already names (`00-OVERVIEW.md` §"Target module layout").
> Status: not started · Depends on: 01 (golden-master safety net), 04/04a (built
> `solve.rs`), 07B (placed it at `attack/solve.rs`) · Blocks: nothing · Size: M
> Sequence: after 07B (the engine + role-dir tracks have settled).

## Goal & why it matters

`src/attack/solve.rs` is **4,016 lines** (`scripts/file-size-allowlist.txt` pins
it at 4016; the single largest non-`gak_attack` file in the crate). Briefs 04 +
04a grew it into the unified solve pipeline: config/IO types, a two-phase
fixed/search evaluator, a codec-search enumerator with a selection-complete
enumeration-level null, a hill-climb/anneal mapping search, the candidate
auto-logging / record-writing path, and a **2,091-line** `#[cfg(test)] mod tests`
(the file is 52% tests). That size is what makes the engine core painful to
navigate and review.

This brief does the **mechanical** split of that one file into the `solve/`
directory, with **zero behavior change**. No statistic, no decode, no CLI byte
may move. It introduces no traits, merges no logic, and edits no fn body — it
only relocates existing items behind a frozen `crate::solve::*` public path. It
**completes** the overview's already-documented `attack/ … solve/` directory
target (`00-OVERVIEW.md` §"Target module layout" lists `solve/`, not
`solve.rs`); it is not new scope.

## Current state (grounded, with file:line)

### `solve.rs` natural seams (line numbers from the live file)

| Seam | Range | Key items |
| ---- | ----- | --------- |
| doc + imports + shared consts | `:1-39` | module doc (`:1-6`); 7 `use crate::<mod>::{…}` (`:8-22`); `DEFAULT_SEED` (`:25`), `DEFAULT_NULL_TRIALS` (`:28`), `SEARCH_BEATS_NULL_MARGIN` (`:36`) |
| **types** (config / IO / error) | `:42-471 (types only)` | `Mapping` (`:42`, +impl `:47`), `Language` (`:90`), `LanguageChoice` (`:99`,+impl `:109`), `MappingSearch` (`:127`), `AnnealSchedule` (`:149`), `MappingStrategy` (`:158`), `CipherFamilySpec` (`:171`), `HypothesisSpace` (`:180`), `SolveRequest` (`:202`), `Candidate` (`:221`), `SolveError` (`:253`, +Display `:315`, +Error `:359`, +5 `From` `:382-410`), `SolveOutcome` (`:439`) |
| **orchestration / entry points** | `:428-577`, `:793-831`, `:1607-1620` | `solve` (`:428`), `solve_with_codec_trace` (`:458`), `solve_fixed_codecs` (`:475`), `run_codec_search` (`:516`), `validate_request` (`:793`), `validate_ciphertext_symbols` (`:817`), `candidate_survives` (`:1616`) |
| **codec search** (Phase 2 enum.) | `:590-772` | `surviving_codecs` (`:590`), `codec_search_mapping` (`:682`), `stamp_enumeration_beats_null` (`:705`), `enumeration_null_mean` (`:726`) |
| **fixed-codec eval + shared scoring** | `:778-983`, `:1007-1086` | `best_codec_fixed_null_score` (`:778`), `evaluate_family` (`:833`), `evaluate_cipher` (`:855`), `decrypt_round_trip` (`:885`), `ScoredText` (`:898`), `score_transduced` (`:905`), `matched_null_mean` (`:918`), `best_family_score` (`:937`), `family_seed_tag` (`:958`), `model_for` (`:967`), `render_indices` (`:974`), `reinsert_transparent` (`:1007`), `rendered_index_for_cipher_index` (`:1048`), `heldout_score` (`:1075`) |
| **mapping search** (driver + internals) | `:1093-1605` | `MappingSearchOutcome` (`:1093`), `Proposal` (`:1099`), `solve_search` (`:1106`), `evaluate_cipher_search` (`:1141`), `heldout_search_score` (`:1199`), `matched_null_search_mean` (`:1227`), `best_family_search_score` (`:1259`), `search_mapping` (`:1287`), `score_table` (`:1352`), `apply_table_into` (`:1362`), `apply_table` (`:1380`), `initial_table` (`:1390`), `propose` (`:1425`), `swap_targets` (`:1469`), `unused_letters` (`:1484`), `undo_proposal` (`:1496`), `accept` (`:1510`), `temperature_at` (`:1521`), `language_frequency_rank` (`:1536`), `symbol_frequency_order` (`:1553`), `to_symbol_indices` (`:1572`), `search_seed` (`:1590`), `language_tag` (`:1600`) |
| **record** (auto-log / write) | `:1626-1924` | `SOLVE_CLAIM_CEILING` (`:1628`), `SolveRecordCandidate` (`:1636`), `SolveRecordInputs` (`:1668`), `solve_record_filename` (`:1690`), `write_solve_candidate_record` (`:1714`), `render_solve_candidate_record` (`:1742`), `render_solve_gates` (`:1788`), `log_solve_run` (`:1880`) |
| tests | `:1926-4016` | one `#[cfg(test)] mod tests` (`:1926`); **30** `#[test]` fns + **1** `#[ignore]`; 8 `include_str!` sites |

### Cross-seam coupling (must be honored; from the structural map)

The shared private helpers that are referenced across the new file boundaries —
each must be promoted from private to **`pub(super)`** (visible across the
`solve` subtree, but *not* the crate; `missing_docs` does not require documenting
them):

- `decrypt_round_trip`, `score_transduced`, `model_for`, `render_indices`,
  `family_seed_tag` — the shared evaluation/scoring primitives used by **both**
  fixed-codec eval and the mapping search (and the null computations).
- `best_family_score`, `best_codec_fixed_null_score` (fixed-eval home) and
  `best_family_search_score` (search home) — all three are called by
  `surviving_codecs`'s enumeration-level null (codec_search seam).
- `evaluate_family` / `evaluate_cipher` (fixed) and `solve_search` /
  `evaluate_cipher_search` (search) and `surviving_codecs` (codec_search) — the
  per-seam entry points the `mod.rs` orchestrator (`solve_fixed_codecs`,
  `run_codec_search`, `solve_with_codec_trace`) dispatches into.
- `reinsert_transparent`, `rendered_index_for_cipher_index` — called by both
  `evaluate_cipher` (fixed) and `evaluate_cipher_search` (search).
- `heldout_score` (fixed) / `heldout_search_score` (search) — each tied to its
  path but `heldout_search_score` lives in the search seam while `heldout_score`
  lives in the fixed-eval seam; both reached from `evaluate_cipher*`.

`search_seed`, `language_tag`, `apply_table`/`apply_table_into`, `to_symbol_indices`,
`score_table`, `initial_table`, `propose`/`undo_proposal`/`accept`/`temperature_at`,
`language_frequency_rank`, `symbol_frequency_order`, `swap_targets`,
`unused_letters` are **search-internal** (subroutines of `search_mapping`); they
stay private inside `search.rs`. `validate_request`/`validate_ciphertext_symbols`
are called only from `solve_with_codec_trace` (mod.rs) and travel with it.

### External references that pin the public path (`crate::solve::*`)

`solve` is referenced by flat path from `src/main.rs` and the in-crate
`keystream` module (grep `crate::solve::` / `solve::` over `src/` `tests/`). The
external symbol surface that **must** keep an identical `crate::solve::Foo` path
(re-exported from `solve/mod.rs`):

- Consts: `DEFAULT_SEED`, `DEFAULT_NULL_TRIALS`, `SEARCH_BEATS_NULL_MARGIN`,
  `SOLVE_CLAIM_CEILING`.
- Types: `Mapping`, `Language`, `LanguageChoice`, `MappingSearch`,
  `AnnealSchedule`, `MappingStrategy`, `CipherFamilySpec`, `HypothesisSpace`,
  `SolveRequest`, `Candidate`, `SolveError`, `SolveOutcome`,
  `SolveRecordCandidate`, `SolveRecordInputs`.
- Functions: `solve`, `solve_with_codec_trace`, `candidate_survives`,
  `log_solve_run`, `write_solve_candidate_record`,
  `render_solve_candidate_record`.

The implementing agent **re-derives this set by grep** (`grep -roE
'solve::[A-Za-z_][A-Za-z0-9_]*' src/ tests/ | sort -u`) before and after, and the
two lists must match exactly. Anything currently `pub` stays `pub` in its new
home and is re-exported; nothing private becomes `pub`.

### `include_str!` — 8 sites, all inside tests, re-root `../../` → `../../../`

All 8 `include_str!("../../research/data/practice-puzzles/…")` sites are inside
the `#[cfg(test)] mod tests` block (loading `three`/`four`/`five`/`seven`/`one`/
`two`×2/`six`). Because `solve/mod.rs` (and any sibling) sits **one directory
deeper** than `solve.rs` did, every site must become
`include_str!("../../../research/data/practice-puzzles/…")`. These tests are the
cross-cutting corpus/end-to-end tests; they exercise the **public** entry points
(`solve`, `solve_with_codec_trace`, `log_solve_run`), so they live in
`solve/mod.rs`'s `#[cfg(test)] mod tests` (`use super::*`). A wrong path is loud
(the corpus tests fail to compile / load), but also grep for zero stale
`../../research` and exactly 8 `../../../research` afterwards.

## Target design (concrete layout)

Replace `src/attack/solve.rs` with `src/attack/solve/` containing seven files.
Siblings are **private submodules** of `solve`; cross-file shares use
`pub(super)` (or `pub(crate)` only where already crate-visible). `mod.rs` ends
with a `pub use` block re-surfacing the full external surface so
`crate::solve::Foo` resolves identically before and after.

```
src/attack/solve/
  mod.rs           // module doc (verbatim from solve.rs:1-6); `use` of crates +
                   //   sub-files; submodule decls; the orchestrator + entry
                   //   points: solve, solve_with_codec_trace, solve_fixed_codecs,
                   //   run_codec_search, candidate_survives, validate_request,
                   //   validate_ciphertext_symbols; the `pub use` re-export block;
                   //   and the cross-cutting corpus/e2e `#[cfg(test)] mod tests`
                   //   (all 8 include_str! sites, re-rooted to ../../../research)
  types.rs         // consts (DEFAULT_SEED, DEFAULT_NULL_TRIALS,
                   //   SEARCH_BEATS_NULL_MARGIN); Mapping(+impl), Language,
                   //   LanguageChoice(+impl), MappingSearch, AnnealSchedule,
                   //   MappingStrategy, CipherFamilySpec, HypothesisSpace,
                   //   SolveRequest, Candidate, SolveError(+Display+Error+5 From),
                   //   SolveOutcome
  eval.rs          // fixed-codec eval + shared scoring primitives + transparent
                   //   reinsertion + fixed held-out: best_codec_fixed_null_score,
                   //   evaluate_family, evaluate_cipher, decrypt_round_trip,
                   //   ScoredText, score_transduced, matched_null_mean,
                   //   best_family_score, family_seed_tag, model_for,
                   //   render_indices, reinsert_transparent,
                   //   rendered_index_for_cipher_index, heldout_score
  codec_search.rs  // surviving_codecs, codec_search_mapping,
                   //   stamp_enumeration_beats_null, enumeration_null_mean
  search.rs        // mapping search driver + internals: solve_search,
                   //   evaluate_cipher_search, heldout_search_score,
                   //   matched_null_search_mean, best_family_search_score,
                   //   search_mapping, score_table, apply_table[_into],
                   //   initial_table, propose, swap_targets, unused_letters,
                   //   undo_proposal, accept, temperature_at,
                   //   language_frequency_rank, symbol_frequency_order,
                   //   to_symbol_indices, search_seed, language_tag,
                   //   MappingSearchOutcome, Proposal
  record.rs        // SOLVE_CLAIM_CEILING, SolveRecordCandidate, SolveRecordInputs,
                   //   solve_record_filename, write_solve_candidate_record,
                   //   render_solve_candidate_record, render_solve_gates,
                   //   log_solve_run
```

**Deviation latitude:** the seam line numbers above are the structural map; if the
compiler reveals a coupling the map under-counted (a private helper referenced
from one more seam), promote it to `pub(super)` and place it in the seam that
*owns* it — do not duplicate a body, do not widen past `pub(super)`, and call out
any such adjustment in the PR notes. The *count* of files (7) and the public
surface are fixed.

**`lib.rs` edit (one line):** `src/lib.rs:154` changes
`#[path = "attack/solve.rs"]` → `#[path = "attack/solve/mod.rs"]`; `pub mod
solve;` (`:155`) is unchanged. This is the only `lib.rs` change.

**Test distribution.** The 30 `#[test]` fns + 1 `#[ignore]` split by the item
each exercises: a sibling's **unit** tests move into that sibling's own
`#[cfg(test)] mod tests` (`use super::*` sees its private items naturally — zero
visibility widening for test access); the **cross-cutting corpus/e2e** tests (the
8 `include_str!` pipeline tests, plus anything driving the public `solve` /
`solve_with_codec_trace` / `log_solve_run` / `render_solve_candidate_record`
surface) stay in `solve/mod.rs`'s test module. A test that needs a `pub(super)`
item of another sibling reaches it via `crate::solve::<seam>::<item>`. No test
**body** changes (only its enclosing module and `use` lines; the 8 include_str!
paths gain one `../`). A mis-placed test or a forgotten visibility bump is a
**compile error** (loud, caught by `make verify` running the suite).

## Implementation steps (ordered, each independently committable & green)

Each step ends green under `make verify` and changes **no fn body**. Run the
golden-master suite after every step (`cargo test --locked --test golden_master`
= 36 passed) and confirm byte-identical CLI output.

1. **Create `solve/mod.rs` as a verbatim copy** of today's `solve.rs`; switch
   `lib.rs:154` to `#[path = "attack/solve/mod.rs"]`; delete `src/attack/solve.rs`;
   re-root the 8 `include_str!` to `../../../research`. Green (identical file,
   new location). This isolates the path/asset move from the content split.
2. **Extract `types.rs`** (the config/IO/error cluster). `mod types;` +
   `pub use types::{…}` for the public types; private types/consts re-exported as
   needed by siblings via `pub(super)` or `pub use`. Green.
3. **Extract `record.rs`** (auto-log/write — depends only on the public surface +
   `candidate_survives`). `pub use record::{…}`. Green; the three
   `solve-{one,two,six}` records still regenerate byte-identically on demand.
4. **Extract `search.rs`** (mapping search driver + internals). Promote
   `best_family_search_score`, `solve_search`, `evaluate_cipher_search`,
   `heldout_search_score` to `pub(super)` for the orchestrator / codec_search;
   keep the search internals private. Green.
5. **Extract `eval.rs`** (fixed-codec eval + shared scoring + transparent +
   fixed held-out). Promote the shared primitives (`decrypt_round_trip`,
   `score_transduced`, `model_for`, `render_indices`, `family_seed_tag`,
   `best_family_score`, `best_codec_fixed_null_score`, `evaluate_family`) to
   `pub(super)`. Green.
6. **Extract `codec_search.rs`** (enumeration + pruning + enumeration null). It
   consumes `best_family_score`/`best_family_search_score`/`best_codec_fixed_null_score`
   from eval/search via `pub(super)`. Green.
7. **Settle `mod.rs`.** What remains is the doc comment, the submodule decls, the
   orchestrator/entry points (`solve`, `solve_with_codec_trace`,
   `solve_fixed_codecs`, `run_codec_search`, `validate_request`,
   `validate_ciphertext_symbols`, `candidate_survives`), the `pub use` re-export
   block, and the cross-cutting corpus/e2e test module. Distribute the remaining
   sibling unit tests into their siblings' `#[cfg(test)] mod tests` (step may fold
   into 2–6 as each sibling is extracted). Green.

## Files to create / change / delete

**Create:** `src/attack/solve/{mod,types,eval,codec_search,search,record}.rs`.
**Change:** `src/lib.rs:154` (one line: `#[path]`); `scripts/file-size-allowlist.txt`
(delete the `src/attack/solve.rs 4016` pin; add an honest pin ONLY for any
resulting file that legitimately exceeds the 600-line cap — expected to be at most
`solve/mod.rs` if the corpus/e2e test module keeps it over 600, with a
`# reason` noting post-split test colocation; aim to need **no** new pin).
**Delete:** `src/attack/solve.rs`.
**Do not touch:** `tests/*.rs`, `tests/golden/*`, any other module, any fn body,
`research/` data.

## Success criteria

- `src/attack/solve.rs` no longer exists; `src/attack/solve/` holds 7 files, each
  a single cohesive responsibility; the max resulting file is far below 4,016.
- `crate::solve::*` is byte-identical: `grep -roE 'solve::[A-Za-z_][A-Za-z0-9_]*'
  src/ tests/ | sort -u` matches before vs after; `main.rs`/`keystream`/tests
  compile with **no path edits**.
- `git diff` contains **only** moves, `mod`/`use`/`pub use` lines,
  visibility-keyword changes (`pub(super)`/`pub(crate)`), the 8 `include_str!`
  one-`../` re-roots, the one `lib.rs` `#[path]` line, and the allowlist re-pin.
  **No fn body diff.**
- `tests/golden/` diff is empty; `cargo test --locked --test golden_master` = 36
  passed; the **same 30 `#[test]` + 1 `#[ignore]`** run before and after.
- `make verify` and `make check` green.

## Verification (exactly how to prove it)

1. **Golden master (load-bearing).** `git diff <base> HEAD -- tests/golden/` = 0
   lines; `cargo test --locked --test golden_master` = 36 passed.
2. **Body diff = empty.** A reviewer greps the diff for `fn` bodies and confirms
   moves only (no `+`/`-` inside any fn body; only signatures' visibility
   keywords, `use`, `mod`, `pub use`, the 8 include_str! literals).
3. **Public-path freeze.** The `solve::<Ident>` grep set matches before vs after;
   pub-item count unchanged (no visibility widened to `pub`).
4. **Test parity.** `grep -rc '#\[test\]' src/attack/solve/` sums to 30 and
   `#\[ignore` to 1 — the same tests run, none silently dropped.
5. **Asset re-root.** `grep -rn 'include_str!' src/attack/solve/` shows exactly 8
   sites, all `../../../research`, zero `../../research`.
6. **Allowlist.** `bash scripts/check-file-size.sh` = OK; the `solve.rs 4016` pin
   is gone; any new pin is honestly reasoned and far below 4016.
7. `make verify` then `make check` green.

## Risks & honesty caveats

- **Visibility is the trap.** Promoting a private helper to `pub(super)` is fine;
  accidentally making it `pub`/`pub(crate)` widens the API surface and can trip
  `missing_docs`. Keep cross-file shares at `pub(super)`; confirm the grep shows
  no *new* `pub` items.
- **Test `use super::*` re-pointing.** The single `mod tests` splits across
  files; each moved block now resolves against a different parent. A miscompile is
  loud (good); a **silently-skipped** `#[cfg(test)]` module is the danger —
  confirm the 30/1 `#[test]`/`#[ignore]` count is identical before and after.
- **include_str! depth.** The +1 `../` is the one content edit in otherwise-moved
  test code; verify by grep AND by the corpus tests actually loading (they fail
  loudly on a wrong path).
- **No claim-surface change.** `SOLVE_CLAIM_CEILING`, the HYPOTHESIS-not-decode
  labels, and the three-gate `candidate_survives` verdict move verbatim into
  `record.rs`/`mod.rs`. The claim ceiling is unchanged.

## Out of scope / non-goals

- **No traits, no logic merges, no fn body edits.** This brief only moves items
  within the one `solve.rs` file into `solve/`.
- **No behavior, statistic, decode, or CLI byte change.** The golden master is the
  proof.
- **No touch to any other module** (`keystream`, `codec`, `quadgram`, etc.) beyond
  the one `lib.rs` `#[path]` line and the frozen re-export consumers.
