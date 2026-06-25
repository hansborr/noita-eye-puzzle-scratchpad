# 07A — Split the `gak_attack.rs` god-file

> One-line: split the 8,147-line `gak_attack.rs` into a cohesive `src/gak_attack/`
> module directory (one file per natural seam) — a pure, behavior-preserving
> move-refactor that changes no fn body and no reported number, and hands brief 04
> a clean `crate::gak_attack::marginalization::*` / `solver::*` seam to import the
> beam search.
> Status: not started · Depends on: 01 (golden-master safety net) · Coordinates
> with: 04 (both touch `gak_attack.rs`) · Blocks: nothing hard; eases 04/06
> navigation · Size: M
> Sequence: right after 02, before 04.

## Goal & why it matters

`gak_attack.rs` is 8,147 lines (`src/lib.rs:82`; line count verified via
`wc -l`) — the single worst god-file in the crate. It bundles a synthetic GAK
generator, a GCTAK solver, a deck-cipher attack, a hidden-state
marginalization/beam-search, the eyes Step-3 path, an error type, and a
1,716-line test module into one flat namespace. That size is what makes brief 04
("reuse its beam-search") painful to navigate.

This brief does the **mechanical** split of that one file into the `gak_attack/`
directory, with **zero behavior change**. No statistic, no decode, no CLI byte
may move. It is deliberately scoped *under* brief 02 (which introduces
`trait Cipher`) and brief 04 (which builds the solve pipeline): this brief only
relocates existing items so brief 04 has clean per-seam seams to build on. It
does **not** introduce traits, merge logic, or touch fn bodies.

The repo-wide `lib.rs` role-directory regroup (moving the 32 flat modules,
including this `gak_attack/` directory, into `core/ data/ analysis/ …`) is a
**separate, later** brief — **07B** — sequenced dead last. This brief touches
only `gak_attack.rs` → `src/gak_attack/`.

## Current state (grounded, with file:line)

### `gak_attack.rs` natural seams (all line numbers from the live file)

| Seam | Range | Key items |
| ---- | ----- | --------- |
| Imports + shared consts | `:55-110` | 9 separate `use crate::<mod>::{…}` imports — chaining_graph, ciphers, glyph, isomorph, language, null, orders, perfect_isomorphism, trigram (`:59-77`); `DEFAULT_SEED` (`:78`), `DEFAULT_SEEDS_PER_KIND` (`:80`), `SOLVER_WINDOW_LEN` (`:106`) |
| **error** | `:250-396` | `enum GakAttackError` (`:250`) + its 5 `From` impls (`:368`,`:374`,`:380`,`:386`,`:392`) |
| **generator** (synthetic) | `:120-249`, `:733-1402` | `GroupKind` (`:120`), `HiddenSubgroupKind` (`:167`), `RealizedStructure` (`:207`), `SyntheticFixture` (`:231`), `generate_fixture` (`:856`), `realized_structure` (`:951`), `group_table`/`dihedral_table` (`:1093`/`:1118`), `apply_small_support` (`:1213`), `repeated_phrase_template` (`:1246`) |
| **solver** (GCTAK) | `:1403-2138` | `GctakSolution` (`:1412`), `solve_gctak` (`:1486`), `collect_chain_links` (`:1625`), `recover_letter_permutations` (`:1816`), `complete_permutation` (`:1908`), `decode_letters_by_edge` (`:1988`), `SmallUnionFind` (`:2063`), `type EdgeMap` (`:1679`), `glyphs_to_values` (`:2038`), `symbol_from_usize` (`:1403`) |
| deck attack | `:2141-3345` | `DeckLetterRegime` (`:2141`), `DeckFixture` (`:2171`), `generate_deck_fixture` (`:2215`), `CosetEdge` (`:2341`), `ContextAction` (`:2357`), `ChainSubstrate` (`:2397`), `build_chain_substrate` (`:2429`), `run_deck_attack` (`:2592`), `DeckAttackOutcome` (`:3024`), `run_deck_attack_sweep` (`:3204`), `mean_f64` (`:3306`) |
| marginalization / beam | `:3348-4330` | `SmallSupportPrior` (`:3371`), `BeamItem` (`:3430`), `SplitColumnEvidence` (`:3469`), `split_column_evidence` (`:3484`), `beam_recover_column` (`:3565`), `run_marginalization_attack` (`:3686`), `MarginalizationReport` (`:3956`), `SmallSupportValidation` (`:4005`), `run_marginalization_sweep` (`:4120`) |
| **eyes** (Step 3) | `:4333-6431` | `EYE_*`/`EYES_*` consts (`:4386-4409`), `EyesAttackConfig` (`:4413`), `EyesAttackReport` (`:4498`), `run_gak_attack_eyes` (`:4725`), `eyes_message_evidence` (`:5341`), `eyes_mapping_null` (`:5924`), `write_eyes_candidate_record` (`:6024`), render helpers (`:6046-6431`) |
| top orchestrator | `:559-732` | `GakAttackReport` (`:559`), `run_gak_attack` (`:616`), `validate_config` (`:782`), `fixture_seed` (`:827`), `retry_selected_exemplar` (`:740`) |
| tests | `:6432-8147` | one `#[cfg(test)] mod tests` (`:6433`), comment-delimited UNIT sections each with its own `use super::{…}` (`:6434`, `:7006`, `:7320`, `:7796`) |

**Coupling that constrains the split (must be honored, verified by grep):**

- `type EdgeMap` is defined at `:1679` (solver region) but used by the generator
  region too: `:995`,`:1001`,`:1018`,`:1042` (`truth_letter_permutations` /
  `permutation_recovery_fraction`). So `EdgeMap` is a **shared** alias, not
  solver-private.
- `CosetEdge` (`:2341`, deck) is used across the marginalization region:
  `:3432`,`:3471`,`:3525`,`:3575`,`:3597`,`:3702`,`:4319`. Deck ↔ marginalization
  share it.
- `spacing_filter` (defined `:2511`, deck) is used by the **eyes** region at
  `:5370`. This is the *only* private generator/solver/deck symbol the eyes
  section reaches backward for, besides the `DEFAULT_BEAM_WIDTH` const (`:3348`,
  consumed via `EYES_DEFAULT_BEAM_WIDTH` at `:4406`).
- `glyphs_to_values` (`:2038`, solver) is used by generator (`:1318`), deck
  (`:3084`), marginalization (`:3880`,`:4263`,`:4287`) — shared utility.
- `mean_f64` (`:3306`, deck) is used by marginalization (`:4182-4184`).
- The eyes section uses `GakAttackError` 26× but **none** of the deck/marginal
  private types (`CosetEdge`, `SmallSupportPrior`, `GakAttackConfig` all 0
  hits in `:4333-6431`). The eyes seam is therefore the cleanest cut in the file.
- `run_gak_attack` (`:616`) is the cross-cutting orchestrator: it calls
  `generate_fixture` (`:633`), `evaluate_fixture` (`:634`), `run_deck_attack_sweep`
  (`:684`), `run_marginalization_sweep` (`:697`). It belongs in `mod.rs`.

### External references that pin the public path

`gak_attack` is referenced by flat path from three places:

- `src/main.rs:12` imports `gak_attack` from `noita_eye_puzzle::{…}`; uses
  `gak_attack::{DEFAULT_SEED, DEFAULT_SEEDS_PER_KIND, DEFAULT_CYCLIC_ORDER,
  DEFAULT_DIHEDRAL_HALF_ORDER, DEFAULT_NUM_PT_LETTERS, DEFAULT_PHRASE_REPEATS,
  DEFAULT_PHRASE_LEN, DEFAULT_SMALL_SUPPORT_RADIUS, GakAttackConfig,
  EyesAttackConfig, EYES_DEFAULT_SEED, EYES_DEFAULT_TRIALS, EYES_DEFAULT_BEAM_WIDTH,
  run_gak_attack, run_gak_attack_eyes}` (`src/main.rs:148-224`,`:625-626`,
  `:687-713`).
- `src/report.rs:10` imports `gak_attack` from `crate::{…}`; uses
  `gak_attack::{GakAttackError, GakAttackReport, EyesAttackReport,
  SmallSupportValidation}` and reaches nested report fields like
  `report.deck`/`report.marginalization` (`src/report.rs:73-143`,
  `:4127-4504`).
- `tests/gak_attack_cli.rs` drives the `gak-attack` subcommand end-to-end and
  asserts gate-independent honesty strings (`tests/gak_attack_cli.rs:16-348`).
  This is the de-facto golden master that brief 01 hardens.

The full external symbol surface (grep `gak_attack::[A-Za-z_]+` over
`src/main.rs src/report.rs tests/*.rs`, deduped) is exactly 22 symbols: the 8
`DEFAULT_*` consts, the 4 `EYES_DEFAULT_*` consts (`SEED`, `TRIALS`,
`BEAM_WIDTH`, `CANDIDATES_DIR`), the 2 report-consumed consts
`EYE_READING_ALPHABET_SIZE` and `EYES_MATERIAL_EFFECT_FRACTION`,
`GakAttackConfig`, `EyesAttackConfig`, `GakAttackReport`,
`EyesAttackReport`, `GakAttackError`, `SmallSupportValidation`, `run_gak_attack`,
`run_gak_attack_eyes`. `report.rs` additionally walks into `GakAttackReport`'s
`deck`/`marginalization` fields, so the public types behind those fields
(`DeckAttackReport` `:3158`, `MarginalizationReport` `:3956`, `TractabilityPoint`
`:3122`, `MarginalizationPoint` `:3916`, `DeckAttackOutcome` `:3024`, etc.) must
stay reachable at `crate::gak_attack::*`.

### `include_str!` — none here

`gak_attack.rs` contains **no `include_str!`** (verified by grep). This split
therefore needs **no asset-path re-rooting**; the only place that matters is the
later repo-wide role-dir move (brief 07B handles re-rooting `corpus.rs`,
`generator.rs`, and `language.rs` asset paths). This brief is a pure move of
`.rs` source with no embedded-asset edits.

## Target design (concrete API / types / layout)

### `gak_attack/` module directory

Replace `src/gak_attack.rs` with `src/gak_attack/` containing seven files. The
split follows the seams above; **siblings are private submodules of `gak_attack`**
and share items via `pub(crate)` (or `pub(super)`) visibility, so no item that is
private today becomes crate-public except where it already was `pub`.

```
src/gak_attack/
  mod.rs            // module doc (moved verbatim from gak_attack.rs:1-54);
                    //   `use` of the sub-files; the cross-cutting orchestrator
                    //   run_gak_attack (+ GakAttackReport, validate_config,
                    //   fixture_seed, retry_selected_exemplar, GroupKind/
                    //   HiddenSubgroupKind, GakAttackConfig, RecoveryRate);
                    //   the `pub use` re-export block (see decision below)
  error.rs          // GakAttackError + its 5 From impls (:250-396)
  generator.rs      // synthetic generator: GroupKind tables, generate_fixture,
                    //   realized_structure, group/dihedral tables,
                    //   apply_small_support, repeated_phrase_template, the
                    //   shared EdgeMap alias + glyphs_to_values/symbol_from_usize
                    //   utilities (these are pub(crate) — used by 3 siblings)
  solver.rs         // GCTAK solver: solve_gctak, collect_chain_links,
                    //   recover_letter_permutations, decode_letters_by_edge,
                    //   SmallUnionFind, evaluate_fixture; the deck attack
                    //   (generate_deck_fixture, run_deck_attack[_sweep], CosetEdge,
                    //   ContextAction, ChainSubstrate, build_chain_substrate,
                    //   spacing_filter, mean_f64)
  marginalization.rs// SmallSupportPrior, BeamItem, split_column_evidence,
                    //   beam_recover_column, run_marginalization_attack/sweep,
                    //   MarginalizationReport, SmallSupportValidation
  eyes.rs           // the entire :4333-6431 block (EyesAttackConfig/Report,
                    //   run_gak_attack_eyes, eyes_* helpers, render_eyes_*)
  fixtures.rs       // (optional) DeckFixture/SyntheticFixture/RealizedStructure
                    //   struct defs + their fixture-seed helpers, IF that keeps
                    //   generator.rs/solver.rs under ~1,500 lines; otherwise fold
                    //   into generator.rs and drop this file
```

The overview names the `gak/` directory (`gak/ (split from gak_attack.rs)`,
`00-OVERVIEW.md:156`) but does not enumerate its individual files; this brief
proposes the per-seam split into `generator.rs`, `solver.rs`,
`marginalization.rs`, `fixtures.rs`, `eyes.rs`, `error.rs`.
**Deviation
note:** the GCTAK solver and the deck attack are placed together in `solver.rs`
because they share `EdgeMap`, `collect_chain_links`, and the chain-substrate
primitives and together total ~1,900 lines (the largest sibling; acceptable, but
see the fixtures.rs/deck.rs escape hatch). If a future reviewer
prefers a separate `deck.rs`, that is a trivial follow-on — call it out, do
not silently diverge from this brief's six-file split.

**Shared-item visibility rules (mechanical):**

- `EdgeMap` (`:1679`), `glyphs_to_values` (`:2038`), `symbol_from_usize`
  (`:1403`), `CosetEdge` (`:2341`), `mean_f64` (`:3306`), `spacing_filter`
  (`:2511`), `DEFAULT_BEAM_WIDTH` (`:3348`), `evaluate_fixture` (`:1313`):
  these are referenced across the new file boundaries, so promote each from
  private to `pub(crate)` (or `pub(super)`), and qualify call sites as
  `crate::gak_attack::generator::EdgeMap` etc. (or rely on a
  `use super::generator::*` in the consuming file). Nothing here changes a *body*.
- `GakAttackError` (`:250`), `GakAttackConfig` (`:405`), `GakAttackReport`
  (`:559`), all the `pub` report structs, and the `DEFAULT_*`/`EYES_*` consts are
  already `pub`; they stay `pub` in their new home.

### Public-path decision: **keep paths stable via re-exports**

**Decision: re-export from `gak_attack/mod.rs`, do NOT rewrite call sites.**
Concretely, `mod.rs` ends with a `pub use` block re-surfacing the full external
symbol set (the 22 symbols main.rs/report.rs/tests use, plus the report sub-types
report.rs walks into) so that `crate::gak_attack::Foo` resolves identically before
and after. Two sub-options exist for the directory name:

1. **Rename `gak_attack` → `gak`** (matches the overview's `gak/` dir name) and
   update the *three* import lines (`src/main.rs:12`, `src/report.rs:10`, and any
   `use crate::gak_attack` inside the crate) plus add `pub mod gak;` to lib.rs.
   Then everything downstream uses `gak::Foo` unchanged because of the `pub use`
   re-exports inside `gak/mod.rs`. This is **one import-line edit per consumer**,
   not a wholesale rewrite.
2. Keep the literal name `gak_attack` by naming the directory `src/gak_attack/`
   (Rust allows `gak_attack/mod.rs`). Then **zero** consumer edits are needed.

**Recommended: option 2 (`src/gak_attack/mod.rs`).** It is the strictly
behavior- and path-preserving choice: `crate::gak_attack::*` and
`noita_eye_puzzle::gak_attack::*` resolve identically before and after, so
`main.rs`, `report.rs`, and every test compile untouched. The overview's `gak/`
name is cosmetic; honor its *structure* (one file per seam) while keeping the
proven path. Record this deviation from the overview's literal `gak/` directory
name in the PR description. (If a later brief renames to `gak`, that is a
one-line follow-up once 04/05/06 have settled.)

Rationale for re-exports over a global rewrite: it **decouples this brief from
brief 04**. Brief 04 reuses the beam-search internals; if 07A rewrote every call
site and 04 also moves beam-search into `attack/solve`, the two collide on the
same lines. Re-exports keep the public surface frozen so 04 can pull
`pub(crate)` internals via `crate::gak_attack::marginalization::*` without a merge
conflict on import paths.

## Implementation steps (ordered, each independently committable & green)

Each step ends green under `make verify` and changes **no fn body**. Run the
golden-master suite from brief 01 (or, until 01 lands, `cargo test` +
`tests/*_cli.rs`) after every step and confirm byte-identical CLI output.

1. **Land brief 01 first.** Do not start until the golden-master safety net is
   green on this branch (or merge it in). The golden master is the proof that
   steps 2–7 are behavior-preserving. Coordinate with 04 on sequencing (see
   "Risks").

2. **Extract `gak_attack/error.rs`.** Create `src/gak_attack/mod.rs` as a copy of
   today's `gak_attack.rs`, then move `GakAttackError` + its 5 `From` impls
   (`:250-396`) into `error.rs`; `mod error;` + `use error::GakAttackError;` (or
   `pub use`) in `mod.rs`. Delete the old `src/gak_attack.rs`. Verify the
   `crate::gak_attack::GakAttackError` path still resolves (report.rs:73). Green.

3. **Extract `eyes.rs`** (the cleanest seam). Move `:4333-6431` plus the matching
   `use super::{…}` test block (the eyes UNIT 2c section, `:7796+`) into
   `eyes.rs`/`#[cfg(test)] mod tests` inside it. Promote `spacing_filter` and
   `DEFAULT_BEAM_WIDTH` to `pub(crate)` so `eyes.rs` reaches them via
   `crate::gak_attack::solver::spacing_filter` (or a `use`). `pub use eyes::{…}`
   the eyes public surface. Green; CLI `gak-attack-eyes` output unchanged.

4. **Extract `generator.rs`.** Move the generator seam (`:120-249`, `:733-1402`)
   + its UNIT test block. Promote the shared `EdgeMap`/`glyphs_to_values`/
   `symbol_from_usize` to `pub(crate)`. Re-export `GroupKind`,
   `HiddenSubgroupKind`, `generate_fixture` as needed by `mod.rs`'s orchestrator.
   Green.

5. **Extract `solver.rs`** (GCTAK + deck). Move `:1403-2138` and the deck region
   `:2141-3345` + their UNIT test blocks. Promote `CosetEdge`, `mean_f64`,
   `evaluate_fixture`, `collect_chain_links` to `pub(crate)` for the
   marginalization sibling. Green.

6. **Extract `marginalization.rs`.** Move `:3348-4330` + its UNIT 2b test block.
   It consumes `CosetEdge`/`mean_f64`/`SmallUnionFind` from `solver.rs` via
   `pub(crate)`. `pub use` `MarginalizationReport`, `SmallSupportValidation`,
   `SmallSupportPrior` from `mod.rs`. Green; `report.rs:4185` still sees
   `SmallSupportValidation`.

7. **Settle `mod.rs`.** What remains in `mod.rs` is the doc comment (`:1-54`,
   moved verbatim), the orchestrator `run_gak_attack` + `GakAttackReport` +
   `validate_config`/`fixture_seed`/`retry_selected_exemplar`, the shared
   `GakAttackConfig`/`RecoveryRate`/`DEFAULT_*` consts, and the `pub use`
   re-export block guaranteeing the frozen external surface. Run `cargo public-api`
   or grep the external symbol list to confirm `crate::gak_attack::*` is
   byte-identical. Green.

Steps 2–7 are independently committable (each leaves a compiling, green crate
with the public surface intact).

## Files to create / change / delete

**Create:**
- `src/gak_attack/mod.rs` (doc + orchestrator + re-exports)
- `src/gak_attack/error.rs`
- `src/gak_attack/generator.rs`
- `src/gak_attack/solver.rs`
- `src/gak_attack/marginalization.rs`
- `src/gak_attack/eyes.rs`
- `src/gak_attack/fixtures.rs` (only if it keeps generator/solver under ~1,500
  lines; otherwise omit)

**Change:**
- `src/main.rs:12` and `src/report.rs:10` — **only if** you pick option 1
  (rename to `gak`). Under the recommended option 2 (`gak_attack/`), these are
  **unchanged**.
- `src/lib.rs` — no content change: `pub mod gak_attack;` already names the
  module, and a `src/gak_attack/mod.rs` directory resolves under the same flat
  path with no `lib.rs` edit (option 2). (Option 1 adds `pub mod gak;`.)

**Delete:**
- `src/gak_attack.rs` (replaced by `src/gak_attack/`)

**Do not touch:** `tests/*.rs` (all CLI tests must compile and pass unchanged —
they import the binary, not internal paths), `corpus.rs` data, any fn body, and
**any other module** (the repo-wide role-dir move is brief 07B).

## Success criteria

- `src/gak_attack.rs` no longer exists; `src/gak_attack/` holds 6–7 files, none
  over ~2,000 lines (the combined GCTAK+deck `solver.rs` is the largest at
  ~1,900), each with a single cohesive responsibility.
- The external symbol surface at `crate::gak_attack::*` (22 symbols + report
  sub-types) is byte-identical: `main.rs`, `report.rs`, `tests/gak_attack_cli.rs`
  compile and pass with **no edits** (option 2) or one import-line edit each
  (option 1).
- `git diff` contains **only** moves, `mod`/`use`/`pub use` lines, and
  visibility-keyword changes (`pub(crate)`/`pub(super)`). No fn body diff.
- `make verify` and `make check` green.

## Verification (exactly how to prove it)

1. **Golden master (the load-bearing proof).** Run brief 01's golden-master suite
   before and after; outputs must be byte-identical. Until 01 lands, capture the
   pre-refactor CLI baselines manually and diff:
   ```sh
   for c in "gak-attack --seeds-per-kind 2 --seed 123" \
            "gak-attack-eyes --trials 64 --seed 1"; do
     cargo run --locked -q -- $c > before.$RANDOM.txt
   done   # capture on the pre-refactor commit, re-run after, diff == empty
   ```
   The existing `tests/gak_attack_cli.rs:16-348` already pins the honesty surface;
   it must pass untouched.
2. **Behavior diff = body diff = empty.** `git diff --stat` should show large
   line moves but `git log -p` per step should reveal no `+`/`-` inside any fn
   body (only signatures' visibility keywords, `use`, `mod`, `pub use`). A
   reviewer greps the diff for `fn ` bodies and confirms moves only.
3. **Public-path freeze.** `grep -roE 'gak_attack::[A-Za-z_]+' src/ tests/ | sort
   -u` before vs after must match exactly.
4. **Determinism.** `run_gak_attack_is_deterministic_for_fixed_seed` and the
   `gctak_solver_recovers_*` / `deck_attack_*` / `idea3_*` tests
   (`gak_attack.rs:6432+`) must all still pass — they are the in-crate proof the
   numbers did not move.
5. `make verify` then `make check` (fmt + clippy `-D` + tests + rustdoc `-D` +
   cargo-deny + machete + codespell + shellcheck + release build).

## Risks & honesty caveats

- **Coordination with brief 04 — sequence 07A BEFORE 04 on the shared branch.**
  Both touch `gak_attack.rs`; 04 reuses the beam-search/marginalization internals.
  Recommendation: **land 07A first**, because 07A's re-export decision (option 2)
  freezes the public path and exposes the beam-search internals as
  `pub(crate) crate::gak_attack::marginalization::*` / `solver::*`, which is
  exactly the clean seam 04 wants to import. If 04 lands first, it will reach into
  an 8,147-line flat file and 07A then has to chase 04's new call sites. Concretely:
  finish 07A steps 2–7, merge, *then* start 04. If they must overlap, run them on
  the **same branch** (the overview anticipates this — `00-OVERVIEW.md:183-186`)
  and have 04 import from the new submodule paths from day one.
- **Re-export visibility is the trap.** Promoting a private item to `pub(crate)`
  is fine, but accidentally making it `pub` widens the API surface and can trip
  `missing_docs` (`AGENTS.md:31`). Keep cross-file shares at `pub(crate)`/
  `pub(super)`, which `missing_docs` does not require documenting, and confirm
  `cargo public-api`/the grep shows no *new* `pub` items.
- **Test `use super::{…}` blocks must be repointed.** The single `mod tests`
  splits across sub-files; each UNIT section's `use super::{…}` (`:6434`,`:7006`,
  `:7320`,`:7796`) now resolves against a *different* parent. Move each test block
  next to the code it tests and fix its `use super::`/`use crate::gak_attack::`
  imports. A miscompile here is loud (good); a silently-skipped `#[cfg(test)]`
  module is the danger — confirm `cargo test` runs the *same count* of gak tests
  before and after (50 `#[test]` functions in `gak_attack.rs` today).
- **No claim-surface change.** This refactor touches structure only; the eyes
  honesty caveats (`gak_attack.rs:1-16`, the `:4343-4345` mapping-is-HYPOTHESIS
  banner) move verbatim into `eyes.rs`/`mod.rs`. The claim ceiling is unchanged:
  *the eyes are deterministic, engine-generated, strikingly structured data of
  unknown meaning; unsolved* (`00-OVERVIEW.md:205-210`).

## Out of scope / non-goals

- **No traits, no logic merges, no fn body edits.** `trait Cipher`/`AnyCipher` is
  brief 02; the solve pipeline is brief 04. This brief only moves files within the
  one `gak_attack.rs` god-file.
- **The repo-wide `lib.rs` role-directory regroup** (moving the 32 flat modules,
  including this `gak_attack/` dir, into `core/ data/ analysis/ nulls/ ciphers/
  attack/ experiments/ report/`) is **brief 07B**, sequenced dead last. Not
  touched here.
- **Splitting `ciphers.rs` internals** (one file per cipher family) is brief 02;
  **dissolving `report.rs`** into per-error `Display`/`Report::render` is brief 06
  — neither is touched here.
- **CLI registry / args dedup** is brief 08; the null/experiment harness is brief
  05; external ingest (`core/sequence`) is brief 03 — none are touched here.
- **Renaming `gak_attack` → `gak`** is deferred (option 1); the recommended path
  keeps `gak_attack/` to guarantee zero consumer churn. A later cosmetic rename
  can happen once 04/05/06 have settled.
