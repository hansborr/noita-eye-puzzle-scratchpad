# 07 — Split god-files + module layout

> One-line: split the 7,967-line `gak_attack.rs` into a cohesive `gak/` module
> directory and regroup the 31 flat `pub mod`s in `lib.rs` into the role
> directories from the overview — a pure, behavior-preserving move-refactor that
> changes no fn body and no reported number.
> Status: not started · Depends on: 01 (golden-master safety net) · Coordinates
> with: 04 (both touch `gak_attack.rs`) · Blocks: nothing hard; eases 04/05/06/08
> navigation · Size: M

## Goal & why it matters

Two files hold 30% of the crate: `gak_attack.rs` is 7,967 lines and `report.rs`
is 5,686 lines (`src/lib.rs:82`, `src/lib.rs:99`; line counts verified via
`wc -l`). `gak_attack.rs` is the single worst offender — it bundles a synthetic
GAK generator, a GCTAK solver, a deck-cipher attack, a hidden-state
marginalization/beam-search, the eyes Step-3 path, an error type, and a
1,640-line test module into one flat namespace. That size is what makes brief 04
("reuse its beam-search") and brief 06/08 painful to navigate.

This brief does the **mechanical** half of the cleanup: move code into files and
directories that match the target layout in `00-OVERVIEW.md:139-156`, with **zero
behavior change**. No statistic, no decode, no CLI byte may move. It is
deliberately scoped *under* brief 02 (which introduces `trait Cipher`) and brief
04 (which builds the solve pipeline): this brief only relocates existing items so
those briefs have clean seams to build on. It does **not** introduce traits,
merge logic, or touch fn bodies.

`report.rs` and `ciphers.rs` are named in the overview as further split
candidates, but `report.rs` is owned by brief 06 (dissolve into per-error
`Display` + `Report::render`) and `ciphers.rs` by brief 02 (`Cipher` trait + one
file per family). To avoid double-ownership churn, **this brief does not split
those two files' contents** — it only *relocates* them into the `ciphers/` and
`report/` role directories as thin moves (mod.rs holding today's content), so 02
and 06 land their real splits inside the new directories. See "Out of scope".

## Current state (grounded, with file:line)

### `gak_attack.rs` natural seams (all line numbers from the live file)

| Seam | Range | Key items |
| ---- | ----- | --------- |
| Imports + shared consts | `:52-105` | `use crate::{chaining_graph,ciphers,glyph,…}` (`:56-69`); `DEFAULT_SEED` (`:72`), `DEFAULT_SEEDS_PER_KIND` (`:74`), `SOLVER_WINDOW_LEN` (`:100`) |
| **error** | `:244-374` | `enum GakAttackError` (`:244`) + its 7 `From` impls (`:340`,`:346`,`:352`,`:358`,`:364`) |
| **generator** (synthetic) | `:114-243`, `:697-1370` | `GroupKind` (`:114`), `HiddenSubgroupKind` (`:161`), `RealizedStructure` (`:201`), `SyntheticFixture` (`:225`), `generate_fixture` (`:813`), `realized_structure` (`:908`), `group_table`/`dihedral_table` (`:1052`/`:1077`), `apply_small_support` (`:1172`), `repeated_phrase_template` (`:1205`) |
| **solver** (GCTAK) | `:1371-2096` | `GctakSolution` (`:1371`), `solve_gctak` (`:1442`), `collect_chain_links` (`:1583`), `recover_letter_permutations` (`:1774`), `complete_permutation` (`:1866`), `decode_letters_by_edge` (`:1946`), `SmallUnionFind` (`:2021`), `type EdgeMap` (`:1637`), `glyphs_to_values` (`:1996`), `symbol_from_usize` (`:1362`) |
| deck attack | `:2099-3303` | `DeckLetterRegime` (`:2099`), `DeckFixture` (`:2129`), `generate_deck_fixture` (`:2173`), `CosetEdge` (`:2299`), `ContextAction` (`:2315`), `ChainSubstrate` (`:2355`), `build_chain_substrate` (`:2387`), `run_deck_attack` (`:2550`), `DeckAttackOutcome` (`:2982`), `run_deck_attack_sweep` (`:3162`), `mean_f64` (`:3264`) |
| marginalization / beam | `:3306-4264` | `SmallSupportPrior` (`:3329`), `BeamItem` (`:3385`), `SplitColumnEvidence` (`:3417`), `split_column_evidence` (`:3432`), `beam_recover_column` (`:3513`), `run_marginalization_attack` (`:3628`), `MarginalizationReport` (`:3898`), `SmallSupportValidation` (`:3945`), `run_marginalization_sweep` (`:4059`) |
| **eyes** (Step 3) | `:4325-6326` | `EYE_*`/`EYES_*` consts (`:4325-4344`), `EyesAttackConfig` (`:4348`), `EyesAttackReport` (`:4431`), `run_gak_attack_eyes` (`:4657`), `eyes_message_evidence` (`:5273`), `eyes_mapping_null` (`:5821`), `write_eyes_candidate_record` (`:5923`), render helpers (`:5945-6326`) |
| top orchestrator | `:531-696` | `GakAttackReport` (`:531`), `run_gak_attack` (`:588`), `validate_config` (`:753`), `fixture_seed` (`:784`), `retry_selected_exemplar` (`:711`) |
| tests | `:6327-7967` | one `#[cfg(test)] mod tests` (`:6328`), comment-delimited UNIT sections each with its own `use super::{…}` (`:6329`, `:6864`, `:7178`, `:7619`) |

**Coupling that constrains the split (must be honored, verified by grep):**

- `type EdgeMap` is defined at `:1637` (solver region) but used by the generator
  region too: `:952`,`:958`,`:975`,`:999` (`truth_letter_permutations` /
  `permutation_recovery_fraction`). So `EdgeMap` is a **shared** alias, not
  solver-private.
- `CosetEdge` (`:2299`, deck) is used across the marginalization region:
  `:3387`,`:3419`,`:3473`,`:3580`,`:3601`,`:3697`,`:4258`. Deck ↔ marginalization
  share it.
- `spacing_filter` (defined `:2469`, deck) is used by the **eyes** region at
  `:5302`. This is the *only* private generator/solver/deck symbol the eyes
  section reaches backward for, besides the `DEFAULT_BEAM_WIDTH` const (`:3306`,
  consumed at `:4344`).
- `glyphs_to_values` (`:1996`, solver) is used by generator (`:1277`), deck
  (`:3042`), marginalization (`:3822`,`:4202`,`:4226`) — shared utility.
- `mean_f64` (`:3264`, deck) is used by marginalization (`:4121-4123`).
- The eyes section uses `GakAttackError` 26× but **none** of the deck/marginal
  private types (`CosetEdge`, `SmallSupportPrior`, `GakAttackConfig` all 0
  hits in `:4325-6326`). The eyes seam is therefore the cleanest cut in the file.
- `run_gak_attack` (`:588`) is the cross-cutting orchestrator: it calls
  `generate_fixture` (`:605`), `evaluate_fixture` (`:606`), `run_deck_attack_sweep`
  (`:656`), `run_marginalization_sweep` (`:668`). It belongs in `mod.rs`.

### External references that pin the public path

`gak_attack` is referenced by flat path from three places:

- `src/main.rs:12` imports `gak_attack` from `noita_eye_puzzle::{…}`; uses
  `gak_attack::{DEFAULT_SEED, DEFAULT_SEEDS_PER_KIND, DEFAULT_CYCLIC_ORDER,
  DEFAULT_DIHEDRAL_HALF_ORDER, DEFAULT_NUM_PT_LETTERS, DEFAULT_PHRASE_REPEATS,
  DEFAULT_PHRASE_LEN, DEFAULT_SMALL_SUPPORT_RADIUS, GakAttackConfig,
  EyesAttackConfig, EYES_DEFAULT_SEED, EYES_DEFAULT_TRIALS, EYES_DEFAULT_BEAM_WIDTH,
  run_gak_attack, run_gak_attack_eyes}` (`src/main.rs:148-209`,`:619-620`,
  `:681-707`).
- `src/report.rs:10` imports `gak_attack` from `crate::{…}`; uses
  `gak_attack::{GakAttackError, GakAttackReport, EyesAttackReport,
  SmallSupportValidation}` and reaches nested report fields like
  `report.deck`/`report.marginalization` (`src/report.rs:73-135`,
  `:4086-4496`).
- `tests/gak_attack_cli.rs` drives the `gak-attack` subcommand end-to-end and
  asserts gate-independent honesty strings (`tests/gak_attack_cli.rs:16-338`).
  This is the de-facto golden master that brief 01 hardens.

The full external symbol surface (grep `gak_attack::[A-Za-z_]+` over
`src/main.rs src/report.rs tests/*.rs`) is exactly: the 8 `DEFAULT_*` consts, the
3 `EYES_DEFAULT_*` consts, `GakAttackConfig`, `EyesAttackConfig`, `GakAttackReport`,
`EyesAttackReport`, `GakAttackError`, `SmallSupportValidation`, `run_gak_attack`,
`run_gak_attack_eyes`. `report.rs` additionally walks into `GakAttackReport`'s
`deck`/`marginalization` fields, so the public types behind those fields
(`DeckAttackReport` `:3116`, `MarginalizationReport` `:3898`, `TractabilityPoint`
`:3080`, `MarginalizationPoint` `:3858`, `DeckAttackOutcome` `:2982`, etc.) must
stay reachable at `crate::gak_attack::*`.

### `lib.rs` flat layout

`src/lib.rs:72-103` is a flat wall of 31 `pub mod` declarations (the doc comment
`:1-70` describes each). No role grouping; every module is a direct child of the
crate root. The overview's target groups them under `core/ data/ analysis/
nulls/ ciphers/ attack/ experiments/ report/` (`00-OVERVIEW.md:143-156`).

## Target design (concrete API / types / layout)

### A. `gak/` module directory

Replace `src/gak_attack.rs` with `src/gak/` containing seven files. The split
follows the seams above; **siblings are private submodules of `gak`** and share
items via `pub(crate)` (or `pub(super)`) visibility, so no item that is private
today becomes crate-public except where it already was `pub`.

```
src/gak/
  mod.rs            // module doc (moved verbatim from gak_attack.rs:1-50);
                    //   `use` of the sub-files; the cross-cutting orchestrator
                    //   run_gak_attack (+ GakAttackReport, validate_config,
                    //   fixture_seed, retry_selected_exemplar, GroupKind/
                    //   HiddenSubgroupKind, GakAttackConfig, RecoveryRate);
                    //   the `pub use` re-export block (see decision below)
  error.rs          // GakAttackError + its 7 From impls (:244-374)
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
  eyes.rs           // the entire :4325-6326 block (EyesAttackConfig/Report,
                    //   run_gak_attack_eyes, eyes_* helpers, render_eyes_*)
  fixtures.rs       // (optional) DeckFixture/SyntheticFixture/RealizedStructure
                    //   struct defs + their fixture-seed helpers, IF that keeps
                    //   generator.rs/solver.rs under ~1,500 lines; otherwise fold
                    //   into generator.rs and drop this file
```

The overview's file list names `gak/generator.rs`, `gak/solver.rs`,
`gak/marginalization.rs`, `gak/fixtures.rs`, `gak/eyes.rs`, `gak/error.rs`
(`00-OVERVIEW.md:152`). This brief realizes exactly those names. **Deviation
note:** the GCTAK solver and the deck attack are placed together in `solver.rs`
because they share `EdgeMap`, `collect_chain_links`, and the chain-substrate
primitives and together total ~1,700 lines (acceptable). If a future reviewer
prefers a separate `gak/deck.rs`, that is a trivial follow-on — call it out, do
not silently diverge from the overview's six-file list.

**Shared-item visibility rules (mechanical):**

- `EdgeMap` (`:1637`), `glyphs_to_values` (`:1996`), `symbol_from_usize`
  (`:1362`), `CosetEdge` (`:2299`), `mean_f64` (`:3264`), `spacing_filter`
  (`:2469`), `DEFAULT_BEAM_WIDTH` (`:3306`), `evaluate_fixture` (`:1272`):
  these are referenced across the new file boundaries, so promote each from
  private to `pub(crate)` (or `pub(super)`), and qualify call sites as
  `crate::gak::generator::EdgeMap` etc. (or rely on a `use super::generator::*`
  in the consuming file). Nothing here changes a *body*.
- `GakAttackError` (`:244`), `GakAttackConfig` (`:377`), `GakAttackReport`
  (`:531`), all the `pub` report structs, and the `DEFAULT_*`/`EYES_*` consts are
  already `pub`; they stay `pub` in their new home.

### B. Public-path decision: **keep paths stable via re-exports**

**Decision: re-export from `gak/mod.rs`, do NOT rewrite call sites.** Concretely,
`mod.rs` ends with a `pub use` block re-surfacing the full external symbol set
(the 14 items main.rs/report.rs/tests use, plus the report sub-types report.rs
walks into) so that `crate::gak_attack::Foo` — wait: the module is renamed to
`gak`, so the import name changes from `gak_attack` to `gak`. Two sub-options:

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
brief 04**. Brief 04 reuses the beam-search internals; if 07 rewrote every call
site and 04 also moves beam-search into `attack/solve`, the two collide on the
same lines. Re-exports keep the public surface frozen so 04 can pull
`pub(crate)` internals via `crate::gak_attack::marginalization::*` without a merge
conflict on import paths.

### C. `lib.rs` role grouping

Group the 31 flat modules (`src/lib.rs:72-103`) into the overview's directories
(`00-OVERVIEW.md:143-156`). Use Rust's `path` attribute or directory `mod.rs`
re-export shims so the **public paths stay flat** (`crate::analysis::…` keeps
working) while the *files* move into role dirs. Concretely, the cleanest
zero-churn mechanism is a role `mod.rs` that re-exports, e.g.:

```rust
// src/lib.rs
mod analysis_group;            // private umbrella module
pub use analysis_group::*;     // keeps crate::analysis path? — NO, see note
```

That does not preserve `crate::analysis`. To keep flat paths exactly, instead
move the *file* and point `lib.rs` at it with `#[path]`:

```rust
// src/lib.rs — path stays `crate::analysis`, file lives in analysis/
#[path = "analysis/analysis.rs"] pub mod analysis;
#[path = "nulls/null.rs"]        pub mod null;
// …one line per module, grouped/commented by role
```

This is the recommended `lib.rs` mechanism: **files move into role directories;
public paths are byte-identical.** Grouping per `00-OVERVIEW.md:143-156`:

- `core/` ← `glyph`, `trigram` (sequence/ingest is brief 03's territory — leave
  `glyph` here)
- `data/` ← `corpus`, `generator`
- `analysis/` ← `analysis`, `isomorph`, `periodicity`, `conditional_structure`,
  `modular_diff`, `grouping`, `orientation_homogeneity`, `transitivity`,
  `chaining`, `chaining_graph`, `perfect_isomorphism`, `honeycomb`, `orders`
- `nulls/` ← `null`, `isomorph_null`, `zero_adjacency_null`, `dof_null`,
  `pipeline_null`, `tree_residual`, `perseus`
- `ciphers/` ← `ciphers` (as `ciphers/mod.rs`, content unchanged — brief 02 owns
  the internal split)
- `attack/` ← `cipher_attack`, `agl_gak`, `gak_attack/` (the dir from part A);
  `solve/` is brief 04's
- `experiments/` ← `pyry_conditions`, `controls`, and the structural-battery
  modules that are clearly experiment drivers (assign conservatively; if a
  module is ambiguous, leave it where the overview is silent and note it)
- `report/` ← `report` (as `report/mod.rs`, content unchanged — brief 06 owns the
  dissolve)

**Deviation latitude:** the overview's grouping is a proposal
(`00-OVERVIEW.md:9-14`). Where a module's role is ambiguous (e.g. `chaining_graph`
is used by both analysis and the gak attack), pick the directory the overview
names and add a one-line `// role: …` comment; do not invent new top-level dirs.

## Implementation steps (ordered, each independently committable & green)

Each step ends green under `make verify` and changes **no fn body**. Run the
golden-master suite from brief 01 (or, until 01 lands, `cargo test` +
`tests/*_cli.rs`) after every step and confirm byte-identical CLI output.

1. **Land brief 01 first.** Do not start until the golden-master safety net is
   green on this branch (or merge it in). The golden master is the proof that
   steps 2–8 are behavior-preserving. Coordinate with 04 on sequencing (see
   "Risks").

2. **Extract `gak_attack/error.rs`.** Create `src/gak_attack/mod.rs` as a copy of
   today's `gak_attack.rs`, then move `GakAttackError` + its 7 `From` impls
   (`:244-374`) into `error.rs`; `mod error;` + `use error::GakAttackError;` (or
   `pub use`) in `mod.rs`. Delete the old `src/gak_attack.rs`. Verify the
   `crate::gak_attack::GakAttackError` path still resolves (report.rs:73). Green.

3. **Extract `eyes.rs`** (the cleanest seam). Move `:4325-6326` plus the matching
   `use super::{…}` test block (the eyes UNIT section, `:7619+`) into
   `eyes.rs`/`#[cfg(test)] mod tests` inside it. Promote `spacing_filter` and
   `DEFAULT_BEAM_WIDTH` to `pub(crate)` so `eyes.rs` reaches them via
   `crate::gak_attack::solver::spacing_filter` (or a `use`). `pub use eyes::{…}`
   the eyes public surface. Green; CLI `gak-attack-eyes` output unchanged.

4. **Extract `generator.rs`.** Move the generator seam (`:114-243`, `:697-1370`)
   + its UNIT test block. Promote the shared `EdgeMap`/`glyphs_to_values`/
   `symbol_from_usize` to `pub(crate)`. Re-export `GroupKind`,
   `HiddenSubgroupKind`, `generate_fixture` as needed by `mod.rs`'s orchestrator.
   Green.

5. **Extract `solver.rs`** (GCTAK + deck). Move `:1371-2096` and the deck region
   `:2099-3303` + their UNIT test blocks. Promote `CosetEdge`, `mean_f64`,
   `evaluate_fixture`, `collect_chain_links` to `pub(crate)` for the
   marginalization sibling. Green.

6. **Extract `marginalization.rs`.** Move `:3306-4264` + its UNIT 2b test block.
   It consumes `CosetEdge`/`mean_f64`/`SmallUnionFind` from `solver.rs` via
   `pub(crate)`. `pub use` `MarginalizationReport`, `SmallSupportValidation`,
   `SmallSupportPrior` from `mod.rs`. Green; `report.rs:4179` still sees
   `SmallSupportValidation`.

7. **Settle `mod.rs`.** What remains in `mod.rs` is the doc comment (`:1-50`,
   moved verbatim), the orchestrator `run_gak_attack` + `GakAttackReport` +
   `validate_config`/`fixture_seed`/`retry_selected_exemplar`, the shared
   `GakAttackConfig`/`RecoveryRate`/`DEFAULT_*` consts, and the `pub use`
   re-export block guaranteeing the frozen external surface. Run `cargo public-api`
   or grep the external symbol list to confirm `crate::gak_attack::*` is
   byte-identical. Green.

8. **Regroup `lib.rs` into role dirs.** Move each module file into its role
   directory and repoint `lib.rs` with `#[path = "<role>/<mod>.rs"] pub mod <mod>;`
   (one commit, or a few commits grouped by role dir for smaller diffs). Move
   `ciphers.rs` → `ciphers/mod.rs`, `report.rs` → `report/mod.rs`,
   `gak_attack/` already done. Confirm every `crate::<mod>::…` path is unchanged.
   Green.

Steps 2–7 are independently committable (each leaves a compiling, green crate
with the public surface intact). Step 8 can be one commit per role directory.

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
- Role directories: `src/core/`, `src/data/`, `src/analysis/`, `src/nulls/`,
  `src/ciphers/`, `src/attack/`, `src/experiments/`, `src/report/` (as the new
  homes for moved files)

**Change:**
- `src/lib.rs` — regroup the 31 `pub mod` decls into role-commented blocks using
  `#[path]` (paths stay flat); the doc comment (`:1-70`) stays, optionally
  re-grouped to mirror the dirs.
- `src/main.rs:12` and `src/report.rs:10` — **only if** you pick option 1
  (rename to `gak`). Under the recommended option 2 (`gak_attack/`), these are
  **unchanged**.

**Delete:**
- `src/gak_attack.rs` (replaced by `src/gak_attack/`)
- (After moves) `src/ciphers.rs`, `src/report.rs`, and each regrouped module's
  old top-level path — each becomes `<role>/<name>.rs`.

**Do not touch:** `tests/*.rs` (all CLI tests must compile and pass unchanged —
they import the binary, not internal paths), `corpus.rs` data, any fn body.

## Success criteria

- `src/gak_attack.rs` no longer exists; `src/gak_attack/` holds 6–7 files, none
  over ~1,800 lines, each with a single cohesive responsibility.
- `lib.rs`'s modules live in the eight role directories from
  `00-OVERVIEW.md:143-156`; the public crate path of every module is unchanged.
- The external symbol surface at `crate::gak_attack::*` (14 items + report
  sub-types) is byte-identical: `main.rs`, `report.rs`, `tests/gak_attack_cli.rs`
  compile and pass with **no edits** (option 2) or one import-line edit each
  (option 1).
- `git diff` contains **only** moves, `mod`/`use`/`#[path]` lines, and
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
   The existing `tests/gak_attack_cli.rs:16-338` already pins the honesty surface;
   it must pass untouched.
2. **Behavior diff = body diff = empty.** `git diff --stat` should show large
   line moves but `git log -p` per step should reveal no `+`/`-` inside any fn
   body (only signatures' visibility keywords, `use`, `mod`, `#[path]`). A
   reviewer greps the diff for `fn ` bodies and confirms moves only.
3. **Public-path freeze.** `grep -roE 'gak_attack::[A-Za-z_]+' src/ tests/ | sort
   -u` before vs after must match exactly. Same for each regrouped module path.
4. **Determinism.** `run_gak_attack_is_deterministic_for_fixed_seed` and the
   `gctak_solver_recovers_*` / `deck_attack_*` / `idea3_*` tests
   (`gak_attack.rs:6327+`) must all still pass — they are the in-crate proof the
   numbers did not move.
5. `make verify` then `make check` (fmt + clippy `-D` + tests + rustdoc `-D` +
   cargo-deny + machete + codespell + shellcheck + release build).

## Risks & honesty caveats

- **Coordination with brief 04 — sequence 07 BEFORE 04 on the shared branch.**
  Both touch `gak_attack.rs`; 04 reuses the beam-search/marginalization internals.
  Recommendation: **land 07 first**, because 07's re-export decision (option 2)
  freezes the public path and exposes the beam-search internals as
  `pub(crate) crate::gak_attack::marginalization::*` / `solver::*`, which is
  exactly the clean seam 04 wants to import. If 04 lands first, it will reach into
  a 7,967-line flat file and 07 then has to chase 04's new call sites. Concretely:
  finish 07 steps 2–7, merge, *then* start 04. If they must overlap, run them on
  the **same branch** (the overview anticipates this — `00-OVERVIEW.md:180-182`)
  and have 04 import from the new submodule paths from day one.
- **Re-export visibility is the trap.** Promoting a private item to `pub(crate)`
  is fine, but accidentally making it `pub` widens the API surface and can trip
  `missing_docs` (`AGENTS.md:31`). Keep cross-file shares at `pub(crate)`/
  `pub(super)`, which `missing_docs` does not require documenting, and confirm
  `cargo public-api`/the grep shows no *new* `pub` items.
- **Test `use super::{…}` blocks must be repointed.** The single `mod tests`
  splits across sub-files; each UNIT section's `use super::{…}` (`:6329`,`:6864`,
  `:7178`,`:7619`) now resolves against a *different* parent. Move each test block
  next to the code it tests and fix its `use super::`/`use crate::gak_attack::`
  imports. A miscompile here is loud (good); a silently-skipped `#[cfg(test)]`
  module is the danger — confirm `cargo test` runs the *same count* of gak tests
  before and after (131 `#[test]`/`fn`/`mod` markers today).
- **`#[path]` vs nested `mod` for lib.rs.** `#[path]` keeps flat public paths with
  minimal churn but is slightly unusual; an alternative is plain nested modules +
  `pub use` shims. Either is acceptable — pick `#[path]` for path-fidelity and
  document the choice. Do not change a public path silently; that would break
  `main.rs`/`report.rs`/tests and is a behavior change in disguise.
- **No claim-surface change.** This refactor touches structure only; the eyes
  honesty caveats (`gak_attack.rs:1-16`, the `:4319-4321` mapping-is-HYPOTHESIS
  banner) move verbatim into `eyes.rs`/`mod.rs`. The claim ceiling is unchanged:
  *the eyes are deterministic, engine-generated, strikingly structured data of
  unknown meaning; unsolved* (`00-OVERVIEW.md:202-206`).

## Out of scope / non-goals

- **No traits, no logic merges, no fn body edits.** `trait Cipher`/`AnyCipher` is
  brief 02; the solve pipeline is brief 04. This brief only moves files.
- **Splitting `ciphers.rs` internals** (one file per cipher family) is brief 02 —
  here it only becomes `ciphers/mod.rs` unchanged.
- **Dissolving `report.rs`** into per-error `Display`/`Report::render` is brief 06
  — here it only becomes `report/mod.rs` unchanged.
- **CLI registry / args dedup** is brief 08; the null/experiment harness is brief
  05; external ingest (`core/sequence`) is brief 03 — none are touched here.
- **Renaming `gak_attack` → `gak`** is deferred (option 1); the recommended path
  keeps `gak_attack/` to guarantee zero consumer churn. A later cosmetic rename
  can happen once 04/05/06 have settled.
