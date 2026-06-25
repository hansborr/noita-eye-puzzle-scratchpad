# 06 — Dissolve report.rs + error Display

> One-line: Break the 5,686-line `report.rs` god-file apart so each module owns its own error-formatting (`Display`) and report-rendering (`Report::render`) code, leaving `report.rs` as a small bag of genuinely shared formatting helpers.
> Status: not started · Depends on: 01 (golden-master net); 05 helps · Blocks: 08 (CLI registry calls `Report::render` generically) · Size: M

## Goal & why it matters

`report.rs` is the crate's coupling hub: it `use`s **27 sibling modules** in a
single import block (`src/report.rs:7-13`) and contains **246 functions**
(`grep -cE '^\s*(pub )?(pub\(crate\) )?fn ' src/report.rs` = 246). Every
experiment module's error enum and `*Report` struct is rendered by hand-written
free functions living *here* instead of next to the type they describe. That
means adding or changing one experiment touches `report.rs`, and `report.rs`
re-imports the whole crate — the textbook god-file / hub smell from the overview
(`docs/refactor/00-OVERVIEW.md:49-50`).

This brief does two mechanical, behavior-preserving moves:

1. Replace each `format_*_error` free function with a `Display` impl **colocated
   with the error enum** in its own module. Six modules already do exactly this
   (see Current state), so we are finishing a half-done migration, not inventing
   a pattern.
2. Introduce a `Report` trait with `fn render(&self) -> String` and move each
   `print_*_report` body into a `Report::render` impl **next to its report
   struct**. The CLI (brief 08) then calls `report.render()` generically instead
   of dispatching to 27 distinct free functions.

The payoff: `report.rs` shrinks to shared formatting primitives only, the
per-experiment edit cost drops, and brief 08 gets a uniform `Report` surface to
build a registry on. It serves the maintainability track of the reframe
(`docs/refactor/00-OVERVIEW.md:112-120`): "Each error enum gets a
`Display`/`thiserror` impl … `report.rs` keeps only shared formatting helpers."

## Current state (grounded, with file:line)

**The error-formatting functions (23 `format_*`, 22 distinct CLI entry points).**
All live in `report.rs:19-744`, each a `pub fn format_X_error(error) -> String`
that `match`es the enum and `format!`s a string:

- `format_corpus_error` — `src/report.rs:19`
- `format_agl_gak_error` — `src/report.rs:36`
- `format_gak_attack_error` — `src/report.rs:73`
- `format_periodicity_error` — `src/report.rs:139`
- `format_null_config_error` — `src/report.rs:160` *(internal: only called by `format_null_run_error`)*
- `format_null_run_error` — `src/report.rs:170`
- `format_honeycomb_error` — `src/report.rs:179`
- `format_dof_null_error` — `src/report.rs:192`
- `format_isomorph_null_error` — `src/report.rs:230`
- `format_chaining_error` — `src/report.rs:253`
- `format_chaining_graph_error` — `src/report.rs:283`
- `format_modular_diff_error` — `src/report.rs:323`
- `format_pyry_conditions_error` — `src/report.rs:350`
- `format_perseus_error` — `src/report.rs:373`
- `format_perfect_isomorphism_error` — `src/report.rs:400`
- `format_zero_adjacency_null_error` — `src/report.rs:433`
- `format_tree_residual_error` — `src/report.rs:463`
- `format_cipher_attack_error` — `src/report.rs:509` *(already just `error.to_string()` — see below)*
- `format_grouping_error` — `src/report.rs:515`
- `format_orientation_homogeneity_error` — `src/report.rs:542`
- `format_controls_error` — `src/report.rs:584`
- `format_conditional_structure_error` — `src/report.rs:684`
- `format_transitivity_error` — `src/report.rs:726`

**Six error enums already have a hand-written `Display` impl in their own
module** — this is the target pattern, already used in-crate:
`src/cipher_attack.rs:128` (`impl fmt::Display for CipherAttackError`, with
`impl std::error::Error` at `:165`), `src/agl_gak.rs:130`, `src/ciphers.rs:212`,
`src/glyph.rs:142`, `src/language.rs:79`, `src/perfect_isomorphism.rs:124`.
`format_cipher_attack_error` (`src/report.rs:509-511`) is *already* just
`error.to_string()`, proving the end state works and is wired through the CLI.

**Two cross-cutting facts that are load-bearing for byte-identical output:**

- `orders::GridError` (`src/orders.rs:28`) has **no `Display` impl** — every
  error renders it via Debug as `format!("grid/order error: {grid_error:?}")`
  (e.g. `src/report.rs:38`, `:141`, `:181`, `:194`, `:233`). The new `Display`
  impls **must keep `{grid_error:?}` (Debug)**, not invent a `GridError`
  `Display`, or the rendered text changes. (Adding a `GridError` `Display` is
  explicitly out of scope here.)
- Some `format_*` fns delegate to siblings: `format_null_run_error` →
  `format_null_config_error` (`src/report.rs:172`); `format_tree_residual_error`
  → `format_perseus_error` (`src/report.rs:469`); `format_transitivity_error` →
  `format_chaining_graph_error` (`src/report.rs:733`). Under `Display` these
  become `{config_error}`, `{perseus_error}`, `{chaining_error}` once the inner
  enums have `Display` — migrate the inner enum first so the outer one can use
  it.

**The report-printing functions (27 distinct CLI entry points + ~140 private
helpers).** All in `report.rs:747-5686`. Each public `print_*_report` is a
`pub fn print_X_report(report: &module::XReport)` that writes directly to stdout
with `println!`, calling many module-private helpers. Representative bodies:
`print_honeycomb_report` (`src/report.rs:993-1025`) calls
`print_honeycomb_pair_section` (`:1027`), `print_honeycomb_position_section`
(`:1057`), `print_honeycomb_parity_section` (`:1074`),
`print_honeycomb_interpretation` (`:1105`), plus shared `format_probability`,
`print_tail_line`, etc. The 27 entry points (all called from `main.rs`):

`print_null_report` (`:747`), `print_dof_null_report` (`:800`),
`print_honeycomb_report` (`:993`), `print_periodicity_report` (`:1147`),
`print_monoalphabetic_control_report` (`:1527`), `print_isomorph_control_report`
(`:1597`), `print_pipeline_null_report` (`:1670`), `print_isomorph_null_report`
(`:1708`), `print_conditional_structure_report` (`:1795`), `print_perseus_report`
(`:2347`), `print_perfect_isomorphism_report` (`:2504`),
`print_zero_adjacency_null_report` (`:2766`), `print_tree_residual_report`
(`:2882`), `print_chaining_report` (`:3002`), `print_chaining_graph_report`
(`:3119`), `print_transitivity_report` (`:3236`), `print_modular_diff_report`
(`:3325`), `print_pyry_conditions_report` (`:3500`), `print_cipher_attack_report`
(`:3691`), `print_agl_gak_report` (`:3914`), `print_gak_attack_report` (`:4086`),
`print_gak_attack_eyes_report` (`:4406`), `print_input_randomness_report`
(`:4808`), `print_orientation_homogeneity_report` (`:4847`),
`print_grouping_report` (`:5066`), `print_orders_report` (`:5346`),
`print_report` (`:5394`).

**The CLI consumes these by free function.** `main.rs` has **53** `report::`
call sites (`grep -c 'report::' src/main.rs`), the error path and the print path
side by side, e.g.:

```
651:  eprintln!("{}", report::format_corpus_error(error));
665:  report::print_null_report(&report);
673:  eprintln!("AGL-GAK error: {}", report::format_agl_gak_error(&error));
677:  report::print_agl_gak_report(&report);
```

`print_report` (`src/report.rs:5394`) and `print_orders_report`
(`src/report.rs:5346`) are **not** keyed to a single `*Report` struct — the
first takes `(label, &Sequence)`, the second takes
`(&GridSummary, &[NamedOrderStats], &[NamedReadingLayerFlatnessStats])`. These
two stay as free functions or get a thin wrapper; they do not fit the
single-struct `Report` trait cleanly (see Out of scope).

**Output mechanism is `println!` to stdout, not a returned `String`.** Every
`print_*` body prints directly (e.g. `src/report.rs:994-1024`). The target
`render(&self) -> String` must build a `String` (via `use std::fmt::Write;` +
`writeln!`/`write!`) and the CLI prints it once. Trailing-newline behavior is
load-bearing: a body ending in `println!(...)` emits a final `\n`; the assembled
`String` must reproduce the exact same bytes (including the final newline) and
the CLI must use `print!("{}", report.render())` — **not** `println!` — so no
extra `\n` is appended.

**Golden-master coverage.** Brief 01 provides the full-output byte-for-byte net.
Today's CLI tests (e.g. `tests/honeycomb_cli.rs:9-44`) only assert *substrings*
via `common::assert_contains` (`tests/common/mod.rs:39`), and capture stdout from
the compiled binary (`tests/common/mod.rs:6-16`). Substring tests will *not*
catch a dropped/added newline or reordered line — **brief 01's full-output
snapshot is the mandatory guard for this refactor**; do not start until 01 is
merged.

**Dependency reality for `thiserror`.** `thiserror` is **not** a current
dependency (`grep thiserror Cargo.toml Cargo.lock` = empty;
`Cargo.toml [dependencies]` lists only `clap` and `statrs`). The crate already
hand-writes `Display` for six error enums with zero ceremony. **Decision:
hand-write `Display` (do not add `thiserror`).** Rationale: (a) it adds a
proc-macro dependency tree gated by `deny.toml`'s `multiple-versions = "deny"`
and license allow-list for no behavioral gain; (b) the existing six impls set
the house style; (c) AGENTS.md says justify every new dependency by use and keep
the surface minimal. Hand-writing is strictly less risk and keeps the diff
purely mechanical. (If a future brief wants `thiserror` crate-wide it can be
argued separately; this brief does not need it.)

## Target design (concrete API / types / layout)

### 1. `Display` on each error enum, colocated

For each module `m` with `format_m_error`, add to `src/m.rs`, next to the enum:

```rust
use std::fmt;

impl fmt::Display for HoneycombError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
        }
    }
}

impl std::error::Error for HoneycombError {}
```

The arm text must be **byte-identical** to the current `format_honeycomb_error`
arms (`src/report.rs:179-188`): copy the `format!` payloads verbatim, swapping
`format!(...)` → `write!(f, ...)` and `.to_owned()` strings → `write!(f, "...")`.
Add `impl std::error::Error` to match the existing `CipherAttackError` precedent
(`src/cipher_attack.rs:165`) so the enums are real errors (enables `?` ergonomics
later; harmless now). For delegating arms, prefer `{inner}` once `inner` has
`Display` (e.g. `TreeResidualError::Perseus(e) => write!(f, "shared-region
reconstruction error: {e}")`, replacing the `format_perseus_error(e)` call at
`src/report.rs:469`) — **verify the inner `Display` produces the same bytes** as
the old `format_*` delegate before deleting the delegate.

`format_null_config_error` (`src/report.rs:160`) is internal-only; fold it into
`NullConfigError`'s `Display`, then `NullRunError`'s `Display` uses
`{config_error}`.

### 2. `Report` trait + `render` impls, colocated

Add a tiny trait. Proposed home: a new `src/report/mod.rs` (after brief 07's
directory split) or, pre-07, a new `pub trait` at the top of the surviving
`report.rs`. Keep the name from the overview (`docs/refactor/00-OVERVIEW.md:116`):

```rust
/// A domain report that can render itself to user-facing CLI text.
pub trait Report {
    /// Renders this report as a complete, newline-terminated block of text.
    fn render(&self) -> String;
}
```

For each `print_X_report(report: &m::XReport)`, add `impl Report for m::XReport`
in `src/m.rs` (next to the struct), moving the body and converting `println!` →
`writeln!(out, ...)` into a `let mut out = String::new();`:

```rust
use std::fmt::Write as _;
use crate::report::Report;

impl Report for HoneycombReport {
    fn render(&self) -> String {
        let mut out = String::new();
        // body of the former print_honeycomb_report, println! -> writeln!(out, ...)
        // (writeln! into a String cannot fail; bind the Result to `_ = writeln!(...)`
        //  or use `let _ =` to satisfy `unused_results`/`must_use` lints — see Risks)
        out
    }
}
```

The dozens of module-private helpers (`print_honeycomb_pair_section` etc.,
`src/report.rs:1027-1144`) move into the same module as private free functions
taking `&mut String` (or `&self`), e.g. `fn pair_section(out: &mut String,
report: &HoneycombReport)`. Helpers that are **shared across modules** stay in
`report.rs` (see §3).

### 3. What survives in `report.rs` (shared helpers only)

After migration, `report.rs` keeps the formatting primitives used by **more than
one** experiment module, re-exported as `pub(crate)` so the moved `render` impls
can call them. Candidates from the helper inventory (`src/report.rs`):
`format_probability` (`:3905`), `format_percent` (`:3901`), `fraction`
(`:3893`), `print_interval`/`format` of `WilsonInterval` (`:5338`),
`format_widths` (`:5410`), `format_span` (`:5418`), `yes_no` (`:4759`),
`preview_text` (`:4763`), `format_positions` (`:4779`), `format_optional_*`
(`:4792-4800`), `format_u8_values`/`format_usize_values` (`:4726`/`:4737`),
`NumberRange` + `format_number_range`/`format_ratio_range` (`:4582`/`:4590`),
`counted_form` (`:1326`), `format_seed_list` (`:1478`). **Before moving a helper,
`grep` its call sites**: if it is called from exactly one `print_*` family,
co-locate it with that report; if from several, keep it shared. Convert the
shared `print_*`-style helpers (e.g. `print_interval`) to return/append-to a
`String` so the `render` impls can use them.

`print_report` (`:5394`) and `print_orders_report` (`:5346`) — the two
multi-arg/non-struct entry points — stay as `pub fn … -> String` shared
renderers (rename to `render_sequence_report` / `render_orders_report` or keep
the name but change the return type), since they have no single owning struct.

### 4. CLI call-site shape (sets up brief 08)

After this brief, `main.rs` collapses both paths to `Display` + `Report`:

```rust
// error path: Display via {}
Err(error) => { eprintln!("AGL-GAK error: {error}"); ... }
// print path: Report::render, printed once with print! (no trailing newline added)
print!("{}", report.render());
```

Brief 08 then iterates a registry of `Box<dyn Report>` / `impl Report` instead
of 27 named functions. This brief does **not** build the registry — it only
makes `render` exist so 08 can.

## Implementation steps (ordered, each independently committable & green)

Migrate **one experiment at a time**; each step is a self-contained green commit
guarded by brief 01's golden master. Recommended ordering puts the
self-contained, no-delegation experiments first, leaves the delegating ones
(perseus→tree_residual, chaining_graph→transitivity, null_config→null_run) for
after their dependencies, and does the two big god-modules (gak_attack,
conditional_structure) last.

0. **Prerequisite gate.** Confirm brief 01's full-output golden master is merged
   and green on this branch (run `make verify`; inspect the snapshot files exist
   for every subcommand). If 01 is not merged, stop. (05 helping is optional: if
   05 has already moved null orchestration, re-check the helper inventory in §3.)

1. **Introduce the `Report` trait only.** Add `pub trait Report { fn render(&self)
   -> String; }` (in `report.rs` for now; brief 07 will move it under
   `src/report/mod.rs`). No impls yet. `make verify`. Commit. (Trait is unused →
   may trip `dead_code`; if so add `#[allow(dead_code, reason = "impls land in
   subsequent commits of brief 06")]` and remove the allow once the first impl
   lands, or land step 2 in the same commit.)

2. **Migrate the leaf modules with an already-existing `Display`.** For
   `cipher_attack`, `agl_gak`, `perfect_isomorphism` (Display already present at
   `src/cipher_attack.rs:128`, `src/agl_gak.rs:130`,
   `src/perfect_isomorphism.rs:124`): delete `format_cipher_attack_error`
   (`:509`), `format_agl_gak_error` (`:36`), `format_perfect_isomorphism_error`
   (`:400`); update `main.rs` to use `{error}`. Then add `impl Report` for
   `CipherAttackReport` / `AglGakReport` / `PerfectIsomorphismReport`, moving the
   `print_*` bodies + their private helpers. Update `main.rs` print sites to
   `print!("{}", report.render())`. One commit per module. `make verify` + golden
   diff each.

3. **Migrate the self-contained, non-delegating experiments**, one commit each:
   `corpus` (`CorpusError` Display; note `print_report` for `Sequence` is shared,
   not corpus-owned), `honeycomb`, `periodicity`, `dof_null`, `isomorph_null`,
   `chaining`, `modular_diff`, `pyry_conditions`, `perseus`,
   `zero_adjacency_null`, `grouping`, `orientation_homogeneity`, `controls`
   (both `MonoalphabeticControlReport` and `IsomorphControlReport`),
   `pipeline_null` (`InputRandomnessReport` + the `print_pipeline_null_report`
   which reuses `null::NullReport`). For each: (a) add `Display` + `Error` impl
   colocated, copying arm text verbatim from the corresponding `format_*` in
   `report.rs`; (b) add `impl Report` for the struct(s), moving body + private
   helpers; (c) delete the old `format_*`/`print_*` from `report.rs`; (d) update
   `main.rs`. `make verify` + golden diff after each.

4. **Migrate `null`** (`NullConfigError` + `NullRunError`, and `NullReport`).
   Fold `format_null_config_error` into `NullConfigError::Display`, then
   `NullRunError::Display` uses `{config_error}`. Move `print_null_report`
   (`:747`) into `impl Report for NullReport`. Verify the `print_pipeline_null_report`
   (`:1670`, also takes `&null::NullReport`) reuse still renders identically — it
   may need a distinct wrapper since two CLI paths render the same struct
   differently; if so keep a small free `render_pipeline_null(&NullReport)` shared
   fn rather than a second `Report` impl on the same type.

5. **Migrate the delegating experiments** (after their inner deps are done):
   `tree_residual` (uses `PerseusError` Display — step 3 must have done perseus
   first; replace `format_perseus_error` delegate at `:469` with `{perseus_error}`),
   `chaining_graph` then `transitivity` (transitivity delegates to
   `format_chaining_graph_error` at `:733`; do `chaining_graph` first, then
   transitivity uses `{chaining_error}`). `conditional_structure` (large: ~25
   private helpers `src/report.rs:1854-2345`) — move all colocated.

6. **Migrate `gak_attack`** (`GakAttackError`, `GakAttackReport`,
   `EyesAttackReport`). This is the largest: `print_gak_attack_report` (`:4086`),
   `print_gak_attack_eyes_report` (`:4406`), and ~12 private helpers
   (`src/report.rs:4120-4404`, `:4434-4564`). `gak_attack.rs` is already a
   7,967-line god-file (brief 07 splits it) — **coordinate with brief 07**: if 07
   has split `gak_attack.rs` into `src/attack/gak/`, place the `impl Report` next
   to the report struct in whichever sub-file owns it. Do this on the same branch
   as, or after, 07's gak split to avoid a three-way merge.

7. **Consolidate shared helpers + the two non-struct renderers.** Once every
   `print_*_report` is gone, audit what remains in `report.rs`: keep only the
   cross-module helpers (§3), convert them to `String`-appending form, mark
   `pub(crate)`, and re-point the moved `render` impls at them. Convert
   `print_orders_report` (`:5346`) and `print_report` (`:5394`) to
   `render_*  -> String`. Update their two `main.rs` call sites
   (`src/main.rs:647`, `:1048`, `:1055`). `report.rs` should now be a few hundred
   lines of helpers + the `Report` trait. `make check` (full gate incl.
   `cargo-machete` to confirm no now-unused imports remain, and the giant
   `use crate::{...}` block at `src/report.rs:8-13` shrinks). Commit.

Each commit: `make verify` green; brief-01 golden master byte-identical; and the
existing `assert_contains` CLI tests still pass.

## Files to create / change / delete

**Change (add `Display` + `Error` + `impl Report`, colocated):** `src/corpus.rs`,
`src/honeycomb.rs`, `src/periodicity.rs`, `src/null.rs`, `src/dof_null.rs`,
`src/isomorph_null.rs`, `src/chaining.rs`, `src/chaining_graph.rs`,
`src/modular_diff.rs`, `src/pyry_conditions.rs`, `src/perseus.rs`,
`src/perfect_isomorphism.rs`, `src/zero_adjacency_null.rs`,
`src/tree_residual.rs`, `src/cipher_attack.rs`, `src/grouping.rs`,
`src/orientation_homogeneity.rs`, `src/controls.rs`,
`src/conditional_structure.rs`, `src/transitivity.rs`, `src/agl_gak.rs`,
`src/gak_attack.rs`, `src/pipeline_null.rs`. (Six already have `Display`:
`cipher_attack`, `agl_gak`, `perfect_isomorphism`, plus `ciphers`/`glyph`/
`language` which have no `format_*` and are untouched.)

**Change (shrink to shared helpers + `Report` trait):** `src/report.rs` — drops
all 23 `format_*_error` and all 27 `print_*_report` entry points and their
module-private helpers; keeps cross-module helpers + the two non-struct
renderers; the `use crate::{...}` hub import (`:8-13`) shrinks to only what the
shared helpers need.

**Change (call sites):** `src/main.rs` — 53 `report::` sites become `{error}`
(error path) and `print!("{}", report.render())` (print path), plus the two
shared renderers (`render_orders_report`, `render_sequence_report`).

**Change (trait home, with brief 07):** if 07 lands first, the `Report` trait and
remaining helpers live in `src/report/mod.rs`; otherwise they stay in
`src/report.rs`. Coordinate the trait's final path with 07 and 08.

**Create:** none strictly required (the trait can live in the surviving
`report.rs`). Optionally `src/report/mod.rs` if co-sequenced with 07.

**Delete:** none as files in this brief — `report.rs` survives, much smaller.
(Brief 07 may later move the surviving `report.rs` into `src/report/`.)

## Success criteria

- Every `format_*_error` free function is gone from `report.rs`; every error enum
  that had one now has a colocated `impl fmt::Display` (+ `impl std::error::Error`)
  in its own module. `grep -n 'pub fn format_.*_error' src/report.rs` returns
  nothing.
- Every `print_*_report` CLI entry point is gone from `report.rs`; the
  corresponding `*Report` struct has `impl Report` in its own module.
  `grep -n 'pub fn print_' src/report.rs` returns only the two intentional
  non-struct shared renderers (or nothing if they are renamed `render_*`).
- A `pub trait Report { fn render(&self) -> String; }` exists, with one impl per
  report struct; the CLI calls it generically (no per-experiment `print_*`
  dispatch except the two shared renderers).
- `report.rs` is reduced to shared formatting helpers + the trait (target: well
  under ~700 lines vs. today's 5,686), and its hub import block no longer pulls
  in all 27 modules.
- No new dependency (`Cargo.toml`/`Cargo.lock` unchanged except possibly nothing;
  `thiserror` not added). `cargo machete` clean.
- **Behavior-preserving:** brief 01's golden master is byte-identical for every
  subcommand; every existing `tests/*_cli.rs` `assert_contains` still passes; the
  corpus base-7 decode cross-check and all null calibrations are numerically
  unchanged.

## Verification (exactly how to prove it)

1. `make verify` green after every commit (fmt-check + clippy `-D` + tests +
   rustdoc `-D` + cargo-deny). `make check` before final push (adds
   `cargo machete` — proves the removed imports really were removable).
2. **Golden-master diff (the primary guard).** Run brief 01's snapshot suite
   before and after each commit; require byte-for-byte equality. Manually spot a
   trailing-newline case: capture `noita-eye honeycomb --trials 5 --seed 123`
   stdout before/after and `diff` — must be empty (this is the canonical case for
   the `println!`→`writeln!`-into-`String` + `print!` conversion).
3. **Error-path parity.** For at least one error per migrated module, trigger the
   CLI error (e.g. an out-of-range `--trials 0` or similar invalid arg) and
   confirm the stderr text is byte-identical to pre-refactor. The existing
   negative test helper `run_noita_eye_failure` (`tests/common/mod.rs:23`) and
   suites that use it cover several of these; extend a snapshot for any error
   variant not already exercised.
4. **New unit tests (cheap, colocated):** add a `#[test]` per migrated module
   asserting `error.to_string()` equals the exact former `format_*` output for
   one representative variant (especially the delegating arms:
   `NullRunError::Config`, `TreeResidualError::Perseus`,
   `TransitivityError::ChainingGraph`), and a `render()` smoke test asserting a
   known headline line is present. These live in the module's `#[cfg(test)]` block
   where `unwrap`/`indexing_slicing` are relaxed (`clippy.toml`).
5. Confirm the `use crate::{...}` block at the top of the surviving `report.rs`
   has shrunk (it imported 27 modules at `src/report.rs:8-13`).

## Risks & honesty caveats

- **Trailing newline / line-order drift is the #1 risk.** `println!` appends `\n`;
  the assembled `String` must reproduce it, and the CLI must switch to
  `print!("{}", report.render())` (no `println!`) so no extra `\n` is added. The
  existing `assert_contains` tests **cannot** catch this (substring-only,
  `tests/common/mod.rs:39`) — rely on brief 01's full-output golden master.
- **`GridError` Debug formatting must be preserved.** It has no `Display`
  (`src/orders.rs:28`); every error renders it as `{grid_error:?}`. Keep `{:?}` in
  the new `Display` arms. Do **not** add a `GridError` `Display` in this brief —
  that would change the rendered text and is a separate change.
- **Delegating arms must reuse the *new* `Display`, verified equal.** Migrate the
  inner enum first; before deleting `format_perseus_error`/`format_null_config_error`/
  `format_chaining_graph_error`, assert the inner `Display` output matches the old
  delegate byte-for-byte (step 4 unit tests). A subtle wording diff here silently
  changes a downstream message.
- **`unused_results`/`must_use` on `writeln!`.** `writeln!`/`write!` into a
  `String` return `Result` and cannot fail, but the lint set (`-D warnings`,
  AGENTS.md) flags the unused `Result`. Bind it: `let _ = writeln!(out, …);` or
  `use std::fmt::Write as _;` and rely on the established crate idiom — check how
  the six existing `Display` impls and any in-crate `String`-builder handle it and
  match that style (avoid a bare `#[allow]`; AGENTS.md forbids bare allows).
- **`missing_docs`.** The new `pub trait Report`, its `render` method, and any
  newly-`pub`/`pub(crate)` helper need doc comments (`missing_docs` is `-D`).
  `Display`/`Error` trait impls do not need item docs.
- **Two non-struct renderers don't fit the trait.** `print_report` (`&Sequence`)
  and `print_orders_report` (three slices) have no owning struct. Do not force a
  newtype just to fit the trait — keep them as shared `render_* -> String` free
  functions. This is an accepted, documented deviation from "every report is a
  `Report`."
- **Coordinate `gak_attack` with brief 07.** `gak_attack.rs` is split by 07; doing
  its `impl Report` independently risks a three-way merge. Sequence step 6 after
  07's gak split, or do both on one branch (overview's noted conflict point,
  `docs/refactor/00-OVERVIEW.md:181-182`).
- **No claim/statistic changes.** This is pure presentation plumbing: no reported
  number, p-value, decode, or null calibration may move. The claim ceiling is
  untouched.

## Out of scope / non-goals

- Adding `thiserror` (decided against — hand-write `Display`, matching the six
  existing in-crate impls; revisit crate-wide only via a separate dependency
  brief).
- Adding a `Display` impl to `orders::GridError` (would change rendered text;
  separate change).
- The `Experiment` trait / experiment registry and the CLI registry — that is
  brief 08 (`docs/refactor/00-OVERVIEW.md:171`); this brief only delivers the
  `Report::render` surface 08 builds on.
- Splitting `gak_attack.rs` / module-directory reorg — brief 07.
- Null/experiment-harness dedup — brief 05 (it *helps* by collapsing duplicated
  null orchestration before the helper-inventory step, but is not required).
- Changing any report's *content* or wording. Every arm string and report line is
  copied verbatim; rewording is a follow-up, not part of this behavior-preserving
  refactor.
