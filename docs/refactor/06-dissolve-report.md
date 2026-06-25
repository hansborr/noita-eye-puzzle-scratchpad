# 06 — Dissolve report.rs + error Display

> One-line: Break the 5,694-line `report.rs` god-file apart so each module owns its own error-formatting (`Display`) and report-rendering (`Report::render`) code, leaving `report.rs` as a small bag of genuinely shared formatting helpers.
> Status: not started · Depends on: 01 (golden-master net); 05 helps · Blocks: 08 (CLI registry calls `Report::render` generically) · Size: M

## Goal & why it matters

`report.rs` is the crate's coupling hub: it `use`s **27 sibling modules** in a
single import block (`src/report.rs:7-13`) and contains **246 functions**
(`grep -cE '^\s*(pub )?(pub\(crate\) )?fn ' src/report.rs` = 246). Every
experiment module's error enum and `*Report` struct is rendered by hand-written
free functions living *here* instead of next to the type they describe. That
means adding or changing one experiment touches `report.rs`, and `report.rs`
re-imports the whole crate — the textbook god-file / hub smell from the overview
(`docs/refactor/00-OVERVIEW.md:53-54`).

This brief does two mechanical, behavior-preserving moves:

1. Replace each `format_*_error` free function with a `Display` impl **colocated
   with the error enum** in its own module. Six modules already do exactly this
   (see Current state), so we are finishing a half-done migration, not inventing
   a pattern.
2. Introduce a `Report` trait with `fn render(&self) -> String` and move each
   `print_*_report` body into a `Report::render` impl **next to its report
   struct**. The CLI (brief 08) then calls `report.render()` generically instead
   of dispatching to 27 distinct free functions.

The report-rendering move (#2) carries **two independent risks** that this brief
deliberately keeps in separate, separately-green commits: (A) the
`println!`-to-stdout → `writeln!`-into-`String` + trailing-newline conversion
(the byte-parity risk), and (B) relocating the renderer body out of `report.rs`
into the owning module (the move risk). The implementation splits each module's
migration into **Phase A** (convert `print_X_report` → `render_X_report(&report)
-> String` **in place inside `report.rs`**, CLI switches to `print!`) and
**Phase B** (move the now-`String`-returning render into `impl Report::render` in
the owning module, delete the `report.rs` free fn). Phase A isolates the
newline/stdout-parity risk with zero relocation; Phase B is then a pure move
whose bytes are already proven stable by Phase A.

The payoff: `report.rs` shrinks to shared formatting primitives only, the
per-experiment edit cost drops, and brief 08 gets a uniform `Report` surface to
build a registry on. It serves the maintainability track of the reframe
(`docs/refactor/00-OVERVIEW.md:123-124`): "Each error enum gets a
`Display`/`thiserror` impl … `report.rs` keeps only shared formatting helpers."

## Current state (grounded, with file:line)

**The error-formatting functions (23 `format_*`, 22 distinct CLI entry points).**
All live in `report.rs:19-750`, each a `pub fn format_X_error(error) -> String`
that `match`es the enum and `format!`s a string:

- `format_corpus_error` — `src/report.rs:19`
- `format_agl_gak_error` — `src/report.rs:36`
- `format_gak_attack_error` — `src/report.rs:73`
- `format_periodicity_error` — `src/report.rs:145`
- `format_null_config_error` — `src/report.rs:166` *(internal: only called by `format_null_run_error`)*
- `format_null_run_error` — `src/report.rs:176`
- `format_honeycomb_error` — `src/report.rs:185`
- `format_dof_null_error` — `src/report.rs:198`
- `format_isomorph_null_error` — `src/report.rs:236`
- `format_chaining_error` — `src/report.rs:259`
- `format_chaining_graph_error` — `src/report.rs:289`
- `format_modular_diff_error` — `src/report.rs:329`
- `format_pyry_conditions_error` — `src/report.rs:356`
- `format_perseus_error` — `src/report.rs:379`
- `format_perfect_isomorphism_error` — `src/report.rs:406`
- `format_zero_adjacency_null_error` — `src/report.rs:439`
- `format_tree_residual_error` — `src/report.rs:469`
- `format_cipher_attack_error` — `src/report.rs:515` *(already just `error.to_string()` — see below)*
- `format_grouping_error` — `src/report.rs:521`
- `format_orientation_homogeneity_error` — `src/report.rs:548`
- `format_controls_error` — `src/report.rs:590`
- `format_conditional_structure_error` — `src/report.rs:690`
- `format_transitivity_error` — `src/report.rs:732`

**Six in-crate types already have a hand-written `Display` impl in their own
module** — this is the target pattern, already used in-crate (five of the six are
error enums; `glyph::Glyph` is a value type whose `Display` follows the same
colocated style):
`src/cipher_attack.rs:128` (`impl fmt::Display for CipherAttackError`, with
`impl std::error::Error` at `:165`), `src/agl_gak.rs:130`,
`src/ciphers.rs:212` (`CipherError`), `src/glyph.rs:142` (`Glyph`),
`src/language.rs:79` (`LanguageError`),
`src/perfect_isomorphism.rs:124` (`PerfectIsomorphismError`).
`format_cipher_attack_error` (`src/report.rs:515-517`) is *already* just
`error.to_string()`, proving the end state works and is wired through the CLI.

**Two cross-cutting facts that are load-bearing for byte-identical output:**

- `orders::GridError` (`src/orders.rs:28`) has **no `Display` impl** — every
  error renders it via Debug as `format!("grid/order error: {grid_error:?}")`
  (e.g. `src/report.rs:38`, `:148`, `:188`, `:201`, `:239`). The new `Display`
  impls **must keep `{grid_error:?}` (Debug)**, not invent a `GridError`
  `Display`, or the rendered text changes. (Adding a `GridError` `Display` is
  explicitly out of scope here.)
- Some `format_*` fns delegate to siblings: `format_null_run_error` →
  `format_null_config_error` (`src/report.rs:178`); `format_tree_residual_error`
  → `format_perseus_error` (`src/report.rs:477`); `format_transitivity_error` →
  `format_chaining_graph_error` (`src/report.rs:740`). Under `Display` these
  become `{config_error}`, `{perseus_error}`, `{chaining_error}` once the inner
  enums have `Display` — migrate the inner enum first so the outer one can use
  it.

**The report-printing functions (27 distinct CLI entry points + ~140 private
helpers).** All in `report.rs:753-5694`. Each public `print_*_report` is a
`pub fn print_X_report(report: &module::XReport)` that writes directly to stdout
with `println!`, calling many module-private helpers. Representative bodies:
`print_honeycomb_report` (`src/report.rs:999-1031`) calls
`print_honeycomb_pair_section` (`:1033`), `print_honeycomb_position_section`
(`:1063`), `print_honeycomb_parity_section` (`:1080`),
`print_honeycomb_interpretation` (`:1111`), plus shared `format_probability`,
`print_tail_line`, etc. The 27 entry points (all called from `main.rs`):

`print_null_report` (`:753`), `print_dof_null_report` (`:806`),
`print_honeycomb_report` (`:999`), `print_periodicity_report` (`:1153`),
`print_monoalphabetic_control_report` (`:1533`), `print_isomorph_control_report`
(`:1603`), `print_pipeline_null_report` (`:1676`), `print_isomorph_null_report`
(`:1714`), `print_conditional_structure_report` (`:1801`), `print_perseus_report`
(`:2353`), `print_perfect_isomorphism_report` (`:2510`),
`print_zero_adjacency_null_report` (`:2772`), `print_tree_residual_report`
(`:2888`), `print_chaining_report` (`:3008`), `print_chaining_graph_report`
(`:3125`), `print_transitivity_report` (`:3242`), `print_modular_diff_report`
(`:3331`), `print_pyry_conditions_report` (`:3506`), `print_cipher_attack_report`
(`:3697`), `print_agl_gak_report` (`:3920`), `print_gak_attack_report` (`:4092`),
`print_gak_attack_eyes_report` (`:4412`), `print_input_randomness_report`
(`:4816`), `print_orientation_homogeneity_report` (`:4855`),
`print_grouping_report` (`:5074`), `print_orders_report` (`:5354`),
`print_report` (`:5402`).

**The CLI consumes these by free function.** `main.rs` has **53** `report::`
call sites (`grep -c 'report::' src/main.rs`), the error path and the print path
side by side, e.g.:

```
657:  eprintln!("{}", report::format_corpus_error(error));
671:  report::print_null_report(&report);
679:  eprintln!("AGL-GAK error: {}", report::format_agl_gak_error(&error));
683:  report::print_agl_gak_report(&report);
```

`print_report` (`src/report.rs:5402`) and `print_orders_report`
(`src/report.rs:5354`) are **not** keyed to a single `*Report` struct — the
first takes `(label, &Sequence)`, the second takes
`(&GridSummary, &[NamedOrderStats], &[NamedReadingLayerFlatnessStats])`. These
two stay as free functions or get a thin wrapper; they do not fit the
single-struct `Report` trait cleanly (see Out of scope).

**Output mechanism is `println!` to stdout, not a returned `String`.** Every
`print_*` body prints directly (e.g. `src/report.rs:1000-1030`). The target
`render(&self) -> String` must build a `String` (via `use std::fmt::Write;` +
`writeln!`/`write!`) and the CLI prints it once. Trailing-newline behavior is
load-bearing: a body ending in `println!(...)` emits a final `\n`; the assembled
`String` must reproduce the exact same bytes (including the final newline) and
the CLI must use `print!("{}", report.render())` — **not** `println!` — so no
extra `\n` is appended.

**Golden-master coverage.** Brief 01 provides the full-output byte-for-byte net.
Today's CLI tests (e.g. `tests/honeycomb_cli.rs:8-33`) only assert *substrings*
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
arms (`src/report.rs:185-194`): copy the `format!` payloads verbatim, swapping
`format!(...)` → `write!(f, ...)` and `.to_owned()` strings → `write!(f, "...")`.
Add `impl std::error::Error` to match the existing `CipherAttackError` precedent
(`src/cipher_attack.rs:165`) so the enums are real errors (enables `?` ergonomics
later; harmless now). For delegating arms, prefer `{inner}` once `inner` has
`Display` (e.g. `TreeResidualError::Perseus(e) => write!(f, "shared-region
reconstruction error: {e}")`, replacing the `format_perseus_error(e)` call at
`src/report.rs:477`) — **verify the inner `Display` produces the same bytes** as
the old `format_*` delegate before deleting the delegate.

`format_null_config_error` (`src/report.rs:166`) is internal-only; fold it into
`NullConfigError`'s `Display`, then `NullRunError`'s `Display` uses
`{config_error}`.

### 2. In-place `render_X_report(&report) -> String` (Phase A — byte parity, no move)

**Before** moving anything, convert each `print_X_report` to return a `String`
**while it still lives in `report.rs`**. This isolates the
`println!`→`writeln!`-into-`String` + trailing-newline conversion under brief 01's
golden master, with **zero** module relocation:

```rust
// IN PLACE in report.rs — same module, same private helpers, only the I/O shape changes.
use std::fmt::Write as _;

pub fn render_honeycomb_report(report: &HoneycombReport) -> String {
    let mut out = String::new();
    // body of the former print_honeycomb_report, println! -> writeln!(out, ...)
    // private helpers stay in report.rs for now, threaded a `&mut String`
    out
}
```

The CLI then switches to `print!("{}", report::render_honeycomb_report(&r))` —
`print!`, **not** `println!`, so no extra `\n` is appended past the final
`writeln!`. Because the body, its private helpers, and the shared helpers are all
still in `report.rs`, the **only** thing this commit changes is the output
mechanism (stdout-`println!` → `String`-`writeln!` + `print!`); the golden master
proves the bytes are identical. This is the byte-parity risk, isolated.

### 3. `Report` trait + `render` impls, colocated (Phase B — pure move)

Add a tiny trait. Proposed home: a new `src/report/mod.rs` (after brief 07B's
directory split) or, pre-07B, a new `pub trait` at the top of the surviving
`report.rs`. Keep the name from the overview (`docs/refactor/00-OVERVIEW.md:120`):

```rust
/// A domain report that can render itself to user-facing CLI text.
pub trait Report {
    /// Renders this report as a complete, newline-terminated block of text.
    fn render(&self) -> String;
}
```

For each `render_X_report(report: &m::XReport)` produced by Phase A, move the body
into `impl Report for m::XReport` in `src/m.rs` (next to the struct) and delete
the `report.rs` free fn. Because Phase A already converted `println!` →
`writeln!(out, ...)` and proved the bytes under the golden master, **Phase B is a
pure move** — the `String`-building code is relocated unchanged:

```rust
use std::fmt::Write as _;
use crate::report::Report;

impl Report for HoneycombReport {
    fn render(&self) -> String {
        let mut out = String::new();
        // the Phase-A render_honeycomb_report body, moved verbatim (already uses
        // writeln!(out, ...); no I/O change here)
        // (writeln! into a String cannot fail; bind the Result to `_ = writeln!(...)`
        //  or use `let _ =` to satisfy `unused_results`/`must_use` lints — see Risks)
        out
    }
}
```

In Phase B the dozens of module-private helpers (`print_honeycomb_pair_section`
etc., `src/report.rs:1033-1150`) move into the same module alongside their
`render` impl as private free functions taking `&mut String` (or `&self`), e.g.
`fn pair_section(out: &mut String, report: &HoneycombReport)`. Helpers that are
**shared across modules** stay in `report.rs` (see §4).

### 4. What survives in `report.rs` (shared helpers only)

After migration, `report.rs` keeps the formatting primitives used by **more than
one** experiment module, re-exported as `pub(crate)` so the moved `render` impls
can call them. Candidates from the helper inventory (`src/report.rs`):
`format_probability` (`:3911`), `format_percent` (`:3907`), `fraction`
(`:3899`), `print_interval`/`format` of `WilsonInterval` (`:5346`),
`format_widths` (`:5418`), `format_span` (`:5426`), `yes_no` (`:4767`),
`preview_text` (`:4771`), `format_positions` (`:4787`), `format_optional_*`
(`:4800-4808`), `format_u8_values`/`format_usize_values` (`:4734`/`:4745`),
`NumberRange` + `format_number_range`/`format_ratio_range` (`:4590`/`:4598`),
`counted_form` (`:1332`), `format_seed_list` (`:1484`). **Before moving a helper,
`grep` its call sites**: if it is called from exactly one `print_*` family,
co-locate it with that report; if from several, keep it shared. Convert the
shared `print_*`-style helpers (e.g. `print_interval`) to return/append-to a
`String` so the `render` impls can use them.

`print_report` (`:5402`) and `print_orders_report` (`:5354`) — the two
multi-arg/non-struct entry points — get **Phase A only**: they become
`pub fn … -> String` shared renderers (rename to `render_sequence_report` /
`render_orders_report` or keep the name but change the return type) and **stay in
`report.rs`**. They have no single owning struct, so there is no Phase-B move and
no `Report` impl for them — the accepted, documented deviation from "every report
is a `Report`" (see Out of scope).

### 5. CLI call-site shape (sets up brief 08)

The `print!` switch happens in **Phase A** (CLI calls
`print!("{}", report::render_X_report(&r))`); **Phase B** only changes the
right-hand side to `r.render()`. After both phases, `main.rs` collapses both
paths to `Display` + `Report`:

```rust
// error path: Display via {}
Err(error) => { eprintln!("AGL-GAK error: {error}"); ... }
// print path (Phase A): the in-place report.rs free fn, printed once with print!
print!("{}", report::render_agl_gak_report(&report));
// print path (Phase B): the colocated Report::render, same bytes
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

**Every module's render migration is split into two commits that isolate the two
distinct risks:**

- **Phase A (byte parity, IN PLACE):** convert `print_X_report(report)` →
  `render_X_report(&report) -> String` **while it still lives in `report.rs`**
  (build via `use std::fmt::Write; writeln!`), and switch the CLI to
  `print!("{}", report::render_X_report(&r))` (no `println!`). This isolates the
  trailing-newline / `println!`→`writeln!`-into-`String` / stdout-parity risk
  under the golden master, with **zero** module relocation.
- **Phase B (relocation, pure move):** move the now-`String`-returning
  `render_X_report` body into a colocated `impl Report::render` in the owning
  module (and the `Display` impl next to the error enum), delete the `report.rs`
  free fn, and update the CLI to `r.render()`. Because Phase A already proved the
  bytes, Phase B touches no output logic — it is a pure move.

Recommended cadence is **per-module A→B** (each module fully lands before the next)
so a regression is bisected to one module; you *may* batch all Phase-A commits
first then all Phase-B, but per-module keeps the blast radius smallest. The
`Display` migration (error enums) rides with each module's Phase B (the colocated
`Display` is itself a relocation; its byte-parity is guarded by the unit tests in
Verification step 4, not by Phase A's render golden master).

0. **Prerequisite gate.** Confirm brief 01's full-output golden master is merged
   and green on this branch (run `make verify`; inspect the snapshot files exist
   for every subcommand). If 01 is not merged, stop. (05 helping is optional: if
   05 has already moved null orchestration, re-check the helper inventory in §4.)

1. **Introduce the `Report` trait only.** Add `pub trait Report { fn render(&self)
   -> String; }` (in `report.rs` for now; brief 07B will move it under
   `src/report/mod.rs`). No impls yet. `make verify`. Commit. (Trait is unused →
   may trip `dead_code`; if so add `#[allow(dead_code, reason = "impls land in
   subsequent commits of brief 06")]` and remove the allow once the first impl
   lands, or land the first module's Phase B in the same commit.) Note: the trait
   is only needed for Phase B; Phase A renders are plain `report.rs` free fns and
   do not depend on it, so the per-module Phase-A commits can precede this step.

2. **Migrate the leaf modules with an already-existing `Display`.** For
   `cipher_attack`, `agl_gak`, `perfect_isomorphism` (Display already present at
   `src/cipher_attack.rs:128`, `src/agl_gak.rs:130`,
   `src/perfect_isomorphism.rs:124`), per module:
   - **Phase A:** convert `print_cipher_attack_report` / `print_agl_gak_report` /
     `print_perfect_isomorphism_report` to `render_*_report(&report) -> String`
     **in place in `report.rs`**; switch the `main.rs` print site to
     `print!("{}", report::render_*_report(&r))`. `make verify` + golden diff.
   - **Phase B:** move the `String`-returning body into `impl Report` for
     `CipherAttackReport` / `AglGakReport` / `PerfectIsomorphismReport` (next to
     the struct, with its private helpers), delete the `report.rs` free fn, and
     switch `main.rs` to `print!("{}", report.render())`. The error side is
     already done (these have `Display`): delete `format_cipher_attack_error`
     (`:515`), `format_agl_gak_error` (`:36`), `format_perfect_isomorphism_error`
     (`:406`) and switch `main.rs` to `{error}`. `make verify` + golden diff.

   One Phase-A + one Phase-B commit per module.

3. **Migrate the self-contained, non-delegating experiments**, per-module A→B:
   `corpus` (`CorpusError` Display; note `print_report` for `Sequence` is shared,
   not corpus-owned), `honeycomb`, `periodicity`, `dof_null`, `isomorph_null`,
   `chaining`, `modular_diff`, `pyry_conditions`, `perseus`,
   `zero_adjacency_null`, `grouping`, `orientation_homogeneity`, `controls`
   (both `MonoalphabeticControlReport` and `IsomorphControlReport`),
   `pipeline_null` (`InputRandomnessReport` + the `print_pipeline_null_report`
   which reuses `null::NullReport`). For each module:
   - **Phase A:** convert the module's `print_*_report` to `render_*_report(&report)
     -> String` in place in `report.rs` (its private helpers stay put, threaded a
     `&mut String`); switch `main.rs` to `print!("{}", report::render_*_report(&r))`.
     `make verify` + golden diff.
   - **Phase B:** (a) add the `Display` + `Error` impl colocated, copying arm text
     verbatim from the corresponding `format_*` in `report.rs`; (b) move the
     `render_*_report` body into `impl Report` for the struct(s), carrying the
     private helpers; (c) delete the old `format_*` and the now-moved
     `render_*_report` from `report.rs`; (d) update `main.rs` to `{error}` /
     `report.render()`. `make verify` + golden diff.

4. **Migrate `null`** (`NullConfigError` + `NullRunError`, and `NullReport`).
   **Phase A:** convert `print_null_report` (`:753`) to `render_null_report(&NullReport)
   -> String` in place; switch `main.rs` to `print!`. Note `print_pipeline_null_report`
   (`:1676`, also takes `&null::NullReport`) renders the same struct differently —
   give it its own Phase-A `render_pipeline_null(&NullReport) -> String` so the two
   CLI paths stay distinct. `make verify` + golden diff.
   **Phase B:** fold `format_null_config_error` into `NullConfigError::Display`, then
   `NullRunError::Display` uses `{config_error}`. Move `render_null_report`'s body
   into `impl Report for NullReport`. Keep `render_pipeline_null` as a small free
   shared fn (a second `Report` impl on `NullReport` is impossible — one struct, one
   impl), colocated in `null`; do not force it into the trait. `make verify` + golden
   diff.

5. **Migrate the delegating experiments** (after their inner deps are done), each
   per-module A→B: `tree_residual` (its Phase B uses `PerseusError` Display — step 3
   must have done perseus first; replace the `format_perseus_error` delegate at
   `:477` with `{perseus_error}`), `chaining_graph` then `transitivity`
   (transitivity's Phase B delegates to `ChainingGraphError`'s `Display`, so do
   `chaining_graph` first; the `format_chaining_graph_error` call at `:740` becomes
   `{chaining_error}`). `conditional_structure` (large: ~25 private helpers
   `src/report.rs:1860-2350`) — Phase A renders in place, Phase B moves the body and
   all those helpers colocated. The delegation only affects each module's Phase B
   (the `Display` migration); Phase A's render conversion is independent of it.

6. **Migrate `gak_attack`** (`GakAttackError`, `GakAttackReport`,
   `EyesAttackReport`). This is the largest: `print_gak_attack_report` (`:4092`),
   `print_gak_attack_eyes_report` (`:4412`), and ~12 private helpers
   (`src/report.rs:4126-4404`, `:4440-4572`).
   - **Phase A** is unaffected by the gak split: convert both `print_*` to
     `render_*_report -> String` **in `report.rs`** (helpers stay put) and switch
     `main.rs` to `print!`. This commit can land regardless of 07A's status.
   - **Phase B** is the move that interacts with brief **07A** (the `gak_attack.rs`
     8,147-line god-file split). If 07A has split `gak_attack.rs` into
     `src/gak_attack/` sub-files, place the `impl Report` next to the report struct
     in whichever sub-file owns it. Do Phase B on the same branch as, or after, 07A's
     gak split to avoid a three-way merge. (Phase A's byte parity is already proven,
     so the only thing the merge risks is the move target, not the rendered bytes.)

7. **Consolidate shared helpers + the two non-struct renderers.** Once every
   per-struct `print_*_report` has been through Phase B, audit what remains in
   `report.rs`: keep only the cross-module helpers (§4), convert them to
   `String`-appending form, mark `pub(crate)`, and re-point the moved `render`
   impls at them. The two non-struct entry points `print_orders_report` (`:5354`)
   and `print_report` (`:5402`) get **Phase A only** — convert to
   `render_orders_report` / `render_sequence_report` `-> String` and **leave them in
   `report.rs`** (no owning struct ⇒ no Phase B, no `Report` impl). Update their
   `main.rs` call sites to `print!("{}", …)` (`src/main.rs:653`, `:1054`, `:1061`).
   `report.rs` should now be a few hundred lines of helpers + the two shared
   renderers + the `Report` trait. `make check` (full gate incl. `cargo-machete` to
   confirm no now-unused imports remain, and the giant `use crate::{...}` block at
   `src/report.rs:8-13` shrinks). Commit.

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

**Change (trait home, with brief 07B):** if 07B lands first, the `Report` trait and
remaining helpers live in `src/report/mod.rs`; otherwise they stay in
`src/report.rs`. Coordinate the trait's final path with 07B and 08.

**Create:** none strictly required (the trait can live in the surviving
`report.rs`). Optionally `src/report/mod.rs` if co-sequenced with 07B.

**Delete:** none as files in this brief — `report.rs` survives, much smaller.
(Brief 07B may later move the surviving `report.rs` into `src/report/`.)

## Success criteria

- Every `format_*_error` free function is gone from `report.rs`; every error enum
  that had one now has a colocated `impl fmt::Display` (+ `impl std::error::Error`)
  in its own module. `grep -n 'pub fn format_.*_error' src/report.rs` returns
  nothing.
- Every `print_*_report` CLI entry point is gone from `report.rs` — each went
  through Phase A (`render_*_report -> String` in place) then Phase B (moved into a
  colocated `impl Report` on its `*Report` struct). `grep -n 'pub fn print_'
  src/report.rs` returns **nothing**: the two non-struct entry points are renamed
  to the `render_*` shared renderers in their Phase-A-only path, and no `print_*`
  survives.
- A `pub trait Report { fn render(&self) -> String; }` exists, with one impl per
  report struct; the CLI calls it generically (no per-experiment `print_*`
  dispatch except the two shared renderers).
- `report.rs` is reduced to shared formatting helpers + the trait (target: well
  under ~700 lines vs. today's 5,694), and its hub import block no longer pulls
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

- **Trailing newline / line-order drift is the #1 risk — but the Phase A / Phase B
  split confines it to Phase A.** `println!` appends `\n`; the assembled `String`
  must reproduce it, and the CLI must switch to `print!("{}", …render…)` (no
  `println!`) so no extra `\n` is added. This entire conversion happens in **Phase A
  while the renderer still lives in `report.rs`** (no relocation), so the
  trailing-newline / line-order risk is caught by brief 01's golden master
  *independent of any module move*. Phase B then relocates already-proven bytes and
  cannot introduce a newline drift. The existing `assert_contains` tests **cannot**
  catch this (substring-only, `tests/common/mod.rs:39`) — rely on brief 01's
  full-output golden master, run after both Phase A and Phase B.
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
- **Coordinate `gak_attack` Phase B with brief 07A.** `gak_attack.rs` is split by
  brief 07A; doing its `impl Report` (Phase B) independently risks a three-way merge.
  Sequence step 6's Phase B after 07A's gak split, or do both on one branch
  (overview's noted conflict point, `docs/refactor/00-OVERVIEW.md:183-186`). Note
  `gak_attack`'s **Phase A is unaffected** — converting `print_*` to `render_*` in
  `report.rs` does not touch `gak_attack.rs`, so it can land before 07A.
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
  brief 08 (`docs/refactor/00-OVERVIEW.md:175`); this brief only delivers the
  `Report::render` surface 08 builds on.
- Splitting `gak_attack.rs` — brief 07A; the repo-wide module-directory reorg
  (including the `report.rs` → `report/` move) — brief 07B.
- Null/experiment-harness dedup — brief 05 (it *helps* by collapsing duplicated
  null orchestration before the helper-inventory step, but is not required).
- Changing any report's *content* or wording. Every arm string and report line is
  copied verbatim; rewording is a follow-up, not part of this behavior-preserving
  refactor.
