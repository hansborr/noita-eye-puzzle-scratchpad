# Report 04 — Structure, API surface, CLI & build

Crate organization and idiomaticity. The build/lint/test tooling is a **model
setup** — most of this report is "keep it," with three real changes: convert the
`#[path]`-flattened module tree, decide the library-vs-workbench identity, and
split `main.rs` into bin-local modules.

---

## 1. P1 — Convert the `#[path]`-flattened `lib.rs` to a real nested module tree

**Finding.** `src/lib.rs:101-205` declares 41 leaf modules as top-level `pub mod`,
each redirected with `#[path = "subdir/file.rs"]` (e.g.
`#[path = "analysis/chaining.rs"] pub mod chaining;`). Files live in
`core/ data/ analysis/ nulls/ ciphers/ attack/ experiments/ report/`, but **none
of those directories is a module** — there is no per-directory `mod.rs`, so
`crate::analysis::chaining` does **not** exist; the path is `crate::chaining`. The
directory tree is cosmetic; it carries zero namespace meaning.

This is *actively misleading*, not merely terse: the filesystem looks nested but
the module graph is flat. An outside Rust reader expects
`src/analysis/chaining.rs` → `crate::analysis::chaining` (and
`use noita_eye_puzzle::analysis::chaining`). `cargo doc` and rust-analyzer present
**43 ungrouped top-level modules**, and the ~96-line hand-maintained module
catalogue at `src/lib.rs:3-98` is a manual substitute for the grouping the
directories already imply.

**The decisive tell:** the crate already nests properly where it was free to —
`ciphers` (`lib.rs:158`) and `report` (`lib.rs:206`) are plain `pub mod` resolving
to `*/mod.rs`, and inside `attack/solve/` and `attack/gak_attack/` there are
conventional private submodules + `pub(crate)`. So the flat top level is a
deliberate **transitional state** (the campaign "froze public paths" so files
could move into directories during an in-flight, behavior-preserving refactor
without a breaking path change) — defensible *as a transition*, but a smell to
ship.

**Recommendation (decisive): convert now, as part of going public.**
- End state: `pub mod analysis { pub mod chaining; … }` (or 2018-style
  `src/analysis.rs` siblings), paths become `crate::analysis::chaining`, the
  directory layout finally means something, the `#[path]` attrs disappear, and the
  `lib.rs` catalogue shrinks to per-module rustdoc.
- **Blast radius is ~zero.** The only consumers today are the in-repo binary, one
  integration test (`tests/first_trigram.rs`), and inline tests. The "frozen
  paths" rationale was about not destabilizing the refactor; "make it public" is
  exactly the checkpoint to unfreeze. Doing it pre-publish is free; doing it after
  publish breaks downstreams.
- **Cost is mechanical:** delete `#[path]`, add `analysis.rs`/`mod.rs` re-export
  shims, then rename `crate::chaining` → `crate::analysis::chaining` internally
  (sed + rust-analyzer). Golden fixtures are stdout-based and unaffected; only
  `main.rs`'s big `use` block (`:11-20`) and the one library-calling test change.
  Belt-and-suspenders: keep flat `pub use` re-exports for one release — though
  there is no external user to protect.
- **Sequence this before report 02's big splits** so the split targets land in
  real directories rather than `#[path]` includes.

---

## 2. P1 — Decide and document the library-vs-workbench identity

**Finding.** `rg 'pub fn|pub struct|pub enum' src | wc -l` = **688** (was 656; the
`exploration` merge added ~32 across the two new files — e.g. `leak_ceiling.rs`'s
combinatorics helpers are each `pub fn`); `pub(crate)` = **146** (concentrated in
`gak_attack/*`,
`report`, `chaining_graph`, `ciphers` — so cross-module-private discipline exists
where the code was nested). But **19 of
22 integration test files spawn the compiled binary** via `CARGO_BIN_EXE`
(`tests/common/mod.rs:23`); only `tests/first_trigram.rs` calls the library
directly. So nearly the entire 656-item `pub` surface exists to serve a
*separate-crate binary* + golden tests — **this is a CLI workbench with a thin
library backing, not a general-purpose library** (README says as much;
`main.rs:1-5` documents the bin as intentionally thin).

Consequence: most of the surface is `pub` only because `main.rs` is a separate
crate, not because it's a designed API. Publishing commits all of it to an
accidental semver contract. There is also **no prelude/facade** — `lib.rs` has
zero `pub use` re-exports, and `main.rs:11-20` imports ~35 modules in one flat
alphabetical block (the namespace can't express grouping — ties to §1).

**Recommendation — pick one and document it:**
- **Stays a workbench (most honest):** say so in the crate-level docs; treat the
  library as "internal API, no stability guarantee" (a `#![doc]` note, optionally
  `#[doc(hidden)]` on the leaf `run_*`/helper items). Defuses the semver concern
  with no churn.
- **Want library use:** add a curated `prelude` / top-level `pub use` of the dozen
  genuinely-useful types (`Glyph`, `Sequence`, `Alphabet`, the `Report` trait,
  corpus accessors) and demote internal helpers from `pub` to `pub(crate)`. The §1
  conversion is the natural vehicle. Extend the existing `pub(crate)` discipline
  (in `solve`/`gak_attack`/`ciphers`) to the flat experiment modules so their
  internal helpers stop being `pub`.

---

## 3. P1 — Split `main.rs` (2107 lines) into bin-local modules

**Finding.** Idiomatic `clap` derive: a `Cli`/`Command` enum (`main.rs:37-130`)
with 31 subcommands and a **genuinely nice** dispatch registry (brief 08) —
`RunOutcome` (`:969`), `emit` (`:982`), generic `dispatch<C,R,E: Display>`
(`:1002-1011`) collapse ~20 uniform subcommands to one-line match arms; irregular
ones (solve/keystream/ragbaby/profile/…) correctly stay bespoke. **Keep the
registry as-is.** The smell is only length + the ~25 `Args`-struct + hand-written
`From<Args> for Config` pairs (repetitive but type-safe and mechanical — not a
smell, just bulk). AGENTS.md already anticipates this ("Move to `clap`
subcommands as the CLI grows").

**Recommendation.** A binary *can* have bin-private submodules (not `pub`, doesn't
touch the library API). Split into a `cli/` tree (also in report 02 §5):
`cli/args.rs` (the `*Args` + `From` impls + `ValueEnum`s), `cli/dispatch.rs`
(`RunOutcome`/`emit`/`dispatch`), `cli/commands/{solve,keystream,ragbaby,misc}.rs`
for the bespoke pipelines. `main.rs` shrinks to the `Cli` definition + dispatch
match. Leave the registry pattern untouched.

---

## 4. P2 — Tests layout (exemplary; minor notes only)

**The golden-master harness is a standout — keep it as the model.**
`tests/golden_master.rs` does byte-exact stdout/stderr comparison via
`include_str!` + two macros (`:83-99`), carries a documented copy-pasteable
regeneration guard (`:3-54`) that frames fixture changes as behavior changes, and
redacts machine-coupled tokens to portable placeholders (`<CANDIDATES_DIR>`,
`:326-355`). 31 stdout + 3 stderr fixtures. Better than most production crates.

Minor:
- **Bloat:** the inline `#[cfg(test)]` modules are a major file-size contributor
  (report 02 owns extraction). Move the largest to `#[path]` siblings — *not* to
  `tests/`, since they use private items.
- **Overlap:** several subcommands are covered by *both* a per-command
  characterization test (`tests/chaining_cli.rs`, `periodicity_cli.rs`,
  `perseus_cli.rs`) *and* the byte-exact `golden_master.rs`. They assert different
  things (semantic substrings vs byte-exactness), so it's defensible — but make a
  deliberate decision on whether the `*_cli.rs` substring tests still earn their
  keep once golden coverage exists.

---

## 5. P2 — Build/tooling config (strong; align two flags)

**Confirmed strong — ship essentially as-is.** Standouts: `unsafe_code = "forbid"`
crate-wide (`Cargo.toml:38`); `correctness`/`perf = deny`, `pedantic = warn` with
the panic/silent-failure family as warn→`-D` in CI; `allow_attributes_without_reason
= warn` (`:77`, what forces the `reason=` discipline); `clippy.toml` complexity
ceilings + test-only panic relaxation; `deny.toml` `multiple-versions/wildcards =
deny`; `lto + codegen-units = 1`; `--locked` everywhere; edition 2024 / MSRV 1.96
consistent across `Cargo.toml`/`clippy.toml`/`rust-toolchain.toml`; and a
coherently-mirrored gate across `Makefile`, `.githooks/pre-commit`, and CI.

Nitpicks (none blocking):
- **shellcheck glob differs:** `Makefile:50` lints `scripts/*.sh` (non-recursive)
  while CI (`.github/workflows/ci.yml:74-76`) uses `scripts/**/*.sh` — CI catches a
  nested script `make shellcheck` misses. Align them.
- **`--all-features` drift:** `Makefile` `test` is `cargo test --locked`; CI adds
  `--all-features`. The crate has no features today (no-op), but make them
  identical so they don't drift.
- **Toolchain pin:** `rust-toolchain.toml` pins `channel = "stable"`, not an exact
  version. Fine for a workbench, but for reproducible public CI consider pinning
  the exact MSRV `1.96.0` (the file's own comment flags this).
- **Allowlist archaeology (also report 01 P1.5):** the `bumped X->Y` histories in
  `scripts/file-size-allowlist.txt:18,28` are commit archaeology in a shipped
  config — reduce each `# reason` to current ownership + retirement plan.

---

## 6. P2 — Wildcard imports / blanket re-exports undermine the split modules

GAK submodules use `use super::*` (`gak_attack/eyes.rs:7`, `solver.rs:8`) and
`gak_attack/mod.rs:88` re-exports whole modules; `solve/mod.rs:36` does
`pub use record::*`. After the §1 nesting conversion, replace these with explicit
imports and explicit `pub use` lists so the module boundaries actually constrain
what each file sees.

---

## Bottom line

Three real structural changes before publishing: **(P1)** convert the
`#[path]`-flatten to nested modules — the single most surprising thing for an
outside Rust reader, and free in the pre-publish window; **(P1)** decide and
document library-vs-workbench so 656 `pub` items don't become an accidental semver
contract; **(P1/P2)** split `main.rs` into bin-local modules. The dispatch
registry, the golden-master harness, and the entire lint/supply-chain/CI setup are
high quality — keep them.
