# 08 — CLI registry + args dedup

> One-line: collapse the per-subcommand CLI boilerplate in `main.rs` into a
> shared flattened `seed`/`trials` arg struct plus an `Experiment`-trait-backed
> registry, so adding an experiment is one table entry instead of four scattered
> edits — serving the maintainability track (keep `main.rs` thin so the solve
> engine has a clean front door).
> Status: not started · Depends on: 06 (Report trait); 02 & 05 help; 01 is the
> safety net · Blocks: — · Size: M

## Goal & why it matters

`src/main.rs` is 1,085 lines that are almost entirely mechanical. Adding a single
new experiment today means **four scattered, easy-to-desync edits**: (1) a
`Command` enum variant, (2) an `Args` struct with `#[arg(...)]` defaults, (3) a
`From<Args> for ...Config` impl, and (4) a `run_*` fn that threads
`run → match Ok/Err → format_error → print_report`. The `From` impls and `run_*`
fns are pure copy-paste with the type names swapped (compare
`run_periodicity` at `src/main.rs:729-742` against `run_honeycomb` at
`src/main.rs:744-757` — identical modulo `periodicity::`↔`honeycomb::`).

The overview flags this directly: "Per-experiment boilerplate | 22 `Config` + 24
`Args` + 22 `From<Args>` + 28 `run_*` CLI dispatchers in `main.rs` ≈ 4 scattered
edits per experiment" (`docs/refactor/00-OVERVIEW.md:55`). This brief is the
`main.rs`-side payoff of
the `Report` trait that brief 06 introduces: once each experiment's report can
`render(&self) -> String` and each error enum has a `Display` impl, the per-fn
`match`/`format_*_error`/`print_*_report` triad collapses into one generic
dispatch, and `main.rs` becomes the thin CLI the house rules ask for
(`AGENTS.md:57` — "The CLI in `main.rs` is intentionally thin").

Behavior-preserving is mandatory: identical flags, identical defaults, identical
stdout/stderr. The existing `tests/*_cli.rs` characterization suite (e.g.
`tests/nulls_cli.rs`) and the brief-01 golden masters are the guard.

## Current state (grounded, with file:line)

**The four-part repetition, by the numbers** (`src/main.rs`):

- `Command` enum: 26 variants, `src/main.rs:34-104`.
- `Args` structs: 24 (`StatsArgs` `:107`, `AglGakArgs` `:113`, … through the two
  control-arg structs `MonoalphabeticControlArgs` `:596` and
  `IsomorphControlArgs` `:608`).
- `From<Args> for ...Config` impls: 22 (`:126`, `:178`, `:215`, `:234`, `:253`,
  `:279`, `:301`, `:318`, `:340`, `:360`, `:382`, `:401`, `:422`, `:443`, `:463`,
  `:483`, `:501`, `:523`, `:549`, `:568`, `:601`, `:613`).
- `run_*` fns: 28 (`run_demo` `:650` … `run_stats` `:1058`), 22 of which follow
  the strict `match run(config) { Ok(r) => print_*(&r), Err(e) => { eprintln!(..,
  format_*_error(e)); FAILURE } }` shape (config in → single report → print) —
  see `run_nulltest` `:663-672`. The other 6 are the irregular subcommands
  (`Demo`, `Orders`, `Grouping`, `Stats`, `Pipelinenull`, `Controls`) below.
- The `main` dispatch `match` is itself a 26-arm table, `src/main.rs:620-647`,
  every arm `Command::X(args) => run_x(args.into())`.

**The duplicated `seed`/`trials` fields.** Nearly every `Args` struct repeats the
same two `#[arg(long)] seed: u64` / `trials: usize` fields with a per-module
default constant:

- `NullArgs` (`src/main.rs:227-232`) is *already* a shared two-field
  `seed`+`trials` struct, reused by both `Nulltest` (`:54`) and `Pipelinenull`
  (`:64`) — proving the flatten pattern works. Its defaults are the crate-level
  `DEFAULT_NULL_SEED` / `DEFAULT_NULL_TRIALS` (`src/main.rs:17-18`).
- But the other ~16 experiment arg structs each re-declare `seed`/`trials`
  inline with **module-specific defaults**: e.g. `PeriodicityArgs`
  (`:264-277`) uses `periodicity::DEFAULT_SEED` / `periodicity::DEFAULT_TRIALS`;
  `HoneycombArgs` (`:294-299`) uses `honeycomb::DEFAULT_SEED` /
  `honeycomb::DEFAULT_TRIALS`; `ChainingArgs` (`:329-338`) plus two extra
  period fields; etc.

**Critical behavior constraint — the defaults differ per subcommand.** The
per-module `DEFAULT_SEED` constants are all distinct (`periodicity` =
`0x6579_652d_7065_7235` at `src/periodicity.rs:33`; `honeycomb` =
`0x686f_6e65_7963_6f6d` at `src/honeycomb.rs:20`; `chaining` =
`0x6368_6169_6e37_6221` at `src/chaining.rs:42`; ten more, all different) and
the `DEFAULT_TRIALS` differ too (`periodicity`/`honeycomb`/`isomorph_null` =
`1_000`; `chaining`/`modular_diff` = `256` at `src/chaining.rs:44`,
`src/modular_diff.rs:32`). **A naive single shared `NullArgs` with one
`default_value_t` would silently rewrite every subcommand's default seed and
trial count — a behavior change.** The dedup must preserve per-subcommand
defaults (see Target design).

**`null_trials` is a separate axis.** Only two subcommands carry it, both with a
distinct `--null-trials` long flag: `AglGakArgs.null_trials`
(`src/main.rs:116-117`, default `agl_gak::DEFAULT_NULL_TRIALS`) and
`CipherAttackArgs.null_trials` (`:540-541`, default
`cipher_attack::DEFAULT_NULL_TRIALS`). They do **not** also carry the plain
`trials` field — `agl_gak` and `cipher_attack` use `seed` + `null_trials` (+
others), never `seed`+`trials`+`null_trials` together. So `null_trials` is not a
universal third column; it is a per-experiment extra.

**Irregular subcommands that the registry must accommodate (not all fit a
uniform table):**

- `Demo` (`:38`/`:650-661`), `Orders` (`:40`/`:1031-1055`), `Grouping`
  (`:66`/`:783-793`): **no Args, no config** — `run` takes nothing.
- `Stats` (`:36`/`:1058-1069`): Args is a bare positional `sequence: String`
  (`:107-110`), no seed/trials, and it parses via `parse_rendered_sequence`
  (`:1071-1085`) rather than a `Config`.
- `Pipelinenull` (`:64`/`:759-781`): one `run` produces **two** reports
  (`run_pipeline_null` + `input_randomness_report`) and prints both with a blank
  line between (`:777-779`).
- `Orders` (`:1031-1055`): builds three structs (`summary`, `stats`, `flatness`)
  and calls `print_orders_report` with all three (`:1054`).
- `Controls` (`:103`/`:987-999`): a **nested subcommand** (`ControlsArgs` with
  `#[command(subcommand)] target: Option<ControlTarget>` and a top-level
  `--seed`, `src/main.rs:579-584`), dispatching to two inner controls with a
  `None`→monoalphabetic default fallback (`:992-998`).
- `Dofnull` (`:57`/`DofNullArgs` `:244-251`): has a `--calib-trials`
  `Option<usize>` that defaults to `trials` inside the `From` impl
  (`:257`, `args.calibration_trials.unwrap_or(args.trials)`).

**The dispatch target (brief-06 surface).** Today each `run_*` calls a pair of
free fns in `report.rs`: a `format_*_error(...) -> String` (23 of them,
`src/report.rs:19-750`) and a per-experiment `print_*_report(&Report)` (25 pub
single-report printers, `src/report.rs:753-5399` — excluding the 3-arg
`print_orders_report` and the generic `print_report(label, seq)`). Brief 06
replaces these with `impl Display`/`thiserror` on each error enum and a
`Report::render(&self) -> String` per report type
(`docs/refactor/00-OVERVIEW.md:116-121`). This brief consumes that surface: the
registry's generic dispatch calls `report.render()` and `eprintln!("{err}")`
instead of the named `print_*`/`format_*` fns. **Order this brief after 06.**

**Existing safety net.** `tests/common/mod.rs:6-15` (`run_noita_eye`) shells out
to `CARGO_BIN_EXE_noita-eye` and asserts on stable report labels via
`assert_contains` (`:39-44`). `tests/nulls_cli.rs` already pins
`nulltest`/`dofnull`/`pipelinenull` flag behavior, including
`dofnull_calibration_trials_default_to_trials` (`tests/nulls_cli.rs:39-45`).
clap is `4.5.4`-pinned in `Cargo.toml:24` (resolved `4.6.1` in `Cargo.lock`) with
the `derive` feature — `#[command(flatten)]` is available.

## Target design (concrete API / types / layout)

Two independent pieces, landed in order: **(a)** the flattened arg struct, then
**(b)** the registry.

### (a) Shared `NullArgs` flattened via `#[command(flatten)]`

Keep the existing `NullArgs` name (it already exists at `src/main.rs:227`) but
make it the *one* place `seed`+`trials` live, and flatten it into every
subcommand that repeats those two fields. The blocker is per-subcommand defaults.
clap's `default_value_t` is a compile-time attribute on the field, so a single
`NullArgs` definition cannot itself express "default depends on which parent
flattened me." Resolve it with the **standard clap pattern**: make the flattened
fields take *no* `default_value_t` and be `Option<u64>`/`Option<usize>`, then
apply the per-experiment default in the `From`/`Config`-builder step.

```rust
/// Shared seed + trial-count flags reused across null-model subcommands.
#[derive(Clone, Copy, Debug, clap::Args)]
struct NullArgs {
    /// Deterministic PRNG seed (defaults to the experiment's own constant).
    #[arg(long)]
    seed: Option<u64>,
    /// Monte-Carlo trial count (defaults to the experiment's own constant).
    #[arg(long)]
    trials: Option<usize>,
}

impl NullArgs {
    fn seed_or(self, default: u64) -> u64 { self.seed.unwrap_or(default) }
    fn trials_or(self, default: usize) -> usize { self.trials.unwrap_or(default) }
}
```

Each experiment's arg struct then flattens it and keeps only its *extra* fields:

```rust
#[derive(Clone, Copy, Debug, clap::Args)]
struct PeriodicityArgs {
    #[command(flatten)]
    null: NullArgs,
    #[arg(long = "max-period", default_value_t = periodicity::DEFAULT_MAX_PERIOD)]
    max_period: usize,
    // ... the other periodicity-only fields, unchanged ...
}

impl From<PeriodicityArgs> for periodicity::PeriodicityConfig {
    fn from(args: PeriodicityArgs) -> Self {
        Self {
            seed: args.null.seed_or(periodicity::DEFAULT_SEED),
            trials: args.null.trials_or(periodicity::DEFAULT_TRIALS),
            max_period: args.max_period,
            // ...
            ..Self::default()
        }
    }
}
```

**Why `Option` + builder, not bare `default_value_t`:** it is the *only* way to
keep distinct per-subcommand defaults while sharing one field definition. The
help text loses the literal `[default: 0x...]` clap annotation for the flattened
fields. To preserve user-visible behavior, set the default in the help string via
`#[arg(long, help = "...", default_value_t = ...)]` is **not** available on the
shared struct; instead, restore it per-subcommand by *not flattening the
common-default ones* where the help default matters, OR document the default in
the long help text. **Honesty caveat (see Risks):** if any `tests/*_cli.rs` or a
brief-01 golden master asserts on the `--help` default annotation, flattening
changes that string. The implementer must diff `--help` output for every
subcommand before/after and, if it regresses, fall back to the simpler dedup
below.

**Simpler fallback if `--help` parity must be byte-exact:** keep `seed`/`trials`
inline per struct (no flatten) and only dedup the *runtime* boilerplate via the
registry in part (b). Part (b) delivers the bulk of the win and is
`--help`-neutral; part (a) is the smaller, riskier half. The two parts are
independent commits — land (b) first if (a)'s `--help` diff is unacceptable.

`NullArgs`'s two *current* consumers (`Nulltest`, `Pipelinenull`) already share
one default pair (`DEFAULT_NULL_SEED`/`DEFAULT_NULL_TRIALS`), so they map cleanly
to `seed_or(DEFAULT_NULL_SEED)` / `trials_or(DEFAULT_NULL_TRIALS)` with no
behavior change.

### (b) `Experiment`-trait-backed registry

Lean on brief 02's `Experiment`/`Report` traits
(`docs/refactor/00-OVERVIEW.md:116-121`). Define, in `main.rs` (or a thin
`src/cli.rs` module), a registry that maps each clap variant to one entry that
owns: build `Config` from `Args`, call the run fn, and `render` the report.

Because each experiment has a *different* `Config`/`Report` type, the registry
cannot be a homogeneous `Vec<&dyn Experiment>`. Use a **per-variant closure that
erases to `String` + `ExitCode`** at the dispatch boundary:

```rust
/// Outcome of one experiment run, ready for the thin CLI to emit.
enum RunOutcome {
    /// Render to stdout and exit SUCCESS.
    Ok(String),
    /// Render to stderr and exit FAILURE.
    Err(String),
}

/// Runs one experiment end-to-end: build config, execute, render via `Report`.
/// `run` returns the domain `Result`; both arms are rendered to `String` here,
/// so the dispatch table has a single uniform shape.
fn dispatch<C, R, E>(
    cfg: C,
    run: impl FnOnce(C) -> Result<R, E>,
) -> RunOutcome
where
    R: noita_eye_puzzle::report::Report, // brief 06: render(&self) -> String
    E: std::fmt::Display,                // brief 06: error Display impls
{
    match run(cfg) {
        Ok(report) => RunOutcome::Ok(report.render()),
        Err(error) => RunOutcome::Err(error.to_string()),
    }
}
```

The top-level `match` in `main` then shrinks to one line per *regular*
experiment:

```rust
let outcome = match Cli::parse().command {
    Command::Periodicity(a) => dispatch(a.into(), periodicity::run_periodicity),
    Command::Honeycomb(a)   => dispatch(a.into(), honeycomb::run_honeycomb),
    Command::Nulltest(a)    => dispatch(a.into(), null::run_standard36_null),
    // ... ~20 uniform arms ...
    // irregular arms handled explicitly (see below)
    Command::Demo => return emit(run_demo()),
    Command::Stats(a) => return emit(run_stats(&a.sequence)),
    Command::Pipelinenull(a) => return emit(run_pipelinenull(a.into())),
    Command::Orders => return emit(run_orders()),
    Command::Grouping => return emit(run_grouping()),
    Command::Controls(a) => return emit(run_controls(a)),
};
emit(outcome)
```

where `emit(RunOutcome) -> ExitCode` does the `println!`/`eprintln!` + exit code.
This removes the per-experiment `run_*` fn *and* the per-fn error-prefix string:
today each `eprintln!` hardcodes a label like `"periodicity error: {}"`
(`src/main.rs:734`) or `"honeycomb lattice error: {}"` (`:749`). **Behavior
note:** brief 06's `Display` impls must reproduce those user-facing prefixes (the
`tests/*_cli.rs` negative suites and brief-01 golden masters assert on stderr
text). If a prefix like `"periodicity error: "` is part of the contract, fold it
into the variant's `dispatch` call (e.g. a `dispatch_labelled(cfg, run,
"periodicity error")`) rather than dropping it. The implementer must confirm
against the golden masters which prefixes are load-bearing.

**Irregular variants stay as bespoke `run_*` fns** returning `RunOutcome` (or
`ExitCode` via `emit`): `Demo`, `Orders`, `Grouping` (no config), `Stats`
(positional parse), `Pipelinenull` (two reports — concatenate the two
`render()`s with the blank-line separator from `src/main.rs:778`), and `Controls`
(nested subcommand with the `None` fallback at `:992-998`). These are ~6 fns; the
registry collapses the other ~18. Do **not** force them into the uniform table —
forcing the two-report and nested-subcommand cases would obscure, not simplify.

### Before/after: cost to add a hypothetical new experiment

| Step | Before (today) | After (this brief) |
| ---- | -------------- | ------------------ |
| clap variant | add `Command::Foo(FooArgs)` (`main.rs:34-104`) | same — add `Command::Foo(FooArgs)` |
| Args struct | new `FooArgs` with inline `seed`/`trials` + extras (`~10 lines`) | new `FooArgs` with `#[command(flatten)] null: NullArgs` + extras only (`~5 lines`) |
| `From<Args>` | new `impl From<FooArgs> for foo::FooConfig` (`~8 lines`) | new `impl` using `null.seed_or(..)`/`trials_or(..)` (`~6 lines`) |
| dispatch wiring | new `fn run_foo(cfg) -> ExitCode` (`~12 lines`) **plus** an arm in `main`'s `match` **plus** a `format_foo_error` + `print_foo_report` in `report.rs` | **one** `match` arm: `Command::Foo(a) => dispatch(a.into(), foo::run_foo)` |
| report rendering | hand-written `print_foo_report` in `report.rs` | `impl Report for FooReport` (brief 06), no `main.rs` edit |
| **total `main.rs` edits** | **4 scattered** (variant + Args + From + run_ + match-arm) | **3 contiguous** (variant + Args + From) + **1 trivial** match arm |

The net win is the elimination of the `run_*` fn and the per-experiment
`report.rs` `print_*`/`format_*` pair; the registry makes the `main` match arm a
one-liner. With brief 06 in place, no `report.rs` edit is needed for a new
experiment at all.

## Implementation steps (ordered, each independently committable & green)

Each step ends green (`make verify`) and changes **no** stdout/stderr (golden
masters + `tests/*_cli.rs` unchanged).

1. **Prereq check (no code).** Confirm brief 06 has landed on this branch:
   every report type used by a *regular* (uniform-dispatch) subcommand implements
   `Report::render`, and every dispatched error enum implements `Display` with
   the load-bearing CLI prefix preserved. If 06 is not merged, stop — this brief
   cannot be green without it. Record which stderr prefixes are golden
   (`grep -rn 'error:' tests/*_cli.rs`).

2. **Introduce `dispatch` + `emit` + `RunOutcome`, convert ONE regular
   subcommand** (suggest `Nulltest`, already covered by `tests/nulls_cli.rs`).
   Replace `run_nulltest` (`src/main.rs:663-672`) with a `dispatch(...,
   null::run_standard36_null)` arm and `emit`. Keep all other `run_*` fns
   untouched. Green + `tests/nulls_cli.rs` passes ⇒ the pattern is proven.

3. **Convert the remaining ~17 uniform subcommands** to `dispatch`, one commit
   per small batch (group by report module to keep diffs reviewable). Delete each
   converted `run_*` fn. After each batch: `make verify`. The irregular six
   (`Demo`, `Orders`, `Grouping`, `Stats`, `Pipelinenull`, `Controls`) keep their
   bespoke fns, now returning via `emit`.

4. **Flatten `seed`/`trials` into `NullArgs` (part a).** First migrate the two
   *existing* `NullArgs` consumers to the `Option` + `seed_or`/`trials_or` form
   (their default pair is shared, so zero behavior change). Then, one experiment
   per commit, replace inline `seed`/`trials` fields with
   `#[command(flatten)] null: NullArgs` and route the per-module default through
   the `From` impl. **Before each commit, diff `--help` output** for that
   subcommand (`cargo run -- <sub> --help`) against the pre-change binary; if the
   `[default: ...]` annotation regresses and a golden master/cli test asserts on
   it, revert to inline fields for that subcommand and note it (part a is
   best-effort per-subcommand; part b is the guaranteed win).

5. **`null_trials` consumers** (`AglGakArgs`, `CipherAttackArgs`): leave their
   `--null-trials` field inline — they do not share the `seed`+`trials` pair, so
   they are out of `NullArgs`'s scope. (Optionally, a separate one-field
   `SeedArg`/`NullTrialsArg` flatten if it reads cleanly, but do not over-fit.)

6. **Final tidy.** Confirm `main`'s top-level dispatch is one arm per command,
   `main.rs` is materially shorter (target: well under 700 lines), and the
   crate-level `DEFAULT_NULL_SEED`/`DEFAULT_NULL_TRIALS`
   (`src/main.rs:17-18`) / `DEFAULT_DOF_NULL_SEED`/`DEFAULT_DOF_NULL_TRIALS`
   (`:19-20`) are still wired through. `make check`.

## Files to create / change / delete

- **Change** `src/main.rs`: redefine `NullArgs` (`:227-241`, struct + `From`
  impl) as the shared flattened struct with `seed_or`/`trials_or`; add
  `dispatch`/`emit`/`RunOutcome`; convert ~18 `Args` structs to flatten
  `NullArgs`; convert their `From` impls to use the builder helpers; delete ~18
  uniform `run_*` fns; shrink the `main` match (`:620-647`) to one-line arms;
  keep the 6 irregular fns. This is the only
  file this brief *must* change.
- **Create (optional)** `src/cli.rs` (+ `pub mod cli;` in `lib.rs`) if the
  registry/`dispatch` helpers read better factored out of `main.rs`. Keep it thin
  and CLI-only; do not move domain logic. Only do this if it shortens `main.rs`
  meaningfully without leaking experiment knowledge into the library.
- **Depend on (do not edit here)** `src/report.rs`: brief 06 already added the
  `Report` trait + `Display` impls. This brief consumes them; it should not need
  to touch `report.rs`. If a load-bearing stderr prefix is missing from a
  `Display` impl, that is a brief-06 gap — fix it in coordination, noted as such.
- **No deletes of `report.rs` fns here** — that is brief 06's job. If brief 06
  left any `print_*`/`format_*` free fns that this brief renders obsolete, list
  them for a follow-up cleanup rather than deleting mid-stream.
- **No new dependencies.** clap `flatten` is already available
  (`Cargo.toml:24`). No `deny.toml`/`cargo-machete` impact.

## Success criteria

- `main.rs`'s top-level dispatch is one arm per command; the uniform arms are
  one line each; the ~18 boilerplate `run_*` fns are gone.
- `seed`/`trials` are declared **once** (in `NullArgs`) and flattened, not
  re-declared per struct — except any subcommand intentionally kept inline for
  `--help` parity (documented).
- Adding a new uniform experiment requires **no** new `run_*` fn and **no**
  `report.rs` edit — only a clap variant, an `Args` struct, a `From` impl, and a
  one-line match arm (the before/after table above).
- Every flag, default value, default seed, default trial count, stdout report,
  and stderr error string is **byte-identical** to pre-refactor.
- `make verify` green at every commit; `make check` before final push.

## Verification (exactly how to prove it)

- **Golden-master diff (primary).** Run the brief-01 golden-master capture for
  *every* subcommand with its default args and with a fixed `--seed 123
  --trials 5` (where applicable) before and after; assert zero diff on stdout and
  stderr. This is the behavior-preservation gate.
- **`--help` parity.** For each subcommand, capture `noita-eye <sub> --help`
  before and after; diff. Any change to a `[default: ...]` annotation from
  flattening must be either absent (no test/golden asserts it) or reverted to
  inline fields for that subcommand. Capture top-level `noita-eye --help` and
  `noita-eye help` too (subcommand order/about text must be unchanged).
- **Existing CLI suites.** `tests/nulls_cli.rs`,
  `tests/periodicity_cli.rs`, `tests/chaining_cli.rs`,
  `tests/controls_cli.rs`, et al. (the `tests/*_cli.rs` set) must pass unchanged —
  in particular `dofnull_calibration_trials_default_to_trials`
  (`tests/nulls_cli.rs:39-45`), which pins the `--calib-trials`→`trials` default,
  and the `--trials`/`--seed` flag handling exercised throughout.
- **Negative paths.** Run each error path that has a `run_noita_eye_failure`
  test (`tests/common/mod.rs:23-36`) and confirm the stderr prefix + message are
  unchanged (this is where brief-06 `Display` impls and any
  `dispatch_labelled` prefix are validated).
- `make verify` then `make check` (fmt + clippy `-D` + tests + rustdoc `-D` +
  cargo-deny + machete + codespell + shellcheck + release build).

## Risks & honesty caveats

- **`--help` default annotations are the real risk.** Flattening
  `seed`/`trials` as `Option` drops clap's literal `[default: 0x...]` from help
  for those fields. If any golden master or `--help` test asserts on that
  annotation, part (a) regresses output. Mitigation: the brief explicitly makes
  part (a) per-subcommand best-effort and part (b) the guaranteed,
  `--help`-neutral win; revert any subcommand whose `--help` diff is unacceptable
  and keep its fields inline. **Do not** present a flattened-but-help-regressed
  state as behavior-preserving.
- **Load-bearing stderr prefixes.** The per-`run_*` `eprintln!` labels
  (`"periodicity error: "` `:734`, `"honeycomb lattice error: "` `:749`, etc.)
  are user-facing and may be golden. They must survive — either inside brief-06
  `Display` impls or via a `dispatch_labelled` wrapper. Verify against the golden
  masters which are contractual before removing any.
- **Hard dependency on brief 06.** Without `Report::render` and error `Display`,
  the generic `dispatch` cannot compile. If 06 is incomplete, this brief is
  blocked — do not stub a partial `Report` impl just to land 08.
- **Irregular subcommands must not be over-abstracted.** `Pipelinenull`
  (two reports), `Orders` (three structs), and `Controls` (nested subcommand)
  do not fit the uniform table; forcing them in would add accidental complexity.
  Keeping ~6 bespoke fns is the correct, honest design, not a failure to dedup.
- **No statistic or decode changes.** This is pure CLI plumbing; the corpus
  base-7 cross-check, every null calibration, and every reported p-value/z must
  be untouched. The golden-master diff is the proof, per
  `docs/refactor/00-OVERVIEW.md:192-195`.

## Out of scope / non-goals

- Brief 06's work itself (introducing `Report`/`Display`) — assumed done.
- Splitting/relocating `report.rs` or any module (brief 07).
- Adding `Sequence`/external-ciphertext ingest as a new subcommand (brief 03) —
  the registry should make that a one-entry add *later*, but this brief adds no
  new command.
- Changing any flag name, default value, default seed, alias (e.g. the
  `gak-eyes`/`perfect-isomorphism`/`dihedral` aliases at `src/main.rs:50,83,92`),
  subcommand ordering, or `about`/`after_help` text.
- Touching the `Experiment`/solve pipeline (briefs 02/04) beyond consuming the
  trait names the overview fixes.
- Promoting the registry to a fully data-driven `Vec<RegistryEntry>` with runtime
  reflection — the closure-per-variant `dispatch` is sufficient and keeps clap's
  compile-time arg checking; a heavier framework is not justified here.
