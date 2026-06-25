# API infrastructure: adding an analysis module + CLI subcommand + report

Read-only map of the existing conventions, so a new GAK/AGL structural module
(null + positive control + CLI report) drops into the same grooves as
`pyry_conditions`, `cipher_attack`, `controls`, etc. No build was run; line
references are to the tree at review time.

Scope reminder (house rules): a new module stays **mapping-independent** —
it may use only ciphertext symbol *equality* and group structure, must ship a
matched null and a positive control that fires on known signal, and must never
print anything stronger than "deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved." Cite the exact wiki page each
predicate encodes; preserve "tentative" labels.

## Files to touch (in order)

1. `src/<module>.rs` — new engine. Owns `Config`, `Report`, `Error`, the
   `pub fn run_<module>(config) -> Result<Report, Error>` entry point, the
   null, the positive control, and `#[cfg(test)]` tests.
2. `src/lib.rs` — add one `pub mod <module>;` line, kept **alphabetical**
   (the existing block at lines 62-88 is sorted: `analysis` … `zero_adjacency_null`).
3. `src/report.rs` — add `pub fn format_<module>_error(...) -> String` and
   `pub fn print_<module>_report(report: &<module>::<Report>)`; extend the
   `use crate::{…}` list (lines 8-12, also alphabetical).
4. `src/main.rs` — add a `Command` variant, an `Args` struct, a
   `From<Args> for <module>::Config` impl, a `run_<module>` dispatch fn, and a
   match arm in `main()`. Extend the `use noita_eye_puzzle::{…}` import (lines
   10-15) with the new module name.

No `Cargo.toml`/`Makefile`/CI edits are needed: the gate (`make verify` /
`make check`) discovers everything through these four files.

## Engine module shape (`src/<module>.rs`)

Mirror `pyry_conditions.rs` (predicate harness) or `cipher_attack.rs` (attack +
shuffle null + positive control). Required public surface, every item documented
(`missing_docs = "warn"` → `-D` in CI):

- `pub const DEFAULT_SEED: u64` and any `DEFAULT_*` knobs (used directly as
  clap `default_value_t`, e.g. `pyry_conditions::DEFAULT_SEED`,
  `DEFAULT_FIXTURE_DRAWS`).
- `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct <Module>Config { … }`
  with a `impl Default` that fills from the `DEFAULT_*` consts
  (`pyry_conditions.rs:61`). `Copy` only if all fields are `Copy`.
- `pub enum <Module>Error { Grid(GridError), ZeroTrials, RandomBoundTooLarge {
  bound: usize }, … }` with `#[derive(Clone, Debug, PartialEq, Eq)]`. Provide
  `From<GridError>`, `From<ciphers::CipherError>`, and
  `From<crate::null::RandomBoundError>` impls so `?` works
  (`pyry_conditions.rs:93-109`). For an error carried by a `&` in `main`
  (`cipher_attack`), also `impl fmt::Display` + `impl std::error::Error`.
- `pub struct <Module>Report { pub config, pub order, … }`
  (`#[derive(Clone, Debug, PartialEq)]`).
- `pub fn run_<module>(config: <Module>Config) -> Result<<Module>Report, <Module>Error>`
  with a `# Errors` rustdoc section (required; `cargo doc` runs `-D warnings`).
  Body: `validate_config(config)?` → build fixtures → evaluate eyes →
  evaluate null/controls → return report.

Fixtures / corpus access (read-only, no mapping):
- `orders::corpus_grids()?` then `orders::read_corpus_message_values(&grids,
  order)?`, with `order = orders::accepted_honeycomb_order()` — never re-select a
  reading order (`pyry_conditions.rs:397-401`, `cipher_attack.rs:444-461`).
- Alphabet size: `orders::READING_LAYER_ALPHABET_SIZE` /
  `ciphers::EYE_READING_ALPHABET_SIZE` (both 83). Values are `TrigramValue`
  (0..=82); glyph indices are `glyph::Glyph(u16)`.

Null (mandatory, matched):
- Use only `crate::null` PRNG primitives: `SplitMix64::new(seed)`,
  `fisher_yates`, `shuffled_permutation`, `random_index_below`,
  `stateless_splitmix` — the in-crate reproducible PRNG (AGENTS.md keeps it for
  deterministic nulls). Derive per-trial/per-family seeds with a `mix_seed(seed,
  tag)` helper (`pyry_conditions.rs:1313`, `cipher_attack.rs:1156`).
- A **within-message shuffle** that preserves message lengths and symbol
  multisets is the canonical structural null (`cipher_attack.rs:1122` and its
  `null_model` string at `:417`). Aggregate within-message evidence only — no
  cross-message bigrams/lags/runs.
- For a structural *negative*, frame it as the expected outcome and report it as
  a tail/exceedance, not a verdict (`cipher_attack.rs` module doc, lines 14-18).

Positive control (mandatory, must fire on known signal):
- Plant a known structure, then prove the harness recovers/detects it with a
  margin over the null (`cipher_attack.rs::run_positive_controls` :1173, gated by
  `POSITIVE_CONTROL_MIN_MARGIN`). For a predicate harness, instead score named
  generated cipher families and show the condition vector discriminates
  (`pyry_conditions.rs::evaluate_generated_families` :831). A failing control is
  an error variant (`PositiveControlFailed`) — methodology is suspect, not data.

If the module introduces a new cipher KEY (GAK/AGL/`S_83` deck variant), add it
to `src/ciphers.rs`, mirroring `DeckCipherKey` (ciphers.rs:384):
- `pub struct <Name>Key { alphabet_size, … }`; `pub fn new(...) ->
  Result<Self, CipherError>` validating via `validate_alphabet_size`,
  `validate_permutation`, `validate_control_cards`; a `pub fn identity(...)`
  convenience; `#[must_use] pub const` accessors.
- Free `pub fn <name>_encrypt/_decrypt(&[Glyph], &Key) -> Result<Vec<Glyph>,
  CipherError>`, each with an `# Errors` doc line.
- **Exact round-trip control test** in `#[cfg(test)] mod tests`: small alphabet
  + `EYE_READING_ALPHABET_SIZE`, random plaintexts via `SplitMix64`,
  `assert_eq!(decrypt(encrypt(p)), p)` (ciphers.rs:1224-1245). This is the
  template a new key must satisfy.

## `From<Args>` pattern (`src/main.rs`)

Each subcommand has an `Args` struct whose every field is a clap `#[arg]` whose
`default_value_t` is the module's `DEFAULT_*` const, plus a `From<Args>` that
builds the module `Config`. Canonical (`NullArgs`, main.rs:92-107):

```rust
#[derive(Clone, Copy, Debug, Args)]
struct GakArgs {
    #[arg(long, default_value_t = gak::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = gak::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<GakArgs> for gak::GakConfig {
    fn from(args: GakArgs) -> Self {
        Self { seed: args.seed, trials: args.trials, ..Self::default() }
    }
}
```

- Use `..Self::default()` when `Config` has fields not exposed on the CLI
  (`IsomorphNullArgs` :184, `ChainingArgs` :206, `PyryConditionsArgs` :376).
- Rename long flags with `#[arg(long = "max-period", …)]` where the field name
  differs (`PeriodicityArgs` :135).
- Register: add `Gak(GakArgs)` to `enum Command` (main.rs:34) with a `///` doc
  line (becomes `--help` text) and optional `#[command(name = "gak", alias =
  "…")]`; add `Command::Gak(args) => run_gak(args.into()),` to `main()`
  (:427-450).

## Report-printing pattern (`src/report.rs` + `run_*` in main.rs)

`run_*` dispatch fn (main.rs:684-697 `run_pyry` is the cleanest template):

```rust
fn run_gak(config: gak::GakConfig) -> ExitCode {
    let report = match gak::run_gak(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("GAK error: {}", report::format_gak_error(&error));
            return ExitCode::FAILURE;
        }
    };
    report::print_gak_report(&report);
    ExitCode::SUCCESS
}
```

- Pass `&error` to the formatter when the error isn't `Copy`/contains `String`
  (`format_cipher_attack_error(&error)`, `format_pyry_conditions_error(&error)`);
  pass by value for small `Copy`-ish enums (`format_periodicity_error(error)`).
- `format_<module>_error` is `#[must_use] pub fn … -> String`, a `match` over
  every variant returning user-facing text (report.rs:35-52, 190-209). No
  `unwrap`/`panic`.
- `print_<module>_report(report: &…)` uses `println!` only; factor sub-sections
  into private `fn print_*` helpers (report.rs:815, 845, 862…). Add a final
  `Interpretation:` paragraph that states the defensible-claim ceiling and a
  `Multiplicity note:` when several tails are tested
  (report.rs:908-931, 1379-1381). Cite the wiki page the predicate encodes and
  keep "tentative" wording.

## Lint conventions (non-negotiable; `-D warnings` in CI)

- `missing_docs` (rust) + `missing_docs` discipline: **every** `pub` item,
  including struct fields and enum variants, needs a `///` doc.
- No `unwrap`/`expect`/`panic`/`indexing_slicing`/`string_slice` in lib/CLI
  code. Index via `.get(i)` + `let Some(x) = … else { return Err(...) }`, slice
  via `.windows()/.chunks()`. These are relaxed **only in tests**
  (`clippy.toml`: `allow-unwrap-in-tests` etc.), so `unwrap()` is fine inside
  `#[cfg(test)] mod tests`.
- `unused_results`/`unused_result_ok`/`let_underscore_must_use`: bind dropped
  `#[must_use]` results, e.g. `let _inserted = set.insert(x);`
  (`pyry_conditions.rs:681`).
- `panic_in_result_fn`: a `-> Result<…>` fn must not panic.
- `float_cmp`/`lossy_float_literal`: compare floats with `total_cmp` /
  tolerance, not `==` (report.rs uses `.total_cmp`).
- `map_err_ignore`: don't `map_err(|_| …)` discarding info unless deliberate;
  prefer `From` impls so `?` carries the source.
- Allow attributes must carry a reason: `#[allow(lint, reason = "…")]`. Bare
  `#[allow(...)]` is itself denied (`allow_attributes_without_reason`).
- `cognitive-complexity-threshold = 20`, `too-many-arguments-threshold = 7`,
  `max-struct-bools = 3`: split large fns, bundle args into a small `struct`
  (see `PairInput` in `pyry_conditions.rs:552`), and avoid >3 bool fields.
- `wildcard_imports`: name every import explicitly.
- `--locked` everywhere; don't let any command re-resolve `Cargo.lock`. `unsafe`
  is forbidden crate-wide.

## Test checklist for the new module (`#[cfg(test)] mod tests`)

- Determinism: `run_<module>(cfg) == run_<module>(cfg)` for a fixed seed
  (`cipher_attack.rs:1317`, `pyry_conditions.rs:1446`).
- Eye pin: assert the eyes' headline metric is the known constant (e.g.
  `total_symbols == 1_036`, 83 distinct values, 0 adjacent-equal —
  `pyry_conditions.rs:1430`).
- Positive control fires: planted signal is recovered with margin over null
  (`cipher_attack.rs:1334`).
- Predicate discrimination: each predicate true on a hand-built positive and
  false on a negative fixture (`pyry_conditions.rs:1357-1427`).
- New cipher key (if any): exact encrypt→decrypt round-trip
  (`ciphers.rs:1224`).
