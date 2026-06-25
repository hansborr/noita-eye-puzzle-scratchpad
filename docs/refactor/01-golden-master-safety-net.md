# 01 — Golden-master safety net

> One-line: capture the exact current stdout/stderr/exit-code of every CLI subcommand as committed golden fixtures, so every later refactor (02–08) is provably behavior-preserving.
> Status: not started · Depends on: — · Blocks: 02, 03, 04, 05, 06, 07a, 07b, 08 · Size: M

## Goal & why it matters

The overview's first ground rule is **behavior-preserving**: "No refactor may change a reported statistic or a decode" and "Brief **01** pins these with golden-master tests *before* any other brief touches code — land 01 first" (`docs/refactor/00-OVERVIEW.md:192-195`, `:177`). Every other brief leans on this safety net.

The existing integration tests in `tests/` are *characterization* tests, not golden masters: they assert that output **contains** specific substrings via `assert_contains` (`tests/common/mod.rs:39-44`). That catches deletion of a pinned line but is blind to:
- reordering of report sections,
- changes to lines nobody happened to pin,
- whitespace/formatting drift,
- new or dropped lines between the pinned ones,
- changes to **stderr** wording or **exit codes** on error paths (only `nulltest`/`pipelinenull`/`controls` have any failure-path coverage today — `tests/nulls_cli.rs:92-105`, `tests/controls_cli.rs:52-71`).

A refactor like brief 06 (dissolving `report.rs`'s 209 `print_*`/`format_*` functions) or brief 08 (CLI registry) can silently reorder or reword a whole report and still pass every current test. This brief closes that gap by capturing **byte-exact full stdout** per subcommand at a fixed seed into committed fixture files, plus representative error stderr+exit-code, asserted byte-for-byte.

The headline numbers and the Experiment-0 corpus cross-check are the crown jewels of "never present unverified numbers as findings" (`AGENTS.md` claim-discipline section); they get explicit dedicated pins on top of the full-stdout snapshots.

## Current state (grounded, with file:line)

**Subcommand surface.** The `Command` enum has 26 variants (`src/main.rs:34-104`), dispatched in `main()` (`src/main.rs:619-648`). Each maps to a `run_*` function (`src/main.rs:650-1069`). The `controls` subcommand has its own nested `ControlTarget` subcommand enum with `monoalphabetic`/`isomorph` (alias `polyalphabetic`) targets (`src/main.rs:586-593`, `:987-999`), so it expands to multiple golden cases. Full list of top-level subcommands and their default seeds:

| Subcommand | run fn | seed source | trials/cost default |
| --- | --- | --- | --- |
| `stats <seq>` | `run_stats` `src/main.rs:1058` | none (deterministic on input) | — |
| `demo` | `run_demo` `src/main.rs:650` | none | — |
| `orders` | `run_orders` `src/main.rs:1031` | none | — |
| `agl-gak` | `run_agl_gak` `src/main.rs:675` | `agl_gak::DEFAULT_SEED` `src/main.rs:114` | `DEFAULT_NULL_TRIALS = 2_000_000` `src/agl_gak.rs:21` |
| `gak-attack` | `run_gak_attack` `src/main.rs:687` | `gak_attack::DEFAULT_SEED` `src/main.rs:148` | `DEFAULT_SEEDS_PER_KIND = 3` `src/gak_attack.rs:80` |
| `gak-attack-eyes` | `run_gak_attack_eyes` `src/main.rs:702` | `EYES_DEFAULT_SEED` `src/main.rs:197` | `EYES_DEFAULT_TRIALS = 2_000` `src/gak_attack.rs:4401`; **writes a file** |
| `nulltest` | `run_nulltest` `src/main.rs:663` | `DEFAULT_NULL_SEED` `src/main.rs:17`,`228` | `DEFAULT_NULL_TRIALS = 1_000` `src/main.rs:18` |
| `dofnull` | `run_dofnull` `src/main.rs:717` | `DEFAULT_DOF_NULL_SEED` `src/main.rs:19`,`245` | `DEFAULT_DOF_NULL_TRIALS = 1_000` `src/main.rs:20` |
| `periodicity` | `run_periodicity` `src/main.rs:729` | `periodicity::DEFAULT_SEED` `src/main.rs:265` | `DEFAULT_TRIALS = 1_000` `src/periodicity.rs:35` |
| `honeycomb` | `run_honeycomb` `src/main.rs:744` | `honeycomb::DEFAULT_SEED` `src/main.rs:295` | `DEFAULT_TRIALS` |
| `pipelinenull` | `run_pipelinenull` `src/main.rs:759` | `DEFAULT_NULL_SEED` `src/main.rs:228` | prints **two** reports `src/main.rs:777-779` |
| `grouping` | `run_grouping` `src/main.rs:783` | none | — |
| `homogeneity` | `run_homogeneity` `src/main.rs:795` | `orientation_homogeneity::DEFAULT_SEED` `src/main.rs:435` | per-seed trials |
| `isomorphnull` | `run_isomorphnull` `src/main.rs:810` | `isomorph_null::DEFAULT_SEED` `src/main.rs:312` | trials |
| `chaining` | `run_chaining` `src/main.rs:825` | `chaining::DEFAULT_SEED` `src/main.rs:330` | trials |
| `chaining-graph` | `run_chaining_graph` `src/main.rs:837` | `chaining_graph::DEFAULT_SEED` `src/main.rs:354` | trials |
| `moddiff` | `run_moddiff` `src/main.rs:852` | `modular_diff::DEFAULT_SEED` `src/main.rs:372` | trials |
| `perseus` | `run_perseus` `src/main.rs:867` | `perseus::DEFAULT_SEED` `src/main.rs:395` | trials |
| `perfectiso` | `run_perfectiso` `src/main.rs:882` | `perfect_isomorphism::DEFAULT_SEED` `src/main.rs:412` | trials |
| `zeroadjnull` | `run_zeroadjnull` `src/main.rs:897` | `zero_adjacency_null::DEFAULT_SEED` `src/main.rs:455` | per-seed trials |
| `treeresidual` | `run_treeresidual` `src/main.rs:912` | `tree_residual::DEFAULT_SEED` `src/main.rs:475` | trials |
| `transitivity` | `run_transitivity` `src/main.rs:927` | `transitivity::DEFAULT_SEED` `src/main.rs:495` | trials |
| `conditional` | `run_conditional` `src/main.rs:942` | `conditional_structure::DEFAULT_SEED` `src/main.rs:512` | per-seed trials |
| `cipherattack` | `run_cipherattack` `src/main.rs:957` | `cipher_attack::DEFAULT_SEED` `src/main.rs:536` | `DEFAULT_SAMPLES = 512` `src/cipher_attack.rs:40` |
| `pyry` | `run_pyry` `src/main.rs:972` | `pyry_conditions::DEFAULT_SEED` `src/main.rs:562` | `DEFAULT_FIXTURE_DRAWS = 24` `src/pyry_conditions.rs:33` |
| `controls monoalphabetic` | `run_monoalphabetic_control` `src/main.rs:1001` | `controls::DEFAULT_MONOALPHABETIC_SEED` `src/main.rs:597` | — |
| `controls isomorph` (alias `polyalphabetic`) | `run_isomorph_control` `src/main.rs:1016` | `controls::DEFAULT_ISOMORPH_SEED` `src/main.rs:609` | — |
| `controls` (no target) | falls through to monoalphabetic `src/main.rs:992-998` | `DEFAULT_MONOALPHABETIC_SEED` | — |

**Determinism is real and verified.** All randomness flows through the in-crate `SplitMix64` seeded from the config (`src/null.rs:38-72`; the seed-reproducibility property is itself doc-tested at `src/null.rs:27-36` and unit-tested at `src/null.rs:665-672`, `:705-728`). I confirmed byte-identical repeat runs for `demo` (no seed), `nulltest --trials 5 --seed 123`, and `grouping` (no seed) against the current release binary. So a fixed `--seed`/`--trials` invocation has a single canonical stdout that can be frozen as a fixture.

**Cost.** The production defaults are expensive (`agl-gak` = 2,000,000 trials; `cipherattack` = 512 samples). The existing CLI tests already work around this by passing small overrides (e.g. `tests/agl_gak_cli.rs:12` uses `--null-trials 32`; `tests/gak_attack_cli.rs:20` uses `--seeds-per-kind 2`). I timed the slow ones at small overrides: `agl-gak --null-trials 32 --seed 123` ≈ 6 ms; `gak-attack-eyes --trials 16` ≈ 1.4 s (the slowest). **The golden master must pin a fixed *small* override, not the production default**, exactly as the current suite does — otherwise the test is too slow and we still would not be exercising the production-trial RNG path (which the dedicated regression test `standard36_seed_12345_null_matches_headline_regression` at `src/null.rs:765` already pins, gated behind `--ignored`).

**Filesystem side effect.** `gak-attack-eyes` writes a candidate record (path built at `src/gak_attack.rs:4834`; written by `write_eyes_candidate_record`, `:6024-6038`) into `--candidates-dir` (default `research/gak-threads/candidates` — `src/main.rs:208-212`). The existing test redirects this to a temp dir (`tests/gak_attack_cli.rs:238-252`). The golden test must do the same, and the record filename embeds the seed/trials/beam but is otherwise clock-free (`eyes_record_filename`, `src/gak_attack.rs:5977-5982`) — confirm the filename is seed-stable before snapshotting it.

**Corpus cross-check (must never change).** `experiment_0_cross_validates_transcription_against_engine_decode` (`src/corpus.rs:321-348`) asserts the vendored `MESSAGES` digits equal the ngraham20 transcription **and** equal the base-7 engine decode byte-for-byte. The `demo` subcommand renders this corpus (`run_demo` → `corpus::combined_sequence()` → `report::print_report`, `src/main.rs:651-653`), and `tests/basic_cli.rs:17-18` already pins the headline `2.2801 bits/glyph` and `0.2108` IoC. These two numbers are the corpus's content fingerprint and get an explicit dedicated pin.

**Dependencies.** Only `clap` + `statrs` (`Cargo.toml:24-25`); `[dev-dependencies]` is empty (`:27-30`). `deny.toml` bans `multiple-versions` and `wildcards` (`deny.toml:30-33`) and restricts licenses (`:10-25`). Adding a snapshot crate (`insta`) would pull in `similar`, `console`, etc. — new supply-chain surface that must clear `cargo-deny` and `cargo-machete`. **This brief does NOT add a crate** (see Target design).

## Target design (concrete API / types / layout)

**No new dependency.** Use plain committed-string comparison against fixture files loaded with `include_str!`, asserted with `assert_eq!`. Rationale, weighed explicitly:

- **`insta` (considered, rejected for now).** `insta` gives ergonomic snapshot review (`cargo insta review`) and inline snapshots, but it adds a dev-dependency tree (`similar`, `console`, `linked-hash-map`, …) that must pass `cargo-deny` license/ban checks (`deny.toml:10-33`) and `cargo-machete`. The golden masters here are a *one-time* capture that should change **only** when behavior intentionally changes; we want regeneration to be a deliberate, reviewed act, not a fast `review` loop. The `include_str!` + `assert_eq!` approach needs zero new crates, keeps the dependency surface minimal per the house rule (`AGENTS.md` "Vetted, minimal external crates"), and the diff on failure is already legible because fixtures are committed text files visible in `git diff`. **Decision: plain committed-string comparison.** Revisit `insta` only if fixture maintenance becomes painful and a maintainer justifies it against `deny.toml`.

**Layout.**

```
tests/
  golden/                         # committed expected-output fixtures (one file per case)
    demo.stdout
    orders.stdout
    stats_012340123455.stdout
    stats_unknown_digit.stderr     # error-path stderr
    nulltest_t5_s123.stdout
    pipelinenull_t5_s123.stdout    # both reports, exactly as printed
    agl-gak_nt32_s123.stdout
    gak-attack_spk2_s123.stdout
    gak-attack-eyes_t16.stdout     # candidates-dir redirected to a temp dir
    ... one .stdout per subcommand at the fixed invocation ...
    controls_monoalphabetic_s123.stdout
    controls_isomorph_s123.stdout
    controls_no_target.stdout
    nulltest_t0_s123.stderr        # error-path stderr (exit code asserted in harness)
    pipelinenull_t0_s123.stderr
  golden_master.rs                 # the harness: one #[test] per case
  common/mod.rs                    # extend with raw-output + exit-code helpers
```

**Harness helpers** (extend `tests/common/mod.rs`). Add functions that return the *full* captured streams plus status, instead of only success-stdout:

```rust
pub struct CliRun { pub stdout: String, pub stderr: String, pub success: bool }
pub fn run_noita_eye_raw(args: &[&str]) -> CliRun;          // no success assertion
```

Keep the existing `run_noita_eye` / `run_noita_eye_failure` / `assert_contains` untouched so the current characterization tests still compile.

**One golden helper per assertion shape:**

```rust
fn assert_golden_stdout(args: &[&str], fixture: &str);     // success + byte-eq stdout vs include_str!
fn assert_golden_stderr_failure(args: &[&str], fixture: &str); // !success + byte-eq stderr
```

`assert_golden_stdout` asserts `run.success == true`, then `assert_eq!(run.stdout, expected_fixture_contents)`. `assert_golden_stderr_failure` asserts `run.success == false` (exit code FAILURE) and byte-eq stderr.

**Fixed invocations (deterministic + cheap).** Mirror the small overrides the current suite already uses, so cost stays low and the captured stream is canonical:
- seeded subcommands: `--seed 123` plus the smallest `--trials`/`--seeds-per-kind`/`--draws`/`--samples`/`--seed-count` the existing sibling test uses (cross-reference each `tests/*_cli.rs` for the exact small args already validated — e.g. `agl-gak --null-trials 32 --seed 123`, `gak-attack --seeds-per-kind 2 --seed 123`, `cipherattack --samples 1 --null-trials 1 --max-vigenere-period 1 --seed 123`, `pyry --seed 123 --draws 4`).
- `gak-attack-eyes`: `--trials 16 --candidates-dir <tempdir>`; snapshot stdout only (the record file's existence is asserted, its body is *not* snapshotted unless verified clock-free).
- `stats`, `demo`, `orders`, `grouping`: no seed needed.

**Dedicated headline pins** (belt-and-suspenders on top of full-stdout snapshots, so a refactor that touches both the report and the fixture can't slip a number change past review):
- a `#[test]` asserting `demo` stdout contains `2.2801 bits/glyph` and `0.2108` (the corpus content fingerprint — matches `tests/basic_cli.rs:17-18`);
- a `#[test]` asserting `nulltest`/`homogeneity`/`moddiff`/`honeycomb` headline statistic lines that are already pinned in their sibling `*_cli.rs` files remain present (these are the regression-locked numbers from `src/null.rs:765` family).

**Do not delete or weaken** the existing `tests/*_cli.rs` characterization tests — they document *intent* (which strings are load-bearing). The golden masters are additive: full-stream snapshots that catch everything else.

## Implementation steps (ordered, each independently committable & green)

1. **Harness scaffolding (no fixtures yet).** Add `CliRun` + `run_noita_eye_raw` to `tests/common/mod.rs` (with `#[allow(dead_code, reason = "...")]` if a helper is not yet referenced, matching the existing pattern at `tests/common/mod.rs:19-22`). Add an empty `tests/golden_master.rs` with a single trivial `#[test]` that calls `run_noita_eye_raw(&["demo"])` and asserts `success`. Commit. `make verify` green.

2. **Capture deterministic, zero-cost subcommands.** Generate fixtures for `demo`, `orders`, `grouping`, `stats 012340123455`, `controls monoalphabetic --seed 123`, `controls isomorph --seed 123`, `controls polyalphabetic --seed 123` (alias must match the non-alias output), and `controls --seed 123` (no target). Write each via `target/release/noita-eye <args> > tests/golden/<case>.stdout`. Add one `assert_golden_stdout` test per case in `tests/golden_master.rs`. Add the dedicated `demo` corpus-fingerprint pin (`2.2801 bits/glyph`, `0.2108`). Commit. `make verify` green.

3. **Capture seeded null/structural subcommands at small fixed args.** For each of the ~20 seeded subcommands, run at `--seed 123` + the smallest trial args already validated in its sibling `tests/*_cli.rs`, freeze stdout into `tests/golden/<case>.stdout`, add an `assert_golden_stdout` test. Handle `pipelinenull` specially: capture the **combined two-report** stdout (`src/main.rs:777-779`). Commit. `make verify` green.

4. **Capture `gak-attack-eyes` (filesystem side effect).** Run with `--trials 16` and `--candidates-dir` pointed at a per-test temp dir (mirror `tests/gak_attack_cli.rs:238-252`); freeze stdout; assert a record file `eyes-*` was written (existence only). Confirm with two repeat runs that stdout is byte-identical before committing the fixture. Commit. `make verify` green.

5. **Capture error paths (stderr + exit code).** Freeze stderr for: `stats 012x` (unknown-digit, exit FAILURE — `src/main.rs:1064-1067`), `nulltest --trials 0 --seed 123` (`src/main.rs:666-669`), `pipelinenull --trials 0 --seed 123` (`src/main.rs:762-768`). Add `assert_golden_stderr_failure` tests for each, which also assert non-success exit. These mirror and harden `tests/nulls_cli.rs:92-105`. Commit. `make verify` green.

6. **Regeneration doc + guard.** Add a short header comment in `tests/golden_master.rs` documenting the exact command to regenerate every fixture (a small loop over the fixed-arg table) and stating that **a fixture change in a refactor PR is a behavior change and must be reviewed line-by-line, not blindly regenerated**. Confirm `codespell` (`make spell`) and `shellcheck` pass on any helper script. Commit. `make check` green.

## Files to create / change / delete

**Create:**
- `tests/golden_master.rs` — the harness (one `#[test]` per case) + regeneration header.
- `tests/golden/*.stdout` — one fixture per subcommand invocation (~30 files including the `controls` variants and `pipelinenull`'s combined output).
- `tests/golden/*.stderr` — error-path fixtures (`stats_unknown_digit`, `nulltest_t0`, `pipelinenull_t0`).
- *(optional)* `scripts/regen-golden.sh` — regeneration helper; if added it must pass `shellcheck -x` (`Makefile:45-46`) and codespell.

**Change:**
- `tests/common/mod.rs` — add `CliRun` + `run_noita_eye_raw` (and `assert_golden_stdout`/`assert_golden_stderr_failure`, or place those in `golden_master.rs`). Keep existing helpers intact.

**Delete:** none. Existing `tests/*_cli.rs` characterization tests are kept as intent documentation.

No `src/` changes — this brief is test-only and must not modify library/CLI behavior.

## Success criteria

- A `tests/golden/` fixture exists for **every** top-level subcommand variant (all 26 `Command` variants plus the three `controls` target cases), each asserted byte-for-byte.
- At least three error paths are captured as stderr fixtures with non-success exit codes asserted.
- The corpus content fingerprint (`2.2801 bits/glyph`, `0.2108`) and the regression-locked null/structural headline numbers are pinned (both inside the full-stdout snapshots and via at least one dedicated `assert_contains` test).
- No new entry in `Cargo.toml [dependencies]` or `[dev-dependencies]`; `cargo-deny` and `cargo-machete` unchanged and green.
- `make verify` and `make check` are green; the new golden tests run in CI's normal (non-`--ignored`) test pass and complete fast (the slowest, `gak-attack-eyes --trials 16`, ≈ 1.4 s).
- Running the capture commands a second time produces byte-identical fixtures (determinism re-confirmed).

## Verification (exactly how to prove it)

1. `make verify` — fmt, clippy `-D`, **all golden tests**, rustdoc, deny.
2. **Determinism proof:** regenerate every fixture into a scratch dir and `diff -r` against the committed `tests/golden/` — must be empty. (I already confirmed byte-stability for `demo`, `nulltest --trials 5 --seed 123`, and `grouping`.)
3. **Safety-net proof (do once, do not commit):** apply a trivial cosmetic change to one `report::print_*` function (e.g. reorder two output lines), run `cargo test --test golden_master`, and confirm the relevant golden test **fails** with a clear byte diff; then revert. This demonstrates the net catches what `assert_contains` would miss.
4. `make check` for the full local CI (adds `cargo-machete`, `codespell`, `shellcheck`, release build).
5. For briefs 02–08: after each refactor commit, `cargo test --test golden_master` must stay green with **zero** fixture edits. Any required fixture edit is a behavior change and must be justified in that brief's PR, never silently regenerated.

## Risks & honesty caveats

- **Over-pinning brittleness.** Byte-exact snapshots will flag *intended* output changes too. This is the point — but a refactor PR that legitimately changes wording must update the fixture *and* explain why, reviewed line-by-line. The step-6 regeneration doc must state this loudly. Do not let a future agent "just regenerate" to make red turn green.
- **Hidden nondeterminism.** If any subcommand mixes in wall-clock, env, locale, or `HashMap` iteration order, its snapshot would be flaky. The eyes/null path is `SplitMix64`-seeded (`src/null.rs:38-72`) and I verified three representative subcommands are byte-stable, but the implementer must run the determinism diff (Verification step 2) across **all** subcommands before committing, and quarantine (do not snapshot) any stream that fails to reproduce — instead pin only its stable headline lines and note the reason.
- **`gak-attack-eyes` record file.** Its filename embeds the seed/trials/beam and is clock-free (`eyes_record_filename`, `src/gak_attack.rs:5977-5982`), but the implementer must confirm the *body* is clock-free before snapshotting it; if not, snapshot stdout only and assert record existence (as the existing test does, `tests/gak_attack_cli.rs:338-347`). The candidates dir must always be a temp dir so the committed `research/gak-threads/candidates/` tree is never touched by tests.
- **Cost discipline.** Capturing at production defaults (`agl-gak` 2M trials) would make CI slow without testing anything the `--ignored` regression at `src/null.rs:765` doesn't already cover. The golden masters deliberately use the same small overrides as the existing suite; this brief does **not** pin production-default-trial output.
- **Claim ceiling unchanged.** This is pure test scaffolding; it asserts nothing about glyph *meaning*. The standing claim ceiling ("deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved") is untouched, and the golden master in fact *protects* the honesty strings (e.g. `tests/gak_attack_cli.rs`, `tests/agl_gak_cli.rs`) by freezing them byte-for-byte.

## Out of scope / non-goals

- Any `src/` change, refactor, or new abstraction (that is briefs 02–08).
- Adding a snapshot crate (`insta` etc.) — explicitly rejected above; revisit only with a maintainer's `deny.toml` justification.
- Re-deriving or re-validating the statistics themselves — this brief *freezes* current output; the numbers' correctness is already gated by `src/corpus.rs:321-348` and the `--ignored` regressions in `src/null.rs`.
- Pinning production-default-trial output (covered by existing `--ignored` regression tests).
- Removing or rewriting the existing `tests/*_cli.rs` characterization tests (a later cleanup could fold them in, but not here).
- Golden-mastering `--help`/`--version`/usage text (clap-owned, low refactor risk; add later only if brief 08 changes the CLI surface).
