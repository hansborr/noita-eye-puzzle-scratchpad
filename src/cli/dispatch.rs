//! The CLI dispatch core: the [`run`] entry point invoked from `main`, the
//! generic uniform-experiment [`dispatch`]/[`emit`] registry, and the
//! [`RunOutcome`] glue between them.

use std::process::ExitCode;

use clap::Parser;
use noita_eye_puzzle::{
    analysis::honeycomb,
    attack::{agl_gak, cipher_attack, gak_attack},
    experiments::{
        conditional_structure, modular_diff, orientation_homogeneity, periodicity, pyry_conditions,
        transitivity,
    },
    nulls::{dof_null, null, perseus, tree_residual, zero_adjacency_null},
    report::Report,
};

use super::args::{Cli, Command};
use super::commands::{
    run_chaining, run_chaining_graph, run_codecpower, run_controls, run_crcscan, run_cribfit,
    run_ctakscan, run_demo, run_gak, run_grouping, run_groupscan, run_isomorphimperf,
    run_isomorphnull, run_isoscan, run_keydiff, run_keystream, run_leakceiling, run_orders,
    run_perfectiso, run_pipelinenull, run_predscan, run_profile, run_ragbaby, run_rankcodec,
    run_rlcodec, run_solve, run_stats,
};

/// Outcome of one experiment run, ready for the thin CLI to emit.
enum RunOutcome {
    /// Rendered report for stdout; exit `SUCCESS`.
    Ok(String),
    /// Fully-formatted (label-prefixed) error line for stderr; exit `FAILURE`.
    Err(String),
}

/// Emits a [`RunOutcome`]: the rendered report to stdout on success, or the
/// error line to stderr on failure, returning the matching [`ExitCode`].
///
/// `print!` is used for the report because `Report::render` already ends in a
/// newline; `eprintln!` supplies the trailing newline for the error line. Both
/// match the pre-registry per-`run_*` behavior byte-for-byte.
fn emit(outcome: RunOutcome) -> ExitCode {
    match outcome {
        RunOutcome::Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        RunOutcome::Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs one uniform experiment end-to-end: execute `run` on `cfg`, then either
/// render the report (success) or prefix the error with `label` (failure).
///
/// This collapses the per-subcommand `match run(cfg) { Ok => print!, Err =>
/// eprintln! }` boilerplate into one generic call, so each `main` dispatch arm
/// for a uniform experiment is a single line. The `label` reproduces the exact
/// pre-registry stderr prefix (e.g. `"periodicity error"`).
fn dispatch<C, R, E>(label: &str, cfg: C, run: impl FnOnce(C) -> Result<R, E>) -> RunOutcome
where
    R: Report,
    E: std::fmt::Display,
{
    match run(cfg) {
        Ok(report) => RunOutcome::Ok(report.render()),
        Err(error) => RunOutcome::Err(format!("{label}: {error}")),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "flat subcommand dispatch registry; one arm per command is clearest"
)]
pub(crate) fn run() -> ExitCode {
    match Cli::parse().command {
        // Irregular subcommands keep their bespoke handlers (multi-report,
        // nested subcommand, positional parse, or the elaborate solve/keystream
        // pipelines); see their fns below.
        Command::Stats(args) => run_stats(&args),
        Command::Demo => run_demo(),
        Command::Orders => run_orders(),
        Command::Pipelinenull(args) => run_pipelinenull(args.into()),
        Command::Grouping => run_grouping(),
        Command::Controls(args) => run_controls(args),
        Command::Solve(args) => run_solve(&args),
        Command::Keystream(args) => run_keystream(&args),
        Command::Ragbaby(args) => run_ragbaby(&args),
        Command::Profile(args) => run_profile(&args),
        Command::Gak(args) => run_gak(&args),
        Command::Isoscan(args) => run_isoscan(&args),
        Command::Rlcodec(args) => run_rlcodec(&args),
        Command::Codecpower(args) => run_codecpower(&args),
        Command::Cribfit(args) => run_cribfit(&args),
        Command::Rankcodec(args) => run_rankcodec(&args),
        Command::Groupscan(args) => run_groupscan(&args),
        Command::Ctakscan(args) => run_ctakscan(&args),
        Command::Predscan(args) => run_predscan(&args),
        Command::Keydiff(args) => run_keydiff(&args),
        Command::Crcscan(args) => run_crcscan(&args),
        Command::Chaining(args) => run_chaining(&args),
        Command::Isomorphnull(args) => run_isomorphnull(&args),
        Command::ChainingGraph(args) => run_chaining_graph(&args),
        Command::Perfectiso(args) => run_perfectiso(&args),
        Command::Isomorphimperf(args) => run_isomorphimperf(&args),
        Command::Leakceiling(args) => run_leakceiling(&args),
        // Uniform experiments: build config, run, render report (or label the
        // error) via the generic `dispatch`/`emit` registry. The `&str` label
        // is the exact pre-registry stderr prefix.
        Command::AglGak(a) => emit(dispatch("AGL-GAK error", a.into(), agl_gak::run_agl_gak)),
        Command::GakAttack(a) => emit(dispatch(
            "GAK-attack error",
            a.into(),
            gak_attack::run_gak_attack,
        )),
        Command::GakAttackEyes(a) => emit(dispatch(
            "GAK-attack eyes error",
            a.into(),
            gak_attack::run_gak_attack_eyes,
        )),
        Command::Nulltest(a) => emit(dispatch(
            "null test error",
            a.into(),
            null::run_standard36_null,
        )),
        Command::Dofnull(a) => emit(dispatch("DoF null error", a.into(), dof_null::run_dof_null)),
        Command::Periodicity(a) => emit(dispatch(
            "periodicity error",
            a.into(),
            periodicity::run_periodicity,
        )),
        Command::Honeycomb(a) => emit(dispatch(
            "honeycomb lattice error",
            a.into(),
            honeycomb::run_honeycomb,
        )),
        Command::Homogeneity(a) => emit(dispatch(
            "orientation homogeneity error",
            a.into(),
            orientation_homogeneity::run_orientation_homogeneity,
        )),
        Command::Moddiff(a) => emit(dispatch(
            "modular-difference error",
            a.into(),
            modular_diff::run_modular_diff,
        )),
        Command::Perseus(a) => emit(dispatch(
            "Perseus recurrence error",
            a.into(),
            perseus::run_perseus,
        )),
        Command::Zeroadjnull(a) => emit(dispatch(
            "zero-adjacency null error",
            a.into(),
            zero_adjacency_null::run_zero_adjacency_null,
        )),
        Command::Treeresidual(a) => emit(dispatch(
            "tree-residual null error",
            a.into(),
            tree_residual::run_tree_residual,
        )),
        Command::Transitivity(a) => emit(dispatch(
            "transitivity error",
            a.into(),
            transitivity::run_transitivity,
        )),
        Command::Conditional(a) => emit(dispatch(
            "conditional structure error",
            a.into(),
            conditional_structure::run_conditional_structure,
        )),
        Command::Cipherattack(a) => emit(dispatch(
            "cipher attack error",
            a.into(),
            cipher_attack::run_cipher_attack,
        )),
        Command::Pyry(a) => emit(dispatch(
            "Pyry's Conditions error",
            a.into(),
            pyry_conditions::run_pyry_conditions,
        )),
    }
}
