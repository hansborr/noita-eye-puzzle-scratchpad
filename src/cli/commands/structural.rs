//! Bespoke handlers for the structural-battery subcommands.
//!
//! Each analysis keeps its verified eye-corpus default (run with no input flags)
//! and gains a file-driven path: an arbitrary positional / `--input-file` /
//! `--stdin` stream under `--alphabet`, run through the same library computation
//! the eye path uses. A stream is treated as a single message under a neutral
//! raw-rows label — no eye honeycomb traversal is claimed for arbitrary input.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::chaining::{self, ChainingConfig};
use noita_eye_puzzle::analysis::chaining_graph::{self, ChainingGraphConfig};
use noita_eye_puzzle::analysis::perfect_isomorphism::{self, PerfectIsomorphismConfig};
use noita_eye_puzzle::core::trigram::TrigramValue;
use noita_eye_puzzle::nulls::isomorph_null::{self, IsomorphNullConfig};
use noita_eye_puzzle::report::Report;

use crate::cli::args_analysis::{
    ChainingArgs, ChainingGraphArgs, IsomorphNullArgs, PerfectIsomorphismArgs,
};
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Resolves a file-driven structural-battery stream to its [`TrigramValue`]s plus
/// the declared alphabet size, or an error exit code (after printing the reason).
///
/// A stream input requires `--alphabet`: there is no off-corpus reading-layer
/// default, so the alphabet's char count is the only honest alphabet size. The
/// whole stream is one message; the per-message `5` row delimiter and grid
/// reconstruction are corpus-only.
fn resolve_stream(
    sequence: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
    alphabet: Option<&str>,
) -> Result<(Vec<TrigramValue>, usize), ExitCode> {
    let Some(alphabet_spec) = alphabet else {
        eprintln!("a stream input requires --alphabet (its char count is the alphabet size)");
        return Err(ExitCode::FAILURE);
    };
    let text = match resolve_input_text(sequence, input_file, stdin) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let parsed = match parse_cli_sequence(&text, Some(alphabet_spec), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let mut values = Vec::with_capacity(parsed.glyphs.len());
    for glyph in parsed.glyphs {
        let Ok(raw) = u8::try_from(glyph.0) else {
            eprintln!("alphabet symbol value {} exceeds 255", glyph.0);
            return Err(ExitCode::FAILURE);
        };
        match TrigramValue::new(raw) {
            Ok(value) => values.push(value),
            Err(raw) => {
                eprintln!("symbol value {raw} exceeds 124");
                return Err(ExitCode::FAILURE);
            }
        }
    }
    Ok((values, alphabet_spec.chars().count()))
}

/// Renders a structural-battery report to stdout, or prints a labelled error to
/// stderr, returning the matching exit code. `print!` (not `println!`) because
/// [`Report::render`] is already newline-terminated.
fn emit_report<R: Report, E: std::fmt::Display>(label: &str, result: Result<R, E>) -> ExitCode {
    match result {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{label}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `chaining`: Experiment 7B alphabet-chaining structural control.
///
/// With no input flags, runs the verified eye corpus unchanged (the tuning flags
/// `--seed`/`--trials`/`--min-period`/`--max-period` still apply). With a stream
/// input, runs the same calibrated chaining signature over the arbitrary stream,
/// regenerating the Vigenere positive control and the independent-substitution
/// null to the stream's length and `--alphabet`.
pub(crate) fn run_chaining(args: &ChainingArgs) -> ExitCode {
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        let config = ChainingConfig {
            seed: args.seed,
            trials: args.trials,
            min_period: args.min_period,
            max_period: args.max_period,
            alphabet_size: chaining::DEFAULT_ALPHABET_SIZE,
        };
        return emit_report("chaining error", chaining::run_chaining(config));
    }
    let (values, alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let config = ChainingConfig {
        seed: args.seed,
        trials: args.trials,
        min_period: args.min_period,
        max_period: args.max_period,
        alphabet_size,
    };
    emit_report(
        "chaining error",
        chaining::chaining_for_stream(config, &[values]),
    )
}

/// `isomorphnull`: Experiment 7A real isomorphs vs within-message shuffle null.
///
/// With no input flags, runs the verified eye corpus unchanged. With a stream
/// input, runs the same real-vs-shuffle comparison over the arbitrary stream;
/// the within-message shuffle null is matched to the stream's own length and
/// multiset. The statistic is equality-based, so `--alphabet` only declares the
/// symbol identity (its size is not threaded into the config).
pub(crate) fn run_isomorphnull(args: &IsomorphNullArgs) -> ExitCode {
    let config = IsomorphNullConfig {
        seed: args.seed,
        trials: args.trials,
        min_window: isomorph_null::DEFAULT_MIN_WINDOW,
        max_window: isomorph_null::DEFAULT_MAX_WINDOW,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "isomorph null error",
            isomorph_null::run_isomorph_null(config),
        );
    }
    let (values, _alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    emit_report(
        "isomorph null error",
        isomorph_null::isomorph_null_for_stream(config, &values),
    )
}

/// `chaining-graph`: Thread 5 graph-chaining conflict and coverage audit.
///
/// With no input flags, runs the verified eye corpus unchanged. With a stream
/// input, runs the same audit over the arbitrary stream; `--alphabet`'s char count
/// is the coverage denominator. The synthetic non-commutative positive control is
/// stream-independent, so it self-validates the instrument on any input.
pub(crate) fn run_chaining_graph(args: &ChainingGraphArgs) -> ExitCode {
    let config = ChainingGraphConfig {
        seed: args.seed,
        trials: args.trials,
        ..ChainingGraphConfig::default()
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "chaining-graph error",
            chaining_graph::run_chaining_graph(config),
        );
    }
    let (values, alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    emit_report(
        "chaining-graph error",
        chaining_graph::chaining_graph_for_stream(config, &[values], alphabet_size),
    )
}

/// `perfectiso`: Thread 3 perfect-isomorphism / allomorph-consistency scan.
///
/// With no input flags, runs the verified eye corpus unchanged (the tuning flags
/// `--seed`/`--trials`/`--min-window`/`--max-window` still apply). With a stream
/// input, runs the same mapping-independent compute over the arbitrary stream as a
/// single `"input"` message under a neutral raw-rows label. The scan is equality-
/// and gap-based, so `--alphabet` only declares symbol identity (its size is not
/// threaded into the config). The eye wiki-regression checks are replaced
/// off-corpus by the stream-independent synthetic short-island positive control,
/// which self-validates the detector on any input.
///
/// Honest limitation: perfect isomorphism compares aligned repeats *across* >=2
/// messages, so a single-message stream has an empty cross-message catalog by
/// construction and the internal-violation test does not apply to it. This path
/// therefore self-validates the detector (synthetic control) and reports that the
/// test is not applicable; it never claims "supports perfect isomorphism" for an
/// untestable single stream.
pub(crate) fn run_perfectiso(args: &PerfectIsomorphismArgs) -> ExitCode {
    let config = PerfectIsomorphismConfig {
        seed: args.seed,
        trials: args.trials,
        min_window: args.min_window,
        max_window: args.max_window,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "perfect-isomorphism error",
            perfect_isomorphism::run_perfect_isomorphism(config),
        );
    }
    let (values, _alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    emit_report(
        "perfect-isomorphism error",
        perfect_isomorphism::perfect_isomorphism_for_stream(config, &[values]),
    )
}
