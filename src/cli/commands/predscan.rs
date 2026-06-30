//! Handler for the `predscan` subcommand: the Toboter predicate battery plus the
//! multiple-comparisons meta-analysis (Thread C).
//!
//! It calls the same library functions the module's tests exercise
//! ([`predicates::run_battery`] / [`predicates::run_corpus_battery`] /
//! [`predicates::predicate_self_test`]). With no input flags it runs the verified
//! eye corpus under the accepted honeycomb reading order; a stream input (which
//! requires `--alphabet`) runs the identical battery over arbitrary value streams,
//! with the honest caveat that no honeycomb reading is claimed for off-corpus
//! input. Every per-predicate number is a recomputed empirical p, and the
//! meta-analysis — not any single predicate — is the deliverable.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::predicates::{self, predicate_self_test};
use noita_eye_puzzle::core::glyph::Glyph;
use noita_eye_puzzle::core::trigram::TrigramValue;
use noita_eye_puzzle::report::Report;

use crate::cli::args_predicates::PredscanArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text, split_blank_line_messages};

/// Dispatches the `predscan` subcommand (corpus, stream, or `--self-test`).
pub(crate) fn run_predscan(args: &PredscanArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return run_corpus(args);
    }
    run_stream(args)
}

/// Runs the battery on the verified eye corpus.
fn run_corpus(args: &PredscanArgs) -> ExitCode {
    match predicates::run_corpus_battery(args.seed, args.shuffle_trials, args.resample_trials) {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("predscan error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the battery on a file-driven multi-message stream.
fn run_stream(args: &PredscanArgs) -> ExitCode {
    let (messages, alphabet_size) = match resolve_stream(args) {
        Ok(resolved) => resolved,
        Err(code) => return code,
    };
    match predicates::run_battery(
        &messages,
        alphabet_size,
        args.seed,
        args.shuffle_trials,
        args.resample_trials,
    ) {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("predscan error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `predscan --self-test`: planted controls + matched nulls, PASS/FAIL.
fn run_self_test(seed: u64) -> ExitCode {
    let result = predicate_self_test(seed);
    println!("predscan self-test (seed=0x{seed:016x}):");
    for check in &result.checks {
        println!("  {:<4} {}", pass_fail(check.passed), check.name);
    }
    println!("  SELF-TEST: {}", pass_fail(result.passed));
    if result.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Resolves a file-driven multi-message stream to per-message [`TrigramValue`]s
/// plus the declared alphabet size, or an error exit code (after printing why).
///
/// Blank lines separate messages (see [`split_blank_line_messages`]); a stream
/// input requires `--alphabet`, whose char count is the only honest alphabet size
/// off-corpus.
fn resolve_stream(args: &PredscanArgs) -> Result<(Vec<Vec<TrigramValue>>, usize), ExitCode> {
    let Some(alphabet_spec) = args.alphabet.as_deref() else {
        eprintln!("a stream input requires --alphabet (its char count is the alphabet size)");
        return Err(ExitCode::FAILURE);
    };
    let text = match resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let blocks = split_blank_line_messages(&text);
    if blocks.is_empty() {
        eprintln!("input contained no symbols");
        return Err(ExitCode::FAILURE);
    }
    let mut messages = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let parsed = match parse_cli_sequence(block, Some(alphabet_spec), false) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("{error}");
                return Err(ExitCode::FAILURE);
            }
        };
        messages.push(glyphs_to_values(parsed.glyphs)?);
    }
    Ok((messages, alphabet_spec.chars().count()))
}

/// Converts one message's parsed glyphs to bounded reading values.
fn glyphs_to_values(glyphs: Vec<Glyph>) -> Result<Vec<TrigramValue>, ExitCode> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
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
    Ok(values)
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}
