//! Handler for the `gak` subcommand: file-driven instruments over the
//! hidden-state (deck-stabilizer, convention B) GAK.
//!
//! Each mode runs the same library functions the module's tests exercise
//! (`discriminate` / `solve_candidate` / `run_self_test`). A solve prints a
//! **candidate**, never a decode (AGENTS.md honesty discipline): the candidate fit
//! is only meaningful against the matched no-English control floor and the
//! genuine-English ceiling, and the bounded search states its limits.

use std::process::ExitCode;

use noita_eye_puzzle::attack::gak_attack::hidden_state_solver::{self, HiddenVisibleVerdict};
use noita_eye_puzzle::attack::quadgram;

use crate::cli::args_attack::{
    GakArgs, GakDiscriminateArgs, GakMode, GakSelfTestArgs, GakSolveArgs,
};
use crate::cli::shared::{display_prefix, parse_cli_sequence, resolve_input_text};

/// Default cipher alphabet for the 12-symbol convention-B GAK.
const GAK_ALPHABET: &str = "ABCDEFGHIJKL";

/// Dispatches the `gak` subcommand to its instrument mode.
pub(crate) fn run_gak(args: &GakArgs) -> ExitCode {
    match &args.mode {
        GakMode::Discriminate(mode_args) => run_discriminate(mode_args),
        GakMode::Solve(mode_args) => run_solve(mode_args),
        GakMode::SelfTest(mode_args) => run_self_test(*mode_args),
    }
}

/// Resolves ciphertext input and parses it to convention-B symbol values plus the
/// declared alphabet size.
fn resolve_values(
    ciphertext: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
    alphabet: Option<&str>,
) -> Result<(Vec<u8>, usize), ExitCode> {
    let text = match resolve_input_text(ciphertext, input_file, stdin) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let alphabet_spec = alphabet.unwrap_or(GAK_ALPHABET);
    let parsed = match parse_cli_sequence(&text, Some(alphabet_spec), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let mut values = Vec::with_capacity(parsed.glyphs.len());
    for glyph in parsed.glyphs {
        match u8::try_from(glyph.0) {
            Ok(value) => values.push(value),
            Err(_overflow) => {
                eprintln!("alphabet symbol value {} exceeds 255", glyph.0);
                return Err(ExitCode::FAILURE);
            }
        }
    }
    Ok((values, alphabet_spec.chars().count()))
}

/// `gak discriminate`: the structural hidden-vs-visible Markov-excess verdict.
fn run_discriminate(args: &GakDiscriminateArgs) -> ExitCode {
    let (values, alphabet_size) = match resolve_values(
        args.ciphertext.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let report = match hidden_state_solver::discriminate(&values, alphabet_size) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("gak discriminate error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "gak discriminate: {} symbols over a {}-symbol alphabet",
        report.length, report.alphabet_size
    );
    println!("  markov-excess drop: {:.4}", report.excess);
    if let (Some(hidden), Some(visible)) = (report.hidden_reference, report.visible_reference) {
        println!("  hidden-state reference (same length): {hidden:.4}");
        println!("  visible-state reference (same length): {visible:.4}");
    } else {
        println!("  (calibration references require the 12-symbol convention-B alphabet)");
    }
    println!("  verdict: {}", verdict_label(report.verdict));
    println!("note: a structural heuristic (no language model), not a proof.");
    ExitCode::SUCCESS
}

/// `gak solve`: the honest candidate generator, gated by a matched no-English
/// control. Emits a candidate, never a decode.
fn run_solve(args: &GakSolveArgs) -> ExitCode {
    let (values, alphabet_size) = match resolve_values(
        args.ciphertext.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    if alphabet_size != hidden_state_solver::VISIBLE_ALPHABET {
        eprintln!(
            "gak solve targets the 12-symbol convention-B GAK; the alphabet has {alphabet_size} symbols (pass --alphabet with 12 symbols, e.g. {GAK_ALPHABET})"
        );
        return ExitCode::FAILURE;
    }
    let lm_text = match &args.lm_corpus {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("failed to read --lm-corpus: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => quadgram::ENGLISH_CORPUS_LARGE.to_owned(),
    };
    let candidate = match hidden_state_solver::solve_candidate(
        &values,
        &lm_text,
        args.population,
        args.generations,
        args.seed,
    ) {
        Ok(candidate) => candidate,
        Err(error) => {
            eprintln!("gak solve error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "gak solve: {} symbols (population={} generations={} seed=0x{:016x})",
        values.len(),
        args.population,
        args.generations,
        args.seed
    );
    println!(
        "  CANDIDATE (not a decode): {}",
        display_prefix(&render_plaintext(&candidate.plaintext), 120)
    );
    println!(
        "  candidate bigram fit:       {:.4} nat/bigram",
        candidate.candidate_fit
    );
    println!(
        "  matched no-English control: {:.4} nat/bigram  (the floor overfitting reaches on noise)",
        candidate.control_fit
    );
    println!(
        "  genuine-English ceiling:    {:.4} nat/bigram",
        candidate.english_ceiling
    );
    let delta = candidate.candidate_fit - candidate.control_fit;
    if candidate.beats_control {
        println!(
            "  verdict: ENGLISH-LIKE CANDIDATE — clears the no-English control by {delta:+.4}; a hypothesis to verify externally, NOT a confirmed decode."
        );
    } else {
        println!(
            "  verdict: NO ENGLISH RECOVERED — candidate does not beat the no-English control ({delta:+.4} <= {:.2}); blocked on the unknown codec/convention.",
            hidden_state_solver::ENGLISH_MARGIN
        );
    }
    println!(
        "  bounded search: population={}, generations={}, seed=0x{:016x}; this does NOT exhaust the key space.",
        args.population, args.generations, args.seed
    );
    ExitCode::SUCCESS
}

/// `gak self-test`: the synthetic positive control + matched null, PASS/FAIL.
fn run_self_test(args: GakSelfTestArgs) -> ExitCode {
    let report = match hidden_state_solver::run_self_test(args.seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("gak self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("gak self-test (seed=0x{:016x}):", args.seed);
    println!(
        "  known-key decode accuracy: {:.3}  (>= {:.2} required)",
        report.known_key_accuracy,
        hidden_state_solver::SELF_TEST_MIN_KNOWN_KEY
    );
    println!(
        "  blind solver accuracy:     {:.3}  (>= {:.2} required)",
        report.blind_accuracy,
        hidden_state_solver::SELF_TEST_MIN_RECOVERY
    );
    println!(
        "  positive control: {}",
        pass_fail(report.positive_control_passed)
    );
    println!(
        "  matched null: {}/{} trials rejected by the no-same-class precondition; max recovery {:.3} (< {:.2} required)",
        report.null_rejected,
        report.null_trials,
        report.null_max_accuracy,
        hidden_state_solver::SELF_TEST_MAX_NULL
    );
    println!("  null: {}", pass_fail(report.null_failed));
    println!("  SELF-TEST: {}", pass_fail(report.passed));
    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Renders the 8-symbol candidate plaintext as digits for display.
fn render_plaintext(symbols: &[usize]) -> String {
    symbols
        .iter()
        .map(|&symbol| char::from_digit(u32::try_from(symbol).unwrap_or(0), 10).unwrap_or('?'))
        .collect()
}

/// Human-readable label for a hidden-vs-visible verdict.
fn verdict_label(verdict: HiddenVisibleVerdict) -> &'static str {
    match verdict {
        HiddenVisibleVerdict::HiddenState => {
            "HIDDEN-STATE (excess clears the visible reference by the margin)"
        }
        HiddenVisibleVerdict::VisibleState => {
            "VISIBLE-STATE (excess sits at the visible reference)"
        }
        HiddenVisibleVerdict::Ambiguous => {
            "AMBIGUOUS (excess in the gray band above the visible reference)"
        }
        HiddenVisibleVerdict::Uncalibrated => {
            "UNCALIBRATED (no 12-symbol convention-B calibration available)"
        }
    }
}

/// `PASS`/`FAIL` label for a boolean gate result.
fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}
