//! Handler for the `ctakscan` subcommand: the ciphertext-autokey (feedback) deck
//! discriminator for the `C3 × H` hidden-state GAK reading.
//!
//! It calls the same library functions the module's tests exercise
//! ([`ctak_feedback::ctak_scan`] / [`ctak_feedback::ctak_self_test`]). A verdict
//! is a **structural discriminator, not a decode** (AGENTS.md honesty discipline):
//! it reports whether a single-symbol-feedback advance map reproduces the
//! rotor-anchor plaintext repeat in the deck channel — it never recovers plaintext
//! or the digit→language codec.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::ctak_feedback::{self, Convention, CtakVerdict, Readout, Side};

use crate::cli::args_ctak::CtakscanArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Orientation-digit alphabet size used when no `--alphabet` is supplied.
const ORIENTATION_ALPHABET: usize = 5;

/// Dispatches the `ctakscan` subcommand (scan, or `--self-test` controls).
pub(crate) fn run_ctakscan(args: &CtakscanArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Scans the resolved input and reports the feedback-deck verdict.
fn run_scan(args: &CtakscanArgs) -> ExitCode {
    let text = match resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let parsed = match parse_cli_sequence(&text, args.alphabet.as_deref(), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let values: Vec<u16> = parsed.glyphs.iter().map(|glyph| glyph.0).collect();
    let alphabet_size = args
        .alphabet
        .as_deref()
        .map_or(ORIENTATION_ALPHABET, |spec| spec.chars().count());

    let report = match ctak_feedback::ctak_scan(
        &values,
        alphabet_size,
        args.rotor_mod,
        args.min_anchor_len,
        args.top_k,
        args.null_trials,
        args.seed,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("ctakscan error: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "ctakscan: {} symbols over a {}-symbol alphabet",
        report.input_len, report.alphabet_size
    );
    println!(
        "  channels: rotor mod {} (transparent), deck channel of {} card values; advance search {}^{}",
        report.rotor_mod,
        report.deck_size,
        factorial(report.deck_size),
        report.deck_size
    );
    println!(
        "  rotor-difference-channel crib anchors (significant, len >= {}; isoscan null ceiling {}): {}",
        report.min_anchor_len,
        report.anchor_null_ceiling,
        report.anchors.len()
    );
    for anchor in &report.anchors {
        println!(
            "    anchor len {:>4} at ciphertext {}/{}",
            anchor.length, anchor.first, anchor.second
        );
    }
    println!("  per-convention best advance map (joint-minimum crib run across all anchors):");
    for result in &report.conventions {
        let general = if result.d0_cancels {
            "D0-free (general)"
        } else {
            "D0=identity slice"
        };
        println!(
            "    {:>7}/{:<7} {:<18} min-run {:>3}  per-anchor {:?}  null(mean {:.1}, ceiling {})  p={:.4}{}",
            convention_side(result.convention),
            convention_readout(result.convention),
            general,
            result.min_run,
            result.per_anchor_runs,
            result.null_mean,
            result.null_ceiling,
            result.p_value,
            if result.fires() { "  *FIRES*" } else { "" },
        );
    }
    print_verdict(&report.verdict, report.conventions_tested);
    println!(
        "  note: a verdict is a structural discriminator over the feedback-deck family, never recovered plaintext or the codec."
    );
    ExitCode::SUCCESS
}

/// Renders the verdict line(s) with the honest interpretation.
fn print_verdict(verdict: &CtakVerdict, conventions_tested: usize) {
    match verdict {
        CtakVerdict::FeedbackDeckSignal {
            convention,
            g,
            min_run,
            p_value,
        } => {
            println!(
                "  VERDICT: FeedbackDeckSignal — convention {}/{} reproduces the crib in the deck channel (joint min-run {min_run}, p={p_value:.4} vs the deck-resample null) with advance map g={g:?}.",
                convention_side(*convention),
                convention_readout(*convention),
            );
            println!(
                "    This recovers the deck *mechanism* (an advance map consistent with the repeat), NOT plaintext: the digit→language codec is a separate unknown. Bonferroni across {conventions_tested} conventions: require p < {:.4}.",
                0.05 / conventions_tested as f64
            );
        }
        CtakVerdict::NoFeedbackSignal => println!(
            "  VERDICT: NoFeedbackSignal — no convention's advance map reproduces the rotor-anchor plaintext repeat in the deck channel above the deck-resample null (across {conventions_tested} conventions). The ciphertext-autokey single-symbol-feedback deck is excluded too; with passive-deck plaintext-autokey already excluded, no computable-deck reading reproduces the real repeat."
        ),
    }
}

/// `ctakscan --self-test`: planted feedback-deck positive + no-feedback negative,
/// PASS/FAIL.
fn run_self_test(seed: u64) -> ExitCode {
    let result = match ctak_feedback::ctak_self_test(seed) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("ctakscan self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("ctakscan self-test (seed=0x{seed:016x}):");
    println!(
        "  planted feedback deck -> FeedbackDeckSignal recovered:        {}",
        pass_fail(result.positive_recovered)
    );
    println!(
        "  recovered map reproduces the full planted repeat:             {}",
        pass_fail(result.positive_full_repeat)
    );
    println!(
        "  no-feedback (deck-noise) control -> NoFeedbackSignal:         {}",
        pass_fail(result.negative_rejected)
    );
    println!("  SELF-TEST: {}", pass_fail(result.passed));
    if result.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn convention_side(convention: Convention) -> &'static str {
    match convention.side {
        Side::Right => "right",
        Side::Left => "left",
    }
}

fn convention_readout(convention: Convention) -> &'static str {
    match convention.readout {
        Readout::Forward => "forward",
        Readout::Inverse => "inverse",
    }
}

fn factorial(n: usize) -> usize {
    (1..=n).product::<usize>().max(1)
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}
