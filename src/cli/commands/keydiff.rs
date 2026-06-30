//! Handler for the `keydiff` subcommand: the Thread B isomorph key-difference
//! discriminator. It calls the same library functions the module's tests
//! exercise ([`key_difference::key_difference_scan`] /
//! [`key_difference::key_difference_self_test`]).
//!
//! A verdict is a **structural discriminator, not a decode** (AGENTS.md honesty
//! discipline): it reports the additive order of the keystream difference behind
//! an isomorph relabelling — it never recovers plaintext.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::key_difference::{
    self, AutokeyFamily, KeyDiffReport, KeyDiffVerdict,
};

use crate::cli::args_analysis::KeydiffArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Orientation-digit alphabet size used when no `--alphabet` is supplied.
const ORIENTATION_ALPHABET: usize = 5;

/// Dispatches the `keydiff` subcommand (scan, or `--self-test` controls).
pub(crate) fn run_keydiff(args: &KeydiffArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Scans the resolved input and reports the key-difference verdict.
fn run_scan(args: &KeydiffArgs) -> ExitCode {
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

    let report = match key_difference::key_difference_scan(
        &values,
        alphabet_size,
        args.max_order,
        args.min_anchor_len,
        args.top_k,
        args.null_trials,
        args.seed,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("keydiff error: {error}");
            return ExitCode::FAILURE;
        }
    };

    print_report(&report);
    ExitCode::SUCCESS
}

/// Prints the per-order firings, the regression (if any), and the verdict.
fn print_report(report: &KeyDiffReport) {
    println!(
        "keydiff: {} symbols over a {}-symbol alphabet (modulus m = {})",
        report.input_len, report.alphabet_size, report.alphabet_size
    );
    println!(
        "  finite-difference firings (significant exact repeat clearing the order-1 Markov null, len >= {}):",
        report.min_anchor_len
    );
    for firing in &report.firings {
        let marker = if firing.fired { "FIRED" } else { "     " };
        println!(
            "    order {} [{}]  observed max {:>4}  null ceiling {:>3}  p {:.4}  significant {}  ({} channel symbols, {} anchors)",
            firing.order,
            marker,
            firing.observed_max,
            firing.null_ceiling,
            firing.p_value,
            firing.significant,
            firing.channel_len,
            firing.anchors.len(),
        );
        if firing.fired {
            for anchor in &firing.anchors {
                println!(
                    "        anchor len {:>4} at {}/{} (gap {})",
                    anchor.length, anchor.first, anchor.second, anchor.gap
                );
            }
        }
    }
    match report.fired_order {
        Some(order) => println!("  lowest firing additive order: {order}"),
        None => println!("  lowest firing additive order: none"),
    }
    println!(
        "  gap-pattern isomorph certificate (raw stream): {}",
        report.gap_isomorph_present
    );
    if let Some(fit) = &report.regression {
        println!(
            "  constant-Δ regression: {} pairs over {} distinct gaps; best slope r = {} consistent on {}/{} pairs",
            fit.pairs, fit.distinct_gaps, fit.best_slope, fit.consistent_pairs, fit.pairs
        );
    }
    print_verdict(&report.verdict);
    println!(
        "  note: a verdict is a structural discriminator over the keystream-difference family, never recovered plaintext."
    );
}

/// Renders the verdict line with the honest interpretation.
fn print_verdict(verdict: &KeyDiffVerdict) {
    match verdict {
        KeyDiffVerdict::IdenticalKey => println!(
            "  VERDICT: identical key (Δ ≡ 0) — a raw exact repeat; the two occurrences share the same keystream (e.g. Vigenère with the gap a period multiple)."
        ),
        KeyDiffVerdict::ConstantAdditive { family } => {
            println!(
                "  VERDICT: constant additive Δ (order 1) — classical autokey / Wadsworth / progressive-alphabet."
            );
            print_family(family);
        }
        KeyDiffVerdict::LinearAdditive => println!(
            "  VERDICT: linear additive Δ (order 2) — an accelerating progressive keystream."
        ),
        KeyDiffVerdict::HigherOrderAdditive { order } => {
            println!("  VERDICT: higher-order polynomial additive Δ (order {order}).");
        }
        KeyDiffVerdict::Irregular => println!(
            "  VERDICT: irregular Δ — a relabelled repeat exists (gap-pattern certificate) but NO additive order fired up to the scanned ceiling: the relabelling is non-additive (deck / GAK / self-modifying keystream)."
        ),
        KeyDiffVerdict::NoSignal => println!(
            "  VERDICT: no signal — no additive order fired and no gap-pattern isomorph certificate was found. No relabelled-repeat structure to classify; NOT evidence of any family."
        ),
    }
}

/// Renders the autokey-family sub-line for a constant-`Δ` verdict.
fn print_family(family: &AutokeyFamily) {
    match family {
        AutokeyFamily::ProgressiveAlphabet { slope } => println!(
            "           family: progressive-alphabet — a single shared slope r = {slope} fits δ ≡ r·g (mod m) across distinct gaps."
        ),
        AutokeyFamily::ClassicalAutokey => println!(
            "           family: classical autokey — the per-pair offset δ is content-driven (no single slope explains the gaps)."
        ),
        AutokeyFamily::SingleGap => println!(
            "           family: indeterminate — only one distinct gap observed; the slope is underdetermined (constant Δ still established)."
        ),
    }
}

/// `keydiff --self-test`: planted controls + matched null, PASS/FAIL.
fn run_self_test(seed: u64) -> ExitCode {
    let result = match key_difference::key_difference_self_test(seed) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("keydiff self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("keydiff self-test (seed=0x{seed:016x}):");
    println!(
        "  planted ciphertext-autokey -> constant additive Δ (order 1):   {}",
        pass_fail(result.ctak_constant)
    );
    println!(
        "  planted Vigenère (period-multiple gap) -> identical key (k=0): {}",
        pass_fail(result.vigenere_identical)
    );
    println!(
        "  planted additive-progressive -> progressive-alphabet family:   {}",
        pass_fail(result.progressive_family)
    );
    println!(
        "  planted deck relabel -> irregular (non-additive relabelling):  {}",
        pass_fail(result.deck_irregular)
    );
    println!(
        "  matched-null agreement (controls clear null, deck does not):   {}",
        pass_fail(result.null_agreement)
    );
    println!("  SELF-TEST: {}", pass_fail(result.passed));
    if result.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}
