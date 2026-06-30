//! Handler for the `isoscan` subcommand: a file-driven translate-isomorph
//! (exact repeated-substring) scanner with an order-1 Markov matched null.
//!
//! It calls the same library functions the module's tests exercise
//! ([`translate_isomorph::iso_scan`] / [`translate_isomorph::iso_scan_self_test`]).
//! A reported anchor is a **structural candidate, never a decode** (AGENTS.md
//! honesty discipline): it only locates where a stream repeats more than the
//! transition-preserving null explains, which can seed a crib attack — it does
//! not recover plaintext.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::translate_isomorph;

use crate::cli::args_attack::IsoscanArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Orientation-digit alphabet size used when no `--alphabet` is supplied.
const ORIENTATION_ALPHABET: usize = 5;

/// Dispatches the `isoscan` subcommand (scan, or `--self-test` positive control).
pub(crate) fn run_isoscan(args: &IsoscanArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Scans the resolved input for translate-isomorphs.
fn run_scan(args: &IsoscanArgs) -> ExitCode {
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

    let report = match translate_isomorph::iso_scan(
        &values,
        alphabet_size,
        args.delta_mod,
        args.top_k,
        args.null_trials,
        args.seed,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isoscan error: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "isoscan: {} symbols over a {}-symbol alphabet",
        report.input_len, report.alphabet_size
    );
    match report.delta_mod {
        Some(modulus) => println!(
            "  projection: difference channel mod {modulus} -> {} symbols (alphabet {})",
            report.projected_len, report.projected_alphabet
        ),
        None => println!(
            "  projection: none (raw stream, {} symbols)",
            report.projected_len
        ),
    }
    println!("  longest exact repeat: {} symbols", report.observed_max);
    println!(
        "  matched null (order-1 Markov, {} trials): mean longest {:.1}, ceiling {}, p-value {:.4}",
        report.null_trials, report.null_max_mean, report.null_max_ceiling, report.p_value
    );
    if report.significant {
        println!(
            "  verdict: STRUCTURAL CANDIDATE — longest repeat clears every null trial (ceiling {}); a crib anchor to verify, NOT a decode.",
            report.null_max_ceiling
        );
        if report.anchors.is_empty() {
            println!("  (no anchors above the null ceiling were enumerated)");
        } else {
            println!("  anchors (difference-channel positions; longest first):");
            for anchor in &report.anchors {
                println!(
                    "    len {:>4}  at {} and {}  (gap {})",
                    anchor.length, anchor.first, anchor.second, anchor.gap
                );
            }
        }
    } else {
        println!(
            "  verdict: NO REPEAT BEYOND NULL — longest repeat does not clear the transition-preserving null floor; no crib anchor."
        );
    }
    println!(
        "  note: an anchor is a structural candidate (a repeated span), never recovered plaintext."
    );
    ExitCode::SUCCESS
}

/// `isoscan --self-test`: planted positive control + matched null, PASS/FAIL.
fn run_self_test(seed: u64) -> ExitCode {
    let report = match translate_isomorph::iso_scan_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isoscan self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("isoscan self-test (seed=0x{seed:016x}):");
    println!("  planted exact repeat:   {} symbols", report.planted_len);
    println!("  recovered longest:      {} symbols", report.recovered_len);
    println!(
        "  matched-null ceiling:   {} symbols (< {} required)",
        report.null_max_ceiling, report.planted_len
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed { "PASS" } else { "FAIL" }
    );
    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
