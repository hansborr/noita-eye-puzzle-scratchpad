//! Handler for the `groupscan` subcommand: the D4/A4/S4 hidden-group
//! element-order discriminator for the `C3 × H` hidden-state GAK reading.
//!
//! It calls the same library functions the module's tests exercise
//! ([`group_order::group_scan`] / [`group_order::group_scan_self_test`]). A
//! verdict is a **structural discriminator, not a decode** (AGENTS.md honesty
//! discipline): it reports which hidden deck group the observed deck-channel
//! cycle-length spectrum is consistent with — it never recovers plaintext.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::group_order::{self, GroupVerdict};

use crate::cli::args_analysis::GroupscanArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Orientation-digit alphabet size used when no `--alphabet` is supplied.
const ORIENTATION_ALPHABET: usize = 5;

/// Dispatches the `groupscan` subcommand (scan, or `--self-test` controls).
pub(crate) fn run_groupscan(args: &GroupscanArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Scans the resolved input and reports the element-order verdict.
fn run_scan(args: &GroupscanArgs) -> ExitCode {
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

    let report = match group_order::group_scan(
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
            eprintln!("groupscan error: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "groupscan: {} symbols over a {}-symbol alphabet",
        report.input_len, report.alphabet_size
    );
    println!(
        "  channels: rotor mod {} (transparent), deck channel of {} card values",
        report.rotor_mod, report.deck_size
    );
    println!(
        "  difference-channel anchors examined (len >= {}): {}",
        report.min_anchor_len, report.anchors_examined
    );
    println!(
        "  consistent deck-channel contexts: {}",
        report.consistent_contexts
    );
    for reading in &report.readings {
        let anchor = &reading.anchor;
        match (&reading.cycle_lengths, reading.element_order) {
            (Some(cycles), Some(order)) => println!(
                "    anchor len {:>4} at {}/{}  coverage {}  prefix {}  -> cycle type {:?} (order {})",
                anchor.length,
                anchor.first,
                anchor.second,
                reading.coverage,
                reading.prefix_len,
                cycles,
                order
            ),
            _ => println!(
                "    anchor len {:>4} at {}/{}  coverage {}  prefix {}  -> no consistent deck context",
                anchor.length, anchor.first, anchor.second, reading.coverage, reading.prefix_len
            ),
        }
    }
    println!(
        "  observed deck-channel cycle lengths: {:?}",
        report.observed_cycle_lengths
    );
    println!(
        "  matched null (deck channel decoupled, order-1 Markov, {} trials): mean consistent {:.2}, ceiling {}, p-value {:.4}",
        report.null.trials, report.null.mean_consistent, report.null.ceiling, report.null.p_value
    );
    print_verdict(&report.verdict);
    println!(
        "  note: a verdict is a structural discriminator over the hidden group, never recovered plaintext."
    );
    ExitCode::SUCCESS
}

/// Renders the verdict line(s) with the honest interpretation.
fn print_verdict(verdict: &GroupVerdict) {
    match verdict {
        GroupVerdict::S4 => println!(
            "  VERDICT: hidden group is S4 — both a 3-cycle and a 4-cycle were observed (only S4 contains elements of both orders)."
        ),
        GroupVerdict::ExcludesA4 {
            contexts,
            s4_miss_prob,
        } => println!(
            "  VERDICT: rules out A4 — a 4-cycle was observed (A4 has none). Remaining: D4 or S4. Under a uniform-context model, if the group were S4 the chance of seeing no 3-cycle across {contexts} contexts is {s4_miss_prob:.4} (smaller ⇒ leans D4)."
        ),
        GroupVerdict::ExcludesD4 {
            contexts,
            s4_miss_prob,
        } => println!(
            "  VERDICT: rules out D4 — a 3-cycle was observed (D4 has none). Remaining: A4 or S4. Under a uniform-context model, if the group were S4 the chance of seeing no 4-cycle across {contexts} contexts is {s4_miss_prob:.4} (smaller ⇒ leans A4)."
        ),
        GroupVerdict::Inconclusive { contexts } => println!(
            "  VERDICT: inconclusive — only cycle lengths <= 2 observed across {contexts} contexts; consistent with D4, A4, or S4."
        ),
        GroupVerdict::NoDeckSignal => println!(
            "  VERDICT: no significant deck-channel signal (vs the deck-decoupled null) — no anchor yielded a significant consistent deck-channel permutation (eps-only repeats, a non-TopCard readout, too little coverage, or chance consistency). NOT evidence for any group."
        ),
    }
}

/// `groupscan --self-test`: planted controls + matched null, PASS/FAIL.
fn run_self_test(seed: u64) -> ExitCode {
    let result = match group_order::group_scan_self_test(seed) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("groupscan self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("groupscan self-test (seed=0x{seed:016x}):");
    println!(
        "  cycle-type recovery (identity/transposition/double/3-cycle/4-cycle): {}",
        pass_fail(result.cycle_recovery_passed)
    );
    println!(
        "  planted C3xD4 stream -> rules out A4:                                {}",
        pass_fail(result.d4_excludes_a4)
    );
    println!(
        "  planted C3xA4 stream -> rules out D4:                                {}",
        pass_fail(result.a4_excludes_d4)
    );
    println!(
        "  planted C3xS4 stream -> forces S4:                                   {}",
        pass_fail(result.s4_verdict)
    );
    println!(
        "  eps-only matched null -> no deck signal:                             {}",
        pass_fail(result.null_rejected)
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
