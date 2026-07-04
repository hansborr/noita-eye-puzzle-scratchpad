//! CLI reporting for the pairclass Avenue G pattern-crib scan.

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::{
    PatternCribAnchor, PatternCribConfig, PatternCribHit, PatternCribNegativeControl,
    PatternCribRunReport, PatternCribScan, PatternCribVerdict, StreamPrep, run_pattern_crib_scan,
};

use crate::cli::args_pairclass::PairclassArgs;

/// Runs and prints the controls-first repeated-span pattern-crib scan.
pub(super) fn run_pattern_crib_analysis(
    args: &PairclassArgs,
    prep: &StreamPrep,
) -> Result<ExitCode, String> {
    let Some(corpus_path) = args.crib_corpus_file.as_ref() else {
        return Err("--pattern-crib-scan requires --crib-corpus-file <path>".to_owned());
    };
    let corpus_text = std::fs::read_to_string(corpus_path).map_err(|error| {
        format!(
            "failed to read crib corpus {}: {error}",
            corpus_path.display()
        )
    })?;
    let positive_storage;
    let (positive_text, positive_label) = if let Some(path) = args.plant_text_file.as_ref() {
        positive_storage = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "failed to read positive-control text {}: {error}",
                path.display()
            )
        })?;
        (positive_storage.as_str(), path.display().to_string())
    } else {
        (
            corpus_text.as_str(),
            format!("same as {}", corpus_path.display()),
        )
    };
    let (first, second, len) = prep.longest_tie.ok_or_else(|| {
        "--pattern-crib-scan requires a repeated token anchor; keep --min-anchor-len enabled"
            .to_owned()
    })?;
    let anchor = PatternCribAnchor { first, second, len };
    let report = run_pattern_crib_scan(
        &prep.tokens,
        prep.n_classes,
        anchor,
        &corpus_text,
        positive_text,
        PatternCribConfig {
            max_hits: args.crib_top,
            null_trials: args.crib_null_trials,
            random_negatives: args.crib_random_negatives,
            seed: args.seed,
        },
    )
    .map_err(|error| error.to_string())?;
    print_report(args, corpus_path, &positive_label, &report);
    Ok(ExitCode::SUCCESS)
}

fn print_report(
    args: &PairclassArgs,
    corpus_path: &std::path::Path,
    positive_label: &str,
    report: &PatternCribRunReport,
) {
    println!();
    println!("Avenue G pattern-crib scan (controls-first):");
    println!("  corpus: {}", corpus_path.display());
    println!("  positive-control text: {positive_label}");
    println!(
        "  anchor: phase {}, positions {} and {}, len {} tokens",
        args.phase, report.anchor.first, report.anchor.second, report.anchor.len
    );
    println!(
        "  observed class pattern: {}",
        render_pattern(&report.observed_pattern)
    );
    print_controls(report);
    match report.verdict {
        PatternCribVerdict::ControlsFailed => {
            println!();
            println!(
                "VERDICT: ControlsFailed -- the real `two` stream was NOT scanned. The planted \
                 positive must fire and every matched/random negative must stay quiet before any \
                 real-stream result is reportable."
            );
        }
        PatternCribVerdict::Candidate => {
            if let Some(scan) = report.real_scan.as_ref() {
                print_real_scan(scan);
            }
            println!();
            println!(
                "VERDICT: Candidate -- at least one corpus span survived the repeated-anchor \
                 isomorph constraint after quiet controls. This is a CANDIDATE crib, never a \
                 decode; it needs a hypothesis record and later exact verification."
            );
        }
        PatternCribVerdict::NoCandidate => {
            if let Some(scan) = report.real_scan.as_ref() {
                print_real_scan(scan);
            }
            println!();
            println!(
                "VERDICT: NoCandidate -- no span in this corpus survived the class-isomorph \
                 constraint. Claim ceiling: this excludes only literal spans present in the \
                 scanned corpus under the fixed phase/anchor/static-coloring model; it does not \
                 exclude custom plaintext, another corpus, or a stateful codec."
            );
        }
    }
}

fn print_controls(report: &PatternCribRunReport) {
    let positive = &report.controls.positive;
    println!();
    println!("Controls:");
    println!(
        "  planted positive: start {}, \"{}\", distinct {}, repeated {}, planted hits {}, total hits {} -> {}",
        positive.planted_start,
        positive.planted_text,
        positive.distinct_letters,
        positive.repeated_positions,
        positive.planted_hits,
        positive.scan.hit_count,
        if positive.fired { "FIRED" } else { "MISSED" }
    );
    print_negative_group("matched Markov null", &report.controls.matched_nulls);
    print_negative_group("random negative", &report.controls.random_negatives);
    println!(
        "  controls result: {}",
        if report.controls.passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
}

fn print_negative_group(label: &str, trials: &[PatternCribNegativeControl]) {
    let candidate_like = trials.iter().filter(|trial| trial.hit_count > 0).count();
    println!(
        "  {label}: {candidate_like}/{} candidate-like -> {}",
        trials.len(),
        if candidate_like == 0 {
            "QUIET"
        } else {
            "BLOCKED"
        }
    );
    if let Some(first_bad) = trials.iter().find(|trial| trial.hit_count > 0) {
        println!(
            "    first non-quiet trial {}: {} hits",
            first_bad.trial, first_bad.hit_count
        );
        if let Some(hit) = first_bad.first_hit.as_ref() {
            print_hit("      example", hit);
        }
    }
}

fn print_real_scan(scan: &PatternCribScan) {
    println!();
    println!(
        "Real scan: {} normalized letters, {} windows, {} surviving spans",
        scan.corpus_letters, scan.windows_scanned, scan.hit_count
    );
    for (index, hit) in scan.hits.iter().enumerate() {
        print_hit(&format!("  hit {:>2}", index + 1), hit);
    }
    if scan.capped() {
        println!(
            "  ... {} additional hits omitted by --crib-top",
            scan.hit_count.saturating_sub(scan.hits.len())
        );
    }
}

fn print_hit(prefix: &str, hit: &PatternCribHit) {
    println!(
        "{prefix}: start {}  distinct {}  repeated {}  \"{}\"",
        hit.letter_start, hit.distinct_letters, hit.repeated_positions, hit.text
    );
    println!("{}  coloring: {}", prefix, render_coloring(hit));
}

fn render_pattern(pattern: &[u8]) -> String {
    pattern
        .iter()
        .map(|&token| char::from(b'0' + token.min(9)))
        .collect()
}

fn render_coloring(hit: &PatternCribHit) -> String {
    hit.coloring
        .iter()
        .enumerate()
        .filter_map(|(letter, class)| {
            class.map(|class| format!("{}={class}", char::from(b'a' + letter as u8)))
        })
        .collect::<Vec<_>>()
        .join(" ")
}
