//! Handler for the `cribfit` subcommand: the crib-anchored consistency filter for
//! the codec-with-memory regime of `rlcodec`'s run-length carrier.
//!
//! It calls the same library functions the module's tests exercise
//! ([`cribfit::run_cribfit`] / [`cribfit::cribfit_self_test`]). The filter is a
//! language-free necessary condition (repeated plaintext spans must decode
//! identically); a crib-consistent + English-viable candidate is then language-gated
//! against the *same* matched null `rlcodec` uses. A high n-gram score is **not** a
//! decode (AGENTS.md honesty discipline); the expected verdict on real `one` is an
//! honest negative plus the derived structural constraint.

use std::process::ExitCode;

use noita_eye_puzzle::attack::cribfit::{self, CribCandidate, CribfitReport};
use noita_eye_puzzle::attack::rlcodec::{BatteryCfg, CodecVerdict};

use crate::cli::args_cribfit::CribfitArgs;
use crate::cli::shared::{display_prefix, parse_cli_sequence, resolve_input_text};

/// Walk base used when no `--alphabet` is supplied (the five orientation digits).
const DEFAULT_BASE: usize = 5;
/// Characters of rendered plaintext shown per gated candidate.
const TEXT_PREVIEW: usize = 60;

/// Dispatches the `cribfit` subcommand (filter, or `--self-test`).
pub(crate) fn run_cribfit(args: &CribfitArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Builds the (reused) battery configuration from the CLI arguments.
fn cfg_from(args: &CribfitArgs) -> BatteryCfg {
    BatteryCfg {
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        top_k: args.top_k,
        census_null_trials: noita_eye_puzzle::attack::rlcodec::DEFAULT_CENSUS_NULL_TRIALS,
        seed: args.seed,
    }
}

/// Runs the filter on the resolved input and prints the report.
fn run_scan(args: &CribfitArgs) -> ExitCode {
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
    let base = args
        .alphabet
        .as_deref()
        .map_or(DEFAULT_BASE, |spec| spec.chars().count());

    let cfg = cfg_from(args);
    let report = match cribfit::run_cribfit(&parsed.glyphs, base, &cfg) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("cribfit error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report);
    ExitCode::SUCCESS
}

/// The three-way crib-filter status of a candidate (consistent / excluded /
/// inapplicable — set aside, never excluded).
fn status_str(candidate: &CribCandidate) -> &'static str {
    if candidate.consistency.consistent {
        "consistent"
    } else if candidate.consistency.excluded() {
        "excluded"
    } else {
        "inapplicable"
    }
}

/// Renders a list of periods/moduli as `{a, b, c}`.
fn set_str(values: &[usize]) -> String {
    format!(
        "{{{}}}",
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Prints the full report (header, Sections A/B/C, overall verdict).
fn print_report(report: &CribfitReport) {
    print_header(report);
    print_section_a(report);
    print_section_b(report);
    print_section_c(report);
}

/// Prints the carrier-derivation header.
fn print_header(report: &CribfitReport) {
    let carrier = &report.carrier;
    let distribution = carrier
        .distribution
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "cribfit: {} digits over base {} (clean ±1 walk)",
        carrier.n_digits, carrier.base
    );
    println!("  moves: {} bits", carrier.n_bits);
    println!(
        "  carrier: direction-blind magnitudes |M| = {}  sum {}  distribution {{{}}}",
        carrier.n_magnitudes, carrier.sum, distribution
    );
}

/// Prints Section A: the crib geometry and derived admissible-period lattice.
fn print_section_a(report: &CribfitReport) {
    let geometry = &report.geometry;
    let census = &report.census;
    println!();
    println!("Section A — crib geometry (census-significant carrier repeats as plaintext cribs):");
    if census.significant {
        println!(
            "  cribs are census-significant: longest repeat {} vs null ceiling {} (p {:.4}) — a structural candidate, not a decode.",
            census.observed_max, census.null_ceiling, census.p_value
        );
    } else {
        println!(
            "  longest repeat {} does NOT clear the order-1 Markov null ceiling {} (p {:.4}): no significant crib.",
            census.observed_max, census.null_ceiling, census.p_value
        );
    }
    if geometry.anchors.is_empty() {
        println!("  (no census-significant cribs — the crib filter is inapplicable to this input)");
        return;
    }
    println!("  anchors (run positions; longest first):");
    for anchor in &geometry.anchors {
        println!(
            "    len {:>3}  M[{}..{}] == M[{}..{}]  run-gap {}  bit-gap {}",
            anchor.length,
            anchor.first,
            anchor.first + anchor.length,
            anchor.second,
            anchor.second + anchor.length,
            anchor.run_gap,
            anchor.bit_gap
        );
    }
    println!(
        "  gcd(run-gaps) = {}    gcd(bit-gaps) = {}",
        geometry.gcd_run_gaps, geometry.gcd_bit_gaps
    );
    println!("  derived admissible periods:");
    println!(
        "    run-periodic key periods  {}  (divisors of gcd(run-gaps))",
        set_str(&geometry.run_periods)
    );
    println!(
        "    bit-periodic key periods  {}  (divisors of gcd(bit-gaps))",
        set_str(&geometry.bit_periods)
    );
    println!(
        "    cumulative-sum moduli     {}  (divisors of gcd(bit-gaps))",
        set_str(&geometry.bit_periods)
    );
}

/// Prints Section B: each family's crib-consistency verdict.
fn print_section_b(report: &CribfitReport) {
    let geometry = &report.geometry;
    println!();
    println!("Section B — per-family crib-consistency:");

    println!(
        "  [1] CumulativeSumMod(n): output[i] = (Σ M[0..=i]) mod n; consistent ⟺ n | every bit-gap."
    );
    println!(
        "      caveat: the output is a bounded-increment walk (consecutive symbols differ by M[i]∈1..5 mod n) —"
    );
    println!(
        "              a strong structural constraint on the English it could carry, not a proof of impossibility;"
    );
    println!(
        "              the matched-null gate (Section C), not the walk structure, is the evidence."
    );
    println!(
        "      {:<8} {:>4}  {:<13}  english-viable",
        "n", "|S|", "status"
    );
    for candidate in &report.cumsum {
        print_candidate_row(candidate);
    }

    println!(
        "  [2] RunPeriodicKey(p): state advances per run; consistent ⟺ p | every run-gap ⟺ p | gcd(run-gaps)={}.",
        geometry.gcd_run_gaps
    );
    println!(
        "      admissible periods (analytic): {}",
        set_str(&geometry.run_periods)
    );
    if geometry.run_periods == [1] {
        println!(
            "      verdict: no nontrivial run-periodic keyed codec is crib-consistent (only p=1, the memoryless case)."
        );
    }

    println!(
        "  [3] BitPeriodicKey(p): state advances per carrier bit; consistent ⟺ p | every bit-gap ⟺ p | gcd(bit-gaps)={}.",
        geometry.gcd_bit_gaps
    );
    println!(
        "      admissible periods (analytic): {}",
        set_str(&geometry.bit_periods)
    );
    println!(
        "      concrete substitution family: free monoalphabetic map on augmented symbols (magnitude, bit-coset)."
    );
    println!(
        "      note: english-viable requires the realized augmented alphabet to fall in [8, 26];"
    );
    println!(
        "            a period whose augmented alphabet exceeds 26 is monoalphabetic-infeasible and is reported, not silently dropped."
    );
    println!(
        "      {:<8} {:>4}  {:<13}  english-viable",
        "p", "|S|", "status"
    );
    for candidate in &report.bitperiodic {
        print_bitperiodic_row(candidate);
    }

    println!(
        "  [4] EvolvingTableMtf(tokenization): move-to-front rank code; consistency checked directly on M."
    );
    println!(
        "      (excluded = aligned + inconsistent; inapplicable = token boundaries do not align across the cribs, set aside)"
    );
    println!(
        "      {:<8} {:>4}  {:<13}  {:<28}  english-viable",
        "tok", "|S|", "status", "agreements per anchor"
    );
    for candidate in &report.mtf {
        print_mtf_row(candidate);
    }
}

/// Prints one cumulative-sum candidate row.
fn print_candidate_row(candidate: &CribCandidate) {
    let n = cumsum_mod(candidate);
    println!(
        "      {:<8} {:>4}  {:<13}  {}",
        n,
        candidate.alphabet,
        status_str(candidate),
        if candidate.english_viable {
            "yes"
        } else {
            "no"
        }
    );
}

/// Extracts the display modulus from a cumulative-sum candidate name.
fn cumsum_mod(candidate: &CribCandidate) -> &str {
    candidate
        .name
        .strip_prefix("CumulativeSumMod{n=")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(&candidate.name)
}

/// Prints one bit-periodic substitution candidate row.
fn print_bitperiodic_row(candidate: &CribCandidate) {
    let p = bitperiodic_period(candidate);
    println!(
        "      {:<8} {:>4}  {:<13}  {}",
        p,
        candidate.alphabet,
        status_str(candidate),
        if candidate.english_viable {
            "yes"
        } else {
            "no"
        }
    );
}

/// Extracts the display period from a bit-periodic substitution candidate name.
fn bitperiodic_period(candidate: &CribCandidate) -> &str {
    candidate
        .name
        .strip_prefix("BitPeriodicSubst{p=")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(&candidate.name)
}

/// Prints one MTF candidate row, with per-anchor occurrence-agreement detail.
fn print_mtf_row(candidate: &CribCandidate) {
    let tag = candidate
        .name
        .trim_start_matches("Mtf{tok=")
        .trim_end_matches('}');
    let agreements = candidate
        .consistency
        .anchors
        .iter()
        .map(|a| {
            if a.aligned {
                format!("L{}:{}/{}", a.length, a.agreements, a.compared)
            } else {
                format!("L{}:misaligned", a.length)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "      {:<8} {:>4}  {:<13}  {:<28}  {}",
        tag,
        candidate.alphabet,
        status_str(candidate),
        agreements,
        if candidate.english_viable {
            "yes"
        } else {
            "no"
        }
    );
}

/// Prints Section C: the language-gate results and the overall verdict.
fn print_section_c(report: &CribfitReport) {
    println!();
    println!(
        "Section C — language gate (crib-consistent + English-viable candidates vs matched null):"
    );
    if report.gated.is_empty() {
        println!("  (no crib-consistent + English-viable candidate to gate)");
    } else {
        println!(
            "  {:<24} {:>4} {:>4} {:>9} {:>9} {:>9} {:>7} {:>7}  verdict",
            "candidate", "#let", "|S|", "real", "null_mu", "null_max", "z", "p"
        );
        for verdict in &report.gated {
            print_verdict_row(verdict);
        }
        println!();
        println!("  rendered text (best substitution; first {TEXT_PREVIEW} chars):");
        for verdict in &report.gated {
            if verdict.evaluated {
                println!(
                    "    {:<24} {}",
                    verdict.codec_name,
                    display_prefix(&verdict.text, TEXT_PREVIEW)
                );
            } else {
                println!("    {:<24} {}", verdict.codec_name, verdict.text);
            }
        }
    }

    let geometry = &report.geometry;
    println!();
    if report.overall_survivor {
        println!(
            "OVERALL VERDICT: SURVIVOR present — a crib-consistent candidate beat its matched null (verify as a candidate, never a decode)."
        );
    } else if report.has_cribs() {
        let gated_names = report
            .gated
            .iter()
            .map(|verdict| verdict.codec_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!("OVERALL VERDICT: no survivor (honest negative) + derived structural constraint.");
        println!(
            "  constraint: a run-periodic key must have period | gcd(run-gaps)={} (so {} — only the memoryless case when gcd=1);",
            geometry.gcd_run_gaps,
            set_str(&geometry.run_periods)
        );
        println!(
            "              a bit-periodic key / cumsum modulus must divide gcd(bit-gaps)={} (so {}).",
            geometry.gcd_bit_gaps,
            set_str(&geometry.bit_periods)
        );
        if gated_names.is_empty() {
            println!(
                "  scope: no crib-consistent English-viable candidate reached the matched-null gate — the filter is structural, not a proof `one` is non-English."
            );
        } else {
            println!(
                "  scope: gated crib-consistent English-viable candidates were {gated_names}; all are below their matched nulls — this excludes these searchable codec signals, not a short genuine message."
            );
        }
    } else {
        println!("OVERALL VERDICT: inapplicable — no census-significant crib to filter against.");
    }
}

/// Prints one gated candidate's numeric row (or a degenerate marker).
fn print_verdict_row(verdict: &CodecVerdict) {
    if !verdict.evaluated {
        println!(
            "  {:<24} {:>4} {:>4} {:>9} {:>9} {:>9} {:>7} {:>7}  n/a (degenerate/skipped)",
            verdict.codec_name, verdict.n_letters, verdict.alphabet, "-", "-", "-", "-", "-"
        );
        return;
    }
    let label = if verdict.survivor {
        "SURVIVOR"
    } else {
        "below-null"
    };
    println!(
        "  {:<24} {:>4} {:>4} {:>9.3} {:>9.3} {:>9.3} {:>+7.2} {:>7.4}  {}",
        verdict.codec_name,
        verdict.n_letters,
        verdict.alphabet,
        verdict.real_mean,
        verdict.null_mean,
        verdict.null_max,
        verdict.z,
        verdict.p,
        label
    );
}

/// `cribfit --self-test`: planted positive control + discrimination control +
/// real-`one` honest negative.
fn run_self_test(seed: u64) -> ExitCode {
    let report = match cribfit::cribfit_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("cribfit self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("cribfit self-test (seed=0x{seed:016x}):");
    println!(
        "  GEOMETRY (real one): gcd(bit-gaps) = {} (want 21), gcd(run-gaps) = {} (want 1), bit-periods/cumsum moduli = {}",
        report.gcd_bit_gaps,
        report.gcd_run_gaps,
        set_str(&report.bit_periods)
    );
    println!(
        "  MTF single-magnitude on real one: applicable = {} (want true), len-26 windows agree {}/{} (< {} ⟹ EXCLUDED) — consistent = {}",
        report.mtf_single_applicable,
        report.mtf_single_len26_agreements,
        report.mtf_single_len26_compared,
        report.mtf_single_len26_compared,
        report.mtf_single_consistent
    );
    println!(
        "  MTF variable-length on real one: at least one tokenization INAPPLICABLE (set aside, not excluded) = {} (want true)",
        report.one_has_inapplicable_mtf
    );
    println!(
        "  DISCRIMINATION control: matching-modulus cumsum consistent = {} (want true), memoryful MTF excluded = {} (want true; consistent = {} want false)",
        report.control_cumsum_consistent,
        report.control_mtf_excluded,
        report.control_mtf_consistent
    );
    println!(
        "  BITPERIODIC real one: p=3 alphabet {} (want 14), consistent = {} (want true), english-viable = {} (want true); p=7 alphabet {} (want 24), english-viable = {} (want true); p=21 alphabet {} (want 47), english-viable = {} (want false)",
        report.bitperiodic_p3_alphabet,
        report.bitperiodic_p3_consistent,
        report.bitperiodic_p3_english_viable,
        report.bitperiodic_p7_alphabet,
        report.bitperiodic_p7_english_viable,
        report.bitperiodic_p21_alphabet,
        report.bitperiodic_p21_english_viable
    );
    println!(
        "  BITPERIODIC discrimination control: p=3 consistent = {} (want true)",
        report.bitperiodic_control_p3_consistent
    );
    println!(
        "  POSITIVE (planted English via gate): survivor = {} (want true)",
        report.positive_survivor
    );
    println!(
        "  NEGATIVE (real one full filter): overall survivor = {} (want false)",
        report.negative_overall_survivor
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
