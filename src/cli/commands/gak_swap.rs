//! Handler for the `gak-swap-recover` known-plaintext recovery command.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    GakSwapSelfTestConfig, GakSwapSelfTestReport, KnownPlaintextPair, LYMM_DEFAULT_DECIMATION,
    LYMM_DEFAULT_SHIFT, LymmDeckSpec, NullControlReport, PositiveControlReport, RecoveryReport,
    SwapRecoveryConfig, SwapRecoveryError, gak_swap_self_test, lymm_default_ct_alphabet,
    parse_known_plaintext_pairs, recover_known_plaintext_swaps,
};

use crate::cli::args_gak_swap::{GakSwapOutput, GakSwapPairFormat, GakSwapRecoverArgs};
use crate::cli::shared::split_blank_line_messages;

/// Dispatches the `gak-swap-recover` subcommand.
pub(crate) fn run_gak_swap_recover(args: &GakSwapRecoverArgs) -> ExitCode {
    if let Err(error) = validate_task02_knobs(args) {
        eprintln!("gak-swap-recover error: {error}");
        return ExitCode::FAILURE;
    }

    let controls = if args.run_controls {
        let config = GakSwapSelfTestConfig {
            seed: args.seed,
            max_nodes: args.max_nodes.or(Some(50_000)),
        };
        match gak_swap_self_test(config) {
            Ok(report) if report.passed() => Some(report),
            Ok(report) => {
                print_self_test(&report, args.output);
                eprintln!("gak-swap-recover error: planted controls or matched nulls failed");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("gak-swap-recover control error: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    if args.plaintext_file.is_none() && args.ciphertext_file.is_none() {
        if let Some(report) = &controls {
            print_self_test(report, args.output);
            return ExitCode::SUCCESS;
        }
        eprintln!(
            "gak-swap-recover error: provide --plaintext-file and --ciphertext-file, or use --run-controls"
        );
        return ExitCode::FAILURE;
    }

    let spec = match build_spec(args) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("gak-swap-recover spec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let pairs = match read_pairs(&spec, args) {
        Ok(pairs) => pairs,
        Err(error) => {
            eprintln!("gak-swap-recover input error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let max_swaps = args.num_swaps.or(args.max_swaps).unwrap_or(2);
    let mut config = SwapRecoveryConfig::with_max_swaps(max_swaps);
    config.max_nodes = args.max_nodes;
    config.time_budget = args.time_budget_secs.map(Duration::from_secs);

    let recovery = match recover_known_plaintext_swaps(&spec, &pairs, config) {
        Ok(report) => report,
        Err(SwapRecoveryError::UnsupportedBudget { max_swaps }) => {
            eprintln!(
                "gak-swap-recover error: unsupported top-swap budget {max_swaps}; measured Task-02 frontier is currently ns<=2, and ns=3 remains a recorded wall"
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("gak-swap-recover recovery error: {error}");
            return ExitCode::FAILURE;
        }
    };

    match args.output {
        GakSwapOutput::Text => print_text_report(&recovery, controls.as_ref(), pairs.len()),
        GakSwapOutput::Json => print_json_report(&recovery, controls.as_ref(), pairs.len()),
    }
    ExitCode::SUCCESS
}

fn validate_task02_knobs(args: &GakSwapRecoverArgs) -> Result<(), String> {
    if args.beam.is_some() {
        return Err("--beam is reserved for a Task-03 fallback and is not implemented".to_owned());
    }
    if args.infer_swaps {
        return Err("--infer-swaps is reserved for Task-03".to_owned());
    }
    if let Some(direction) = &args.compose_direction
        && direction != "left"
    {
        return Err("--compose-direction currently supports only 'left'".to_owned());
    }
    if let Some(emit_index) = args.emit_index
        && emit_index != 0
    {
        return Err("--emit-index currently supports only 0".to_owned());
    }
    if let Some(generator_set) = &args.generator_set
        && generator_set != "top-swaps"
    {
        return Err("--generator-set currently supports only 'top-swaps'".to_owned());
    }
    Ok(())
}

fn build_spec(args: &GakSwapRecoverArgs) -> Result<LymmDeckSpec, String> {
    let ct_alphabet = args
        .ct_alphabet
        .clone()
        .unwrap_or_else(|| lymm_default_ct_alphabet(args.n));
    let mut spec = if let Some(path) = &args.base_file {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read --base-file: {error}"))?;
        LymmDeckSpec::from_base(
            args.n,
            &args.pt_alphabet,
            &ct_alphabet,
            parse_usize_list(&text)?,
        )
    } else {
        let (shift, decimation) = parse_affine_base(&args.base_permutation)?;
        LymmDeckSpec::from_shift_decimation(
            args.n,
            &args.pt_alphabet,
            &ct_alphabet,
            shift,
            decimation,
        )
    }
    .map_err(|error| error.to_string())?;

    if let Some(initial_state) = &args.initial_state
        && initial_state != "identity"
    {
        spec = spec
            .with_initial_state(parse_usize_list(initial_state)?)
            .map_err(|error| error.to_string())?;
    }
    Ok(spec)
}

fn parse_affine_base(raw: &str) -> Result<(usize, usize), String> {
    let rest = raw.strip_prefix("affine:").ok_or_else(|| {
        "only affine:shift=<k>,decimation=<d> base specs are supported".to_owned()
    })?;
    let mut shift = None;
    let mut decimation = None;
    for part in rest.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("malformed base component {part:?}"))?;
        let parsed = value
            .parse::<usize>()
            .map_err(|error| format!("invalid base component {part:?}: {error}"))?;
        match key.trim() {
            "shift" => shift = Some(parsed),
            "decimation" => decimation = Some(parsed),
            other => return Err(format!("unknown affine base component {other:?}")),
        }
    }
    Ok((
        shift.unwrap_or(LYMM_DEFAULT_SHIFT),
        decimation.unwrap_or(LYMM_DEFAULT_DECIMATION),
    ))
}

fn parse_usize_list(raw: &str) -> Result<Vec<usize>, String> {
    raw.split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<usize>()
                .map_err(|error| format!("invalid permutation entry {part:?}: {error}"))
        })
        .collect()
}

fn read_pairs(
    spec: &LymmDeckSpec,
    args: &GakSwapRecoverArgs,
) -> Result<Vec<KnownPlaintextPair>, String> {
    let plaintext_path = args
        .plaintext_file
        .as_ref()
        .ok_or_else(|| "missing --plaintext-file".to_owned())?;
    let ciphertext_path = args
        .ciphertext_file
        .as_ref()
        .ok_or_else(|| "missing --ciphertext-file".to_owned())?;
    let plaintexts = std::fs::read_to_string(plaintext_path)
        .map_err(|error| format!("failed to read --plaintext-file: {error}"))?;
    let ciphertexts = std::fs::read_to_string(ciphertext_path)
        .map_err(|error| format!("failed to read --ciphertext-file: {error}"))?;
    match args.pair_format {
        GakSwapPairFormat::Labels => parse_known_plaintext_pairs(spec, &plaintexts, &ciphertexts)
            .map_err(|error| error.to_string()),
        GakSwapPairFormat::BlankLines => parse_blank_line_pairs(&plaintexts, &ciphertexts),
        GakSwapPairFormat::Jsonl => {
            Err("--pair-format jsonl is reserved for Task-03 shareability".to_owned())
        }
    }
}

fn parse_blank_line_pairs(
    plaintexts: &str,
    ciphertexts: &str,
) -> Result<Vec<KnownPlaintextPair>, String> {
    let plaintext_messages = split_blank_line_messages(plaintexts);
    let ciphertext_messages = split_blank_line_messages(ciphertexts);
    if plaintext_messages.len() != ciphertext_messages.len() {
        return Err(format!(
            "blank-line pair count mismatch: {} plaintext messages vs {} ciphertext messages",
            plaintext_messages.len(),
            ciphertext_messages.len()
        ));
    }
    Ok(plaintext_messages
        .into_iter()
        .zip(ciphertext_messages)
        .enumerate()
        .map(|(index, (plaintext, ciphertext))| KnownPlaintextPair {
            label: format!("m{index}"),
            plaintext,
            ciphertext: ciphertext
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect(),
        })
        .collect())
}

fn print_text_report(
    report: &RecoveryReport,
    controls: Option<&GakSwapSelfTestReport>,
    pair_count: usize,
) {
    if let Some(self_test) = controls {
        print_self_test(self_test, GakSwapOutput::Text);
    } else {
        println!("gak swap controls: not run (pass --run-controls to gate this run)");
    }
    println!(
        "gak-swap-recover: {pair_count} known-plaintext pairs, n={}, max-swaps={}",
        report.pt_mapping.values().next().map_or(0, Vec::len),
        report.config.max_swaps
    );
    let exact = report.round_trip.exact();
    println!(
        "  verdict: {}",
        if exact {
            "VERIFIED RECOVERY (exact re-encryption)"
        } else {
            "CANDIDATE (not exact)"
        }
    );
    println!(
        "  round-trip: {}/{} ciphertext symbols matched",
        report.round_trip.matched, report.round_trip.total
    );
    if let Some((label, index, expected, actual)) = &report.round_trip.first_divergence {
        println!(
            "  first divergence: message {label} at ct index {index}: expected {expected:?}, got {actual:?}"
        );
    }
    println!(
        "  stats: candidates={} pruned={} deductions={} nodes={} sat-decisions={} sat-conflicts={} beam-drops={}",
        report.stats.enumerated_candidates,
        report.stats.domains_pruned,
        report.stats.deductions,
        report.stats.nodes,
        report.stats.sat_decisions,
        report.stats.sat_conflicts,
        report.stats.beam_drops
    );
    println!("  per-message:");
    for (label, matched, total) in &report.round_trip.per_message {
        println!("    {label}: {matched}/{total}");
    }
    println!("  per-letter:");
    for letter in &report.letters {
        println!(
            "    {} occ={} target={} support={} swaps={} equiv={} no-doubles={} verdict={:?}",
            letter.letter,
            letter.occurrences,
            format_option_usize(letter.target),
            format_usize_slice(&letter.support),
            format_usize_slice(&letter.canonical_swaps),
            letter.equivalent_count,
            letter.no_doubles,
            letter.verdict
        );
    }
}

fn print_self_test(report: &GakSwapSelfTestReport, output: GakSwapOutput) {
    if output == GakSwapOutput::Json {
        println!("{}", self_test_json(report));
        return;
    }
    println!(
        "gak swap self-test (seed=0x{:016x}, max-nodes={}):",
        report.config.seed,
        report
            .config
            .max_nodes
            .map_or_else(|| "none".to_owned(), |nodes| nodes.to_string())
    );
    print_positive("positive ns=1", &report.positive_ns1);
    print_positive("positive ns=2", &report.positive_ns2);
    print_null(&report.full_permutation_null);
    print_null(&report.over_budget_null);
    println!(
        "  over-budget recovery at supported bound: {}",
        pass_fail(report.over_budget_recovery_exact)
    );
    print_null(&report.label_shuffle_null);
    println!("  SELF-TEST: {}", pass_fail(report.passed()));
}

fn print_positive(label: &str, report: &PositiveControlReport) {
    println!(
        "  {label}: {} matched-unique={} ambiguous={} mismatched-unique={} observed={} nodes={} sat-decisions={} sat-conflicts={}",
        pass_fail(report.exact),
        report.matched_observed_letters,
        report.ambiguous_observed_letters,
        report.mismatched_unique_letters,
        report.observed_letters,
        report.nodes,
        report.sat_decisions,
        report.sat_conflicts
    );
}

fn print_null(report: &NullControlReport) {
    println!("  null {}: {}", report.label, pass_fail(report.failed));
}

fn print_json_report(
    report: &RecoveryReport,
    controls: Option<&GakSwapSelfTestReport>,
    pair_count: usize,
) {
    let mut out = String::new();
    writeln!(&mut out, "{{").expect("write to String");
    writeln!(&mut out, "  \"tool\": \"gak-swap-recover\",").expect("write to String");
    writeln!(&mut out, "  \"pair_count\": {pair_count},").expect("write to String");
    match controls {
        Some(self_test) => {
            writeln!(&mut out, "  \"controls\": {},", self_test_json(self_test))
                .expect("write to String");
        }
        None => {
            writeln!(&mut out, "  \"controls\": null,").expect("write to String");
        }
    }
    writeln!(&mut out, "  \"max_swaps\": {},", report.config.max_swaps).expect("write to String");
    writeln!(&mut out, "  \"exact\": {},", report.round_trip.exact()).expect("write to String");
    writeln!(
        &mut out,
        "  \"round_trip\": {{\"matched\": {}, \"total\": {}}},",
        report.round_trip.matched, report.round_trip.total
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"stats\": {{\"candidates\": {}, \"domains_pruned\": {}, \"deductions\": {}, \"nodes\": {}, \"sat_decisions\": {}, \"sat_conflicts\": {}, \"beam_drops\": {}}},",
        report.stats.enumerated_candidates,
        report.stats.domains_pruned,
        report.stats.deductions,
        report.stats.nodes,
        report.stats.sat_decisions,
        report.stats.sat_conflicts,
        report.stats.beam_drops
    )
    .expect("write to String");
    writeln!(&mut out, "  \"letters\": [").expect("write to String");
    for (index, letter) in report.letters.iter().enumerate() {
        let comma = if index + 1 == report.letters.len() {
            ""
        } else {
            ","
        };
        writeln!(
            &mut out,
            "    {{\"letter\": \"{}\", \"occurrences\": {}, \"target\": {}, \"support\": {}, \"swaps\": {}, \"equivalent_count\": {}, \"no_doubles\": {}, \"verdict\": \"{:?}\"}}{}",
            json_escape(&letter.letter.to_string()),
            letter.occurrences,
            option_json(letter.target),
            usize_slice_json(&letter.support),
            usize_slice_json(&letter.canonical_swaps),
            letter.equivalent_count,
            letter.no_doubles,
            letter.verdict,
            comma
        )
        .expect("write to String");
    }
    writeln!(&mut out, "  ]").expect("write to String");
    writeln!(&mut out, "}}").expect("write to String");
    print!("{out}");
}

fn self_test_json(report: &GakSwapSelfTestReport) -> String {
    format!(
        "{{\"seed\":\"0x{:016x}\",\"passed\":{},\"positive_ns1\":{},\"positive_ns2\":{},\"full_permutation_null\":{},\"over_budget_null\":{},\"over_budget_recovery_exact\":{},\"label_shuffle_null\":{}}}",
        report.config.seed,
        report.passed(),
        positive_json(&report.positive_ns1),
        positive_json(&report.positive_ns2),
        null_json(&report.full_permutation_null),
        null_json(&report.over_budget_null),
        report.over_budget_recovery_exact,
        null_json(&report.label_shuffle_null)
    )
}

fn positive_json(report: &PositiveControlReport) -> String {
    format!(
        "{{\"num_swaps\":{},\"exact\":{},\"matched_observed_letters\":{},\"ambiguous_observed_letters\":{},\"mismatched_unique_letters\":{},\"observed_letters\":{},\"nodes\":{},\"sat_decisions\":{},\"sat_conflicts\":{}}}",
        report.num_swaps,
        report.exact,
        report.matched_observed_letters,
        report.ambiguous_observed_letters,
        report.mismatched_unique_letters,
        report.observed_letters,
        report.nodes,
        report.sat_decisions,
        report.sat_conflicts
    )
}

fn null_json(report: &NullControlReport) -> String {
    format!(
        "{{\"label\":\"{}\",\"failed\":{}}}",
        json_escape(report.label),
        report.failed
    )
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn format_option_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "-".to_owned(), |found| found.to_string())
}

fn format_usize_slice(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn option_json(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |found| found.to_string())
}

fn usize_slice_json(values: &[usize]) -> String {
    format!("[{}]", format_usize_slice(values))
}

fn json_escape(raw: &str) -> String {
    let mut escaped = String::new();
    for ch in raw.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}
