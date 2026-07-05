//! Handler for the `gak-swap-arc-phase0` measurement command.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    GakSwapArcControlLeg, GakSwapArcLiteral, GakSwapArcPhase0Config,
    GakSwapArcPhase0ControlsReport, GakSwapArcPhase0Report, KnownPlaintextPair,
    LYMM_DEFAULT_DECIMATION, LYMM_DEFAULT_SHIFT, LymmDeckSpec, gak_swap_arc_phase0_controls,
    lymm_default_ct_alphabet, measure_ns3_arc_provenance, parse_known_plaintext_pairs,
};

use crate::cli::args_gak_swap::{GakSwapArcPhase0Args, GakSwapOutput, GakSwapPairFormat};
use crate::cli::shared::split_blank_line_messages;

/// Dispatches the `gak-swap-arc-phase0` subcommand.
pub(crate) fn run_gak_swap_arc_phase0(args: &GakSwapArcPhase0Args) -> ExitCode {
    let has_real_files = match validate_input_presence(args) {
        Ok(has_real_files) => has_real_files,
        Err(exit_code) => return exit_code,
    };
    let config = phase0_config(args);
    let controls = match run_controls_if_needed(args, has_real_files, config) {
        Ok(report) => report,
        Err(exit_code) => return exit_code,
    };
    if !has_real_files {
        if let Some(report) = &controls {
            print_controls(report, args.output);
            return if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        eprintln!("gak-swap-arc-phase0 error: no measurement input and controls were not run");
        return ExitCode::FAILURE;
    }

    let spec = match build_spec(args) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("gak-swap-arc-phase0 spec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let pairs = match read_pairs(&spec, args) {
        Ok(pairs) => pairs,
        Err(error) => {
            eprintln!("gak-swap-arc-phase0 input error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = match measure_ns3_arc_provenance(&spec, &pairs, config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("gak-swap-arc-phase0 measurement error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_measurement_report(
        &report,
        controls.as_ref(),
        args.skip_controls,
        pairs.len(),
        args.output,
    );
    ExitCode::SUCCESS
}

fn phase0_config(args: &GakSwapArcPhase0Args) -> GakSwapArcPhase0Config {
    GakSwapArcPhase0Config {
        max_rejections: args.max_rejections,
        wall_time: Duration::from_secs(args.time_budget_secs),
        replays_per_rejection: args.replay_cap,
        spot_check_samples: args.spot_check_samples,
    }
}

fn controls_required(run_controls: bool, skip_controls: bool, has_real_files: bool) -> bool {
    run_controls || (has_real_files && !skip_controls)
}

fn validate_input_presence(args: &GakSwapArcPhase0Args) -> Result<bool, ExitCode> {
    let has_plaintext = args.plaintext_file.is_some();
    let has_ciphertext = args.ciphertext_file.is_some();
    let has_real_files = has_plaintext && has_ciphertext;
    if has_plaintext != has_ciphertext {
        eprintln!("gak-swap-arc-phase0 error: provide both --plaintext-file and --ciphertext-file");
        return Err(ExitCode::FAILURE);
    }
    if !has_real_files && !args.run_controls {
        eprintln!(
            "gak-swap-arc-phase0 error: provide --plaintext-file and --ciphertext-file, or use --run-controls"
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(has_real_files)
}

fn run_controls_if_needed(
    args: &GakSwapArcPhase0Args,
    has_real_files: bool,
    config: GakSwapArcPhase0Config,
) -> Result<Option<GakSwapArcPhase0ControlsReport>, ExitCode> {
    if !controls_required(args.run_controls, args.skip_controls, has_real_files) {
        return Ok(None);
    }
    match gak_swap_arc_phase0_controls(config) {
        Ok(report) if report.passed() => Ok(Some(report)),
        Ok(report) => {
            print_controls(&report, args.output);
            eprintln!("gak-swap-arc-phase0 error: Phase-0 instrument controls failed");
            Err(ExitCode::FAILURE)
        }
        Err(error) => {
            eprintln!("gak-swap-arc-phase0 control error: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn build_spec(args: &GakSwapArcPhase0Args) -> Result<LymmDeckSpec, String> {
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

fn read_pairs(
    spec: &LymmDeckSpec,
    args: &GakSwapArcPhase0Args,
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

fn print_measurement_report(
    report: &GakSwapArcPhase0Report,
    controls: Option<&GakSwapArcPhase0ControlsReport>,
    controls_skipped: bool,
    pair_count: usize,
    output: GakSwapOutput,
) {
    match output {
        GakSwapOutput::Text => {
            print_controls_status(controls, controls_skipped, output);
            print_text_report(report, pair_count);
        }
        GakSwapOutput::Json => {
            println!(
                "{}",
                measurement_json(report, controls, controls_skipped, pair_count)
            );
        }
    }
}

fn print_controls(report: &GakSwapArcPhase0ControlsReport, output: GakSwapOutput) {
    match output {
        GakSwapOutput::Text => {
            println!("gak swap arc Phase-0 controls:");
            print_control_leg(&report.positive);
            print_control_leg(&report.matched_null);
            println!("  SELF-TEST: {}", pass_fail(report.passed()));
        }
        GakSwapOutput::Json => println!("{}", controls_json(report)),
    }
}

fn print_controls_status(
    controls: Option<&GakSwapArcPhase0ControlsReport>,
    controls_skipped: bool,
    output: GakSwapOutput,
) {
    if let Some(report) = controls {
        print_controls(report, output);
    } else if controls_skipped {
        println!(
            "gak swap arc Phase-0 controls: SKIPPED by --skip-controls; measurement is not control-gated"
        );
    } else {
        println!("gak swap arc Phase-0 controls: not run");
    }
}

fn print_control_leg(report: &GakSwapArcControlLeg) {
    println!(
        "  {}: {} {}",
        report.label,
        pass_fail(report.passed),
        report.detail
    );
}

fn print_text_report(report: &GakSwapArcPhase0Report, pair_count: usize) {
    println!(
        "gak-swap-arc-phase0: {pair_count} known-plaintext pairs, ns=3, max-rejections={}, wall={}s, replay-cap={}",
        report.config.max_rejections,
        report.config.wall_time.as_secs(),
        report.config.replays_per_rejection
    );
    println!(
        "  broad: candidates={} pruned={} deductions={}",
        report.enumerated_candidates,
        report.broad_stats.domains_pruned,
        report.broad_stats.deductions
    );
    println!(
        "  stop: {} target-nodes={} sampled-rejections={} short-go-conflicts={} median-short-tuple-kill-estimate={}",
        report.stop.as_str(),
        report.target_nodes,
        report.rejections.len(),
        report.short_go_conflicts(),
        option_json(report.median_short_tuple_kill_estimate())
    );
    println!(
        "  tuple-kill construction: estimate from per-letter masks induced by letter-local arc/context literals, spot-checked by sampled deterministic propagation"
    );
    for rejection in &report.rejections {
        println!(
            "  rejection node={} bin={} size{}{} replay-checks={} arcs={} context={} tuple-kill={}",
            rejection.node,
            rejection.bin.as_str(),
            if rejection.literal_count_is_upper_bound {
                "<="
            } else {
                "="
            },
            rejection.literal_count,
            rejection.replay_checks,
            format_arcs(&rejection.minimized_arc_literals),
            format_context(&rejection.minimized_context_targets),
            rejection.tuple_kill_estimate.as_ref().map_or_else(
                || "n/a".to_owned(),
                |estimate| {
                    format!(
                        "{} of {} in T={} (spot-check {}/{})",
                        estimate.estimated_killed_tuples,
                        estimate.projected_total_for_t,
                        option_json(estimate.projected_t),
                        estimate.spot_checked_rejections,
                        estimate.spot_checked_samples
                    )
                }
            )
        );
    }
}

fn measurement_json(
    report: &GakSwapArcPhase0Report,
    controls: Option<&GakSwapArcPhase0ControlsReport>,
    controls_skipped: bool,
    pair_count: usize,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "{{").expect("write to String");
    writeln!(&mut out, "  \"tool\": \"gak-swap-arc-phase0\",").expect("write to String");
    writeln!(&mut out, "  \"pair_count\": {pair_count},").expect("write to String");
    match controls {
        Some(report) => writeln!(&mut out, "  \"controls\": {},", controls_json(report))
            .expect("write to String"),
        None if controls_skipped => {
            writeln!(&mut out, "  \"controls\": \"skipped\",").expect("write to String");
        }
        None => writeln!(&mut out, "  \"controls\": null,").expect("write to String"),
    }
    writeln!(
        &mut out,
        "  \"config\": {{\"max_rejections\": {}, \"wall_secs\": {}, \"replay_cap\": {}, \"spot_check_samples\": {}}},",
        report.config.max_rejections,
        report.config.wall_time.as_secs(),
        report.config.replays_per_rejection,
        report.config.spot_check_samples
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"broad\": {{\"candidates\": {}, \"domains_pruned\": {}, \"deductions\": {}}},",
        report.enumerated_candidates,
        report.broad_stats.domains_pruned,
        report.broad_stats.deductions
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"stop\": \"{}\", \"target_nodes\": {}, \"short_go_conflicts\": {}, \"median_short_tuple_kill_estimate\": {},",
        report.stop.as_str(),
        report.target_nodes,
        report.short_go_conflicts(),
        option_json(report.median_short_tuple_kill_estimate())
    )
    .expect("write to String");
    writeln!(&mut out, "  \"rejections\": [").expect("write to String");
    for (index, rejection) in report.rejections.iter().enumerate() {
        let comma = if index + 1 == report.rejections.len() {
            ""
        } else {
            ","
        };
        writeln!(
            &mut out,
            "    {{\"node\": {}, \"bin\": \"{}\", \"literal_count\": {}, \"literal_count_is_upper_bound\": {}, \"replay_checks\": {}, \"arcs\": {}, \"context_targets\": {}, \"tuple_kill_estimate\": {}}}{}",
            rejection.node,
            rejection.bin.as_str(),
            rejection.literal_count,
            rejection.literal_count_is_upper_bound,
            rejection.replay_checks,
            arcs_json(&rejection.minimized_arc_literals),
            context_json(&rejection.minimized_context_targets),
            rejection
                .tuple_kill_estimate
                .as_ref()
                .map_or_else(|| "null".to_owned(), tuple_kill_json),
            comma
        )
        .expect("write to String");
    }
    writeln!(&mut out, "  ]").expect("write to String");
    writeln!(&mut out, "}}").expect("write to String");
    out
}

fn controls_json(report: &GakSwapArcPhase0ControlsReport) -> String {
    format!(
        "{{\"passed\":{},\"positive\":{},\"matched_null\":{}}}",
        report.passed(),
        control_leg_json(&report.positive),
        control_leg_json(&report.matched_null)
    )
}

fn control_leg_json(report: &GakSwapArcControlLeg) -> String {
    format!(
        "{{\"label\":\"{}\",\"passed\":{},\"detail\":\"{}\"}}",
        json_escape(report.label),
        report.passed,
        json_escape(&report.detail)
    )
}

fn tuple_kill_json(
    estimate: &noita_eye_puzzle::attack::gak_attack::lymm_deck::GakSwapArcTupleKillEstimate,
) -> String {
    format!(
        "{{\"projected_t\":{},\"projected_total_for_t\":{},\"estimated_killed_tuples\":{},\"spot_checked_samples\":{},\"spot_checked_rejections\":{},\"construction\":\"{}\"}}",
        option_json(estimate.projected_t),
        estimate.projected_total_for_t,
        estimate.estimated_killed_tuples,
        estimate.spot_checked_samples,
        estimate.spot_checked_rejections,
        json_escape(estimate.construction)
    )
}

fn format_arcs(arcs: &[GakSwapArcLiteral]) -> String {
    if arcs.is_empty() {
        return "-".to_owned();
    }
    arcs.iter()
        .map(|literal| {
            format!(
                "{}:{}->{}",
                literal.letter, literal.post_position, literal.pre_position
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_context(context: &[(char, usize)]) -> String {
    if context.is_empty() {
        return "-".to_owned();
    }
    context
        .iter()
        .map(|(letter, target)| format!("{letter}={target}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn arcs_json(arcs: &[GakSwapArcLiteral]) -> String {
    let rows = arcs
        .iter()
        .map(|literal| {
            format!(
                "{{\"letter\":\"{}\",\"post\":{},\"pre\":{}}}",
                json_escape(&literal.letter.to_string()),
                literal.post_position,
                literal.pre_position
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn context_json(context: &[(char, usize)]) -> String {
    let rows = context
        .iter()
        .map(|(letter, target)| {
            format!(
                "{{\"letter\":\"{}\",\"target\":{}}}",
                json_escape(&letter.to_string()),
                target
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn option_json(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |found| found.to_string())
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

#[cfg(test)]
mod tests {
    use super::controls_required;

    #[test]
    fn phase0_measurement_runs_controls_by_default() {
        assert!(controls_required(false, false, true));
        assert!(controls_required(true, false, true));
        assert!(!controls_required(false, true, true));
        assert!(controls_required(true, false, false));
        assert!(!controls_required(false, false, false));
    }
}
