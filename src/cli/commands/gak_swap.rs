//! Handler for the `gak-swap-recover` known-plaintext recovery command.

use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    GakSwapSelfTestConfig, GakSwapSelfTestReport, KnownPlaintextPair, LYMM_DEFAULT_DECIMATION,
    LYMM_DEFAULT_SHIFT, LymmComposeDirection, LymmDeckSpec, LymmGeneratorSet, RecoveryGeneratorSet,
    SWAP_RECOVERY_FRONTIER_MESSAGE, SwapInferenceRange, SwapRecoveryConfig, SwapRecoveryError,
    gak_swap_self_test, infer_known_plaintext_swap_budget, lymm_default_ct_alphabet,
    parse_known_plaintext_pairs, recover_known_plaintext_swaps,
};

use super::gak_swap_report::{print_inference_report, print_recovery_report, print_self_test};
use crate::cli::args_gak_swap::{GakSwapPairFormat, GakSwapRecoverArgs};
use crate::cli::shared::split_blank_line_messages;

/// Dispatches the `gak-swap-recover` subcommand.
pub(crate) fn run_gak_swap_recover(args: &GakSwapRecoverArgs) -> ExitCode {
    if let Err(error) = validate_task02_knobs(args) {
        eprintln!("gak-swap-recover error: {error}");
        return ExitCode::FAILURE;
    }

    let has_real_files = match validate_input_presence(args) {
        Ok(has_real_files) => has_real_files,
        Err(exit_code) => return exit_code,
    };

    let controls = match run_controls_if_needed(args, has_real_files) {
        Ok(report) => report,
        Err(exit_code) => return exit_code,
    };

    if !has_real_files {
        if let Some(report) = &controls {
            print_self_test(report, args.output);
            return ExitCode::SUCCESS;
        }
        eprintln!("gak-swap-recover error: no recovery input and controls were not run");
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
    let config = match build_recovery_config(&spec, args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("gak-swap-recover config error: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(raw_range) = &args.infer_swaps {
        let range = match parse_infer_range(raw_range) {
            Ok(range) => range,
            Err(error) => {
                eprintln!("gak-swap-recover error: {error}");
                return ExitCode::FAILURE;
            }
        };
        let inference = match infer_known_plaintext_swap_budget(&spec, &pairs, range, config) {
            Ok(report) => report,
            Err(SwapRecoveryError::UnsupportedBudget { max_swaps }) => {
                eprintln!(
                    "gak-swap-recover error: unsupported top-swap budget {max_swaps}; {SWAP_RECOVERY_FRONTIER_MESSAGE}"
                );
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("gak-swap-recover inference error: {error}");
                return ExitCode::FAILURE;
            }
        };
        print_inference_report(
            &inference,
            controls.as_ref(),
            args.skip_controls,
            pairs.len(),
            spec.n,
            args.output,
        );
        return if inference.exact() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let recovery = match recover_known_plaintext_swaps(&spec, &pairs, config) {
        Ok(report) => report,
        Err(SwapRecoveryError::UnsupportedBudget { max_swaps }) => {
            eprintln!(
                "gak-swap-recover error: unsupported top-swap budget {max_swaps}; {SWAP_RECOVERY_FRONTIER_MESSAGE}"
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("gak-swap-recover recovery error: {error}");
            return ExitCode::FAILURE;
        }
    };

    print_recovery_report(
        &recovery,
        controls.as_ref(),
        args.skip_controls,
        pairs.len(),
        args.output,
    );
    ExitCode::SUCCESS
}

fn controls_required(run_controls: bool, skip_controls: bool, has_real_files: bool) -> bool {
    run_controls || (has_real_files && !skip_controls)
}

fn validate_input_presence(args: &GakSwapRecoverArgs) -> Result<bool, ExitCode> {
    let has_plaintext = args.plaintext_file.is_some();
    let has_ciphertext = args.ciphertext_file.is_some();
    let has_real_files = has_plaintext && has_ciphertext;
    if has_plaintext != has_ciphertext {
        eprintln!("gak-swap-recover error: provide both --plaintext-file and --ciphertext-file");
        return Err(ExitCode::FAILURE);
    }
    if !has_real_files && !args.run_controls {
        eprintln!(
            "gak-swap-recover error: provide --plaintext-file and --ciphertext-file, or use --run-controls"
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(has_real_files)
}

fn run_controls_if_needed(
    args: &GakSwapRecoverArgs,
    has_real_files: bool,
) -> Result<Option<GakSwapSelfTestReport>, ExitCode> {
    if !controls_required(args.run_controls, args.skip_controls, has_real_files) {
        return Ok(None);
    }
    let config = GakSwapSelfTestConfig {
        seed: args.seed,
        max_nodes: args.max_nodes.or(Some(50_000)),
    };
    match gak_swap_self_test(config) {
        Ok(report) if report.passed() => Ok(Some(report)),
        Ok(report) => {
            print_self_test(&report, args.output);
            eprintln!("gak-swap-recover error: planted controls or matched nulls failed");
            Err(ExitCode::FAILURE)
        }
        Err(error) => {
            eprintln!("gak-swap-recover control error: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn validate_task02_knobs(args: &GakSwapRecoverArgs) -> Result<(), String> {
    if let Some(max_swaps) = args.num_swaps.or(args.max_swaps)
        && max_swaps >= 3
    {
        return Err(format!(
            "unsupported top-swap budget {max_swaps}; {SWAP_RECOVERY_FRONTIER_MESSAGE}"
        ));
    }
    if args.beam.is_some() {
        return Err("--beam is reserved for a Task-03 fallback and is not implemented".to_owned());
    }
    if let Some(direction) = &args.compose_direction {
        let _parsed = parse_compose_direction(direction)?;
    }
    if let Some(generator_set) = &args.generator_set
        && generator_set != "top-swaps"
    {
        return Err("--generator-set supports only 'top-swaps' or use --generator-file".to_owned());
    }
    Ok(())
}

fn parse_infer_range(raw: &str) -> Result<SwapInferenceRange, String> {
    let (start, end) = raw
        .split_once("..")
        .ok_or_else(|| "expected --infer-swaps range A..B".to_owned())?;
    if end.contains("..") {
        return Err("expected --infer-swaps range A..B".to_owned());
    }
    let start = start
        .parse::<usize>()
        .map_err(|error| format!("invalid --infer-swaps start {start:?}: {error}"))?;
    let end = end
        .parse::<usize>()
        .map_err(|error| format!("invalid --infer-swaps end {end:?}: {error}"))?;
    if start == 0 || start > end {
        return Err(format!(
            "invalid --infer-swaps range {start}..{end}; expected 1 <= start <= end"
        ));
    }
    Ok(SwapInferenceRange::new(start, end))
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
    if let Some(direction) = &args.compose_direction {
        spec = spec.with_compose_dir(parse_compose_direction(direction)?);
    }
    if let Some(emit_index) = args.emit_index {
        spec = spec
            .with_emit_index(emit_index)
            .map_err(|error| error.to_string())?;
    }
    Ok(spec)
}

fn build_recovery_config(
    spec: &LymmDeckSpec,
    args: &GakSwapRecoverArgs,
) -> Result<SwapRecoveryConfig, String> {
    let mut config =
        SwapRecoveryConfig::with_max_swaps(args.num_swaps.or(args.max_swaps).unwrap_or(2));
    config.max_nodes = args.max_nodes;
    config.time_budget = args.time_budget_secs.map(Duration::from_secs);
    if let Some(path) = &args.generator_file {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read --generator-file: {error}"))?;
        let generator_set = LymmGeneratorSet::parse_permutation_file(spec.n, &text)
            .map_err(|error| format!("failed to parse --generator-file: {error}"))?;
        config = config.with_generator_set(RecoveryGeneratorSet::Explicit(generator_set));
    }
    Ok(config)
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

fn parse_compose_direction(raw: &str) -> Result<LymmComposeDirection, String> {
    match raw {
        "left" => Ok(LymmComposeDirection::Left),
        "right" => Ok(LymmComposeDirection::Right),
        other => Err(format!(
            "unsupported --compose-direction {other:?}; expected 'left' or 'right'"
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::controls_required;

    #[test]
    fn real_file_recovery_runs_controls_by_default() {
        assert!(controls_required(false, false, true));
        assert!(controls_required(true, false, true));
        assert!(!controls_required(false, true, true));
        assert!(controls_required(true, false, false));
        assert!(!controls_required(false, false, false));
    }
}
