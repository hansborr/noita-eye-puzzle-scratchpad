//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! will move to `clap` once crates.io is reachable; see `Cargo.toml`.

use std::process::ExitCode;

use noita_eye_puzzle::{
    analysis, controls, corpus, glyph::Sequence, isomorph_null, null, orders, periodicity,
    pipeline_null,
};

const MIN_RELIABLE_PERIODICITY_NULL_TRIALS: usize = 50;

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for rendered digits 0-4
    noita-eye demo               Run analysis on the verified nine-message corpus
    noita-eye orders             Audit reading orders and Experiment 4 flatness
    noita-eye nulltest [--seed <u64>] [--trials <n>]
                                  Monte-Carlo null over random grids + standard36
    noita-eye periodicity [--seed <u64>] [--trials <n>] [--max-period <n>] [--max-lag <n>]
                                  Experiment 5A period/lag/Kasiski battery
    noita-eye pipelinenull [--seed <u64>] [--trials <n>]
                                  Base-7 pipeline null plus input-randomness control
    noita-eye isomorphnull [--seed <u64>] [--trials <n>]
                                  Experiment 7A real isomorphs vs within-message shuffle null
    noita-eye controls monoalphabetic [--seed <u64>]
                                  Experiment 11 monoalphabetic positive control
    noita-eye controls isomorph [--seed <u64>]
                                  Experiment 11 isomorph/polyalphabetic positive control

Digit 5 is treated as a row delimiter and ignored for glyph statistics.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("stats") => {
            let Some(text) = args.get(1) else {
                eprintln!("usage: noita-eye stats <sequence>");
                return ExitCode::FAILURE;
            };
            run_stats(text)
        }
        Some("demo") => match corpus::combined_sequence() {
            Ok(seq) => {
                print_report("verified eye corpus", &seq);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{}", format_corpus_error(error));
                ExitCode::FAILURE
            }
        },
        Some("orders") => run_orders(),
        Some("nulltest") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_nulltest(rest)
        }
        Some("periodicity") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_periodicity(rest)
        }
        Some("pipelinenull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_pipelinenull(rest)
        }
        Some("isomorphnull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_isomorphnull(rest)
        }
        Some("controls") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_controls(rest)
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn format_corpus_error(error: corpus::CorpusError) -> String {
    match error {
        corpus::CorpusError::MalformedSymbol {
            message_key,
            symbol,
        } => format!("corpus parse error in {message_key}: invalid symbol {symbol:?}"),
        corpus::CorpusError::IncompleteTrigram {
            message_key,
            orientations,
        } => format!(
            "corpus parse error in {message_key}: {orientations} orientations cannot form complete trigrams"
        ),
    }
}

fn run_nulltest(args: &[String]) -> ExitCode {
    let config = match parse_null_config(args, "nulltest") {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye nulltest [--seed <u64>] [--trials <n>]");
            return ExitCode::FAILURE;
        }
    };
    let report = match null::run_standard36_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("null test error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    print_null_report(&report);
    ExitCode::SUCCESS
}

fn run_periodicity(args: &[String]) -> ExitCode {
    let config = match parse_periodicity_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: noita-eye periodicity [--seed <u64>] [--trials <n>] [--max-period <n>] [--max-lag <n>] [--min-ngram <n>] [--max-ngram <n>]"
            );
            return ExitCode::FAILURE;
        }
    };
    let report = match periodicity::run_periodicity(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("periodicity error: {}", format_periodicity_error(error));
            return ExitCode::FAILURE;
        }
    };
    print_periodicity_report(&report);
    ExitCode::SUCCESS
}

fn run_pipelinenull(args: &[String]) -> ExitCode {
    let config = match parse_null_config(args, "pipelinenull") {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye pipelinenull [--seed <u64>] [--trials <n>]");
            return ExitCode::FAILURE;
        }
    };
    let pipeline_report = match pipeline_null::run_pipeline_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pipeline null error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let input_report = match pipeline_null::input_randomness_report(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("input-randomness control error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    print_pipeline_null_report(&pipeline_report);
    println!();
    print_input_randomness_report(&input_report);
    ExitCode::SUCCESS
}

fn run_isomorphnull(args: &[String]) -> ExitCode {
    let config = match parse_isomorph_null_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye isomorphnull [--seed <u64>] [--trials <n>]");
            return ExitCode::FAILURE;
        }
    };
    let report = match isomorph_null::run_isomorph_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomorph null error: {}", format_isomorph_null_error(error));
            return ExitCode::FAILURE;
        }
    };
    print_isomorph_null_report(&report);
    ExitCode::SUCCESS
}

fn run_controls(args: &[String]) -> ExitCode {
    let Some(first) = args.first() else {
        return run_monoalphabetic_control(&[]);
    };
    if first == "monoalphabetic" {
        let rest = match args.get(1..) {
            Some(values) => values,
            None => &[],
        };
        return run_monoalphabetic_control(rest);
    }
    if first == "isomorph" || first == "polyalphabetic" {
        let rest = match args.get(1..) {
            Some(values) => values,
            None => &[],
        };
        return run_isomorph_control(rest);
    }
    if first.starts_with("--") {
        return run_monoalphabetic_control(args);
    }

    eprintln!("unknown controls target {first:?}");
    eprintln!(
        "usage: noita-eye controls monoalphabetic [--seed <u64>]\n       noita-eye controls isomorph [--seed <u64>]"
    );
    ExitCode::FAILURE
}

fn run_monoalphabetic_control(args: &[String]) -> ExitCode {
    let config = match parse_monoalphabetic_control_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye controls monoalphabetic [--seed <u64>]");
            return ExitCode::FAILURE;
        }
    };
    let report = match controls::run_monoalphabetic_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "monoalphabetic control failed: {}",
                format_controls_error(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    print_monoalphabetic_control_report(&report);
    ExitCode::SUCCESS
}

fn run_isomorph_control(args: &[String]) -> ExitCode {
    let config = match parse_isomorph_control_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye controls isomorph [--seed <u64>]");
            return ExitCode::FAILURE;
        }
    };
    let report = match controls::run_isomorph_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomorph control failed: {}", format_controls_error(&error));
            return ExitCode::FAILURE;
        }
    };
    print_isomorph_control_report(&report);
    ExitCode::SUCCESS
}

fn parse_monoalphabetic_control_config(
    args: &[String],
) -> Result<controls::MonoalphabeticControlConfig, String> {
    let mut config = controls::MonoalphabeticControlConfig::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --seed".to_owned());
                };
                config.seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown controls monoalphabetic flag {other:?}")),
        }
    }
    Ok(config)
}

fn parse_isomorph_control_config(
    args: &[String],
) -> Result<controls::IsomorphControlConfig, String> {
    let mut config = controls::IsomorphControlConfig::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --seed".to_owned());
                };
                config.seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown controls isomorph flag {other:?}")),
        }
    }
    Ok(config)
}

fn parse_null_config(args: &[String], subcommand: &str) -> Result<null::NullConfig, String> {
    let mut seed = 0x6e6f_6974_612d_6579;
    let mut trials = 1_000usize;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --seed".to_owned());
                };
                seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value {value:?}: {error}"))?;
            }
            "--trials" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --trials".to_owned());
                };
                trials = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --trials value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown {subcommand} flag {other:?}")),
        }
    }
    Ok(null::NullConfig { seed, trials })
}

fn parse_isomorph_null_config(
    args: &[String],
) -> Result<isomorph_null::IsomorphNullConfig, String> {
    let mut config = isomorph_null::IsomorphNullConfig::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --seed".to_owned());
                };
                config.seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value {value:?}: {error}"))?;
            }
            "--trials" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --trials".to_owned());
                };
                config.trials = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --trials value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown isomorphnull flag {other:?}")),
        }
    }
    Ok(config)
}

fn parse_periodicity_config(args: &[String]) -> Result<periodicity::PeriodicityConfig, String> {
    let mut config = periodicity::PeriodicityConfig::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --seed".to_owned());
                };
                config.seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value {value:?}: {error}"))?;
            }
            "--trials" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --trials".to_owned());
                };
                config.trials = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --trials value {value:?}: {error}"))?;
            }
            "--max-period" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --max-period".to_owned());
                };
                config.max_period = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --max-period value {value:?}: {error}"))?;
            }
            "--max-lag" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --max-lag".to_owned());
                };
                config.max_lag = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --max-lag value {value:?}: {error}"))?;
            }
            "--min-ngram" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --min-ngram".to_owned());
                };
                config.min_ngram = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --min-ngram value {value:?}: {error}"))?;
            }
            "--max-ngram" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --max-ngram".to_owned());
                };
                config.max_ngram = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --max-ngram value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown periodicity flag {other:?}")),
        }
    }
    Ok(config)
}

fn format_periodicity_error(error: periodicity::PeriodicityError) -> String {
    match error {
        periodicity::PeriodicityError::Grid(grid_error) => {
            format!("grid/order error: {grid_error:?}")
        }
        periodicity::PeriodicityError::ZeroTrials => {
            "at least one Monte-Carlo trial is required".to_owned()
        }
        periodicity::PeriodicityError::ZeroMaxPeriod => "max period must be at least 1".to_owned(),
        periodicity::PeriodicityError::ZeroMaxLag => "max lag must be at least 1".to_owned(),
        periodicity::PeriodicityError::InvalidNgramRange { min, max } => {
            format!("invalid n-gram range {min}..={max}")
        }
        periodicity::PeriodicityError::InvalidAlphabetSize { alphabet_size } => {
            format!("invalid null alphabet size {alphabet_size}; expected 1..=125")
        }
    }
}

fn format_isomorph_null_error(error: isomorph_null::IsomorphNullError) -> String {
    match error {
        isomorph_null::IsomorphNullError::Grid(grid_error) => {
            format!("grid/order error: {grid_error:?}")
        }
        isomorph_null::IsomorphNullError::ZeroTrials => {
            "at least one Monte-Carlo trial is required".to_owned()
        }
        isomorph_null::IsomorphNullError::InvalidWindowRange {
            min_window,
            max_window,
        } => format!("invalid window range {min_window}..={max_window}"),
        isomorph_null::IsomorphNullError::Isomorph(isomorph_error) => {
            format!("detector configuration error: {isomorph_error:?}")
        }
        isomorph_null::IsomorphNullError::RandomBoundTooLarge { bound } => {
            format!("shuffle bound {bound} is too large")
        }
    }
}

fn format_controls_error(error: &controls::ControlsError) -> String {
    match error {
        controls::ControlsError::EmptyPlaintext { label } => {
            format!("{label}: normalized plaintext is empty")
        }
        controls::ControlsError::UnsupportedPlaintextSymbol { label, symbol } => {
            format!("{label}: unsupported plaintext symbol {symbol:?}")
        }
        controls::ControlsError::GlyphOutsideAlphabet {
            label,
            glyph,
            alphabet_size,
        } => format!("{label}: glyph {glyph} is outside alphabet size {alphabet_size}"),
        controls::ControlsError::AlphabetTooLarge { alphabet_size } => {
            format!("alphabet size {alphabet_size} is too large for this control")
        }
        controls::ControlsError::NonBijectiveKey {
            seed,
            alphabet_size,
        } => {
            format!("seed {seed} did not produce a bijection over alphabet size {alphabet_size}")
        }
        controls::ControlsError::IocNotPreserved {
            label,
            plaintext_bits,
            ciphertext_bits,
        } => format!(
            "{label}: IoC changed across substitution ({plaintext_bits:#x} != {ciphertext_bits:#x})"
        ),
        controls::ControlsError::FrequencyMultisetChanged { label } => {
            format!("{label}: frequency-count multiset changed across substitution")
        }
        controls::ControlsError::BigramMultisetChanged { label } => {
            format!("{label}: bigram-count multiset changed across substitution")
        }
        controls::ControlsError::KnownKeyRecoveryFailed { label } => {
            format!("{label}: known-key inverse did not recover the plaintext")
        }
        controls::ControlsError::RegimeSeparationFailed {
            label,
            plaintext_ioc,
            flattened_ioc,
            uniform_floor,
        } => format!(
            "{label}: IoC did not separate regimes (plain {plaintext_ioc:.6}, balanced uniform {flattened_ioc:.6}, floor {uniform_floor:.6})"
        ),
        controls::ControlsError::InvalidIsomorphWindow {
            label,
            window,
            sequence_len,
        } => {
            format!("{label}: invalid isomorph window {window} for sequence length {sequence_len}")
        }
        controls::ControlsError::InvalidPeriodSearch {
            label,
            min_period,
            max_period,
        } => format!("{label}: invalid isomorph period search {min_period}..={max_period}"),
        controls::ControlsError::IsomorphSignalMissing {
            label,
            expected_period,
            observed_matches,
            required_matches,
        } => format!(
            "{label}: expected period {expected_period} produced {observed_matches} signature matches, below required {required_matches}"
        ),
        controls::ControlsError::IsomorphPeriodRecoveryFailed {
            label,
            expected_period,
            observed_period,
            observed_matches,
        } => {
            let observed =
                observed_period.map_or_else(|| "none".to_owned(), |period| period.to_string());
            format!(
                "{label}: strongest recovered period was {observed} with {observed_matches} signature matches, expected {expected_period}"
            )
        }
        controls::ControlsError::IsomorphFalsePositive {
            label,
            observed_period,
            observed_matches,
            allowed_matches,
        } => format!(
            "{label}: expected-absent period signal {observed_period} produced {observed_matches} signature matches, above allowed {allowed_matches}"
        ),
        controls::ControlsError::IsomorphSeparationFailed {
            present_label,
            absent_label,
            present_matches,
            absent_matches,
            required_gap,
        } => format!(
            "{present_label}: signature-period separation from {absent_label} was {present_matches} vs {absent_matches}, below required gap {required_gap}"
        ),
    }
}

fn print_null_report(report: &null::NullReport) {
    println!("standard36 random-grid null");
    println!("seed: {}", report.config.seed);
    println!("trials: {}", report.config.trials);
    println!("orders searched per trial: {}", report.family_size);
    println!("resampled: verified row-width structure with uniform orientation cells 0..=4");
    println!("held fixed: honeycomb traversal, trigram grouping, and the statistic family");
    println!();

    print_interval(
        "headline exact 0..=82",
        null::wilson_95(report.headline_count, report.config.trials),
    );
    print_interval(
        "some order adjacent_equal == 0",
        null::wilson_95(report.adjacent_zero_count, report.config.trials),
    );
    println!(
        "min distinct achieved over standard36: {}",
        format_usize_histogram(&report.min_distinct_histogram)
    );
    println!(
        "min ceiling achieved over standard36: {}",
        format_u8_histogram(&report.min_ceiling_histogram)
    );
    println!(
        "best distance-4 ratio d4/mean(d1..d6): min {:.3}, median {:.3}, max {:.3}",
        report.distance4_ratio_min, report.distance4_ratio_median, report.distance4_ratio_max
    );
    println!();
    println!("analytic fixed-order headline bounds under independent uniform trigrams:");
    println!(
        "  per-order (83/125)^1036: {:.6e}",
        report.analytic_bounds.per_order
    );
    println!(
        "  Bonferroni over {} orders: {:.6e}",
        report.analytic_bounds.family_size, report.analytic_bounds.bonferroni
    );
    println!(
        "  Sidak over {} orders: {:.6e}",
        report.analytic_bounds.family_size, report.analytic_bounds.sidak
    );
    println!();
    println!(
        "Interpretation: this corrects grid-content randomness and fixed standard36 digit-permutation selection only. It does not correct for broader researcher degrees of freedom such as choosing the traversal family, grouping rule, or headline statistic after looking at the data."
    );
}

fn print_periodicity_report(report: &periodicity::PeriodicityReport) {
    println!("Experiment 5A periodicity/autocorrelation battery");
    println!("order: {}", report.order.name());
    println!("alphabet: reading-layer values 0..=82");
    println!("seed: {}", report.config.seed);
    println!("trials: {}", report.config.trials);
    println!(
        "periods: 1..={} ; lags: 1..={} ; Kasiski n-grams: {}..={}",
        report.config.max_period,
        report.config.max_lag,
        report.config.min_ngram,
        report.config.max_ngram
    );
    println!(
        "message lengths: {}",
        format_message_lengths(&report.message_lengths)
    );
    println!("pooled length: {}", report.pooled_length);
    println!(
        "boundary rule: pooled statistics aggregate within-message evidence only; no lag pairs, period columns, or n-grams cross message joins"
    );
    println!(
        "IoC convention: analysis::index_of_coincidence probability form; x83 normalizes to the uniform 83-symbol baseline"
    );
    println!(
        "sampled report-wide null envelopes: period x83 <= {:.3}; autocorrelation rate <= {:.6}",
        report.period_null_envelope_max, report.autocorrelation_null_envelope_max
    );
    println!();

    print_period_ioc_table("pooled IoC-by-period", &report.pooled_ioc_by_period);
    println!();
    print_autocorrelation_table(
        "pooled autocorrelation profile",
        &report.pooled_autocorrelation,
    );
    println!();
    print_message_periodicity_summary(&report.messages);
    println!();
    print_kasiski_table("pooled Kasiski distances", &report.pooled_kasiski);
    println!();
    print_message_kasiski_summary(&report.messages);
    println!();
    print_periodicity_interpretation(report);
}

fn print_periodicity_interpretation(report: &periodicity::PeriodicityReport) {
    let exceedance_labels = null_envelope_exceedance_labels(report);
    if report.config.trials < MIN_RELIABLE_PERIODICITY_NULL_TRIALS {
        println!(
            "Caveat: only {} Monte-Carlo trial(s) were sampled (< {}); the report-wide null envelope is undersampled and the OUT/inside verdict is not reliable.",
            report.config.trials, MIN_RELIABLE_PERIODICITY_NULL_TRIALS
        );
    }

    if exceedance_labels.is_empty() {
        println!(
            "Interpretation: no pooled or per-message period/lag row exceeds the sampled report-wide random-null envelope (no OUT flags). That rules out a simple fixed-period polyalphabetic cipher under this honeycomb reading order; it does not prove the data is meaningless, and it says nothing about other reading orders or encodings."
        );
    } else {
        let count = exceedance_labels.len();
        println!(
            "Interpretation: {count} pooled/per-message period/lag {} {} the sampled report-wide random-null envelope (OUT): {}. Because at least one row is OUT, this run does not support the no-exceedance verdict and does not rule out a simple fixed-period polyalphabetic cipher under this honeycomb reading order.",
            counted_noun(count, "row", "rows"),
            counted_verb(count, "exceeds", "exceed"),
            exceedance_labels.join(", ")
        );
    }

    println!(
        "Near-uniform IoC-by-period is also exactly what a fixed permutation of structured data can produce. Pointwise pt95 rows are shown as noise candidates only; a peak inside the sampled envelope is not a period claim."
    );
    print_distance4_reconciliation(report, !exceedance_labels.is_empty());
    println!(
        "Any future striking period must be rechecked against Experiment 0 transcription integrity before interpretation."
    );
}

fn null_envelope_exceedance_labels(report: &periodicity::PeriodicityReport) -> Vec<String> {
    let mut labels = Vec::new();
    append_period_exceedance_labels("pooled", &report.pooled_ioc_by_period, &mut labels);
    append_autocorrelation_exceedance_labels("pooled", &report.pooled_autocorrelation, &mut labels);
    for message in &report.messages {
        append_period_exceedance_labels(message.message_key, &message.ioc_by_period, &mut labels);
        append_autocorrelation_exceedance_labels(
            message.message_key,
            &message.autocorrelation,
            &mut labels,
        );
    }
    labels
}

fn append_period_exceedance_labels(
    scope: &str,
    rows: &[periodicity::PeriodIocRow],
    labels: &mut Vec<String>,
) {
    for row in rows.iter().filter(|row| row.above_null_envelope) {
        let period = row.period;
        labels.push(format!("{scope} period p={period}"));
    }
}

fn append_autocorrelation_exceedance_labels(
    scope: &str,
    rows: &[periodicity::AutocorrelationRow],
    labels: &mut Vec<String>,
) {
    for row in rows.iter().filter(|row| row.above_null_envelope) {
        let lag = row.lag;
        labels.push(format!("{scope} lag={lag}"));
    }
}

fn print_distance4_reconciliation(
    report: &periodicity::PeriodicityReport,
    has_envelope_exceedance: bool,
) {
    let lag4 = report
        .pooled_autocorrelation
        .iter()
        .find(|row| row.lag == 4);
    let strongest = strongest_autocorrelation_row(&report.pooled_autocorrelation);
    let lag4_is_dominant = matches!((lag4, strongest), (Some(_), Some(row)) if row.lag == 4);

    match (lag4, strongest) {
        (Some(row), Some(strongest_row)) if strongest_row.lag == 4 => {
            println!(
                "Distance-4 reconciliation: lag 4 is the dominant pooled autocorrelation peak under this honeycomb order, consistent with Experiment 1B's distance-4 spike."
            );
            print_lag4_band_reconciliation(row);
        }
        (Some(row), Some(strongest_row)) => {
            println!(
                "Distance-4 reconciliation: lag 4 is included in this scan, but the strongest pooled autocorrelation peak in the configured range is lag {}. The usual lag-4-dominant wording therefore does not apply to this run.",
                strongest_row.lag
            );
            print_lag4_band_reconciliation(row);
        }
        _ => println!(
            "Distance-4 reconciliation: this configured lag range does not include lag 4, so this run cannot evaluate Experiment 1B's distance-4 spike."
        ),
    }

    println!(
        "Experiment 1B's targeted distance-4 test, appropriate for a pre-identified distance under the best-over-36 null, found d4 significant; this broad conservative sweep does not contradict it."
    );
    if has_envelope_exceedance {
        println!(
            "Because OUT rows are present in this configured run, the broad scan should not be summarized as showing no new family-wise period/lag signal. The d4 structure itself is order-contingent and is not a message claim."
        );
    } else if lag4_is_dominant {
        println!(
            "The broad scan still shows no new dominant period beyond the known d4 structure. The d4 structure itself is order-contingent and is not a message claim."
        );
    } else {
        println!(
            "This configured scan should not be used for a broad no-new-period statement beyond its scanned range. The d4 structure itself is order-contingent and is not a message claim."
        );
    }
}

fn print_lag4_band_reconciliation(row: &periodicity::AutocorrelationRow) {
    if row.above_null_envelope {
        println!(
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is OUT against that envelope in this configured run, and it exceeds its own per-lag band (pt95). Treat that as an envelope exceedance, not as a plaintext claim by itself."
        );
    } else if row.above_pointwise_band {
        println!(
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is inside that envelope, but it still exceeds its own per-lag band (pt95). Therefore, no family-wise exceedance is not evidence that the d4 structure is absent."
        );
    } else {
        println!(
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is inside that envelope and does not exceed its own per-lag band in this configured run."
        );
    }
}

fn counted_noun(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn counted_verb(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn print_period_ioc_table(label: &str, rows: &[periodicity::PeriodIocRow]) {
    println!("{label}");
    println!(
        "{:>3} {:>10} {:>10} {:>19} {:>10} {:>7}",
        "p", "IoC", "x83", "null x83 95%", "null max", "flag"
    );
    for row in rows {
        println!(
            "{:>3} {:>10.6} {:>10.3} {:>19} {:>10.3} {:>7}",
            row.period,
            row.mean_ioc,
            row.normalized_ioc,
            format_null_band(row.null_band),
            row.null_band.max,
            format_null_flag(row.above_pointwise_band, row.above_null_envelope)
        );
    }
}

fn print_autocorrelation_table(label: &str, rows: &[periodicity::AutocorrelationRow]) {
    println!("{label}");
    println!(
        "{:>3} {:>11} {:>10} {:>10} {:>19} {:>10} {:>7}",
        "lag", "matches", "rate", "x83", "null rate 95%", "null max", "flag"
    );
    for row in rows {
        println!(
            "{:>3} {:>11} {:>10.6} {:>10.3} {:>19} {:>10.6} {:>7}",
            row.lag,
            format_match_count(row.matches, row.comparisons),
            row.rate,
            row.normalized_rate,
            format_null_band(row.null_band),
            row.null_band.max,
            format_null_flag(row.above_pointwise_band, row.above_null_envelope)
        );
    }
}

fn print_message_periodicity_summary(messages: &[periodicity::MessagePeriodicityReport]) {
    println!("per-message strongest apparent rows");
    println!(
        "{:<6} {:>5} {:>8} {:>9} {:>7} {:>8} {:>11} {:>7}",
        "msg", "len", "best p", "p x83", "p flag", "best lag", "lag rate", "lag flag"
    );
    for message in messages {
        let period = strongest_period_row(&message.ioc_by_period);
        let lag = strongest_autocorrelation_row(&message.autocorrelation);
        println!(
            "{:<6} {:>5} {:>8} {:>9} {:>7} {:>8} {:>11} {:>7}",
            message.message_key,
            message.length,
            period.map_or_else(|| "none".to_owned(), |row| row.period.to_string()),
            period.map_or_else(
                || "n/a".to_owned(),
                |row| format!("{:.3}", row.normalized_ioc)
            ),
            period.map_or("n/a", |row| {
                format_null_flag(row.above_pointwise_band, row.above_null_envelope)
            }),
            lag.map_or_else(|| "none".to_owned(), |row| row.lag.to_string()),
            lag.map_or_else(|| "n/a".to_owned(), |row| format!("{:.6}", row.rate)),
            lag.map_or("n/a", |row| {
                format_null_flag(row.above_pointwise_band, row.above_null_envelope)
            })
        );
    }
}

fn print_kasiski_table(label: &str, rows: &[periodicity::KasiskiReport]) {
    println!("{label}");
    println!(
        "{:>3} {:>9} {:>9} {:>9} {:>5} {:<28} {:<28} {:<28}",
        "n", "repeat", "occurs", "dist", "gcd", "top distances", "per-ngram gcds", "top factors"
    );
    for row in rows {
        println!(
            "{:>3} {:>9} {:>9} {:>9} {:>5} {:<28} {:<28} {:<28}",
            row.n,
            row.repeated_ngram_kinds,
            row.repeated_occurrences,
            row.distance_count,
            row.all_distance_gcd,
            format_pair_counts(&row.top_distances),
            format_pair_counts(&row.ngram_gcd_histogram),
            format_top_factor_counts(&row.factor_counts)
        );
    }
}

fn print_message_kasiski_summary(messages: &[periodicity::MessagePeriodicityReport]) {
    println!("per-message Kasiski summaries");
    println!(
        "{:<6} {:>3} {:>9} {:>9} {:>9} {:>5} {:<28}",
        "msg", "n", "repeat", "occurs", "dist", "gcd", "top factors"
    );
    for message in messages {
        for row in &message.kasiski {
            println!(
                "{:<6} {:>3} {:>9} {:>9} {:>9} {:>5} {:<28}",
                message.message_key,
                row.n,
                row.repeated_ngram_kinds,
                row.repeated_occurrences,
                row.distance_count,
                row.all_distance_gcd,
                format_top_factor_counts(&row.factor_counts)
            );
        }
    }
}

fn strongest_period_row(rows: &[periodicity::PeriodIocRow]) -> Option<&periodicity::PeriodIocRow> {
    rows.iter()
        .max_by(|left, right| left.normalized_ioc.total_cmp(&right.normalized_ioc))
}

fn strongest_autocorrelation_row(
    rows: &[periodicity::AutocorrelationRow],
) -> Option<&periodicity::AutocorrelationRow> {
    rows.iter()
        .max_by(|left, right| left.rate.total_cmp(&right.rate))
}

fn format_message_lengths(lengths: &[(&'static str, usize)]) -> String {
    lengths
        .iter()
        .map(|(key, length)| format!("{key}:{length}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_null_band(band: periodicity::NullBand) -> String {
    format!("{:.3}..{:.3}", band.q025, band.q975)
}

fn format_null_flag(pointwise: bool, envelope: bool) -> &'static str {
    if envelope {
        "OUT"
    } else if pointwise {
        "pt95"
    } else {
        "inside"
    }
}

fn format_match_count(matches: usize, comparisons: usize) -> String {
    format!("{matches}/{comparisons}")
}

fn format_pair_counts(pairs: &[(usize, usize)]) -> String {
    if pairs.is_empty() {
        return "none".to_owned();
    }
    pairs
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_top_factor_counts(pairs: &[(usize, usize)]) -> String {
    let mut sorted = pairs
        .iter()
        .copied()
        .filter(|(_factor, count)| *count > 0)
        .collect::<Vec<_>>();
    sorted.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    sorted.truncate(8);
    format_pair_counts(&sorted)
}

fn print_monoalphabetic_control_report(report: &controls::MonoalphabeticControlReport) {
    println!("Experiment 11 monoalphabetic positive control");
    println!("seed: {}", report.config.seed);
    println!(
        "alphabet: {} symbols ({})",
        report.alphabet_size, report.alphabet
    );
    println!("generated key: {}", report.key_mapping);
    println!();
    println!(
        "long fixture: {} letters from {}",
        report.long_fixture.length, report.long_fixture.label
    );
    println!(
        "plaintext:  {}",
        preview_text(&report.long_fixture.normalized_plaintext, 96)
    );
    println!(
        "ciphertext: {}",
        preview_text(&report.long_fixture.ciphertext, 96)
    );
    println!(
        "recovered:  {}",
        preview_text(&report.long_fixture.recovered_plaintext, 96)
    );
    println!();
    println!(
        "IoC plaintext/ciphertext: {:.6} / {:.6} (exactly preserved)",
        report.long_fixture.plaintext_ioc, report.long_fixture.ciphertext_ioc
    );
    println!(
        "IoC balanced uniform: {:.6}; uniform floor 1/k: {:.6}",
        report.flattened_ioc, report.uniform_floor
    );
    println!(
        "entropy plaintext/ciphertext/balanced uniform: {:.4} / {:.4} / {:.4} bits/symbol",
        report.long_fixture.plaintext_entropy,
        report.long_fixture.ciphertext_entropy,
        report.flattened_entropy
    );
    println!(
        "frequency multiset preserved: {}",
        yes_no(report.long_fixture.frequency_multiset_preserved)
    );
    println!(
        "bigram count multiset preserved: {}",
        yes_no(report.long_fixture.bigram_multiset_preserved)
    );
    println!(
        "known-key recovery: {}",
        yes_no(report.long_fixture.known_key_recovered)
    );
    println!();
    println!("documented Common Glyphs plaintext vectors (known-key exactness only):");
    for fixture in &report.documented_vectors {
        println!(
            "  {}: {:?} -> {} -> {}",
            fixture.label,
            fixture.source_plaintext,
            fixture.ciphertext,
            fixture.recovered_plaintext
        );
    }
    println!();
    println!(
        "Interpretation: this proves the frequency/substitution tooling is not systematically blind to a known monoalphabetic substitution fixture. It does not claim frequency-only recovery of the short Common Glyphs phrases, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
    );
}

fn print_isomorph_control_report(report: &controls::IsomorphControlReport) {
    println!("Experiment 11 isomorph/polyalphabetic positive control");
    println!("seed: {}", report.config.seed);
    println!(
        "alphabet: {} symbols ({})",
        report.alphabet_size, report.alphabet
    );
    println!(
        "detector: first-occurrence signatures over {}-glyph windows; periods {}..={}",
        report.window, report.min_period, report.max_period
    );
    println!(
        "ground truth: plaintext has period-aligned planted repeats; Vigenere key period is {}; autokey and running-key have no short repeating key",
        report.expected_period
    );
    println!(
        "invariant: Vigenere period matches >= {}; each absent fixture max period matches <= {}",
        report.required_present_matches, report.allowed_absent_matches
    );
    println!();
    print_isomorph_fixture(&report.vigenere);
    println!();
    print_isomorph_fixture(&report.autokey);
    println!();
    print_isomorph_fixture(&report.running_key);
    println!();
    println!(
        "Interpretation: this control shows the isomorph/period tooling recovers the repeating-key Vigenere period when English prose contains period-aligned planted repeats. The autokey and running-key fixtures use the same planted repeats but do not show a short period, so the contrast isolates key structure rather than plaintext content. It does not claim arbitrary natural text would produce this signal, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
    );
}

fn print_isomorph_fixture(fixture: &controls::IsomorphFixtureReport) {
    println!("{} ({})", fixture.label, fixture.cipher);
    println!("key: {}", fixture.key_summary);
    println!("length: {} glyphs", fixture.length);
    println!("plaintext:  {}", preview_text(&fixture.plaintext, 84));
    println!("ciphertext: {}", preview_text(&fixture.ciphertext, 84));
    println!(
        "cipher entropy/IoC/distinct: {:.4} bits / {:.6} / {}",
        fixture.ciphertext_entropy, fixture.ciphertext_ioc, fixture.distinct_cipher_symbols
    );
    println!("plaintext IoC: {:.6}", fixture.plaintext_ioc);
    println!(
        "informative windows: {}; repeated signature kinds: {}; exact repeated windows: {}",
        fixture.informative_windows,
        fixture.repeated_signature_kinds,
        fixture.exact_repeated_windows
    );
    println!(
        "period-{} signature matches: {}",
        fixture.expected_period, fixture.expected_period_matches
    );
    match fixture.best_period {
        Some(signal) => println!(
            "best period: {} ({} matches across {} signatures)",
            signal.period, signal.matches, signal.signature_kinds
        ),
        None => println!("best period: none"),
    }
    if !fixture.strongest_signatures.is_empty() {
        println!("top period-{} signatures:", fixture.expected_period);
        for signature in &fixture.strongest_signatures {
            println!(
                "  [{}] at {} ({} period matches)",
                signature.signature,
                format_positions(&signature.occurrences),
                signature.expected_period_matches
            );
        }
    }
}

fn print_pipeline_null_report(report: &null::NullReport) {
    println!("base-7 generation-pipeline null");
    println!("seed: {}", report.config.seed);
    println!("trials: {}", report.config.trials);
    println!("orders searched per trial: {}", report.family_size);
    println!(
        "resampled: matched engine pair lengths through the u64-capped base-7 decode, filtered to orientation cells 0..=4"
    );
    println!("held fixed: honeycomb traversal, trigram grouping, and the statistic family");
    println!();

    print_interval(
        "headline exact 0..=82",
        null::wilson_95(report.headline_count, report.config.trials),
    );
    print_interval(
        "some order adjacent_equal == 0",
        null::wilson_95(report.adjacent_zero_count, report.config.trials),
    );
    println!(
        "min distinct achieved over standard36: {}",
        format_usize_histogram(&report.min_distinct_histogram)
    );
    println!(
        "min ceiling achieved over standard36: {}",
        format_u8_histogram(&report.min_ceiling_histogram)
    );
    println!(
        "best distance-4 ratio d4/mean(d1..d6): min {:.3}, median {:.3}, max {:.3}",
        report.distance4_ratio_min, report.distance4_ratio_median, report.distance4_ratio_max
    );
    println!();
    println!(
        "Interpretation: the base-7 pipeline does not manufacture the bounded 0..=82 contiguity; uniform-random orientation cells do not either. The contiguity is therefore not explained as a generation artifact, but this is equally consistent with structured-but-meaningless data and is not evidence of a recoverable message."
    );
}

fn print_isomorph_null_report(report: &isomorph_null::IsomorphNullReport) {
    println!("Experiment 7A isomorph shuffle null");
    println!("order: {}", report.order.name());
    println!("seed: {}", report.config.seed);
    println!("trials: {}", report.config.trials);
    println!(
        "windows: {}..={}",
        report.config.min_window, report.config.max_window
    );
    println!(
        "message lengths: {}",
        format_message_lengths(&report.message_lengths)
    );
    println!("pooled length: {}", report.total_length);
    println!(
        "boundary rule: detector runs within each message only; no window crosses a message join"
    );
    println!(
        "null: Fisher-Yates shuffle within each message, preserving that message's exact symbol multiset and length"
    );
    println!(
        "statistic: repeated informative first-occurrence signature kinds, summed over messages; all-distinct windows are ignored"
    );
    println!(
        "longest repeated real isomorph in scanned range: {}",
        report
            .longest_real_repeated_isomorph
            .map_or_else(|| "none".to_owned(), |window| window.to_string())
    );
    println!();
    println!(
        "{:>2} {:>10} {:>8} {:>10} {:>12} {:>8} {:>9}",
        "k", "real kinds", "max rep", "null mean", "null 95%", "null max", "p>=real"
    );
    for row in &report.rows {
        println!(
            "{:>2} {:>10} {:>8} {:>10.2} {:>12} {:>8} {:>9.4}",
            row.window,
            row.real.repeated_signature_kinds,
            row.real.max_repeat_count,
            row.null.mean,
            format_isomorph_band(row.null),
            row.null.max,
            row.empirical_p
        );
    }
    println!();
    print_isomorph_null_interpretation(report);
}

fn print_isomorph_null_interpretation(report: &isomorph_null::IsomorphNullReport) {
    let pointwise_excesses = report
        .rows
        .iter()
        .filter(|row| row.real.repeated_signature_kinds > row.null.q975)
        .map(|row| format!("k={} (p={:.4})", row.window, row.empirical_p))
        .collect::<Vec<_>>();

    if pointwise_excesses.is_empty() {
        println!(
            "Interpretation: the real eye stream does not exceed the pointwise 95% within-message shuffle band for repeated-signature kind counts at the scanned k values. Short repeated isomorphs exist, but this run does not show arrangement structure beyond the same messages shuffled against themselves."
        );
    } else {
        println!(
            "Interpretation: the real eye stream exceeds the pointwise 95% within-message shuffle band at {}. That is an arrangement signal worth rechecking, not a decryption or plaintext claim.",
            pointwise_excesses.join(", ")
        );
    }
    println!(
        "The shuffle null holds symbol frequencies fixed and randomizes only order, so it tests arrangement rather than frequency. The p values are empirical fractions over the configured shuffles and are pointwise over the scanned k values."
    );
    println!(
        "Any striking excess should be rechecked against Experiment 0 transcription integrity before interpretation."
    );
}

fn format_isomorph_band(band: isomorph_null::IsomorphNullBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn preview_text(text: &str, max_chars: usize) -> String {
    let mut preview = String::new();
    let mut omitted = false;
    for (index, symbol) in text.chars().enumerate() {
        if index >= max_chars {
            omitted = true;
            break;
        }
        preview.push(symbol);
    }
    if omitted {
        preview.push_str("...");
    }
    preview
}

fn format_positions(positions: &[usize]) -> String {
    let mut rendered = positions
        .iter()
        .take(12)
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if positions.len() > 12 {
        rendered.push_str(",...");
    }
    rendered
}

fn print_input_randomness_report(report: &pipeline_null::InputRandomnessReport) {
    println!("engine-input randomness negative control");
    println!("seed: {}", report.config.seed);
    println!("trials: {}", report.config.trials);
    println!("engine pairs: {}", report.pair_count);
    println!("decoded storage symbols: {}", report.total_symbols);
    println!(
        "real storage histogram (-1..=5): {}",
        format_storage_histogram(&report.real_symbol_histogram)
    );
    println!("real -1 controls: {}", report.real_minus_one);
    println!("real delimiters: {}", report.real_delimiters);
    println!(
        "real chi-square vs uniform base-7 symbols: {:.3}",
        report.real_chi_square_vs_uniform
    );
    println!(
        "exact P(no -1 in capped matched random corpus): {:.6e}",
        report.analytic_probability_no_minus_one
    );
    println!(
        "matched random corpus mean -1 controls: {:.3}",
        report.mc_mean_minus_one
    );
    println!(
        "matched random corpus mean delimiters: {:.3}",
        report.mc_mean_delimiters
    );
    println!(
        "matched random corpora with zero -1 controls: {}/{}",
        report.mc_corpora_with_zero_minus_one, report.config.trials
    );
    println!();
    println!(
        "Interpretation: this only shows the authored engine inputs live in the 0..=5 storage alphabet (zero -1 controls and 86 delimiters) instead of resembling capped matched-length random integers. The analytic no -1 probability is exact for that capped model, and the Monte-Carlo counts are the empirical check at the configured trial count; neither shows that the authored symbols encode anything."
    );
}

fn print_interval(label: &str, interval: null::WilsonInterval) {
    println!(
        "{label}: {}/{} = {:.6} (95% Wilson {:.6}..{:.6})",
        interval.count, interval.trials, interval.estimate, interval.lower, interval.upper
    );
}

fn run_orders() -> ExitCode {
    let grids = match orders::corpus_grids() {
        Ok(grids) => grids,
        Err(error) => {
            eprintln!("grid reconstruction error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let summary = orders::summarize_grids(&grids);
    println!("grid row widths:");
    for (key, widths) in &summary.row_widths {
        println!("  {key}: {}", format_widths(widths));
    }
    println!("max row width: {}", summary.max_width);
    println!(
        "bottom two rows differ by <=1: {}",
        summary.bottom_two_rows_differ_by_at_most_one
    );
    println!();
    println!(
        "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
        "order", "total", "distinct", "contiguous", "span", ">82", "adj-eq", "recurrence d1..d6"
    );

    let stats = match orders::audit_order_stats(&grids) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("order audit error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let mut winners = Vec::new();
    for item in stats {
        if item.stats.is_contiguous_0_to_82() {
            winners.push(item.order.name());
        }
        println!(
            "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
            item.order.name(),
            item.stats.total,
            item.stats.distinct,
            item.stats.contiguous,
            format_span(item.stats.min, item.stats.max),
            item.stats.values_above_82,
            item.stats.adjacent_equal,
            format_recurrence(&item.stats.recurrence_distance_1_to_6)
        );
    }
    println!();
    if winners.is_empty() {
        println!("contiguous 0..=82 orders: none");
    } else {
        println!("contiguous 0..=82 orders: {}", winners.join(", "));
    }

    let flatness = match orders::audit_order_flatness_stats(&grids) {
        Ok(flatness) => flatness,
        Err(error) => {
            eprintln!("order flatness error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    print_experiment_4_flatness_report(&flatness);
    ExitCode::SUCCESS
}

fn run_stats(text: &str) -> ExitCode {
    match parse_rendered_sequence(text) {
        Ok(seq) => {
            print_report("input", &seq);
            ExitCode::SUCCESS
        }
        Err(c) => {
            eprintln!("unknown rendered digit {c:?}; expected 0-5, with 5 as delimiter");
            ExitCode::FAILURE
        }
    }
}

fn parse_rendered_sequence(text: &str) -> Result<Sequence, char> {
    let mut glyphs = Vec::new();
    for c in text.chars() {
        if c.is_whitespace() || c == '5' {
            continue;
        }
        let Some(digit) = c.to_digit(10) else {
            return Err(c);
        };
        let orientation =
            noita_eye_puzzle::glyph::Orientation::from_digit(digit as u8).map_err(|_symbol| c)?;
        glyphs.push(orientation.glyph());
    }
    Ok(Sequence { glyphs })
}

fn print_report(label: &str, seq: &Sequence) {
    println!("{label}: {} glyphs", seq.len());
    println!(
        "  entropy:               {:.4} bits/glyph",
        analysis::shannon_entropy(&seq.glyphs)
    );
    println!(
        "  index of coincidence:  {:.4}",
        analysis::index_of_coincidence(&seq.glyphs)
    );
    println!("  frequencies:");
    for (glyph, count) in analysis::frequencies(&seq.glyphs) {
        println!("    {glyph}: {count}");
    }
}

fn format_widths(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_span(min: Option<u8>, max: Option<u8>) -> String {
    match min.zip(max) {
        Some((low, high)) => format!("{low}..{high}"),
        None => "empty".to_owned(),
    }
}

fn format_recurrence(recurrence: &[usize; 6]) -> String {
    let [d1, d2, d3, d4, d5, d6] = *recurrence;
    format!("{d1},{d2},{d3},{d4},{d5},{d6}")
}

fn print_experiment_4_flatness_report(flatness: &[orders::NamedReadingLayerFlatnessStats]) {
    println!();
    println!("Experiment 4 reading-layer flatness");
    println!("alphabet: 83 reading-layer symbols, values 0..=82");
    println!(
        "frequency counts are pooled across the nine messages; entropy and IoC p/msg are message-weighted"
    );
    println!(
        "IoC convention: probability form from analysis::index_of_coincidence; x83/all is the concatenated community-reference cross-check"
    );
    println!(
        "{:<24} {:>5} {:>5} {:>7} {:>7} {:>13} {:>17} {:>10} {:>10} {:>10} {:>12}",
        "order",
        "total",
        "in83",
        "outside",
        "mean",
        "freq min..max",
        "entropy/max",
        "IoC p/msg",
        "x83/msg",
        "x83/all",
        "chi2 83"
    );
    for item in flatness
        .iter()
        .filter(|item| is_experiment_4_order(item.order))
    {
        println!(
            "{:<24} {:>5} {:>5} {:>7} {:>7.2} {:>13} {:>17} {:>10.6} {:>10.3} {:>10.3} {:>12}",
            item.order.name(),
            item.flatness.total,
            item.flatness.in_alphabet_total,
            item.flatness.outside_alphabet_occurrences,
            item.flatness.mean_frequency,
            format_frequency_range(&item.flatness),
            format_entropy_ratio(&item.flatness),
            item.flatness.ioc_probability,
            item.flatness.normalized_ioc,
            item.flatness.concatenated_normalized_ioc,
            format_chi_square(item.flatness.chi_square_vs_uniform)
        );
    }
    println!();
    println!(
        "Interpretation: flat per-symbol frequency RULES MONOALPHABETIC OUT; it does NOT rule a real message IN, and near-uniformity is exactly what a fixed honeycomb permutation of structured data also produces. A LOW chi-square (good fit to uniform) is consistent with both a polyalphabetic cipher AND structured-but-meaningless data; do not present flatness as evidence of encoding."
    );
}

fn is_experiment_4_order(order: orders::ReadingOrder) -> bool {
    matches!(
        order,
        orders::ReadingOrder::RawRows | orders::ReadingOrder::HoneycombStandard { .. }
    )
}

fn format_frequency_range(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{}..{} z{}",
        flatness.min_frequency, flatness.max_frequency, flatness.zero_frequency_symbols
    )
}

fn format_entropy_ratio(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{:.4}/{:.4}",
        flatness.entropy_bits_per_symbol, flatness.max_entropy_bits_per_symbol
    )
}

fn format_chi_square(value: f64) -> String {
    if value.is_infinite() {
        "inf(outside)".to_owned()
    } else {
        format!("{value:.3}")
    }
}

fn format_usize_histogram(histogram: &[(usize, usize)]) -> String {
    histogram
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_u8_histogram(histogram: &[(u8, usize)]) -> String {
    histogram
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_storage_histogram(histogram: &[usize; 7]) -> String {
    const STORAGE_LABELS: [&str; 7] = ["-1", "0", "1", "2", "3", "4", "5"];
    STORAGE_LABELS
        .iter()
        .zip(histogram)
        .map(|(label, count)| format!("{label}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}
