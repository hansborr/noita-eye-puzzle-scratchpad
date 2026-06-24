//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! may move to `clap` as the command surface grows.

use std::process::ExitCode;

use noita_eye_puzzle::{
    chaining, cipher_attack, controls, corpus, dof_null, glyph::Sequence, grouping, isomorph_null,
    null, orders, periodicity, perseus, pipeline_null, report,
};

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for rendered digits 0-4
    noita-eye demo               Run analysis on the verified nine-message corpus
    noita-eye orders             Audit reading orders and Experiment 4 flatness
    noita-eye nulltest [--seed <u64>] [--trials <n>]
                                  Monte-Carlo null over random grids + standard36
    noita-eye dofnull [--seed <u64>] [--trials <n>] [--calib-trials <n>]
                                  Calibrated adaptive null over traversal/grouping/statistic DoF
    noita-eye periodicity [--seed <u64>] [--trials <n>] [--max-period <n>] [--max-lag <n>]
                                  Experiment 5A period/lag/Kasiski battery
    noita-eye pipelinenull [--seed <u64>] [--trials <n>]
                                  Base-7 pipeline null plus input-randomness control
    noita-eye grouping          Experiment 8 base-N grouping + state-count estimate
    noita-eye isomorphnull [--seed <u64>] [--trials <n>]
                                  Experiment 7A real isomorphs vs within-message shuffle null
    noita-eye chaining [--seed <u64>] [--trials <n>] [--min-period <n>] [--max-period <n>]
                                  Experiment 7B alphabet-chaining structural control
    noita-eye perseus [--seed <u64>] [--trials <n>]
                                  Experiment 7C Perseus shared-region recurrence null
    noita-eye cipherattack [--seed <u64>] [--samples <n>] [--null-trials <n>]
                                  Experiment 12 candidate-cipher language-scoring null harness
    noita-eye controls monoalphabetic [--seed <u64>]
                                  Experiment 11 monoalphabetic positive control
    noita-eye controls isomorph [--seed <u64>]   (alias: polyalphabetic)
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
                report::print_report("verified eye corpus", &seq);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{}", report::format_corpus_error(error));
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
        Some("dofnull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_dofnull(rest)
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
        Some("grouping") => run_grouping(),
        Some("isomorphnull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_isomorphnull(rest)
        }
        Some("chaining") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_chaining(rest)
        }
        Some("perseus") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_perseus(rest)
        }
        Some("cipherattack") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_cipherattack(rest)
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
    report::print_null_report(&report);
    ExitCode::SUCCESS
}

fn run_dofnull(args: &[String]) -> ExitCode {
    let config = match parse_dof_null_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: noita-eye dofnull [--seed <u64>] [--trials <n>] [--calib-trials <n>]"
            );
            return ExitCode::FAILURE;
        }
    };
    let report = match dof_null::run_dof_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("DoF null error: {}", report::format_dof_null_error(&error));
            return ExitCode::FAILURE;
        }
    };
    report::print_dof_null_report(&report);
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
            eprintln!(
                "periodicity error: {}",
                report::format_periodicity_error(error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_periodicity_report(&report);
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
    report::print_pipeline_null_report(&pipeline_report);
    println!();
    report::print_input_randomness_report(&input_report);
    ExitCode::SUCCESS
}

fn run_grouping() -> ExitCode {
    let report = match grouping::run_experiment8() {
        Ok(report) => report,
        Err(error) => {
            eprintln!("grouping error: {}", report::format_grouping_error(error));
            return ExitCode::FAILURE;
        }
    };
    report::print_grouping_report(&report);
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
            eprintln!(
                "isomorph null error: {}",
                report::format_isomorph_null_error(error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_isomorph_null_report(&report);
    ExitCode::SUCCESS
}

fn run_chaining(args: &[String]) -> ExitCode {
    let config = match parse_chaining_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: noita-eye chaining [--seed <u64>] [--trials <n>] [--min-period <n>] [--max-period <n>]"
            );
            return ExitCode::FAILURE;
        }
    };
    let report = match chaining::run_chaining(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("chaining error: {}", report::format_chaining_error(error));
            return ExitCode::FAILURE;
        }
    };
    report::print_chaining_report(&report);
    ExitCode::SUCCESS
}

fn run_perseus(args: &[String]) -> ExitCode {
    let config = match parse_perseus_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: noita-eye perseus [--seed <u64>] [--trials <n>]");
            return ExitCode::FAILURE;
        }
    };
    let report = match perseus::run_perseus(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "Perseus recurrence error: {}",
                report::format_perseus_error(error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_perseus_report(&report);
    ExitCode::SUCCESS
}

fn run_cipherattack(args: &[String]) -> ExitCode {
    let config = match parse_cipher_attack_config(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: noita-eye cipherattack [--seed <u64>] [--samples <n>] [--null-trials <n>] [--max-vigenere-period <n>]"
            );
            return ExitCode::FAILURE;
        }
    };
    let report = match cipher_attack::run_cipher_attack(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "cipher attack error: {}",
                report::format_cipher_attack_error(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_cipher_attack_report(&report);
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
        "usage: noita-eye controls monoalphabetic [--seed <u64>]\n       noita-eye controls isomorph [--seed <u64>]   (alias: polyalphabetic)"
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
                report::format_controls_error(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_monoalphabetic_control_report(&report);
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
            eprintln!(
                "isomorph control failed: {}",
                report::format_controls_error(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_isomorph_control_report(&report);
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

fn parse_dof_null_config(args: &[String]) -> Result<dof_null::DofNullConfig, String> {
    let mut config = dof_null::DofNullConfig::default();
    let mut calibration_trials = None;
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
            "--calib-trials" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --calib-trials".to_owned());
                };
                calibration_trials =
                    Some(value.parse::<usize>().map_err(|error| {
                        format!("invalid --calib-trials value {value:?}: {error}")
                    })?);
            }
            other => return Err(format!("unknown dofnull flag {other:?}")),
        }
    }
    config.calibration_trials = calibration_trials.unwrap_or(config.trials);
    Ok(config)
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

fn parse_chaining_config(args: &[String]) -> Result<chaining::ChainingConfig, String> {
    let mut config = chaining::ChainingConfig::default();
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
            "--min-period" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --min-period".to_owned());
                };
                config.min_period = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --min-period value {value:?}: {error}"))?;
            }
            "--max-period" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --max-period".to_owned());
                };
                config.max_period = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --max-period value {value:?}: {error}"))?;
            }
            other => return Err(format!("unknown chaining flag {other:?}")),
        }
    }
    Ok(config)
}

fn parse_perseus_config(args: &[String]) -> Result<perseus::PerseusConfig, String> {
    let mut config = perseus::PerseusConfig::default();
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
            other => return Err(format!("unknown perseus flag {other:?}")),
        }
    }
    Ok(config)
}

fn parse_cipher_attack_config(
    args: &[String],
) -> Result<cipher_attack::CipherAttackConfig, String> {
    let mut config = cipher_attack::CipherAttackConfig::default();
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
            "--samples" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --samples".to_owned());
                };
                config.samples = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --samples value {value:?}: {error}"))?;
            }
            "--null-trials" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --null-trials".to_owned());
                };
                config.null_trials = value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --null-trials value {value:?}: {error}"))?;
            }
            "--max-vigenere-period" => {
                let Some(value) = iter.next() else {
                    return Err("missing value for --max-vigenere-period".to_owned());
                };
                config.vigenere_max_period = value.parse::<usize>().map_err(|error| {
                    format!("invalid --max-vigenere-period value {value:?}: {error}")
                })?;
            }
            other => return Err(format!("unknown cipherattack flag {other:?}")),
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

fn run_orders() -> ExitCode {
    let grids = match orders::corpus_grids() {
        Ok(grids) => grids,
        Err(error) => {
            eprintln!("grid reconstruction error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let summary = orders::summarize_grids(&grids);
    let stats = match orders::audit_order_stats(&grids) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("order audit error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let flatness = match orders::audit_order_flatness_stats(&grids) {
        Ok(flatness) => flatness,
        Err(error) => {
            eprintln!("order flatness error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    report::print_orders_report(&summary, &stats, &flatness);
    ExitCode::SUCCESS
}

fn run_stats(text: &str) -> ExitCode {
    match parse_rendered_sequence(text) {
        Ok(seq) => {
            report::print_report("input", &seq);
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
