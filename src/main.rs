//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! will move to `clap` once crates.io is reachable; see `Cargo.toml`.

use std::process::ExitCode;

use noita_eye_puzzle::{analysis, corpus, glyph::Sequence, null, orders, pipeline_null};

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for rendered digits 0-4
    noita-eye demo               Run analysis on the verified nine-message corpus
    noita-eye orders             Audit raw/linear/standard36 reading-order stats
    noita-eye nulltest [--seed <u64>] [--trials <n>]
                                  Monte-Carlo null over random grids + standard36
    noita-eye pipelinenull [--seed <u64>] [--trials <n>]
                                  Base-7 pipeline null plus input-randomness control

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
        Some("pipelinenull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_pipelinenull(rest)
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
        "analytic P(no -1 in matched random corpus): {:.6e}",
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
        "Interpretation: this only shows the authored engine inputs live in the 0..=5 storage alphabet (zero -1 controls and 86 delimiters) instead of resembling matched-length random integers. It does not show that the authored symbols encode anything."
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
