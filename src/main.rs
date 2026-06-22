//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! will move to `clap` once crates.io is reachable; see `Cargo.toml`.

use std::process::ExitCode;

use noita_eye_puzzle::{analysis, controls, corpus, glyph::Sequence, null, orders, pipeline_null};

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for rendered digits 0-4
    noita-eye demo               Run analysis on the verified nine-message corpus
    noita-eye orders             Audit reading orders and Experiment 4 flatness
    noita-eye nulltest [--seed <u64>] [--trials <n>]
                                  Monte-Carlo null over random grids + standard36
    noita-eye pipelinenull [--seed <u64>] [--trials <n>]
                                  Base-7 pipeline null plus input-randomness control
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
        Some("pipelinenull") => {
            let rest = match args.get(1..) {
                Some(values) => values,
                None => &[],
            };
            run_pipelinenull(rest)
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
