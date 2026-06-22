//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! will move to `clap` once crates.io is reachable; see `Cargo.toml`.

use std::process::ExitCode;

use noita_eye_puzzle::{analysis, corpus, glyph::Sequence, orders};

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for rendered digits 0-4
    noita-eye demo               Run analysis on the verified nine-message corpus
    noita-eye orders             Audit raw/linear/standard36 reading-order stats

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
                eprintln!(
                    "corpus parse error in {}: invalid symbol {:?}",
                    error.message_key, error.symbol
                );
                ExitCode::FAILURE
            }
        },
        Some("orders") => run_orders(),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
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
