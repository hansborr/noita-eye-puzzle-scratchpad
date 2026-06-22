//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. A richer CLI (subcommands, flags)
//! will move to `clap` once crates.io is reachable; see `Cargo.toml`.

use std::process::ExitCode;

use noita_eye_puzzle::{analysis, corpus, glyph::Sequence};

const USAGE: &str = "\
noita-eye — Noita eye-glyph puzzle toolkit

USAGE:
    noita-eye stats <sequence>   Frequency / entropy / IoC for a transcribed sequence
    noita-eye demo               Run analysis on the built-in sample corpus

Sequences are transcribed using the placeholder alphabet (a, b, c, ...);
whitespace is ignored.";

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
        Some("demo") => {
            print_report("sample corpus", &corpus::sample());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run_stats(text: &str) -> ExitCode {
    let alphabet = corpus::placeholder_alphabet();
    match Sequence::parse(text, &alphabet) {
        Ok(seq) => {
            print_report("input", &seq);
            ExitCode::SUCCESS
        }
        Err(c) => {
            eprintln!("unknown glyph character {c:?} (not in the placeholder alphabet)");
            ExitCode::FAILURE
        }
    }
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
