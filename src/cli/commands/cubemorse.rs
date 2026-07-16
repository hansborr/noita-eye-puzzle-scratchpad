//! Handler for the `cubemorse` subcommand.

use std::process::ExitCode;

use noita_eye_puzzle::{
    attack::cubemorse::{
        self, CubeMorseConfig, CubeMorseReport, CubeMorseSelfTest, CubeMorseVerdict,
    },
    core::glyph::Glyph,
};

use crate::cli::args_cubemorse::CubeMorseArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text, split_blank_line_messages};

const EMBEDDED_SIX: &str = include_str!("../../../research/data/practice-puzzles/six");

pub(crate) fn run_cubemorse(args: &CubeMorseArgs) -> ExitCode {
    let controls = match cubemorse::cubemorse_self_test(args.seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("cubemorse self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(&controls);
    if !controls.passed() {
        eprintln!("cubemorse refused real input because its self-test failed");
        return ExitCode::FAILURE;
    }
    if args.self_test {
        return ExitCode::SUCCESS;
    }
    let (text, label) = match resolve_text(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("cubemorse input error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if args.alphabet.chars().count() != 6 {
        eprintln!("cubemorse input error: --alphabet must contain exactly six symbols");
        return ExitCode::FAILURE;
    }
    let messages = split_blank_line_messages(&text);
    if messages.is_empty() {
        eprintln!("cubemorse input error: input has no messages");
        return ExitCode::FAILURE;
    }
    let config = CubeMorseConfig {
        null_trials: args.null_trials,
        seed: args.seed,
        top: args.top,
    };
    for (index, message) in messages.iter().enumerate() {
        let words = match parse_words(message, &args.alphabet) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("cubemorse input error in message {}: {error}", index + 1);
                return ExitCode::FAILURE;
            }
        };
        match cubemorse::analyze_cube_morse(&words, config) {
            Ok(report) => print_report(&report, &label, index, messages.len()),
            Err(error) => {
                eprintln!("cubemorse error in message {}: {error}", index + 1);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn resolve_text(args: &CubeMorseArgs) -> Result<(String, String), std::io::Error> {
    if args.input_file.is_none() && !args.stdin {
        return Ok((
            EMBEDDED_SIX.to_owned(),
            "embedded practice puzzle six".to_owned(),
        ));
    }
    let text = resolve_input_text(None, args.input_file.as_ref(), args.stdin)?;
    let label = args
        .input_file
        .as_ref()
        .map_or_else(|| "stdin".to_owned(), |path| path.display().to_string());
    Ok((text, label))
}

fn parse_words(message: &str, alphabet: &str) -> Result<Vec<Vec<Glyph>>, String> {
    message
        .split_whitespace()
        .map(|word| {
            parse_cli_sequence(word, Some(alphabet), false)
                .map(|parsed| parsed.glyphs)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn print_self_test(report: &CubeMorseSelfTest) {
    println!("cubemorse self-test:");
    println!(
        "  planted recovery: {}",
        pass_fail(report.plant_recovered && report.plant_exact)
    );
    println!(
        "  matched cube-walk null: {}",
        pass_fail(report.matched_null_negative)
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed()));
}

fn print_report(report: &CubeMorseReport, label: &str, index: usize, count: usize) {
    println!();
    println!(
        "cubemorse: {label}{} — {} face symbols, {} word blocks",
        if count == 1 {
            String::new()
        } else {
            format!(" message {}", index + 1)
        },
        report.symbols,
        report.words
    );
    println!(
        "  model: cube top-face walk; opposite face-index pairs 0/5, 1/4, 2/3; three used roll directions -> Morse dot/dash/letter separator"
    );
    println!(
        "  matched null: {}/{} produced valid Morse; null_ge {}, p_emp {:.4}{}",
        report.null_survivors,
        report.null_trials,
        report.null_ge,
        report.p_empirical,
        report
            .margin_vs_null_max
            .map_or_else(String::new, |margin| format!(
                ", score margin vs null max {margin:.4}"
            ))
    );
    for (rank, candidate) in report.candidates.iter().enumerate() {
        let cell = candidate.cell;
        println!(
            "  {}. {:?} (quadgram {:.4}; exact RoundTrip {}/{}; {} symmetry-equivalent cells)",
            rank + 1,
            candidate.plaintext,
            candidate.quadgram_score,
            candidate.matched,
            candidate.total,
            candidate.equivalent_cells
        );
        println!(
            "     start T/N/E={}/{}/{}; roles dot={} dash={} separator={}",
            cell.start.top,
            cell.start.north,
            cell.start.east,
            cell.roles.dot.label(),
            cell.roles.dash.label(),
            cell.roles.separator.label()
        );
    }
    match report.verdict {
        CubeMorseVerdict::ExactCandidate => println!(
            "  VERDICT: ExactCandidate — exact fixed-code replay and no matched-null equal; candidate pending external confirmation."
        ),
        CubeMorseVerdict::MatchedNull => println!(
            "  VERDICT: MatchedNull — a readable exact-replay cell exists but does not beat the matched search null."
        ),
        CubeMorseVerdict::NoCandidate => println!(
            "  VERDICT: NoCandidate — no swept cube/Morse cell decoded entirely to standard Morse."
        ),
    }
}

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}
