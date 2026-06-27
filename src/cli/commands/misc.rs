//! Handlers for the small irregular subcommands: demo, pipeline-null,
//! grouping, the Experiment 11 positive controls, reading-order audit, and
//! glyph statistics.

use std::process::ExitCode;

use noita_eye_puzzle::{
    analysis::{grouping, orders},
    core::{glyph::Sequence, ingest},
    data::corpus,
    experiments::controls,
    nulls::{null, pipeline_null},
    report::{self, Report},
};

use crate::cli::args_analysis::{ControlTarget, ControlsArgs};
use crate::cli::args_attack::StatsArgs;
use crate::cli::shared::{CliSequenceError, parse_cli_sequence, resolve_input_text};

pub(crate) fn run_demo() -> ExitCode {
    match corpus::combined_sequence() {
        Ok(seq) => {
            print!(
                "{}",
                report::render_sequence_report("verified eye corpus", &seq)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_pipelinenull(config: null::NullConfig) -> ExitCode {
    let pipeline_report = match pipeline_null::run_pipeline_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pipeline null error: {error}");
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
    print!("{}", pipeline_report.render());
    println!();
    print!("{}", input_report.render());
    ExitCode::SUCCESS
}

pub(crate) fn run_grouping() -> ExitCode {
    let report = match grouping::run_experiment8() {
        Ok(report) => report,
        Err(error) => {
            eprintln!("grouping error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

pub(crate) fn run_controls(args: ControlsArgs) -> ExitCode {
    let ControlsArgs { seed, target } = args;
    match target {
        Some(ControlTarget::Monoalphabetic(config)) => run_monoalphabetic_control(config.into()),
        Some(ControlTarget::Isomorph(config)) => run_isomorph_control(config.into()),
        None => {
            let config = controls::MonoalphabeticControlConfig {
                seed: seed.unwrap_or(controls::DEFAULT_MONOALPHABETIC_SEED),
            };
            run_monoalphabetic_control(config)
        }
    }
}

fn run_monoalphabetic_control(config: controls::MonoalphabeticControlConfig) -> ExitCode {
    let report = match controls::run_monoalphabetic_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("monoalphabetic control failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_isomorph_control(config: controls::IsomorphControlConfig) -> ExitCode {
    let report = match controls::run_isomorph_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomorph control failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

pub(crate) fn run_orders() -> ExitCode {
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
    print!(
        "{}",
        report::render_orders_report(&summary, &stats, &flatness)
    );
    ExitCode::SUCCESS
}

pub(crate) fn run_stats(args: &StatsArgs) -> ExitCode {
    let text = match resolve_input_text(args.sequence.as_deref(), args.input_file.as_ref(), false) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let rendered_layer = args.alphabet.is_none() && !args.honeycomb;

    match parse_cli_sequence(&text, args.alphabet.as_deref(), args.honeycomb) {
        Ok(parsed) => {
            let seq = Sequence {
                glyphs: parsed.glyphs,
            };
            print!("{}", report::render_sequence_report("input", &seq));
            ExitCode::SUCCESS
        }
        // Behavior-preserving: the pre-refactor rendered parser returned an empty
        // `Sequence` for empty / all-whitespace / all-delimiter input (e.g.
        // `stats 555`, `stats ""`), which `print_report` renders as a clean
        // 0-glyph report (entropy/IoC 0.0000, no frequencies, exit 0). The
        // library's `parse_sequence` still signals `Empty` for the solve
        // pipeline (brief 04); `stats` keeps the old report only for the rendered
        // layer (the honeycomb / cipher-alphabet paths are new, so their `Empty`
        // surfaces as an error).
        Err(CliSequenceError::Ingest(ingest::IngestError::Empty)) if rendered_layer => {
            print!(
                "{}",
                report::render_sequence_report("input", &Sequence { glyphs: Vec::new() })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
