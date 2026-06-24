//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. `clap` owns argument parsing and
//! usage text; domain analysis and report rendering live in the library.

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use noita_eye_puzzle::{
    chaining, cipher_attack, controls, corpus, dof_null, glyph::Sequence, grouping, isomorph_null,
    modular_diff, null, orders, periodicity, perseus, pipeline_null, report,
};

const DEFAULT_NULL_SEED: u64 = 0x6e6f_6974_612d_6579;
const DEFAULT_NULL_TRIALS: usize = 1_000;
const DEFAULT_DOF_NULL_SEED: u64 = 0x646f_666e_756c_6c00;
const DEFAULT_DOF_NULL_TRIALS: usize = 1_000;

#[derive(Debug, Parser)]
#[command(
    name = "noita-eye",
    about = "Noita eye-glyph puzzle toolkit",
    after_help = "Digit 5 is treated as a row delimiter and ignored for glyph statistics."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Frequency, entropy, and `IoC` for rendered digits 0-4.
    Stats(StatsArgs),
    /// Run analysis on the verified nine-message corpus.
    Demo,
    /// Audit reading orders and Experiment 4 flatness.
    Orders,
    /// Monte-Carlo null over random grids plus standard36 orders.
    #[command(name = "nulltest")]
    Nulltest(NullArgs),
    /// Calibrated adaptive null over traversal/grouping/statistic `DoF`.
    #[command(name = "dofnull")]
    Dofnull(DofNullArgs),
    /// Experiment 5A period/lag/Kasiski battery.
    Periodicity(PeriodicityArgs),
    /// Base-7 pipeline null plus input-randomness control.
    #[command(name = "pipelinenull")]
    Pipelinenull(NullArgs),
    /// Experiment 8 base-N grouping plus state-count estimate.
    Grouping,
    /// Experiment 7A real isomorphs vs within-message shuffle null.
    #[command(name = "isomorphnull")]
    Isomorphnull(IsomorphNullArgs),
    /// Experiment 7B alphabet-chaining structural control.
    Chaining(ChainingArgs),
    /// Modular-difference family fingerprint.
    #[command(name = "moddiff")]
    Moddiff(ModularDiffArgs),
    /// Experiment 7C Perseus shared-region recurrence null.
    Perseus(PerseusArgs),
    /// Experiment 12 candidate-cipher language-scoring null harness.
    #[command(name = "cipherattack")]
    Cipherattack(CipherAttackArgs),
    /// Experiment 11 positive controls.
    Controls(ControlsArgs),
}

#[derive(Debug, Args)]
struct StatsArgs {
    /// Rendered orientation sequence using digits 0-4 and optional delimiter 5.
    sequence: String,
}

#[derive(Clone, Copy, Debug, Args)]
struct NullArgs {
    #[arg(long, default_value_t = DEFAULT_NULL_SEED)]
    seed: u64,
    #[arg(long, default_value_t = DEFAULT_NULL_TRIALS)]
    trials: usize,
}

impl From<NullArgs> for null::NullConfig {
    fn from(args: NullArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct DofNullArgs {
    #[arg(long, default_value_t = DEFAULT_DOF_NULL_SEED)]
    seed: u64,
    #[arg(long, default_value_t = DEFAULT_DOF_NULL_TRIALS)]
    trials: usize,
    #[arg(long = "calib-trials")]
    calibration_trials: Option<usize>,
}

impl From<DofNullArgs> for dof_null::DofNullConfig {
    fn from(args: DofNullArgs) -> Self {
        Self {
            seed: args.seed,
            calibration_trials: args.calibration_trials.unwrap_or(args.trials),
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PeriodicityArgs {
    #[arg(long, default_value_t = periodicity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = periodicity::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "max-period", default_value_t = periodicity::DEFAULT_MAX_PERIOD)]
    max_period: usize,
    #[arg(long = "max-lag", default_value_t = periodicity::DEFAULT_MAX_LAG)]
    max_lag: usize,
    #[arg(long = "min-ngram", default_value_t = periodicity::DEFAULT_MIN_NGRAM)]
    min_ngram: usize,
    #[arg(long = "max-ngram", default_value_t = periodicity::DEFAULT_MAX_NGRAM)]
    max_ngram: usize,
}

impl From<PeriodicityArgs> for periodicity::PeriodicityConfig {
    fn from(args: PeriodicityArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            max_period: args.max_period,
            max_lag: args.max_lag,
            min_ngram: args.min_ngram,
            max_ngram: args.max_ngram,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct IsomorphNullArgs {
    #[arg(long, default_value_t = isomorph_null::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = isomorph_null::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<IsomorphNullArgs> for isomorph_null::IsomorphNullConfig {
    fn from(args: IsomorphNullArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ChainingArgs {
    #[arg(long, default_value_t = chaining::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = chaining::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "min-period", default_value_t = chaining::DEFAULT_MIN_PERIOD)]
    min_period: usize,
    #[arg(long = "max-period", default_value_t = chaining::DEFAULT_MAX_PERIOD)]
    max_period: usize,
}

impl From<ChainingArgs> for chaining::ChainingConfig {
    fn from(args: ChainingArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            min_period: args.min_period,
            max_period: args.max_period,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ModularDiffArgs {
    #[arg(long, default_value_t = modular_diff::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = modular_diff::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "max-period", default_value_t = modular_diff::DEFAULT_MAX_PERIOD)]
    max_period: usize,
    #[arg(long = "max-lag", default_value_t = modular_diff::DEFAULT_MAX_LAG)]
    max_lag: usize,
}

impl From<ModularDiffArgs> for modular_diff::ModularDiffConfig {
    fn from(args: ModularDiffArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            max_period: args.max_period,
            max_lag: args.max_lag,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PerseusArgs {
    #[arg(long, default_value_t = perseus::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = perseus::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<PerseusArgs> for perseus::PerseusConfig {
    fn from(args: PerseusArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct CipherAttackArgs {
    #[arg(long, default_value_t = cipher_attack::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = cipher_attack::DEFAULT_SAMPLES)]
    samples: usize,
    #[arg(long = "null-trials", default_value_t = cipher_attack::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    #[arg(
        long = "max-vigenere-period",
        default_value_t = cipher_attack::DEFAULT_VIGENERE_MAX_PERIOD
    )]
    vigenere_max_period: usize,
}

impl From<CipherAttackArgs> for cipher_attack::CipherAttackConfig {
    fn from(args: CipherAttackArgs) -> Self {
        Self {
            seed: args.seed,
            samples: args.samples,
            null_trials: args.null_trials,
            vigenere_max_period: args.vigenere_max_period,
        }
    }
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ControlsArgs {
    #[arg(long)]
    seed: Option<u64>,
    #[command(subcommand)]
    target: Option<ControlTarget>,
}

#[derive(Debug, Subcommand)]
enum ControlTarget {
    /// Experiment 11 monoalphabetic positive control.
    Monoalphabetic(MonoalphabeticControlArgs),
    /// Experiment 11 isomorph/polyalphabetic positive control.
    #[command(alias = "polyalphabetic")]
    Isomorph(IsomorphControlArgs),
}

#[derive(Clone, Copy, Debug, Args)]
struct MonoalphabeticControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_MONOALPHABETIC_SEED)]
    seed: u64,
}

impl From<MonoalphabeticControlArgs> for controls::MonoalphabeticControlConfig {
    fn from(args: MonoalphabeticControlArgs) -> Self {
        Self { seed: args.seed }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct IsomorphControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_ISOMORPH_SEED)]
    seed: u64,
}

impl From<IsomorphControlArgs> for controls::IsomorphControlConfig {
    fn from(args: IsomorphControlArgs) -> Self {
        Self { seed: args.seed }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Stats(args) => run_stats(&args.sequence),
        Command::Demo => run_demo(),
        Command::Orders => run_orders(),
        Command::Nulltest(args) => run_nulltest(args.into()),
        Command::Dofnull(args) => run_dofnull(args.into()),
        Command::Periodicity(args) => run_periodicity(args.into()),
        Command::Pipelinenull(args) => run_pipelinenull(args.into()),
        Command::Grouping => run_grouping(),
        Command::Isomorphnull(args) => run_isomorphnull(args.into()),
        Command::Chaining(args) => run_chaining(args.into()),
        Command::Moddiff(args) => run_moddiff(args.into()),
        Command::Perseus(args) => run_perseus(args.into()),
        Command::Cipherattack(args) => run_cipherattack(args.into()),
        Command::Controls(args) => run_controls(args),
    }
}

fn run_demo() -> ExitCode {
    match corpus::combined_sequence() {
        Ok(seq) => {
            report::print_report("verified eye corpus", &seq);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", report::format_corpus_error(error));
            ExitCode::FAILURE
        }
    }
}

fn run_nulltest(config: null::NullConfig) -> ExitCode {
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

fn run_dofnull(config: dof_null::DofNullConfig) -> ExitCode {
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

fn run_periodicity(config: periodicity::PeriodicityConfig) -> ExitCode {
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

fn run_pipelinenull(config: null::NullConfig) -> ExitCode {
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

fn run_isomorphnull(config: isomorph_null::IsomorphNullConfig) -> ExitCode {
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

fn run_chaining(config: chaining::ChainingConfig) -> ExitCode {
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

fn run_moddiff(config: modular_diff::ModularDiffConfig) -> ExitCode {
    let report = match modular_diff::run_modular_diff(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "modular-difference error: {}",
                report::format_modular_diff_error(error)
            );
            return ExitCode::FAILURE;
        }
    };
    report::print_modular_diff_report(&report);
    ExitCode::SUCCESS
}

fn run_perseus(config: perseus::PerseusConfig) -> ExitCode {
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

fn run_cipherattack(config: cipher_attack::CipherAttackConfig) -> ExitCode {
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

fn run_controls(args: ControlsArgs) -> ExitCode {
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

fn run_isomorph_control(config: controls::IsomorphControlConfig) -> ExitCode {
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
