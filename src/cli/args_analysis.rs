//! Argument structs for the uniform analysis / null-model subcommands plus
//! their `From` conversions into the library config types.

use clap::{Args, Subcommand};
use noita_eye_puzzle::{
    analysis::{chaining, chaining_graph, honeycomb, perfect_isomorphism},
    attack::cipher_attack,
    experiments::{
        conditional_structure, controls, modular_diff, orientation_homogeneity, periodicity,
        pyry_conditions, transitivity,
    },
    nulls::{dof_null, isomorph_null, null, perseus, tree_residual, zero_adjacency_null},
};

const DEFAULT_NULL_SEED: u64 = 0x6e6f_6974_612d_6579;
const DEFAULT_NULL_TRIALS: usize = 1_000;
const DEFAULT_DOF_NULL_SEED: u64 = 0x646f_666e_756c_6c00;
const DEFAULT_DOF_NULL_TRIALS: usize = 1_000;

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct NullArgs {
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
pub(crate) struct DofNullArgs {
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
pub(crate) struct PeriodicityArgs {
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
pub(crate) struct HoneycombArgs {
    #[arg(long, default_value_t = honeycomb::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = honeycomb::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<HoneycombArgs> for honeycomb::HoneycombConfig {
    fn from(args: HoneycombArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Debug, Args)]
pub(crate) struct IsomorphNullArgs {
    #[arg(long, default_value_t = isomorph_null::DEFAULT_SEED)]
    pub(crate) seed: u64,
    #[arg(long, default_value_t = isomorph_null::DEFAULT_TRIALS)]
    pub(crate) trials: usize,
    /// Symbol sequence. Optional: omit to run the verified eye corpus, or read
    /// from --input-file / --stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order; required for any non-corpus input. The
    /// isomorph statistic is equality-based, so the alphabet only declares which
    /// characters are the same symbol (its size is not otherwise used).
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ChainingArgs {
    #[arg(long, default_value_t = chaining::DEFAULT_SEED)]
    pub(crate) seed: u64,
    #[arg(long, default_value_t = chaining::DEFAULT_TRIALS)]
    pub(crate) trials: usize,
    #[arg(long = "min-period", default_value_t = chaining::DEFAULT_MIN_PERIOD)]
    pub(crate) min_period: usize,
    #[arg(long = "max-period", default_value_t = chaining::DEFAULT_MAX_PERIOD)]
    pub(crate) max_period: usize,
    /// Reading-layer value stream. Optional: omit to run the verified eye corpus,
    /// or read from --input-file / --stdin.
    pub(crate) sequence: Option<String>,
    /// Read the stream from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the stream from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order; required for any non-corpus input. The
    /// alphabet size is the char count (no eye reading-layer 83 default off-corpus).
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ChainingGraphArgs {
    #[arg(long, default_value_t = chaining_graph::DEFAULT_SEED)]
    pub(crate) seed: u64,
    #[arg(long, default_value_t = chaining_graph::DEFAULT_TRIALS)]
    pub(crate) trials: usize,
    /// Symbol-value sequence. Optional: omit to run the verified eye corpus, or
    /// read from --input-file / --stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order; required for any non-corpus input. Its
    /// char count is the coverage denominator (the alphabet size).
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct ModularDiffArgs {
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
pub(crate) struct PerseusArgs {
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

#[derive(Clone, Debug, Args)]
pub(crate) struct PerfectIsomorphismArgs {
    #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_SEED)]
    pub(crate) seed: u64,
    #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_TRIALS)]
    pub(crate) trials: usize,
    #[arg(long = "min-window", default_value_t = perfect_isomorphism::DEFAULT_MIN_WINDOW)]
    pub(crate) min_window: usize,
    #[arg(long = "max-window", default_value_t = perfect_isomorphism::DEFAULT_MAX_WINDOW)]
    pub(crate) max_window: usize,
    /// Reading-layer value stream. Optional: omit to run the verified eye corpus,
    /// or read from --input-file / --stdin.
    pub(crate) sequence: Option<String>,
    /// Read the stream from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the stream from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order; required for any non-corpus input. The
    /// scan is equality- and gap-based, so the alphabet only declares which symbols
    /// are equal (its size is not threaded into the config).
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct HomogeneityArgs {
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_TRIALS_PER_SEED)]
    trials: usize,
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_SEED_COUNT)]
    seeds: usize,
}

impl From<HomogeneityArgs> for orientation_homogeneity::OrientationHomogeneityConfig {
    fn from(args: HomogeneityArgs) -> Self {
        Self {
            seed: args.seed,
            trials_per_seed: args.trials,
            seed_count: args.seeds,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct ZeroAdjacencyNullArgs {
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_TRIALS_PER_SEED)]
    trials: usize,
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_SEED_COUNT)]
    seeds: usize,
}

impl From<ZeroAdjacencyNullArgs> for zero_adjacency_null::ZeroAdjacencyNullConfig {
    fn from(args: ZeroAdjacencyNullArgs) -> Self {
        Self {
            seed: args.seed,
            trials_per_seed: args.trials,
            seed_count: args.seeds,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TreeResidualArgs {
    #[arg(long, default_value_t = tree_residual::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = tree_residual::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "seed-count", default_value_t = tree_residual::DEFAULT_SEED_COUNT)]
    seed_count: usize,
}

impl From<TreeResidualArgs> for tree_residual::TreeResidualConfig {
    fn from(args: TreeResidualArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            seed_count: args.seed_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TransitivityArgs {
    #[arg(long, default_value_t = transitivity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = transitivity::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<TransitivityArgs> for transitivity::TransitivityConfig {
    fn from(args: TransitivityArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct ConditionalArgs {
    #[arg(long, default_value_t = conditional_structure::DEFAULT_SEED)]
    seed: u64,
    #[arg(long = "seeds", default_value_t = conditional_structure::DEFAULT_SEED_COUNT)]
    seed_count: usize,
    #[arg(
        long = "trials-per-seed",
        default_value_t = conditional_structure::DEFAULT_TRIALS_PER_SEED
    )]
    trials_per_seed: usize,
}

impl From<ConditionalArgs> for conditional_structure::ConditionalStructureConfig {
    fn from(args: ConditionalArgs) -> Self {
        Self {
            seed: args.seed,
            seed_count: args.seed_count,
            trials_per_seed: args.trials_per_seed,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct CipherAttackArgs {
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

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct PyryConditionsArgs {
    #[arg(long, default_value_t = pyry_conditions::DEFAULT_SEED)]
    seed: u64,
    #[arg(long = "draws", default_value_t = pyry_conditions::DEFAULT_FIXTURE_DRAWS)]
    fixture_draws: usize,
}

impl From<PyryConditionsArgs> for pyry_conditions::PyryConditionsConfig {
    fn from(args: PyryConditionsArgs) -> Self {
        Self {
            seed: args.seed,
            fixture_draws: args.fixture_draws,
        }
    }
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct ControlsArgs {
    #[arg(long)]
    pub(crate) seed: Option<u64>,
    #[command(subcommand)]
    pub(crate) target: Option<ControlTarget>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ControlTarget {
    /// Experiment 11 monoalphabetic positive control.
    Monoalphabetic(MonoalphabeticControlArgs),
    /// Experiment 11 isomorph/polyalphabetic positive control.
    #[command(alias = "polyalphabetic")]
    Isomorph(IsomorphControlArgs),
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct MonoalphabeticControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_MONOALPHABETIC_SEED)]
    seed: u64,
}

impl From<MonoalphabeticControlArgs> for controls::MonoalphabeticControlConfig {
    fn from(args: MonoalphabeticControlArgs) -> Self {
        Self { seed: args.seed }
    }
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct IsomorphControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_ISOMORPH_SEED)]
    seed: u64,
}

impl From<IsomorphControlArgs> for controls::IsomorphControlConfig {
    fn from(args: IsomorphControlArgs) -> Self {
        Self { seed: args.seed }
    }
}
