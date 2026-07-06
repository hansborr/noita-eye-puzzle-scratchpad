//! Argument struct for the `substfinish` monoalphabetic candidate finisher.

use clap::Args;
use noita_eye_puzzle::attack::substitution;

use super::shared::parse_seed;

/// `substfinish`: solve an already-segmented monoalphabetic candidate text.
#[derive(Debug, Args)]
pub(crate) struct SubstfinishArgs {
    /// Candidate symbol text. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read candidate symbol text from this file.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read candidate symbol text from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Exact substitution alphabet, one character per cipher symbol.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Matched-null trials.
    #[arg(
        long = "null-trials",
        default_value_t = substitution::DEFAULT_NULL_TRIALS
    )]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts.
    #[arg(long, default_value_t = substitution::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Annealing proposals per restart.
    #[arg(long, default_value_t = substitution::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Candidate threshold on add-one empirical p-value.
    #[arg(long = "alpha", default_value_t = substitution::DEFAULT_ALPHA)]
    pub(crate) alpha: f64,
    /// Deterministic seed.
    #[arg(long, default_value_t = substitution::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run controls and exit.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}

impl From<&SubstfinishArgs> for substitution::SubstitutionConfig {
    fn from(args: &SubstfinishArgs) -> Self {
        Self {
            restarts: args.restarts,
            iters: args.iters,
            null_trials: args.null_trials,
            seed: args.seed,
            alpha: args.alpha,
        }
    }
}
