//! Argument struct for the `rankcodec` subcommand.

use clap::Args;
use noita_eye_puzzle::attack::{rankcodec, rlcodec};

use super::shared::parse_seed;

/// `rankcodec`: bounded-order predictive-rank codec analysis for practice puzzle
/// `one`'s run-length magnitude carrier. Feasibility and crib-consistency are the
/// primary, gate-free discriminators; the quadgram gate is tertiary and
/// underpowered at 135 magnitudes (see `codecpower`).
#[derive(Debug, Args)]
pub(crate) struct RankcodecArgs {
    /// Read the English predictor source from this file. Non-letters are stripped
    /// and letters are uppercased before training.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the English predictor source from stdin.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Read a target digit sequence from this file instead of embedded `one`.
    #[arg(long = "target-file", conflicts_with = "target_stdin")]
    pub(crate) target_file: Option<std::path::PathBuf>,
    /// Read a target digit sequence from stdin instead of embedded `one`.
    #[arg(long = "target-stdin", conflicts_with_all = ["target_file", "stdin"])]
    pub(crate) target_stdin: bool,
    /// Target cipher alphabet chars, in order (e.g. `01234`); defaults to the
    /// five orientation digits for embedded `one` and target overrides.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Predictor orders to sweep. Every requested order must be in `1,2,3` and
    /// is reported.
    #[arg(long, value_delimiter = ',', default_value = "1,2,3")]
    pub(crate) orders: Vec<usize>,
    /// Maximum representable rank in the target carrier.
    #[arg(long = "max-magnitude", default_value_t = rankcodec::DEFAULT_MAX_MAGNITUDE)]
    pub(crate) max_magnitude: usize,
    /// Matched-null trials per order.
    #[arg(long = "null-trials", default_value_t = rlcodec::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts.
    #[arg(long, default_value_t = rlcodec::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Substitution-search proposals per restart.
    #[arg(long, default_value_t = rlcodec::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Maximum number of census anchors to consider as cribs.
    #[arg(long = "top-k", default_value_t = rlcodec::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Deterministic seed (decimal or 0x-hex) for the census, search, and matched
    /// nulls.
    #[arg(long, default_value_t = rankcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run planted controls and print PASS/FAIL instead of scanning real `one`.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
