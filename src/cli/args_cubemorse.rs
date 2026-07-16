//! Argument struct for the `cubemorse` subcommand.

use clap::Args;
use noita_eye_puzzle::attack::cubemorse;

use super::shared::parse_seed;

/// `cubemorse`: interpret a six-symbol stream as successive top faces of a
/// rolling cube, sweep three roll directions as Morse dot/dash/letter separator,
/// and gate exact candidates against matched direction-shuffle nulls.
#[derive(Debug, Args)]
pub(crate) struct CubeMorseArgs {
    /// Read face symbols from this file; blank lines separate equivalent/input
    /// messages and whitespace within a message supplies word boundaries.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read face symbols from stdin instead of embedded practice puzzle `six`.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Six face symbols in index order; opposite pairs are positions 0/5, 1/4,
    /// and 2/3.
    #[arg(long, default_value = "123456")]
    pub(crate) alphabet: String,
    /// Matched direction-shuffle null trials per input message.
    #[arg(long = "null-trials", default_value_t = cubemorse::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Number of distinct plaintext candidates printed per message.
    #[arg(long, default_value_t = cubemorse::DEFAULT_TOP)]
    pub(crate) top: usize,
    /// Deterministic seed (decimal or 0x-hex) for controls and matched nulls.
    #[arg(long, default_value_t = cubemorse::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive and matched-null controls, then exit.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
