//! CLI arguments for the position-polynomial shift instrument.

use clap::Args;

use noita_eye_puzzle::attack::polyshift;

use super::shared::parse_seed;

/// Exhaustive linear/quadratic position-keyed shift attack.
#[derive(Clone, Debug, Args)]
pub(crate) struct PolyshiftArgs {
    /// Ciphertext sequence; omit to read from `--input-file` or stdin.
    pub(crate) sequence: Option<String>,
    /// Read ciphertext from this file.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read ciphertext from stdin.
    #[arg(long, conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Exactly 26 ciphertext symbols, in residue order.
    #[arg(long, default_value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    pub(crate) alphabet: String,
    /// Maximum polynomial degree to search (1 or 2).
    #[arg(long, default_value_t = 2)]
    pub(crate) degree: usize,
    /// Matched ciphertext-shuffle trials; zero disables candidate survival.
    #[arg(long = "null-trials", default_value_t = polyshift::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Deterministic matched-null seed (decimal or `0x` hexadecimal).
    #[arg(long, default_value_t = polyshift::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
}
