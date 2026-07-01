//! Argument struct for the `maskdecode` subcommand.

use clap::Args;
use noita_eye_puzzle::attack::maskdecode;

use super::shared::parse_seed;

/// `maskdecode`: masked `C_n`-walk ASCII readout for `±1`-walk puzzles. Derives
/// the walk's direction bits, sweeps mask x width x offset x bit-order x
/// polarity x direction, and promotes a full-letter readout to a verified
/// decode only via an exact round-trip re-encode. With no input flags it runs
/// the embedded practice puzzle `one` (the recorded verified solve).
#[derive(Debug, Args)]
pub(crate) struct MaskdecodeArgs {
    /// Read the ciphertext digit stream from this file instead of embedded
    /// `one`.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext digit stream from stdin instead of embedded `one`.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. `01234`); defaults to the five
    /// orientation digits.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// ASCII chunk widths to sweep (each in 1..=16).
    #[arg(long, value_delimiter = ',', default_value = "5,6,7,8")]
    pub(crate) widths: Vec<usize>,
    /// Number of ranked cells to print.
    #[arg(long = "top", default_value_t = maskdecode::DEFAULT_TOP_CELLS)]
    pub(crate) top: usize,
    /// Deterministic seed (decimal or 0x-hex) for the self-test's matched null.
    #[arg(long, default_value_t = maskdecode::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run planted controls, the matched null, the walk-gate control, and the
    /// recorded-`one` regression; print PASS/FAIL instead of scanning.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
