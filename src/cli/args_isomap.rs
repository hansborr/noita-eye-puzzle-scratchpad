//! Argument struct for the `isomap` structural column-map instrument.

use clap::Args;
use noita_eye_puzzle::analysis::isomorph_map;

use super::shared::parse_seed;

/// `isomap`: equality-pattern isomorph column-map extraction plus closure of
/// full maps. Reports a reconstructed state-group lower bound, never a decode.
#[derive(Debug, Args)]
pub(crate) struct IsomapArgs {
    /// Symbol sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. ABCDEFGHIJKL or 01234). Defaults to
    /// rendered orientation digits when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Minimum raw equality-pattern span length considered after null
    /// calibration.
    #[arg(long = "min-span-len", default_value_t = isomorph_map::DEFAULT_MIN_SPAN_LEN)]
    pub(crate) min_span_len: usize,
    /// Positions trimmed from each end before extracting a column map.
    #[arg(long = "trim", default_value_t = isomorph_map::DEFAULT_TRIM)]
    pub(crate) trim: usize,
    /// Maximum number of surviving span pairs to report.
    #[arg(long = "top-k", default_value_t = isomorph_map::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Number of matched-null (order-1 Markov resample) trials.
    #[arg(long = "null-trials", default_value_t = isomorph_map::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Maximum generated group size before closure aborts.
    #[arg(long = "closure-cap", default_value_t = isomorph_map::DEFAULT_CLOSURE_CAP)]
    pub(crate) closure_cap: usize,
    /// Deterministic seed (decimal or 0x-hex) for the matched null and controls.
    #[arg(long, default_value_t = isomorph_map::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the in-process controls (GAK positive, matched null, dirty boundary)
    /// and print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
