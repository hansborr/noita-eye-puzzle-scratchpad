//! Argument struct for the `codecpower` subcommand.

use clap::Args;
use noita_eye_puzzle::attack::{codecpower, rlcodec};

use super::shared::parse_seed;

/// `codecpower`: detection-power calibration for practice puzzle `one`'s
/// comma-code matched-null gate. It plants English windows through the comma
/// encoder, gates them with `rlcodec::gate_symbol_stream`, and reports both the
/// power curve and the matched non-English false-positive control.
#[derive(Debug, Args)]
pub(crate) struct CodecpowerArgs {
    /// Read the English source text from this file. Non-letters are stripped and
    /// letters are uppercased before sampling windows.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the English source text from stdin.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Comma-code separator magnitude.
    #[arg(long, default_value_t = rlcodec::DEFAULT_COMMA_SEP)]
    pub(crate) sep: usize,
    /// Cipher alphabet chars, in order (e.g. `01234`). Only its validated length
    /// is used as the synthetic walk base; defaults to base 5 when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Plaintext lengths to sweep.
    #[arg(long, value_delimiter = ',', default_value = "8,12,16,24,32,48,64")]
    pub(crate) lengths: Vec<usize>,
    /// Number of English plants and non-English controls per length.
    #[arg(long, default_value_t = codecpower::DEFAULT_TRIALS)]
    pub(crate) trials: usize,
    /// Detection-power threshold for the reported detectable-length floor.
    #[arg(long = "power-threshold", default_value_t = codecpower::DEFAULT_POWER_THRESHOLD)]
    pub(crate) power_threshold: f64,
    /// Matched-null trials per planted gate run.
    #[arg(long = "null-trials", default_value_t = rlcodec::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts.
    #[arg(long, default_value_t = rlcodec::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Substitution-search proposals per restart.
    #[arg(long, default_value_t = rlcodec::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Deterministic seed (decimal or 0x-hex) for sampling, search, and nulls.
    #[arg(long, default_value_t = rlcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run planted directional controls and print PASS/FAIL instead of the full
    /// power curve.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
