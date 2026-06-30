//! Argument struct for the `rlcodec` subcommand (run-length codec battery).
//!
//! Split out of [`super::args_attack`] so that module stays under the file-size cap.

use clap::Args;
use noita_eye_puzzle::attack::rlcodec;

use super::shared::parse_seed;

/// `rlcodec`: run-length codec battery for `±1`-walk puzzles. Derives the
/// direction-blind run-length magnitude carrier, censuses its exact repeats, and
/// gates a family of codecs against a matched order-1 Markov null over each codec's
/// decoded symbol stream. The expected verdict on real `one` is an honest negative;
/// a high n-gram score that does not beat the matched null is an artifact, never a
/// decode.
#[derive(Debug, Args)]
pub(crate) struct RlcodecArgs {
    /// Base digit sequence (e.g. `01234...`). Optional: omit to read from
    /// --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. `01234`). The walk base is its
    /// length; defaults to the five orientation digits when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Matched-null trials per codec.
    #[arg(long = "null-trials", default_value_t = rlcodec::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts.
    #[arg(long, default_value_t = rlcodec::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Substitution-search proposals per restart.
    #[arg(long, default_value_t = rlcodec::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Maximum number of census anchors to report.
    #[arg(long = "top-k", default_value_t = rlcodec::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Deterministic seed (decimal or 0x-hex) for the search and every matched
    /// null.
    #[arg(long, default_value_t = rlcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive control + real-`one` honest negative and print
    /// PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
