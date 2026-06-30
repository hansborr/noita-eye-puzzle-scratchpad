//! Argument struct for the `cribfit` subcommand (crib-anchored consistency filter).
//!
//! Split out of [`super::args_attack`] so that module stays under the file-size cap;
//! mirrors [`super::args_rlcodec`], the sibling instrument it reuses.

use clap::Args;
use noita_eye_puzzle::attack::rlcodec;

use super::shared::parse_seed;

/// `cribfit`: crib-anchored consistency filter for the codec-with-memory regime of
/// `rlcodec`'s direction-blind run-length carrier. Derives the cribs' geometry
/// (run-gaps / bit-gaps and the periods they admit), tests each codec family by the
/// language-free necessary condition that repeated plaintext spans decode
/// identically, and language-gates the crib-consistent + English-viable survivors
/// against the same matched null `rlcodec` uses. The expected verdict on real `one`
/// is an honest negative plus the derived structural constraint.
#[derive(Debug, Args)]
pub(crate) struct CribfitArgs {
    /// Base digit sequence (e.g. `01234...`). Optional: omit to read from
    /// --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. `01234`). The walk base is its length;
    /// defaults to the five orientation digits when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Matched-null trials per gated candidate.
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
    /// Deterministic seed (decimal or 0x-hex) for the census, search, and every
    /// matched null.
    #[arg(long, default_value_t = rlcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive control + discrimination control + real-`one` honest
    /// negative and print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
