//! Argument struct for the `predscan` subcommand (Thread C — the Toboter
//! predicate battery + multiple-comparisons meta-analysis).
//!
//! Kept in its own module so the new flags do not push `args_analysis.rs` over the
//! 600-line file budget.

use clap::Args;
use noita_eye_puzzle::analysis::predicates;

use super::shared::parse_seed;

/// `predscan`: recompute each community-listed arithmetic predicate against the
/// repo's matched nulls and report the multiple-comparisons meta-analysis.
#[derive(Debug, Args)]
pub(crate) struct PredscanArgs {
    /// Symbol sequence. Optional: omit (and pass no input flags) to run the
    /// verified eye corpus under the accepted honeycomb reading order.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    /// Blank lines separate messages.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin (blank lines separate messages).
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order. Required for a stream input; its char
    /// count is the declared alphabet size. The eye-corpus default needs none.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Monte-Carlo trials for the within-message shuffle null (the gap predicate).
    #[arg(long = "shuffle-trials", default_value_t = predicates::DEFAULT_SHUFFLE_TRIALS)]
    pub(crate) shuffle_trials: usize,
    /// Monte-Carlo trials for the value-resample null (the magnitude/sum predicates).
    #[arg(long = "resample-trials", default_value_t = predicates::DEFAULT_RESAMPLE_TRIALS)]
    pub(crate) resample_trials: usize,
    /// Deterministic seed (decimal or 0x-hex) for every null and the self-test.
    #[arg(long, default_value_t = predicates::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive controls + matched non-satisfying nulls (both null
    /// shapes) and print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
