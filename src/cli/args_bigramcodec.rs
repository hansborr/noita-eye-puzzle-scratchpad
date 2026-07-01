//! Argument struct for the `bigramcodec` subcommand.

use clap::{Args, ValueEnum};
use noita_eye_puzzle::attack::bigramcodec::{self, StreamKind};

use super::shared::parse_seed;

/// CLI value for selecting one token stream family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum BigramStreamArg {
    /// Run all token streams.
    All,
    /// Non-overlapping consecutive digit pairs.
    #[value(name = "digit-pairs")]
    DigitPairs,
    /// Overlapping directed edges.
    Edges,
    /// Non-overlapping run-length magnitude pairs.
    #[value(name = "mag-pairs")]
    MagPairs,
}

impl BigramStreamArg {
    pub(crate) fn to_streams(self) -> Vec<StreamKind> {
        match self {
            Self::All => bigramcodec::all_streams().to_vec(),
            Self::DigitPairs => vec![StreamKind::DigitPairs],
            Self::Edges => vec![StreamKind::Edges],
            Self::MagPairs => vec![StreamKind::MagPairs],
        }
    }
}

/// `bigramcodec`: score simple base-walk tokenizations with a bigram language
/// model, then report both the order-0 shuffle null and the order-1 Markov
/// confound-control null. A candidate text is a hypothesis, never a decode.
#[derive(Debug, Args)]
pub(crate) struct BigramcodecArgs {
    /// Base digit sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order. The walk base is its length; defaults to
    /// the five orientation digits when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Token stream to run. Repeat the flag to run multiple streams; omitted or
    /// `all` runs every stream.
    #[arg(long = "stream", value_enum)]
    pub(crate) streams: Vec<BigramStreamArg>,
    /// Matched-null trials per stream/language/null family.
    #[arg(
        long = "null-trials",
        default_value_t = bigramcodec::DEFAULT_NULL_TRIALS
    )]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts.
    #[arg(long, default_value_t = bigramcodec::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Substitution-search proposals per restart.
    #[arg(long, default_value_t = bigramcodec::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Deterministic seed (decimal or 0x-hex) for the search and every null.
    #[arg(long, default_value_t = bigramcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive control plus real-`one` negative control.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
