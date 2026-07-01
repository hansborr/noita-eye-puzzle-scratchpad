//! Argument struct for the `mdlcodec` subcommand.

use clap::Args;
use noita_eye_puzzle::attack::mdlcodec;

use super::shared::parse_seed;

/// `mdlcodec`: crib-synchronous MDL-like affine running-key search for practice
/// puzzle `one`'s run-length carrier. It emits a candidate, never a decode.
#[derive(Debug, Args)]
pub(crate) struct MdlcodecArgs {
    /// Read an English quadgram training source from this file. Non-letters are
    /// stripped before training; omit to use the built-in English model.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read an English quadgram training source from stdin.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Read a target digit sequence from this file instead of embedded `one`.
    #[arg(long = "target-file", conflicts_with = "target_stdin")]
    pub(crate) target_file: Option<std::path::PathBuf>,
    /// Read a target digit sequence from stdin instead of embedded `one`.
    #[arg(long = "target-stdin", conflicts_with_all = ["target_file", "stdin"])]
    pub(crate) target_stdin: bool,
    /// Target cipher alphabet chars, in order (e.g. `01234`); defaults to the five
    /// orientation digits for embedded `one` and target overrides.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Ring sizes to search, as `10..=26`, `10..26`, or comma-separated integers.
    #[arg(long = "ring-sizes", default_value = "10..=26")]
    pub(crate) ring_sizes: String,
    /// Inclusive coefficient bound for raw `a,b` before canonicalization.
    #[arg(long = "coeff-max", default_value_t = mdlcodec::DEFAULT_COEFF_MAX)]
    pub(crate) coeff_max: usize,
    /// Near-tie band around the best MDL-like value, in bits.
    #[arg(long = "epsilon-bits", default_value_t = mdlcodec::DEFAULT_EPSILON_BITS)]
    pub(crate) epsilon_bits: f64,
    /// Top MDL rows to print.
    #[arg(long, default_value_t = mdlcodec::DEFAULT_TOP)]
    pub(crate) top: usize,
    /// Post-selection matched-null trials.
    #[arg(long = "null-trials", default_value_t = mdlcodec::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Substitution-search random restarts per evaluated cell.
    #[arg(long, default_value_t = mdlcodec::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Substitution-search proposals per restart.
    #[arg(long, default_value_t = mdlcodec::DEFAULT_ITERS)]
    pub(crate) iters: usize,
    /// Maximum number of census anchors to consider as cribs.
    #[arg(long = "top-k", default_value_t = mdlcodec::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Census matched-null trials used to derive the cribs.
    #[arg(long = "census-null-trials", default_value_t = mdlcodec::DEFAULT_CENSUS_NULL_TRIALS)]
    pub(crate) census_null_trials: usize,
    /// Minimum effective alphabet for an English-feasible affine stream.
    #[arg(
        long = "min-effective-alphabet",
        default_value_t = mdlcodec::DEFAULT_MIN_EFFECTIVE_ALPHABET
    )]
    pub(crate) min_effective_alphabet: usize,
    /// Deterministic seed (decimal or 0x-hex) for census, search, and nulls.
    #[arg(long, default_value_t = mdlcodec::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run planted positive and matched-null controls, then print PASS/FAIL.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
