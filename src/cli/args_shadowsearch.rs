//! Argument struct for the `shadowsearch` closure-shadow key-search instrument.

use clap::Args;
use noita_eye_puzzle::analysis::shadow_search;

use super::shared::parse_seed;

/// `shadowsearch`: hidden-state key search over an `isomap`-derived closure
/// group. Emits quotient candidates under the closure shadow, never decodes.
#[derive(Debug, Args)]
pub(crate) struct ShadowsearchArgs {
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
    /// Minimum raw equality-pattern span length considered by the `isomap` basis.
    #[arg(long = "min-span-len", default_value_t = shadow_search::DEFAULT_MIN_SPAN_LEN)]
    pub(crate) min_span_len: usize,
    /// Positions trimmed from each end before extracting closure column maps.
    #[arg(long = "map-trim", default_value_t = shadow_search::DEFAULT_TRIM)]
    pub(crate) map_trim: usize,
    /// Positions trimmed from each end before applying hard anchors.
    #[arg(long = "hard-anchor-trim", default_value_t = shadow_search::DEFAULT_TRIM)]
    pub(crate) hard_anchor_trim: usize,
    /// Minimum trimmed hard-anchor length.
    #[arg(long = "hard-min-len", default_value_t = shadow_search::DEFAULT_HARD_MIN_LEN)]
    pub(crate) hard_min_len: usize,
    /// Maximum number of raw pattern-isomorph span pairs kept by the `isomap` basis.
    #[arg(long = "top-k", default_value_t = shadow_search::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Number of matched-null (order-1 Markov resample) trials.
    #[arg(long = "null-trials", default_value_t = shadow_search::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Maximum generated group size before closure aborts.
    #[arg(long = "closure-cap", default_value_t = shadow_search::DEFAULT_CLOSURE_CAP)]
    pub(crate) closure_cap: usize,
    /// Minimum raw literal-repeat length considered as a soft anchor.
    #[arg(long = "soft-min-len", default_value_t = shadow_search::DEFAULT_SOFT_MIN_LEN)]
    pub(crate) soft_min_len: usize,
    /// Maximum raw literal-repeat length considered as a soft anchor.
    #[arg(long = "soft-max-len", default_value_t = shadow_search::DEFAULT_SOFT_MAX_LEN)]
    pub(crate) soft_max_len: usize,
    /// Positions trimmed from each end before applying soft anchors.
    #[arg(long = "soft-trim", default_value_t = shadow_search::DEFAULT_SOFT_TRIM)]
    pub(crate) soft_trim: usize,
    /// Maximum top canonical classes retained in the report and artifact.
    #[arg(long = "class-report-limit", default_value_t = shadow_search::DEFAULT_CLASS_REPORT_LIMIT)]
    pub(crate) class_report_limit: usize,
    /// Write machine-readable top canonical classes and representative keys.
    /// The in-process self-test must pass before this file is written.
    #[arg(long = "output")]
    pub(crate) output: Option<std::path::PathBuf>,
    /// Deterministic seed (decimal or 0x-hex) for the matched null and controls.
    #[arg(long, default_value_t = shadow_search::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the in-process controls and print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}

impl From<&ShadowsearchArgs> for shadow_search::ShadowSearchConfig {
    fn from(args: &ShadowsearchArgs) -> Self {
        Self {
            min_span_len: args.min_span_len,
            map_trim: args.map_trim,
            hard_anchor_trim: args.hard_anchor_trim,
            hard_min_len: args.hard_min_len,
            top_k: args.top_k,
            null_trials: args.null_trials,
            closure_cap: args.closure_cap,
            seed: args.seed,
            soft_min_len: args.soft_min_len,
            soft_max_len: args.soft_max_len,
            soft_trim: args.soft_trim,
            class_report_limit: args.class_report_limit,
        }
    }
}
