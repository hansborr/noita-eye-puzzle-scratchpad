//! Argument struct for the `shadowfinish` residual-finish instrument.

use clap::Args;
use noita_eye_puzzle::analysis::shadow_finish;

use super::shared::parse_seed;

/// `shadowfinish`: crib-free finish over `shadowsearch --output` q classes.
#[derive(Debug, Args)]
pub(crate) struct ShadowfinishArgs {
    /// Symbol sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the ciphertext sequence from this file.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// `shadowsearch --output` JSON artifact.
    #[arg(long = "artifact")]
    pub(crate) artifact: Option<std::path::PathBuf>,
    /// Wordlist file (`word` or `word count` per line) for word-DP scoring.
    #[arg(long = "wordlist", conflicts_with = "word_corpus_file")]
    pub(crate) wordlist: Option<std::path::PathBuf>,
    /// Derive a `word count` list from this committed text corpus.
    #[arg(long = "word-corpus-file", conflicts_with = "wordlist")]
    pub(crate) word_corpus_file: Option<std::path::PathBuf>,
    /// Keep only the top-N words by frequency for word-DP scoring.
    #[arg(long = "vocab-cap", default_value_t = shadow_finish::DEFAULT_VOCAB_CAP)]
    pub(crate) vocab_cap: usize,
    /// Additional charset table file(s), each line `name=characters`.
    #[arg(long = "table-file")]
    pub(crate) table_files: Vec<std::path::PathBuf>,
    /// Bounded Tier-A survivors retained per canonical class.
    #[arg(long = "top-k-per-class", default_value_t = shadow_finish::DEFAULT_TOP_K_PER_CLASS)]
    pub(crate) top_k_per_class: usize,
    /// Matched-null decoy trials.
    #[arg(long = "null-trials", default_value_t = shadow_finish::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Candidate threshold on add-one empirical p-value.
    #[arg(long = "alpha", default_value_t = shadow_finish::DEFAULT_ALPHA)]
    pub(crate) alpha: f64,
    /// Refuse configurations estimated to exceed this memory cap.
    #[arg(long = "max-mem-mib", default_value_t = shadow_finish::DEFAULT_MAX_MEM_MIB)]
    pub(crate) max_mem_mib: usize,
    /// Also enumerate phase-1 q pairing. Exact full-stream round-trip remains
    /// phase-0 only; dropped q-symbols are reported.
    #[arg(long = "include-phase1")]
    pub(crate) include_phase1: bool,
    /// Write machine-readable report JSON. The self-test must pass first.
    #[arg(long = "output")]
    pub(crate) output: Option<std::path::PathBuf>,
    /// Directory for hypothesis records when a candidate emerges.
    #[arg(
        long = "candidates-dir",
        default_value = "research/gak-threads/candidates"
    )]
    pub(crate) candidates_dir: std::path::PathBuf,
    /// Stable label for candidate record filenames.
    #[arg(long = "label", default_value = "two-shadowfinish")]
    pub(crate) label: String,
    /// Deterministic seed (decimal or 0x-hex) for controls and matched nulls.
    #[arg(long, default_value_t = shadow_finish::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run controls and exit.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}

impl From<&ShadowfinishArgs> for shadow_finish::ShadowFinishConfig {
    fn from(args: &ShadowfinishArgs) -> Self {
        Self {
            top_k_per_class: args.top_k_per_class,
            null_trials: args.null_trials,
            seed: args.seed,
            vocab_cap: args.vocab_cap,
            max_mem_mib: args.max_mem_mib,
            alpha: args.alpha,
            include_phase1: args.include_phase1,
        }
    }
}
