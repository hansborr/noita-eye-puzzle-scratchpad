//! Argument struct for the `gak-swap-recover` known-plaintext recovery command.

use clap::{Args, ValueEnum};
use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    DEFAULT_SWAP_RECOVERY_SEED, LYMM_DEFAULT_N, LYMM_DEFAULT_PT_ALPHABET,
};

use super::shared::parse_seed;

/// `gak-swap-recover`: recover Lymm top-swap deck-cipher mappings from known
/// plaintext/ciphertext pairs. It emits a candidate unless exact re-encryption
/// verifies the recovered mapping.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakSwapRecoverArgs {
    /// Labeled known-plaintext file.
    #[arg(long = "plaintext-file")]
    pub(crate) plaintext_file: Option<std::path::PathBuf>,
    /// Labeled ciphertext file.
    #[arg(long = "ciphertext-file")]
    pub(crate) ciphertext_file: Option<std::path::PathBuf>,
    /// Input pair format.
    #[arg(long = "pair-format", value_enum, default_value_t = GakSwapPairFormat::Labels)]
    pub(crate) pair_format: GakSwapPairFormat,
    /// Plaintext alphabet, in order.
    #[arg(long = "pt-alphabet", default_value = LYMM_DEFAULT_PT_ALPHABET)]
    pub(crate) pt_alphabet: String,
    /// Ciphertext alphabet, in order. Defaults to Lymm's ASCII chr(33+i) alphabet.
    #[arg(long = "ct-alphabet")]
    pub(crate) ct_alphabet: Option<String>,
    /// Deck size.
    #[arg(long = "n", default_value_t = LYMM_DEFAULT_N)]
    pub(crate) n: usize,
    /// Public base permutation, currently `affine:shift=<k>,decimation=<d>`.
    #[arg(
        long = "base-permutation",
        default_value = "affine:shift=26,decimation=3",
        conflicts_with = "base_file"
    )]
    pub(crate) base_permutation: String,
    /// File containing an explicit base permutation as comma/whitespace integers.
    #[arg(long = "base-file", conflicts_with = "base_permutation")]
    pub(crate) base_file: Option<std::path::PathBuf>,
    /// Exact top-swap count hint. Equivalent to `--max-swaps` for Task-02.
    #[arg(long = "num-swaps", conflicts_with = "max_swaps")]
    pub(crate) num_swaps: Option<usize>,
    /// Maximum top-swap budget.
    #[arg(long = "max-swaps", conflicts_with = "num_swaps")]
    pub(crate) max_swaps: Option<usize>,
    /// Reserved Task-03 beam fallback knob.
    #[arg(long = "beam")]
    pub(crate) beam: Option<usize>,
    /// Residual candidate-model cap.
    #[arg(long = "max-nodes")]
    pub(crate) max_nodes: Option<usize>,
    /// Residual wall-clock cap in seconds.
    #[arg(long = "time-budget")]
    pub(crate) time_budget_secs: Option<u64>,
    /// Initial deck state: `identity` or comma/whitespace integers.
    #[arg(long = "initial-state")]
    pub(crate) initial_state: Option<String>,
    /// Run the planted positive controls and matched nulls before any recovery.
    #[arg(long = "run-controls")]
    pub(crate) run_controls: bool,
    /// Deterministic seed for controls.
    #[arg(long, default_value_t = DEFAULT_SWAP_RECOVERY_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Output format.
    #[arg(long = "output", value_enum, default_value_t = GakSwapOutput::Text)]
    pub(crate) output: GakSwapOutput,
    /// Reserved Task-03 compose-direction knob. Only `left` is supported here.
    #[arg(long = "compose-direction")]
    pub(crate) compose_direction: Option<String>,
    /// Reserved Task-03 emit-index knob. Only `0` is supported here.
    #[arg(long = "emit-index")]
    pub(crate) emit_index: Option<usize>,
    /// Reserved Task-03 generator-set knob. Only `top-swaps` is supported here.
    #[arg(long = "generator-set")]
    pub(crate) generator_set: Option<String>,
    /// Reserved Task-03 swap-budget inference knob.
    #[arg(long = "infer-swaps")]
    pub(crate) infer_swaps: bool,
}

/// Known-plaintext pair file layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GakSwapPairFormat {
    /// Lymm vendored format: plaintext rows `label: TEXT`, ciphertext label line
    /// followed by the ciphertext line.
    Labels,
    /// Split plaintext and ciphertext files on blank-line message boundaries.
    #[value(name = "blank-lines")]
    BlankLines,
    /// Reserved for Task-03 shareability; not implemented in Task-02.
    Jsonl,
}

/// CLI output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GakSwapOutput {
    /// Human-readable report.
    Text,
    /// Compact machine-readable report.
    Json,
}
