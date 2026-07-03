//! Argument struct for the `pairclass` subcommand (pair-class decipherment).

use clap::{Args, ValueEnum};
use noita_eye_puzzle::attack::pairclass;

use super::shared::parse_seed;

/// Search order for the pairclass solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PairclassSearchOrder {
    /// Existing left-to-right beam reproduction.
    #[value(name = "left-to-right")]
    LeftToRight,
    /// Anchor-seeded two-phase search.
    #[value(name = "anchor-seed")]
    AnchorSeed,
}

/// Phase-1 anchor harvest strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PairclassHarvestMode {
    /// Existing word-LM score-beam harvest.
    #[value(name = "beam")]
    Beam,
    /// LM-free hard-constraint window enumeration.
    #[value(name = "enumerate")]
    Enumerate,
}

/// Structured-coloring family profile for Avenue A.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PairclassColoringFamily {
    /// Curated Avenue-A deterministic family.
    #[value(name = "core")]
    Core,
    /// Tiny toy family for fast validation and debugging.
    #[value(name = "toy")]
    Toy,
}

/// `pairclass`: pair-class decipherment for `±1`-walk carriers with a
/// two-symbols-per-letter codec (the practice-puzzle-`two` rotor-carrier
/// model). Derives the residue walk's direction-bit pair tokens (a public
/// 4-class image of the plaintext), locates exact repeated spans as tie
/// anchors, and runs a memory-bounded dictionary beam solver in which the
/// coloring is induced incrementally and tied positions are hard letter
/// equalities. Planted controls measure the search's power at length before
/// any real-stream result is trusted; the matched order-1 Markov null gates
/// the real score. Emits candidates, never decodes. With no input flags it
/// runs the embedded practice puzzle `two`.
#[derive(Debug, Args)]
pub(crate) struct PairclassArgs {
    /// Read the ciphertext stream from this file instead of embedded `two`.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext stream from stdin instead of embedded `two`.
    #[arg(long = "stdin", conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order; defaults to `two`'s `A..L`.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Residue-walk modulus (`r = value mod modulus`); `two`'s rotor is 3.
    #[arg(long, default_value_t = pairclass::TWO_MODULUS)]
    pub(crate) modulus: usize,
    /// Pair-token phase (`0` or `1`): which stagger convention to read.
    #[arg(long, default_value_t = 0)]
    pub(crate) phase: usize,
    /// Read the direction-bit stream reversed (the other end-convention).
    #[arg(long = "reversed")]
    pub(crate) reversed: bool,
    /// Word list (one `word` or `word count` per line) for the solver's LM.
    /// Required for a real solve; the embedded run and self-test use a small
    /// built-in lexicon.
    #[arg(long = "wordlist")]
    pub(crate) wordlist: Option<std::path::PathBuf>,
    /// Keep only the top-N words by frequency when building the lexicon.
    #[arg(long = "vocab-cap", default_value_t = 20_000)]
    pub(crate) vocab_cap: usize,
    /// Beam width (kept states per position) — the memory knob.
    #[arg(long, default_value_t = 20_000)]
    pub(crate) beam: usize,
    /// Maximum out-of-vocabulary (gap) segments allowed in a decode.
    #[arg(long = "max-gaps", default_value_t = 2)]
    pub(crate) max_gaps: u8,
    /// Maximum length of one gap segment.
    #[arg(long = "max-gap-len", default_value_t = 8)]
    pub(crate) max_gap_len: u8,
    /// Per-letter score penalty inside a gap segment.
    #[arg(long = "gap-penalty", default_value_t = 3.6)]
    pub(crate) gap_penalty: f32,
    /// Number of ranked candidate decodes to print.
    #[arg(long, default_value_t = 5)]
    pub(crate) top: usize,
    /// Enumerate deterministic structured colorings and oracle-decode each.
    #[arg(long = "coloring-family")]
    pub(crate) coloring_family: Option<PairclassColoringFamily>,
    /// Extra structured relabel decodes after one best relabel per base.
    #[arg(long = "structured-max-decodes", default_value_t = 384)]
    pub(crate) structured_max_decodes: usize,
    /// Marginal L1 threshold for relabel-collapse provenance.
    #[arg(long = "structured-marginal-l1", default_value_t = 0.16)]
    pub(crate) structured_marginal_l1: f64,
    /// Required score margin over random/null baselines for a survivor.
    #[arg(long = "structured-score-margin", default_value_t = 0.0)]
    pub(crate) structured_score_margin: f32,
    /// Use the anchor-seeded two-phase search order instead of left-to-right.
    #[arg(
        long = "anchor-seed",
        num_args = 0..=1,
        default_missing_value = "anchor-seed",
        default_value = "left-to-right"
    )]
    pub(crate) search_order: PairclassSearchOrder,
    /// Phase-1 phrase-harvest beam width for `--anchor-seed`.
    #[arg(long = "phrase-beam", default_value_t = 250_000)]
    pub(crate) phrase_beam: usize,
    /// Distinct harvested colorings to seed into the full solve.
    #[arg(long = "phrase-top", default_value_t = 2_000)]
    pub(crate) phrase_top: usize,
    /// Phase-1 anchor harvest strategy.
    #[arg(long = "harvest-mode", default_value = "beam")]
    pub(crate) harvest_mode: PairclassHarvestMode,
    /// Run only Phase-1 planted harvest retention; never score the real stream.
    #[arg(long = "harvest-only", action = clap::ArgAction::SetTrue)]
    pub(crate) harvest_only: Option<bool>,
    /// Phase-1 maximum out-of-vocabulary gap segments.
    #[arg(long = "phrase-max-gaps", default_value_t = 6)]
    pub(crate) phrase_max_gaps: u8,
    /// Phase-1 maximum length of one gap segment.
    #[arg(long = "phrase-max-gap-len", default_value_t = 8)]
    pub(crate) phrase_max_gap_len: u8,
    /// Phase-1 per-letter score penalty inside a gap segment.
    #[arg(long = "phrase-gap-penalty", default_value_t = 3.6)]
    pub(crate) phrase_gap_penalty: f32,
    /// Refuse to run when the estimated peak memory exceeds this cap (MiB).
    #[arg(long = "max-mem-mib", default_value_t = 2048)]
    pub(crate) max_mem_mib: usize,
    /// Minimum repeated-span length (bits) to treat as a tie anchor. `0`
    /// disables ties.
    #[arg(long = "min-anchor-len", default_value_t = 34)]
    pub(crate) min_anchor_len: usize,
    /// Controls-first power measurement: draw plants from this English text
    /// file (letters only), run the identical search with truth tracking, and
    /// report per-plant recovery before any real-stream result is trusted.
    #[arg(long = "plant-text-file")]
    pub(crate) plant_text_file: Option<std::path::PathBuf>,
    /// Number of planted controls to run (needs `--plant-text-file`).
    #[arg(long = "plants", default_value_t = 6)]
    pub(crate) plants: usize,
    /// Mean plant letter-recovery bar the controls must clear before the real
    /// stream is scored.
    #[arg(long = "plant-bar", default_value_t = 0.4)]
    pub(crate) plant_bar: f64,
    /// Matched order-1 Markov null resamples to gate the real-stream score.
    #[arg(long = "null-trials", default_value_t = 0)]
    pub(crate) null_trials: usize,
    /// Deterministic seed (decimal or 0x-hex) for plants and nulls.
    #[arg(long, default_value_t = pairclass::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the planted positive control, matched null, forced-prune check,
    /// walk gate, and embedded-`two` regression; print PASS/FAIL.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
