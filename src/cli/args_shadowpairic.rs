//! Argument struct for the `shadowpairic` phase-0 pair-IC ranker.

use clap::Args;
use noita_eye_puzzle::analysis::shadow_finish;

use super::shared::parse_seed;

/// `shadowpairic`: phase-0 pair-value IC ranking over shadow-finish q classes.
#[derive(Debug, Args)]
pub(crate) struct ShadowpairicArgs {
    /// `shadowsearch --output` JSON artifact.
    #[arg(long = "artifact")]
    pub(crate) artifact: Option<std::path::PathBuf>,
    /// Target monogram IC for ranking; English is approximately 0.0667.
    #[arg(long = "target-ic", default_value_t = shadow_finish::ENGLISH_MONOGRAM_IC)]
    pub(crate) target_ic: f64,
    /// Deterministic seed for the invariance and matched-flat-null self-test.
    #[arg(long, default_value_t = shadow_finish::DEFAULT_PAIR_IC_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run only the invariance and matched-flat-null self-test.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
