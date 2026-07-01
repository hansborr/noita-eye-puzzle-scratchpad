//! Crib-synchronous MDL-like affine running-key codec search.
//!
//! This is the library half of the `mdlcodec` instrument. It searches the bounded
//! affine family `idx[i] = (a*S_i + b*i) mod R` on the direction-blind
//! run-length carrier `M`, fits the best injective substitution with
//! [`crate::attack::rlcodec::substitution_search`], and compares the selected
//! real winner against a post-selection crib-pinned magnitude null. The output is
//! a candidate and a family-bound verdict, never a recovered plaintext.

use std::fmt;

use crate::attack::cribfit::{CribGeometry, derive_crib_geometry};
use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{CensusReport, RlError, derive_magnitudes, one_practice_digits};
use crate::core::glyph::Glyph;
use crate::nulls::null::mix_seed;

mod eval;
mod grid;
mod selftest;

#[cfg(test)]
mod tests;

pub use grid::AffineCell;
pub use selftest::{MdlSelfTest, mdlcodec_self_test};

/// Default deterministic seed for `mdlcodec`.
pub const DEFAULT_SEED: u64 = 0x6d64_6c63_6f64_0001;
/// Default inclusive ring range.
pub const DEFAULT_RING_MIN: usize = 10;
/// Default inclusive ring range.
pub const DEFAULT_RING_MAX: usize = 26;
/// Default bound on the searched coefficients `a,b`.
pub const DEFAULT_COEFF_MAX: usize = 8;
/// Default near-tie band around the best MDL-like objective.
pub const DEFAULT_EPSILON_BITS: f64 = 2.0;
/// Default top rows printed by the CLI.
pub const DEFAULT_TOP: usize = 10;
/// Default post-selection null trials.
pub const DEFAULT_NULL_TRIALS: usize = 24;
/// Default substitution-search restarts per cell.
pub const DEFAULT_RESTARTS: usize = 6;
/// Default substitution-search proposals per restart.
pub const DEFAULT_ITERS: usize = 900;
/// Default census anchors used as cribs.
pub const DEFAULT_TOP_K: usize = 8;
/// Default census null trials.
pub const DEFAULT_CENSUS_NULL_TRIALS: usize = 120;
/// Default minimum effective alphabet before a cell is treated as English-feasible.
pub const DEFAULT_MIN_EFFECTIVE_ALPHABET: usize = 8;
/// Percentile rule for the post-selection null survivor flag.
pub const SURVIVOR_PERCENTILE: f64 = 0.05;

const CENSUS_TAG: u64 = 0x6d64_6c63_c411_0001;

/// Configuration for one `mdlcodec` analysis.
#[derive(Clone, Debug, PartialEq)]
pub struct MdlCfg {
    /// Ring sizes `R` to enumerate.
    pub ring_sizes: Vec<usize>,
    /// Inclusive upper bound on raw coefficients `a,b` before canonicalization.
    pub coeff_max: usize,
    /// Near-tie band, in bits, used for the under-determination count.
    pub epsilon_bits: f64,
    /// Number of real rows callers usually print.
    pub top: usize,
    /// Post-selection matched-null trials.
    pub null_trials: usize,
    /// Substitution-search restarts per evaluated cell.
    pub restarts: usize,
    /// Substitution-search proposals per restart.
    pub iters: usize,
    /// Maximum number of census anchors to derive as cribs.
    pub top_k: usize,
    /// Census matched-null trials.
    pub census_null_trials: usize,
    /// Deterministic seed for census, search, and nulls.
    pub seed: u64,
    /// Minimum effective alphabet `k` for an English-feasible cell.
    pub min_effective_alphabet: usize,
}

impl MdlCfg {
    /// Returns the default CLI/report configuration.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            ring_sizes: (DEFAULT_RING_MIN..=DEFAULT_RING_MAX).collect(),
            coeff_max: DEFAULT_COEFF_MAX,
            epsilon_bits: DEFAULT_EPSILON_BITS,
            top: DEFAULT_TOP,
            null_trials: DEFAULT_NULL_TRIALS,
            restarts: DEFAULT_RESTARTS,
            iters: DEFAULT_ITERS,
            top_k: DEFAULT_TOP_K,
            census_null_trials: DEFAULT_CENSUS_NULL_TRIALS,
            seed: DEFAULT_SEED,
            min_effective_alphabet: DEFAULT_MIN_EFFECTIVE_ALPHABET,
        }
    }
}

/// Summary of the derived run-length carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdlCarrierSummary {
    /// Number of input digits.
    pub n_digits: usize,
    /// Walk base.
    pub base: usize,
    /// Number of `±1` move bits.
    pub n_bits: usize,
    /// Number of run-length magnitudes.
    pub n_magnitudes: usize,
    /// Sum of the magnitudes.
    pub sum: usize,
    /// Sorted `(magnitude, count)` distribution.
    pub distribution: Vec<(usize, usize)>,
}

/// Cell-count coverage through the affine search filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellCoverage {
    /// Canonical `(R,a,b)` cells enumerated before crib filtering.
    pub searched: usize,
    /// Canonical cells satisfying every crib modular check.
    pub eligible: usize,
    /// Eligible cells with an effective alphabet that can plausibly host English.
    pub feasible: usize,
    /// Feasible cells left after deduping identical densified index streams.
    pub deduped: usize,
}

/// Post-selection null summary for best MDL-like values.
#[derive(Clone, Debug, PartialEq)]
pub struct MdlNullSummary {
    /// Requested null draws.
    pub trials_requested: usize,
    /// Null draws that produced at least one evaluated cell.
    pub trials_evaluated: usize,
    /// Mean best-null MDL-like value, in bits.
    pub mean_mdl_bits: f64,
    /// Population standard deviation of best-null MDL-like values.
    pub std_mdl_bits: f64,
    /// Fifth percentile of best-null MDL-like values (lower is more English).
    pub p05_mdl_bits: f64,
    /// Minimum best-null MDL-like value.
    pub min_mdl_bits: f64,
    /// Maximum best-null MDL-like value.
    pub max_mdl_bits: f64,
}

/// One evaluated affine cell in the real top table.
#[derive(Clone, Debug, PartialEq)]
pub struct MdlCellReport {
    /// Canonical affine cell.
    pub cell: AffineCell,
    /// Effective alphabet `k = #distinct(idx)` after densifying the visited residues.
    pub effective_alphabet: usize,
    /// Codec description charge, in bits.
    pub l_codec_bits: f64,
    /// Text description charge `-best_sum / ln(2)`, in bits.
    pub l_text_bits: f64,
    /// MDL-like objective `L_codec + L_text`, in bits.
    pub mdl_bits: f64,
    /// `mdl_bits - mean(null best MDL)`, in bits; negative is better than null.
    pub delta_mdl_bits: f64,
    /// z-score against the post-selection best-null distribution; negative is better.
    pub z: f64,
    /// Whether this cell beats the stated fifth-percentile post-selection null rule.
    pub survivor: bool,
    /// Best rendered substitution candidate for this cell.
    pub candidate: String,
}

/// Headline family-bound verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdlVerdict {
    /// No affine cell survived the filters and substitution search.
    NoCandidate,
    /// A candidate beat the post-selection null and has no near tie in the band.
    SelectedCandidate,
    /// The family is exhausted or under-determined at this carrier length.
    UnderDetermined,
}

impl MdlVerdict {
    /// Human-readable verdict sentence.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::NoCandidate => {
                "VERDICT: no crib-consistent English-feasible affine running-key candidate was evaluated."
            }
            Self::SelectedCandidate => {
                "VERDICT: one MDL-selected affine candidate beat the post-selection null and stood clear of the near-tie band; it remains a candidate, not a decode."
            }
            Self::UnderDetermined => {
                "VERDICT: this enumerated affine running-key family is exhausted or under-determined at 33 bytes."
            }
        }
    }
}

/// Full `mdlcodec` analysis report.
#[derive(Clone, Debug, PartialEq)]
pub struct MdlReport {
    /// Carrier summary.
    pub carrier: MdlCarrierSummary,
    /// Census-derived crib geometry.
    pub geometry: CribGeometry,
    /// Census calibration of the carrier repeats.
    pub census: CensusReport,
    /// Search coverage counts.
    pub coverage: CellCoverage,
    /// Post-selection best-null summary.
    pub null: MdlNullSummary,
    /// Top real cells by MDL-like objective.
    pub top_cells: Vec<MdlCellReport>,
    /// Global real winner.
    pub winner: MdlCellReport,
    /// Count of real cells within `cfg.epsilon_bits` of the best real MDL.
    pub underdetermination_count: usize,
    /// Width of the populated near-tie band, in bits.
    pub underdetermination_spread_bits: f64,
    /// Headline family-bound verdict.
    pub verdict: MdlVerdict,
}

/// Error type for `mdlcodec`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MdlError {
    /// Shared carrier/census/search machinery failed.
    Rl(RlError),
    /// No ring sizes were supplied after validation.
    EmptyRingGrid,
    /// A searched ring was outside the supported `2..=26` range.
    InvalidRingSize {
        /// Rejected ring size.
        ring: usize,
    },
    /// The near-tie epsilon must be finite and non-negative.
    InvalidEpsilon {
        /// Rejected epsilon value.
        epsilon_bits: f64,
    },
    /// The post-selection null needs at least one trial.
    InvalidNullTrials,
    /// No real affine cell survived filtering and search.
    NoEvaluatedCells,
    /// No null draw produced an evaluated affine cell.
    NoEvaluatedNulls,
}

impl From<RlError> for MdlError {
    fn from(error: RlError) -> Self {
        Self::Rl(error)
    }
}

impl fmt::Display for MdlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Rl(error) => write!(f, "{error}"),
            Self::EmptyRingGrid => write!(f, "ring grid is empty"),
            Self::InvalidRingSize { ring } => {
                write!(f, "ring size {ring} is invalid; mdlcodec supports 2..=26")
            }
            Self::InvalidEpsilon { epsilon_bits } => {
                write!(
                    f,
                    "epsilon bits must be finite and non-negative, got {epsilon_bits}"
                )
            }
            Self::InvalidNullTrials => {
                write!(f, "post-selection null requires at least one trial")
            }
            Self::NoEvaluatedCells => {
                write!(
                    f,
                    "no crib-consistent English-feasible affine cells were evaluated"
                )
            }
            Self::NoEvaluatedNulls => {
                write!(f, "no post-selection null draw produced an evaluated cell")
            }
        }
    }
}

impl std::error::Error for MdlError {}

/// Runs `mdlcodec` with the bundled English quadgram model.
///
/// # Errors
/// Returns [`MdlError`] if the target is not a clean `±1` walk, the configuration
/// is invalid, or a shared census/search/null step fails.
pub fn analyze_mdl(digits: &[Glyph], base: usize, cfg: &MdlCfg) -> Result<MdlReport, MdlError> {
    let model = QuadgramModel::english().map_err(RlError::from)?;
    analyze_mdl_with_model(digits, base, cfg, &model)
}

/// Runs `mdlcodec` with a caller-supplied quadgram model.
///
/// # Errors
/// Returns [`MdlError`] if the target is not a clean `±1` walk, the configuration
/// is invalid, or a shared census/search/null step fails.
pub fn analyze_mdl_with_model(
    digits: &[Glyph],
    base: usize,
    cfg: &MdlCfg,
    model: &QuadgramModel,
) -> Result<MdlReport, MdlError> {
    validate_cfg(cfg)?;
    let derivation = derive_magnitudes(digits, base)?;
    eval::analyze_magnitudes(
        carrier_summary(
            digits.len(),
            base,
            derivation.n_bits,
            &derivation.magnitudes,
        ),
        &derivation.magnitudes,
        cfg,
        model,
    )
}

/// Runs `mdlcodec` on the embedded practice puzzle `one`.
///
/// # Errors
/// Returns [`MdlError`] if the embedded target or analysis fails.
pub fn analyze_embedded_one(cfg: &MdlCfg) -> Result<MdlReport, MdlError> {
    let digits = one_practice_digits()?;
    analyze_mdl(&digits, 5, cfg)
}

fn validate_cfg(cfg: &MdlCfg) -> Result<(), MdlError> {
    if cfg.ring_sizes.is_empty() {
        return Err(MdlError::EmptyRingGrid);
    }
    if !cfg.epsilon_bits.is_finite() || cfg.epsilon_bits < 0.0 {
        return Err(MdlError::InvalidEpsilon {
            epsilon_bits: cfg.epsilon_bits,
        });
    }
    if cfg.null_trials == 0 {
        return Err(MdlError::InvalidNullTrials);
    }
    for &ring in &cfg.ring_sizes {
        if !(2..=26).contains(&ring) {
            return Err(MdlError::InvalidRingSize { ring });
        }
    }
    Ok(())
}

fn carrier_summary(
    n_digits: usize,
    base: usize,
    n_bits: usize,
    magnitudes: &[usize],
) -> MdlCarrierSummary {
    let mut counts = std::collections::BTreeMap::new();
    for &magnitude in magnitudes {
        *counts.entry(magnitude).or_insert(0usize) += 1;
    }
    MdlCarrierSummary {
        n_digits,
        base,
        n_bits,
        n_magnitudes: magnitudes.len(),
        sum: magnitudes.iter().sum(),
        distribution: counts.into_iter().collect(),
    }
}

fn derive_geometry(
    magnitudes: &[usize],
    cfg: &MdlCfg,
) -> Result<(CribGeometry, CensusReport), MdlError> {
    Ok(derive_crib_geometry(
        magnitudes,
        cfg.top_k,
        cfg.census_null_trials,
        mix_seed(cfg.seed, CENSUS_TAG),
    )?)
}
