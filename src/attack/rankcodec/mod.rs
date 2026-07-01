//! Bounded-order predictive-rank codec analysis for practice puzzle `one`.
//!
//! `rankcodec` reads the direction-blind run-length magnitude carrier `M` as
//! ranks into a deterministic order-`k` English next-letter predictor. This is a
//! codec-with-memory family, so its primary evidence is language-free:
//! feasibility of English ranks within `M`'s `1..=5` range and crib-consistency
//! across `cribfit`'s census-derived repeated windows. The quadgram gate is
//! reported only as a tertiary diagnostic and is explicitly underpowered at
//! `one`'s 135 magnitudes (see `codecpower`).

use std::fmt;

use crate::attack::cribfit::{AnchorPair, CribGeometry, derive_crib_geometry};
use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{
    BatteryCfg, CensusReport, CodecVerdict, PLANT_PLAINTEXT, RlError, derive_magnitudes,
    english_letters, gate_symbol_stream_with_nulls, name_seed_tag, one_practice_digits,
};
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

mod codec;
mod predictor;
mod selftest;

#[cfg(test)]
mod tests;

pub use codec::{rank_decode, rank_encode};
pub use predictor::{LETTERS, RankPredictor};
pub use selftest::{RankPositiveSelfTest, RankSelfTest, rankcodec_self_test};

/// The quadgram language scorer is order 4; decode predictors must stay below it.
pub const QUADGRAM_SCORER_ORDER: usize = 4;
/// Default predictor orders swept by the CLI.
pub const DEFAULT_ORDERS: &[usize] = &[1, 2, 3];
/// Default maximum representable rank, matching practice puzzle `one`'s carrier.
pub const DEFAULT_MAX_MAGNITUDE: usize = 5;
/// Default seed for `rankcodec`.
pub const DEFAULT_SEED: u64 = 0x7261_6e6b_900d_0001;

const CENSUS_TAG: u64 = 0x7261_6e6b_c411_0001;
const NULL_MAG_TAG: u64 = 0x7261_6e6b_0011_0001;

/// Error type for `rankcodec`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RankError {
    /// A shared `rlcodec`/`cribfit` primitive failed.
    Rl(RlError),
    /// The predictor source had no usable `A..Z` letters.
    EmptySource,
    /// `--max-magnitude` was zero.
    InvalidMaxMagnitude {
        /// The rejected maximum magnitude.
        max_magnitude: usize,
    },
    /// A requested predictor order was not strictly below the quadgram scorer's order.
    InvalidOrder {
        /// The rejected predictor order.
        order: usize,
        /// The scorer order it must be below.
        scorer_order: usize,
    },
}

impl From<RlError> for RankError {
    fn from(error: RlError) -> Self {
        Self::Rl(error)
    }
}

impl fmt::Display for RankError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Rl(error) => write!(f, "{error}"),
            Self::EmptySource => write!(f, "predictor source contains no letters"),
            Self::InvalidMaxMagnitude { max_magnitude } => {
                write!(f, "max magnitude must be at least 1, got {max_magnitude}")
            }
            Self::InvalidOrder {
                order,
                scorer_order,
            } => write!(
                f,
                "predictor order {order} is invalid: it must be in 1..{scorer_order} so it stays below the quadgram scorer"
            ),
        }
    }
}

impl std::error::Error for RankError {}

/// Configuration for one `rankcodec` run.
#[derive(Clone, Debug, PartialEq)]
pub struct RankCfg {
    /// English source letters used to train the predictor.
    pub source_letters: Vec<usize>,
    /// Predictor orders to sweep. Every requested order is reported.
    pub orders: Vec<usize>,
    /// Largest rank the target carrier can represent.
    pub max_magnitude: usize,
    /// Shared search/null/census budget.
    pub gate: BatteryCfg,
}

impl RankCfg {
    /// Returns the default configuration for a gate budget.
    #[must_use]
    pub fn defaults(gate: BatteryCfg) -> Self {
        Self {
            source_letters: english_letters(PLANT_PLAINTEXT),
            orders: DEFAULT_ORDERS.to_vec(),
            max_magnitude: DEFAULT_MAX_MAGNITUDE,
            gate,
        }
    }
}

/// Summary of the derived run-length carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankCarrierSummary {
    /// Number of input digits.
    pub n_digits: usize,
    /// Walk base.
    pub base: usize,
    /// Number of `±1` move bits.
    pub n_bits: usize,
    /// Number of run-length magnitudes.
    pub n_magnitudes: usize,
    /// Magnitude distribution as sorted `(magnitude, count)` pairs.
    pub distribution: Vec<(usize, usize)>,
}

/// Positive-control rank coverage for one predictor order.
#[derive(Clone, Debug, PartialEq)]
pub struct FeasibilitySummary {
    /// Number of English-source ranks measured.
    pub total: usize,
    /// Number of ranks within the target maximum magnitude.
    pub within_max: usize,
    /// Fraction of English-source ranks within the target maximum magnitude.
    pub fraction_within_max: f64,
    /// `true` iff every measured English-source rank is representable.
    pub all_within_max: bool,
    /// Histogram of English-source ranks `1..=max_magnitude`.
    pub within_distribution: Vec<(usize, usize)>,
    /// Count of English-source ranks greater than `max_magnitude`.
    pub overflow: usize,
}

/// Crib-consistency status for a rankcodec row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RankCribStatus {
    /// No applicable crib was available.
    Inapplicable,
    /// Every crib locks after the allowed order-`k` transient.
    Consistent,
    /// At least one crib fails to lock after the allowed transient.
    Excluded,
}

impl RankCribStatus {
    /// Returns the cribfit-style display word.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inapplicable => "inapplicable",
            Self::Consistent => "consistent",
            Self::Excluded => "excluded",
        }
    }
}

/// Locked-tail comparison for one repeated carrier window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CribLock {
    /// Repeat length in magnitudes.
    pub length: usize,
    /// First occurrence start.
    pub first: usize,
    /// Second occurrence start.
    pub second: usize,
    /// Allowed predictor transient (`min(k, length)`).
    pub transient: usize,
    /// Tail length required to agree after the transient.
    pub required_tail: usize,
    /// Longest common suffix length of the two decoded windows.
    pub locked_tail: usize,
}

impl CribLock {
    /// `true` iff the two decoded windows agree after the allowed transient.
    #[must_use]
    pub const fn consistent(&self) -> bool {
        self.locked_tail >= self.required_tail
    }
}

/// Crib-consistency result for one order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CribSummary {
    /// Overall cribfit-style status.
    pub status: RankCribStatus,
    /// Per-anchor locked-tail detail.
    pub locks: Vec<CribLock>,
}

/// One order row in the `rankcodec` report.
#[derive(Clone, Debug, PartialEq)]
pub struct RankOrderRow {
    /// Predictor order `k`.
    pub order: usize,
    /// Feasibility on the positive-control English source.
    pub feasibility: FeasibilitySummary,
    /// Crib-consistency on real `M` after decoding.
    pub crib: CribSummary,
    /// Tertiary quadgram gate, underpowered at this carrier length.
    pub gate: CodecVerdict,
    /// Raw order-`k` decoded candidate letters for real `M`.
    pub candidate_text: String,
}

/// Full `rankcodec` report.
#[derive(Clone, Debug, PartialEq)]
pub struct RankReport {
    /// Carrier summary.
    pub carrier: RankCarrierSummary,
    /// Crib geometry reused from `cribfit`.
    pub geometry: CribGeometry,
    /// Census calibration attached to the crib geometry.
    pub census: CensusReport,
    /// Maximum representable rank.
    pub max_magnitude: usize,
    /// Number of predictor-source letters.
    pub source_len: usize,
    /// Per-order rows.
    pub rows: Vec<RankOrderRow>,
}

impl RankReport {
    /// Orders whose crib windows are admissible.
    #[must_use]
    pub fn crib_admissible_orders(&self) -> Vec<usize> {
        self.rows
            .iter()
            .filter(|row| row.crib.status == RankCribStatus::Consistent)
            .map(|row| row.order)
            .collect()
    }

    /// `true` iff at least one swept order represents every source letter within
    /// the target rank range.
    #[must_use]
    pub fn english_representable_in_range(&self) -> bool {
        self.rows.iter().any(|row| row.feasibility.all_within_max)
    }
}

/// Runs `rankcodec` on the provided digit stream.
///
/// # Errors
/// Returns [`RankError`] if the target is not a clean `±1` walk, if predictor
/// training/source configuration is invalid, or if a shared census/gate step
/// fails.
pub fn analyze_rank_codec(
    digits: &[Glyph],
    base: usize,
    cfg: &RankCfg,
) -> Result<RankReport, RankError> {
    let derivation = derive_magnitudes(digits, base)?;
    analyze_magnitudes(
        digits.len(),
        base,
        derivation.n_bits,
        &derivation.magnitudes,
        cfg,
    )
}

/// Runs `rankcodec` on the embedded practice puzzle `one`.
///
/// # Errors
/// Returns [`RankError`] if the embedded target or analysis fails.
pub fn analyze_embedded_one(cfg: &RankCfg) -> Result<RankReport, RankError> {
    let digits = one_practice_digits()?;
    analyze_rank_codec(&digits, DEFAULT_MAX_MAGNITUDE, cfg)
}

fn analyze_magnitudes(
    n_digits: usize,
    base: usize,
    n_bits: usize,
    magnitudes: &[usize],
    cfg: &RankCfg,
) -> Result<RankReport, RankError> {
    validate_cfg(cfg)?;
    let (geometry, census) = derive_crib_geometry(
        magnitudes,
        cfg.gate.top_k,
        cfg.gate.census_null_trials,
        mix_seed(cfg.gate.seed, CENSUS_TAG),
    )?;
    let model = QuadgramModel::english().map_err(RlError::from)?;
    let mut rows = Vec::new();
    for &order in &cfg.orders {
        validate_order(order)?;
        let pred = RankPredictor::train(&cfg.source_letters, order);
        let source_ranks = rank_encode(&pred, &cfg.source_letters);
        let feasibility = feasibility(&source_ranks, cfg.max_magnitude);
        let decoded = rank_decode(&pred, magnitudes);
        let crib = crib_summary(&decoded, &geometry.anchors, order);
        let nulls = matched_null_decodes(
            &pred,
            magnitudes,
            &geometry.anchors,
            cfg.max_magnitude,
            &cfg.gate,
            order,
        )?;
        let name = format!("RankCodec{{k={order}}}");
        let gate = gate_symbol_stream_with_nulls(
            name.clone(),
            &decoded,
            &nulls,
            name_seed_tag(&name),
            &model,
            &cfg.gate,
        )?;
        rows.push(RankOrderRow {
            order,
            feasibility,
            crib,
            gate,
            candidate_text: letters_to_string(&decoded),
        });
    }

    Ok(RankReport {
        carrier: carrier_summary(n_digits, base, n_bits, magnitudes),
        geometry,
        census,
        max_magnitude: cfg.max_magnitude,
        source_len: cfg.source_letters.len(),
        rows,
    })
}

fn validate_cfg(cfg: &RankCfg) -> Result<(), RankError> {
    if cfg.source_letters.is_empty() {
        return Err(RankError::EmptySource);
    }
    if cfg.max_magnitude == 0 {
        return Err(RankError::InvalidMaxMagnitude {
            max_magnitude: cfg.max_magnitude,
        });
    }
    for &order in &cfg.orders {
        validate_order(order)?;
    }
    Ok(())
}

fn validate_order(order: usize) -> Result<(), RankError> {
    if order == 0 || order >= QUADGRAM_SCORER_ORDER {
        return Err(RankError::InvalidOrder {
            order,
            scorer_order: QUADGRAM_SCORER_ORDER,
        });
    }
    Ok(())
}

fn carrier_summary(
    n_digits: usize,
    base: usize,
    n_bits: usize,
    magnitudes: &[usize],
) -> RankCarrierSummary {
    let mut counts = std::collections::BTreeMap::new();
    for &magnitude in magnitudes {
        *counts.entry(magnitude).or_insert(0usize) += 1;
    }
    RankCarrierSummary {
        n_digits,
        base,
        n_bits,
        n_magnitudes: magnitudes.len(),
        distribution: counts.into_iter().collect(),
    }
}

fn feasibility(ranks: &[usize], max_magnitude: usize) -> FeasibilitySummary {
    let mut within_distribution = (1..=max_magnitude)
        .map(|rank| (rank, 0usize))
        .collect::<Vec<_>>();
    let mut within_max = 0usize;
    let mut overflow = 0usize;
    for &rank in ranks {
        if (1..=max_magnitude).contains(&rank) {
            within_max += 1;
            if let Some((_, count)) = within_distribution
                .iter_mut()
                .find(|(candidate, _count)| *candidate == rank)
            {
                *count += 1;
            }
        } else {
            overflow += 1;
        }
    }
    let total = ranks.len();
    let fraction_within_max = if total == 0 {
        0.0
    } else {
        within_max as f64 / total as f64
    };
    FeasibilitySummary {
        total,
        within_max,
        fraction_within_max,
        all_within_max: overflow == 0 && total > 0,
        within_distribution,
        overflow,
    }
}

fn crib_summary(decoded: &[usize], anchors: &[AnchorPair], order: usize) -> CribSummary {
    if anchors.is_empty() {
        return CribSummary {
            status: RankCribStatus::Inapplicable,
            locks: Vec::new(),
        };
    }
    let locks = anchors
        .iter()
        .map(|anchor| crib_lock(decoded, *anchor, order))
        .collect::<Vec<_>>();
    let status = if locks.iter().all(CribLock::consistent) {
        RankCribStatus::Consistent
    } else {
        RankCribStatus::Excluded
    };
    CribSummary { status, locks }
}

fn crib_lock(decoded: &[usize], anchor: AnchorPair, order: usize) -> CribLock {
    let transient = order.min(anchor.length);
    let required_tail = anchor.length.saturating_sub(transient);
    let first = decoded
        .get(anchor.first..anchor.first + anchor.length)
        .unwrap_or(&[]);
    let second = decoded
        .get(anchor.second..anchor.second + anchor.length)
        .unwrap_or(&[]);
    let locked_tail = first
        .iter()
        .rev()
        .zip(second.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    CribLock {
        length: anchor.length,
        first: anchor.first,
        second: anchor.second,
        transient,
        required_tail,
        locked_tail,
    }
}

fn matched_null_decodes(
    pred: &RankPredictor,
    magnitudes: &[usize],
    anchors: &[AnchorPair],
    max_magnitude: usize,
    cfg: &BatteryCfg,
    order: usize,
) -> Result<Vec<Vec<usize>>, RlError> {
    let mut rng = SplitMix64::new(mix_seed(
        cfg.seed,
        NULL_MAG_TAG ^ u64::try_from(order).unwrap_or(0),
    ));
    let pinned = pinned_positions(magnitudes.len(), anchors);
    let alphabet = magnitudes
        .iter()
        .copied()
        .max()
        .unwrap_or(max_magnitude)
        .max(max_magnitude)
        .max(1);
    let mut nulls = Vec::with_capacity(cfg.null_trials);
    for _trial in 0..cfg.null_trials {
        let sampled = markov_resample_pinned(magnitudes, alphabet, &pinned, &mut rng)?;
        nulls.push(rank_decode(pred, &sampled));
    }
    Ok(nulls)
}

pub(crate) fn pinned_positions(n: usize, anchors: &[AnchorPair]) -> Vec<bool> {
    let mut pinned = vec![false; n];
    for anchor in anchors {
        for offset in 0..anchor.length {
            if let Some(slot) = pinned.get_mut(anchor.first + offset) {
                *slot = true;
            }
            if let Some(slot) = pinned.get_mut(anchor.second + offset) {
                *slot = true;
            }
        }
    }
    pinned
}

pub(crate) fn markov_resample_pinned(
    magnitudes: &[usize],
    alphabet: usize,
    pinned: &[bool],
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, RlError> {
    let stream = magnitudes
        .iter()
        .map(|&magnitude| u32::try_from(magnitude.saturating_sub(1)).unwrap_or(0))
        .collect::<Vec<_>>();
    let mut counts: Vec<Vec<u32>> = vec![Vec::new(); alphabet];
    for pair in stream.windows(2) {
        if let [cur, next] = pair
            && let Some(bucket) = counts.get_mut(*cur as usize)
        {
            bucket.push(*next);
        }
    }

    // The crib windows are pinned in the magnitude carrier itself; all other
    // positions are resampled from the empirical order-1 transition law. This
    // preserves the carrier repeat structure without running the wrong
    // symbol-stream null for this memoryful decoder.
    let mut out = Vec::with_capacity(stream.len());
    let first = stream.first().copied().unwrap_or(0);
    out.push(first);
    for index in 1..stream.len() {
        if pinned.get(index).copied().unwrap_or(false) {
            out.push(stream.get(index).copied().unwrap_or(first));
            continue;
        }
        let cur = out.last().copied().unwrap_or(first) as usize;
        let bucket = counts.get(cur).filter(|successors| !successors.is_empty());
        let next = match bucket {
            Some(successors) => {
                let pick = random_index_below(successors.len(), rng)?;
                successors.get(pick).copied().unwrap_or(first)
            }
            None => u32::try_from(random_index_below(alphabet, rng)?).unwrap_or(0),
        };
        out.push(next);
    }
    Ok(out
        .iter()
        .map(|&value| usize::try_from(value).unwrap_or(0).saturating_add(1))
        .collect())
}

fn letters_to_string(letters: &[usize]) -> String {
    letters
        .iter()
        .map(|&letter| char::from(b'A'.saturating_add(u8::try_from(letter).unwrap_or(0))))
        .collect()
}
