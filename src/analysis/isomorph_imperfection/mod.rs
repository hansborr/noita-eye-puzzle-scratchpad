//! Thread G2: forward isomorph-imperfection disproof of the GAK family.
//!
//! GAK is *proven* to produce perfect isomorphs: `c(ga) = c(a)` exactly when
//! `c(gb) = c(b)`. One robust same-plaintext isomorph that breaks *internally* —
//! where repeated plaintext predicts a ciphertext match, and the break is not
//! explainable as a plaintext word boundary — would eject the eyes from the
//! entire perfectly-isomorphic family. This module pushes for such a violation
//! and, in parallel, builds a concrete generative imperfectly-isomorphic cipher
//! family so the detector is calibrated against known imperfections.
//!
//! Everything here is mapping-independent: only reading-layer symbol equality
//! and first-occurrence gap structure are used. No symbol-to-meaning mapping or
//! language model is assumed. The break-localization primitives mirror the
//! canonical scan in [`crate::analysis::perfect_isomorphism`] and reuse its public
//! structural constants so the two stay in lock-step; this module extends that
//! scan with longer windows, a matched null for the loose-candidate class, an
//! explicit word-boundary discount, and the imperfect-family fit comparison.

use std::error::Error;
use std::fmt;

use crate::analysis::orders::{CorpusContext, GridError, ReadingOrder};
use crate::nulls::null::{RandomBoundError, SplitMix64, UsizeBand, mix_seed};

mod detector;
mod report;
#[cfg(test)]
mod tests;

use detector::{
    collect_loose_candidates, counts_from_breaks, locate_stutter_candidate, matched_nulls,
    scan_breaks, scan_counts,
};

/// Default deterministic seed for the nulls and the imperfect-family sweep.
pub const DEFAULT_SEED: u64 = 0x6732_5f69_6d70_6600;
/// Default within-message shuffle trials for the loose/robust matched nulls.
pub const DEFAULT_NULL_TRIALS: usize = 2_000;
/// Default imperfect-family trials drawn per imperfection rate.
pub const DEFAULT_FAMILY_TRIALS: usize = 80;
/// Number of synthetic messages in each imperfect-family draw (one perfect
/// reference plus non-reference instances broken with probability epsilon).
pub const FAMILY_MESSAGES: usize = 5;

/// Base catalog windows, matching the canonical perfect-isomorphism scan.
const BASE_WINDOWS: [usize; 3] = [8, 9, 11];
/// Extended catalog windows: the base set plus the longer 13/15/17 windows that
/// localize breaks deeper and lower the chance-collision rate.
const EXTENDED_WINDOWS: [usize; 6] = [8, 9, 11, 13, 15, 17];
/// Imperfection rates swept for the fit comparison; `0.0` is the perfect-GAK
/// baseline and `1.0` breaks every non-reference repeat.
const EPSILON_GRID: [f64; 6] = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0];
/// The high imperfection rate used by the firing positive control.
const HIGH_EPSILON: f64 = 1.0;

/// Deterministic stream tags so the loose null, robust null, and family sweep
/// draw from disjoint, reproducible sub-streams.
const LOOSE_NULL_TAG: u64 = 0x6c6f_6f73_655f_6e75;
const FAMILY_TAG: u64 = 0x6661_6d69_6c79_5f74;
const CONTROL_TAG: u64 = 0x636f_6e74_726f_6c00;

/// Synthetic-family motif: an irregular (non-self-similar) class sequence whose
/// pre-break prefix carries three repeated classes, so a strong (repeat >= 3)
/// catalog window seeds it, and whose post-break suffix resyncs while carrying a
/// cross-island back-reference. It mirrors the proven short-island internal
/// violation in [`crate::analysis::perfect_isomorphism`]. The irregular layout avoids the
/// misaligned self-matches a periodic motif would manufacture.
const MOTIF: [u32; 20] = [
    0, 1, 2, 0, 3, 1, 4, 2, 5, 1, 6, 7, 0, 8, 9, 10, 11, 12, 13, 14,
];
/// Index whose repeated class is replaced by a fresh singleton in broken
/// instances, producing a single-column interior island.
const BREAK_INDEX: usize = 9;
/// Unique-per-message filler columns flanking the motif so perfect instances
/// diverge into a trailing-edge Boundary break, never an internal one.
const FILLER: usize = 6;
/// Per-instance concrete-symbol stride, keeping each message's symbols disjoint.
const MOTIF_BASE_STRIDE: u32 = 1_000;
/// Offset of the fresh break symbol, distinct from every motif and filler class.
const FRESH_BREAK_OFFSET: u32 = 900;
/// Offset of the leading filler columns.
const FILLER_PRE_OFFSET: u32 = 500;
/// Offset of the trailing filler columns.
const FILLER_POST_OFFSET: u32 = 600;

/// Configuration for the isomorph-imperfection scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsomorphImperfectionConfig {
    /// Deterministic PRNG seed for the matched nulls and the family sweep.
    pub seed: u64,
    /// Within-message shuffle trials for the loose/robust matched nulls.
    pub null_trials: usize,
    /// Imperfect-family draws per swept imperfection rate.
    pub family_trials: usize,
}

impl Default for IsomorphImperfectionConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            null_trials: DEFAULT_NULL_TRIALS,
            family_trials: DEFAULT_FAMILY_TRIALS,
        }
    }
}

/// Error returned by the isomorph-imperfection scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsomorphImperfectionError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one shuffle trial and one family trial are required.
    ZeroTrials,
    /// An extended window exceeded the shortest message; the bound is invalid.
    WindowExceedsShortestMessage {
        /// Offending window length.
        window: usize,
        /// Shortest message length in the corpus.
        shortest: usize,
    },
    /// A random draw bound did not fit the deterministic PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The imperfect-family positive control did not fire; methodology is
    /// suspect, not a finding.
    PositiveControlFailed {
        /// Human-readable failure detail.
        detail: String,
    },
}

impl From<GridError> for IsomorphImperfectionError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<RandomBoundError> for IsomorphImperfectionError {
    fn from(value: RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: value.bound }
    }
}

impl fmt::Display for IsomorphImperfectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(formatter, "grid/order error: {error:?}"),
            Self::ZeroTrials => write!(
                formatter,
                "at least one shuffle trial and one family trial are required"
            ),
            Self::WindowExceedsShortestMessage { window, shortest } => write!(
                formatter,
                "window {window} exceeds the shortest message length {shortest}; the extended-window bound is invalid"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(formatter, "shuffle bound {bound} is too large")
            }
            Self::PositiveControlFailed { detail } => write!(
                formatter,
                "imperfect-family positive control failed ({detail}); methodology is suspect, not a finding"
            ),
        }
    }
}

impl Error for IsomorphImperfectionError {}

/// Robust-internal and loose-candidate counts for one window set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanCounts {
    /// Two-sided, short-island, far-run breaks that are not in a named benign
    /// region and survive the word-boundary discount (internalness > 0).
    pub robust_internal_violations: usize,
    /// All breaks whose internalness survives the word-boundary discount,
    /// including those attributed to a named benign desync region.
    pub loose_candidates: usize,
}

/// One matched within-message-shuffle null outcome for a candidate count.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullOutcome {
    /// Observed real-corpus count.
    pub observed: usize,
    /// Null band over the shuffle samples.
    pub band: UsizeBand,
    /// Number of shuffles whose count met or exceeded the observed count.
    pub upper_tail_count: usize,
    /// Add-one upper-tail empirical p-value.
    pub p: f64,
}

/// Localized loose-candidate break in the `east4`/`west4` Stutter pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StutterCandidate {
    /// Absolute break offset in the left message (`east4`).
    pub left_offset: usize,
    /// Absolute break offset in the right message (`west4`).
    pub right_offset: usize,
    /// Desync island width in columns.
    pub island_cols: usize,
    /// Re-synced far-run length after the island.
    pub far_run: usize,
    /// Net internalness after the word-boundary discount.
    pub internalness: usize,
    /// Whether the break is attributed to the named Stutter benign region.
    pub benign_stutter: bool,
    /// Whether the break ever promotes to a robust internal violation.
    pub promoted_to_violation: bool,
}

/// One loose candidate break: any divergence that survives the word-boundary
/// discount (internalness > 0), whether or not it is attributed to a named
/// benign desync region. The negative is conditional on every loose candidate
/// being benign-attributed, so all are surfaced (not only the east4/west4 one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LooseCandidate {
    /// Left message key.
    pub left_key: &'static str,
    /// Right message key.
    pub right_key: &'static str,
    /// Absolute break offset in the left message.
    pub left_offset: usize,
    /// Absolute break offset in the right message.
    pub right_offset: usize,
    /// Desync island width in columns.
    pub island_cols: usize,
    /// Re-synced far-run length after the island.
    pub far_run: usize,
    /// Net internalness after the word-boundary discount.
    pub internalness: usize,
    /// Named benign desync region this break is attributed to, if any. `None`
    /// means the break is non-benign and is itself a robust internal violation.
    pub benign_region: Option<&'static str>,
    /// Whether the break promotes to a robust internal violation.
    pub promoted_to_violation: bool,
}

/// One imperfection-rate row in the imperfect-family fit comparison.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EpsilonFitRow {
    /// Imperfection rate this row summarizes.
    pub epsilon: f64,
    /// Mean robust-internal-violation count across family draws.
    pub mean_robust: f64,
    /// Maximum robust-internal-violation count across family draws.
    pub max_robust: usize,
    /// Mean loose-candidate count across family draws.
    pub mean_loose: f64,
    /// Maximum loose-candidate count across family draws.
    pub max_loose: usize,
}

/// Imperfect-isomorph family fit comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct FamilyFit {
    /// Synthetic messages per family draw.
    pub messages: usize,
    /// Family draws per imperfection rate.
    pub trials_per_epsilon: usize,
    /// Per-rate summary rows, in ascending imperfection-rate order.
    pub rows: Vec<EpsilonFitRow>,
    /// Mean robust-violation count at the `epsilon = 0` perfect baseline.
    pub baseline_mean_robust: f64,
    /// High imperfection rate evaluated by the positive control.
    pub high_epsilon: f64,
    /// Mean robust-violation count at the high imperfection rate.
    pub high_mean_robust: f64,
    /// Whether the detector found clearly elevated violations at high epsilon.
    pub positive_control_fired: bool,
    /// Smallest swept rate whose mean robust-violation count reaches one, if any.
    pub detection_threshold: Option<f64>,
    /// Eyes' observed robust-violation count being fit.
    pub observed_robust: usize,
    /// Imperfection rate whose expected robust count best explains the eyes.
    pub best_fit_epsilon: f64,
}

/// Complete isomorph-imperfection scan report.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphImperfectionReport {
    /// Configuration used for the run.
    pub config: IsomorphImperfectionConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Shortest message length (the extended-window bound).
    pub shortest_message: usize,
    /// Base catalog windows scanned.
    pub base_windows: Vec<usize>,
    /// Extended catalog windows scanned.
    pub extended_windows: Vec<usize>,
    /// Counts under the base window set.
    pub base_counts: ScanCounts,
    /// Counts under the extended window set.
    pub extended_counts: ScanCounts,
    /// Matched loose-candidate-class null (the east4/west4 hardened bar).
    pub loose_null: NullOutcome,
    /// Matched robust-internal-violation null (cross-check vs the canonical scan).
    pub robust_null: NullOutcome,
    /// Localized east4/west4 loose candidate, if present.
    pub stutter_candidate: Option<StutterCandidate>,
    /// Every loose candidate (all breaks surviving the word-boundary discount),
    /// so the conditional benign attribution of each is auditable, not only the
    /// single east4/west4 one in [`Self::stutter_candidate`].
    pub loose_candidates: Vec<LooseCandidate>,
    /// Imperfect-isomorph family fit comparison.
    pub family: FamilyFit,
}

/// Runs the isomorph-imperfection scan on the verified eye corpus.
///
/// # Errors
/// Returns [`IsomorphImperfectionError`] when the corpus cannot be
/// reconstructed, the trial counts are zero, an extended window exceeds the
/// shortest message, a shuffle draw fails, or the imperfect-family positive
/// control does not fire.
pub fn run_isomorph_imperfection(
    config: IsomorphImperfectionConfig,
) -> Result<IsomorphImperfectionReport, IsomorphImperfectionError> {
    if config.null_trials == 0 || config.family_trials == 0 {
        return Err(IsomorphImperfectionError::ZeroTrials);
    }
    let CorpusContext {
        order,
        keys,
        message_values,
    } = CorpusContext::load()?;
    let messages = to_symbol_messages(&message_values);
    let key_refs = keys.clone();

    let shortest = messages.iter().map(Vec::len).min().unwrap_or_default();
    validate_window_bound(&EXTENDED_WINDOWS, shortest)?;

    let base_counts = scan_counts(&key_refs, &messages, &BASE_WINDOWS);
    let extended_breaks = scan_breaks(&key_refs, &messages, &EXTENDED_WINDOWS);
    let extended_counts = counts_from_breaks(&extended_breaks);

    let (loose_null, robust_null) = matched_nulls(&key_refs, &messages, extended_counts, config)?;
    let stutter_candidate = locate_stutter_candidate(&key_refs, &extended_breaks);
    let loose_candidates = collect_loose_candidates(&keys, &extended_breaks);

    let family = run_family_fit(config, extended_counts.robust_internal_violations);
    ensure_positive_control(config)?;

    let lengths = messages.iter().map(Vec::len).collect::<Vec<_>>();
    Ok(IsomorphImperfectionReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        shortest_message: shortest,
        base_windows: BASE_WINDOWS.to_vec(),
        extended_windows: EXTENDED_WINDOWS.to_vec(),
        base_counts,
        extended_counts,
        loose_null,
        robust_null,
        stutter_candidate,
        loose_candidates,
        family,
    })
}

fn to_symbol_messages(message_values: &[Vec<crate::core::trigram::TrigramValue>]) -> Vec<Vec<u32>> {
    message_values
        .iter()
        .map(|message| message.iter().map(|value| u32::from(value.get())).collect())
        .collect()
}

fn validate_window_bound(
    windows: &[usize],
    shortest: usize,
) -> Result<(), IsomorphImperfectionError> {
    for window in windows {
        if *window > shortest {
            return Err(IsomorphImperfectionError::WindowExceedsShortestMessage {
                window: *window,
                shortest,
            });
        }
    }
    Ok(())
}

// ===========================================================================
// Generative imperfectly-isomorphic cipher family.
//
// Each synthetic message embeds one instance of a period-4 motif whose
// pre-break region (length BREAK_POS >= the longest extended window) is shared
// across messages: at epsilon = 0 every instance is a perfect isomorph of the
// reference, so the only breaks are trailing-edge Boundary divergences into
// disjoint filler. With probability epsilon a non-reference instance has one
// interior repeat replaced by a fresh singleton, producing the canonical
// internal violation (two-sided agreement, single-column island, far resync
// carrying a cross-island back-reference). Mapping-independent throughout.
// ===========================================================================

fn build_message(base: u32, broken: bool) -> Vec<u32> {
    let mut values = Vec::with_capacity(FILLER + MOTIF.len() + FILLER);
    for index in 0..FILLER {
        values.push(base + FILLER_PRE_OFFSET + u32::try_from(index).unwrap_or_default());
    }
    for (index, class) in MOTIF.iter().enumerate() {
        if broken && index == BREAK_INDEX {
            values.push(base + FRESH_BREAK_OFFSET);
        } else {
            values.push(base + *class);
        }
    }
    for index in 0..FILLER {
        values.push(base + FILLER_POST_OFFSET + u32::try_from(index).unwrap_or_default());
    }
    values
}

fn uniform01(rng: &mut SplitMix64) -> f64 {
    // 53 high bits give an evenly spaced double in [0, 1).
    let bits = rng.next_u64() >> 11;
    bits as f64 / 9_007_199_254_740_992.0
}

fn generate_family(epsilon: f64, seed: u64, messages: usize) -> Vec<Vec<u32>> {
    let mut rng = SplitMix64::new(seed);
    let mut out = Vec::with_capacity(messages);
    for message_index in 0..messages {
        let draw = uniform01(&mut rng);
        let base = u32::try_from(message_index)
            .unwrap_or_default()
            .saturating_add(1)
            .saturating_mul(MOTIF_BASE_STRIDE);
        let broken = message_index != 0 && draw < epsilon;
        out.push(build_message(base, broken));
    }
    out
}

fn family_counts(epsilon: f64, seed: u64, messages: usize) -> ScanCounts {
    let family = generate_family(epsilon, seed, messages);
    let keys = vec!["synthetic"; family.len()];
    scan_counts(&keys, &family, &EXTENDED_WINDOWS)
}

fn run_family_fit(config: IsomorphImperfectionConfig, observed_robust: usize) -> FamilyFit {
    let mut rows = Vec::with_capacity(EPSILON_GRID.len());
    for (grid_index, epsilon) in EPSILON_GRID.into_iter().enumerate() {
        rows.push(epsilon_row(config, grid_index, epsilon));
    }
    let baseline_mean_robust = rows.first().map_or(0.0, |row| row.mean_robust);
    let high_mean_robust = rows
        .iter()
        .find(|row| row.epsilon >= HIGH_EPSILON)
        .map_or(0.0, |row| row.mean_robust);
    let positive_control_fired = high_mean_robust > baseline_mean_robust + 1.0;
    let detection_threshold = rows
        .iter()
        .find(|row| row.mean_robust >= 1.0)
        .map(|row| row.epsilon);
    let best_fit_epsilon = best_fit_epsilon(&rows, observed_robust);
    FamilyFit {
        messages: FAMILY_MESSAGES,
        trials_per_epsilon: config.family_trials,
        rows,
        baseline_mean_robust,
        high_epsilon: HIGH_EPSILON,
        high_mean_robust,
        positive_control_fired,
        detection_threshold,
        observed_robust,
        best_fit_epsilon,
    }
}

fn epsilon_row(
    config: IsomorphImperfectionConfig,
    grid_index: usize,
    epsilon: f64,
) -> EpsilonFitRow {
    let mut robust = Vec::with_capacity(config.family_trials);
    let mut loose = Vec::with_capacity(config.family_trials);
    for trial in 0..config.family_trials {
        let seed = mix_seed(
            config.seed,
            FAMILY_TAG
                ^ (u64::try_from(grid_index).unwrap_or_default() << 32)
                ^ u64::try_from(trial).unwrap_or(u64::MAX),
        );
        let counts = family_counts(epsilon, seed, FAMILY_MESSAGES);
        robust.push(counts.robust_internal_violations);
        loose.push(counts.loose_candidates);
    }
    EpsilonFitRow {
        epsilon,
        mean_robust: mean_usize(&robust),
        max_robust: robust.iter().copied().max().unwrap_or_default(),
        mean_loose: mean_usize(&loose),
        max_loose: loose.iter().copied().max().unwrap_or_default(),
    }
}

fn best_fit_epsilon(rows: &[EpsilonFitRow], observed_robust: usize) -> f64 {
    let observed = observed_robust as f64;
    let mut best_epsilon = 0.0;
    let mut best_distance = f64::INFINITY;
    for row in rows {
        let distance = (row.mean_robust - observed).abs();
        if distance < best_distance {
            best_distance = distance;
            best_epsilon = row.epsilon;
        }
    }
    best_epsilon
}

fn ensure_positive_control(
    config: IsomorphImperfectionConfig,
) -> Result<(), IsomorphImperfectionError> {
    let seed = mix_seed(config.seed, CONTROL_TAG);
    let perfect = family_counts(0.0, seed, FAMILY_MESSAGES).robust_internal_violations;
    let imperfect = family_counts(HIGH_EPSILON, seed, FAMILY_MESSAGES).robust_internal_violations;
    if perfect != 0 {
        return Err(IsomorphImperfectionError::PositiveControlFailed {
            detail: format!("perfect-family baseline produced {perfect} robust violations"),
        });
    }
    if imperfect <= perfect {
        return Err(IsomorphImperfectionError::PositiveControlFailed {
            detail: format!(
                "high-epsilon family produced {imperfect} robust violations, not elevated above the baseline {perfect}"
            ),
        });
    }
    Ok(())
}

fn mean_usize(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<usize>() as f64 / samples.len() as f64
    }
}
