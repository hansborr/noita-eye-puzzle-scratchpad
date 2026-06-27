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
//! canonical scan in [`crate::perfect_isomorphism`] and reuse its public
//! structural constants so the two stay in lock-step; this module extends that
//! scan with longer windows, a matched null for the loose-candidate class, an
//! explicit word-boundary discount, and the imperfect-family fit comparison.
//!
//! The standing claim ceiling holds throughout: the eyes are deterministic,
//! engine-generated, strikingly structured data of unknown meaning; unsolved.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::isomorph::PatternSignature;
use crate::null::{
    RandomBoundError, SplitMix64, UsizeBand, add_one_p_value, fisher_yates, mix_seed, usize_band,
};
use crate::orders::{self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values};
use crate::perfect_isomorphism::{
    MAX_ISLAND_COLS, MIN_TWO_SIDED_FLANK, POST_MIN, SIGNIFICANCE_ALPHA, STRONG_MIN_OCCURRENCES,
    STRONG_MIN_REPEATS,
};
use crate::report::{self, Report};

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
/// violation in [`crate::perfect_isomorphism`]. The irregular layout avoids the
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
/// benign desync region. The negative is conditional on EVERY loose candidate
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

impl Report for IsomorphImperfectionReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Thread G2 isomorph-imperfection disproof scan");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "null trials: {}, family trials per rate: {}",
            self.config.null_trials,
            self.config.family_trials
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(
            &mut out,
            "mapping-independent scope: ciphertext symbol equality and first-occurrence gap structure only"
        );
        report::appendln!(&mut out);
        append_window_section(&mut out, self);
        report::appendln!(&mut out);
        append_null_section(&mut out, self);
        report::appendln!(&mut out);
        append_stutter_section(&mut out, self);
        report::appendln!(&mut out);
        append_loose_candidates_section(&mut out, self);
        report::appendln!(&mut out);
        append_family_section(&mut out, self);
        report::appendln!(&mut out);
        append_verdict_section(&mut out, self);
        out
    }
}

fn append_window_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "extended-window push");
    report::appendln!(
        out,
        "  shortest message: {} (bound for the longest extended window {})",
        report.shortest_message,
        report.extended_windows.last().copied().unwrap_or_default()
    );
    report::appendln!(
        out,
        "  base windows {:?}: robust {}, loose {}",
        report.base_windows,
        report.base_counts.robust_internal_violations,
        report.base_counts.loose_candidates
    );
    report::appendln!(
        out,
        "  extended windows {:?}: robust {}, loose {}",
        report.extended_windows,
        report.extended_counts.robust_internal_violations,
        report.extended_counts.loose_candidates
    );
    report::appendln!(
        out,
        "  word-boundary discount: a break with no resync (trailing-edge divergence, no cross-island back-reference) is attributed to a possible plaintext word/segment boundary and discounted to internalness 0; only a two-sided break flanking a short island (<= {MAX_ISLAND_COLS}) with a far resync (>= {POST_MIN}) carrying a cross-island back-reference earns positive internalness"
    );
    report::appendln!(
        out,
        "  detector blind spot (tested envelope): a break counts as a robust violation ONLY if far_run >= {POST_MIN} AND island_cols <= {MAX_ISLAND_COLS} AND a cross-island back-reference exists; otherwise it is discounted to internalness 0 (invisible). The eye scan AND the entire positive-control family exercise only ONE geometry (single fresh-singleton island = 1, long far resync), so \"the detector fires on imperfections\" is demonstrated ONLY for that shape. Short-resync (far_run < {POST_MIN}) or wide-island (> {MAX_ISLAND_COLS}) imperfections are OUTSIDE the tested envelope"
    );
}

fn append_null_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(
        out,
        "matched within-message-shuffle nulls (multiset-preserving, SplitMix64 Fisher-Yates) -- NOTE: this shuffle is STRUCTURE-DESTROYING for the isomorph statistics; it is weak for the robust falsifier (see the reading line). It is NOT the calibration of the family-falsifier statistic."
    );
    append_null_row(out, "loose-candidate class", &report.loose_null);
    append_null_row(out, "robust internal      ", &report.robust_null);
    report::appendln!(
        out,
        "  reading: the robust (non-benign) count is the family-falsifier statistic, but this within-message shuffle is NOT its calibration -- the shuffle destroys the very isomorphs an internal divergence lives in, so for observed robust {} the add-one p {} is the TRIVIAL COUNT FLOOR (0 is the minimum possible count) and carries NO evidential weight. The BINDING calibration of the robust statistic is the generative epsilon = 0 family (mean robust 0) in the family-fit section below. For the same structure-destroying reason the loose-candidate count EXCEEDS the shuffle null (add-one p small) -> that loose excess is genuine benign isomorph structure, not imperfection.",
        report.robust_null.observed,
        report::format_probability(report.robust_null.p)
    );
    report::appendln!(
        out,
        "  community context: the borderline A.B..B.A pattern is cited at ~13% chance coincidence; here the discriminating statistic is the non-benign robust count, which is {}.",
        report.extended_counts.robust_internal_violations
    );
}

fn append_null_row(out: &mut String, label: &str, outcome: &NullOutcome) {
    report::appendln!(
        out,
        "  {label}: observed {}, null mean {:.3}, median {:.1}, q97.5 {}, max {}, add-one p {}",
        outcome.observed,
        outcome.band.mean,
        outcome.band.median,
        outcome.band.q975,
        outcome.band.max,
        report::format_probability(outcome.p)
    );
}

fn append_stutter_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "east4/west4 Stutter loose-candidate chase");
    match report.stutter_candidate {
        Some(candidate) => {
            report::appendln!(
                out,
                "  located east4@{} / west4@{}: island {}, far-run {}, internalness {}, benign-Stutter {}",
                candidate.left_offset,
                candidate.right_offset,
                candidate.island_cols,
                candidate.far_run,
                candidate.internalness,
                candidate.benign_stutter
            );
            report::appendln!(
                out,
                "  promoted to robust internal violation: {}",
                candidate.promoted_to_violation
            );
        }
        None => report::appendln!(
            out,
            "  no qualifying east4/west4 loose candidate located under the extended windows"
        ),
    }
}

fn append_loose_candidates_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(
        out,
        "all loose candidates (every break surviving the word-boundary discount; the negative is CONDITIONAL on EACH being benign-attributed, not only the east4/west4 one)"
    );
    report::appendln!(out, "  count: {}", report.loose_candidates.len());
    for candidate in &report.loose_candidates {
        report::appendln!(
            out,
            "  {}@{} / {}@{}: island {}, far-run {}, internalness {}, region {}, promoted {}",
            candidate.left_key,
            candidate.left_offset,
            candidate.right_key,
            candidate.right_offset,
            candidate.island_cols,
            candidate.far_run,
            candidate.internalness,
            candidate
                .benign_region
                .unwrap_or("UNATTRIBUTED (non-benign -> robust violation)"),
            candidate.promoted_to_violation
        );
    }
}

fn append_family_section(out: &mut String, report: &IsomorphImperfectionReport) {
    let family = &report.family;
    report::appendln!(
        out,
        "imperfect-isomorph family fit (model-conditional: one constructed family, not all imperfect ciphers)"
    );
    report::appendln!(
        out,
        "  {} synthetic messages, {} draws per rate",
        family.messages,
        family.trials_per_epsilon
    );
    report::appendln!(
        out,
        "  {:>7} {:>12} {:>10} {:>12} {:>10}",
        "epsilon",
        "mean-robust",
        "max-robust",
        "mean-loose",
        "max-loose"
    );
    for row in &family.rows {
        report::appendln!(
            out,
            "  {:>7.2} {:>12.3} {:>10} {:>12.3} {:>10}",
            row.epsilon,
            row.mean_robust,
            row.max_robust,
            row.mean_loose,
            row.max_loose
        );
    }
    report::appendln!(
        out,
        "  positive control: epsilon {:.2} mean-robust {:.3} vs baseline {:.3} -> {}",
        family.high_epsilon,
        family.high_mean_robust,
        family.baseline_mean_robust,
        if family.positive_control_fired {
            "FIRED"
        } else {
            "did not fire"
        }
    );
    report::appendln!(
        out,
        "  detection threshold (first rate with mean-robust >= 1): {}",
        family
            .detection_threshold
            .map_or_else(|| "none in grid".to_owned(), |value| format!("{value:.2}"))
    );
    report::appendln!(
        out,
        "  eyes observed robust {} -> best-fit epsilon {:.2}",
        family.observed_robust,
        family.best_fit_epsilon
    );
    if family.observed_robust == 0 {
        let min_positive_mean = family
            .rows
            .iter()
            .filter(|row| row.epsilon > 0.0)
            .map(|row| row.mean_robust)
            .fold(f64::INFINITY, f64::min);
        report::appendln!(
            out,
            "    note: with observed robust = 0 this best-fit is DEGENERATE -- epsilon = 0 gives mean robust 0 while every epsilon > 0 gives mean robust >= {:.3}, so the argmin is forced to 0. It is a restatement of \"robust count = 0,\" NOT an independent gradient fit. The epsilon axis is QUALITATIVE only: the family has {} synthetic messages vs the eyes' 9, robust counts scale with the message-pair count, and the motif geometry differs.",
            min_positive_mean,
            family.messages
        );
    } else {
        report::appendln!(
            out,
            "    note: the epsilon axis is QUALITATIVE only -- the family has {} synthetic messages vs the eyes' 9, robust counts scale with the message-pair count, and the motif geometry differs.",
            family.messages
        );
    }
}

fn append_verdict_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "verdict");
    report::appendln!(out, "  {}", verdict_line(report));
    report::appendln!(
        out,
        "  Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    );
}

fn verdict_line(report: &IsomorphImperfectionReport) -> String {
    let robust = report.extended_counts.robust_internal_violations;
    let promoted = report
        .stutter_candidate
        .is_some_and(|candidate| candidate.promoted_to_violation);
    let fire_at = report
        .family
        .detection_threshold
        .unwrap_or(report.family.high_epsilon);
    if robust == 0 && !promoted {
        format!(
            "HARDENED NEGATIVE: 0 robust non-benign internal violations under extended windows {:?}; every loose candidate is attributed to a named benign desync region and the east4/west4 Stutter candidate does not promote. The binding calibration is the generative epsilon = 0 family (mean robust 0); the within-message shuffle is structure-destroying, so the robust-null add-one p {} at observed 0 is the trivial count floor, not evidence. The imperfect-family detector fires at epsilon >= {:.2}, and the eyes' observed robust 0 trivially places them at epsilon = 0 (a restatement of robust = 0, not an independent fit). Scope: this rules out only imperfections that produce single/double-column islands (<= {}) with a far resync (>= {}) carrying a cross-island back-reference; short-resync (far_run < {}) or wide-island (> {}) imperfections are OUTSIDE the tested envelope. Within that envelope the eyes are NOT FALSIFIED by perfect isomorphism (consistent with it) -> GAK not falsified (mildly strengthened). This does NOT prove the eyes are GAK (XGAK's upper edge is <=, not equality) and is CONDITIONAL on the benign attribution of east4/west4 (and of every loose candidate listed above).",
            report.extended_windows,
            report::format_probability(report.robust_null.p),
            fire_at,
            MAX_ISLAND_COLS,
            POST_MIN,
            POST_MIN,
            MAX_ISLAND_COLS,
        )
    } else if report.robust_null.p <= SIGNIFICANCE_ALPHA {
        format!(
            "FAMILY-EJECTING VIOLATION: {robust} robust non-benign internal violation(s) under extended windows survive the word-boundary discount AND sit in the upper tail of the matched robust null (add-one p {} <= alpha {}); the eyes leave the perfectly-isomorphic family. Caveat: the binding calibration remains the generative epsilon = 0 family, and the falsifier is restricted to single/double-column islands (<= {}) with a far resync (>= {}) -- imperfections outside that envelope are untested.",
            report::format_probability(report.robust_null.p),
            SIGNIFICANCE_ALPHA,
            MAX_ISLAND_COLS,
            POST_MIN,
        )
    } else {
        format!(
            "CANDIDATE VIOLATION REQUIRING FOLLOW-UP: {robust} robust non-benign internal violation(s) survive the word-boundary discount but sit WITHIN the matched robust null (add-one p {} > alpha {}). This does NOT eject the family on its own: the within-message shuffle null is structure-destroying and weak (see the nulls section), so a count inside it is not yet a falsification. Binding calibration is the generative epsilon = 0 family; this break warrants direct follow-up against a structure-preserving null.",
            report::format_probability(report.robust_null.p),
            SIGNIFICANCE_ALPHA,
        )
    }
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
    let grids = orders::corpus_grids()?;
    let keys = grids
        .iter()
        .map(GlyphGrid::message_key)
        .collect::<Vec<&'static str>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
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

fn to_symbol_messages(message_values: &[Vec<crate::trigram::TrigramValue>]) -> Vec<Vec<u32>> {
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
// Break localization and classification (mapping-independent).
//
// These primitives mirror crate::perfect_isomorphism and reuse its public
// structural constants (MIN_TWO_SIDED_FLANK, MAX_ISLAND_COLS, POST_MIN,
// STRONG_MIN_REPEATS, STRONG_MIN_OCCURRENCES) so the two scans agree on the
// real eyes. They are re-derived here only to add the extended windows, the
// loose-candidate-class counting, and the explicit word-boundary discount
// without growing the size-capped canonical module.
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenignRegion {
    FunnyLookingObstacle,
    Caboose,
    StutterSection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BreakKind {
    Boundary,
    InternalCandidate,
    Benign(BenignRegion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalizedBreak {
    left_index: usize,
    right_index: usize,
    anchor: (usize, usize),
    break_index: usize,
    island_cols: usize,
    far_run: usize,
    class: BreakKind,
}

impl LocalizedBreak {
    fn left_offset(&self) -> usize {
        self.anchor.0 + self.break_index
    }

    fn right_offset(&self) -> usize {
        self.anchor.1 + self.break_index
    }

    /// Net internalness after the word-boundary discount: a `Boundary`-class
    /// break is fully discounted to zero (it looks like a plaintext word/segment
    /// boundary); a qualifying internal break keeps its resync far-run length.
    fn internalness(&self) -> usize {
        match self.class {
            BreakKind::Boundary => 0,
            BreakKind::InternalCandidate | BreakKind::Benign(_) => self.far_run,
        }
    }

    fn is_loose_candidate(&self) -> bool {
        self.internalness() > 0
    }

    fn is_robust_violation(&self) -> bool {
        matches!(self.class, BreakKind::InternalCandidate) && self.internalness() > 0
    }
}

#[derive(Clone, Copy)]
struct Occurrence {
    message_index: usize,
    start: usize,
}

struct Record {
    window: usize,
    occurrences: Vec<Occurrence>,
}

fn scan_counts(keys: &[&str], messages: &[Vec<u32>], windows: &[usize]) -> ScanCounts {
    counts_from_breaks(&scan_breaks(keys, messages, windows))
}

fn counts_from_breaks(breaks: &[LocalizedBreak]) -> ScanCounts {
    ScanCounts {
        robust_internal_violations: breaks
            .iter()
            .filter(|break_row| break_row.is_robust_violation())
            .count(),
        loose_candidates: breaks
            .iter()
            .filter(|break_row| break_row.is_loose_candidate())
            .count(),
    }
}

fn scan_breaks(keys: &[&str], messages: &[Vec<u32>], windows: &[usize]) -> Vec<LocalizedBreak> {
    let records = strong_records(messages, windows);
    let mut breaks = Vec::new();
    let mut seen = BTreeSet::new();
    for record in &records {
        for (position, left) in record.occurrences.iter().enumerate() {
            for right in record.occurrences.iter().skip(position + 1) {
                if left.message_index == right.message_index {
                    continue;
                }
                let (Some(left_values), Some(right_values)) = (
                    messages.get(left.message_index),
                    messages.get(right.message_index),
                ) else {
                    continue;
                };
                if let Some(break_row) = localize_pair(
                    keys,
                    left_values,
                    right_values,
                    *left,
                    *right,
                    record.window,
                ) {
                    let key = (
                        break_row.left_index,
                        break_row.right_index,
                        break_row.left_offset(),
                        break_row.right_offset(),
                    );
                    if seen.insert(key) {
                        breaks.push(break_row);
                    }
                }
            }
        }
    }
    breaks
}

fn strong_records(messages: &[Vec<u32>], windows: &[usize]) -> Vec<Record> {
    let mut records = Vec::new();
    for window in windows {
        let mut grouped: BTreeMap<PatternSignature, Vec<Occurrence>> = BTreeMap::new();
        for (message_index, values) in messages.iter().enumerate() {
            if *window > values.len() {
                continue;
            }
            for (start, symbols) in values.windows(*window).enumerate() {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    grouped.entry(signature).or_default().push(Occurrence {
                        message_index,
                        start,
                    });
                }
            }
        }
        for (signature, mut occurrences) in grouped {
            occurrences.sort_by(|left, right| {
                (left.message_index, left.start).cmp(&(right.message_index, right.start))
            });
            let distinct = occurrences
                .iter()
                .map(|occurrence| occurrence.message_index)
                .collect::<BTreeSet<_>>()
                .len();
            if distinct >= STRONG_MIN_OCCURRENCES
                && repeated_symbol_count(&signature) >= STRONG_MIN_REPEATS
            {
                records.push(Record {
                    window: *window,
                    occurrences,
                });
            }
        }
    }
    records
}

struct PairSlice<'a> {
    left_key: &'a str,
    right_key: &'a str,
    left: &'a [u32],
    right: &'a [u32],
    left_start: usize,
    right_start: usize,
    prefix_len: usize,
}

fn localize_pair(
    keys: &[&str],
    left: &[u32],
    right: &[u32],
    left_occurrence: Occurrence,
    right_occurrence: Occurrence,
    window: usize,
) -> Option<LocalizedBreak> {
    let mut left_start = left_occurrence.start;
    let mut right_start = right_occurrence.start;
    let mut len = window;
    while left_start > 0
        && right_start > 0
        && signature_eq(left, left_start - 1, right, right_start - 1, len + 1)
    {
        left_start -= 1;
        right_start -= 1;
        len += 1;
    }
    while signature_eq(left, left_start, right, right_start, len + 1) {
        len += 1;
    }
    if left.get(left_start + len).is_none() || right.get(right_start + len).is_none() {
        return None;
    }
    let left_key = keys
        .get(left_occurrence.message_index)
        .copied()
        .unwrap_or("");
    let right_key = keys
        .get(right_occurrence.message_index)
        .copied()
        .unwrap_or("");
    let input = PairSlice {
        left_key,
        right_key,
        left,
        right,
        left_start,
        right_start,
        prefix_len: len,
    };
    let (class, island_cols, far_run) = classify_break(&input);
    Some(LocalizedBreak {
        left_index: left_occurrence.message_index,
        right_index: right_occurrence.message_index,
        anchor: (left_start, right_start),
        break_index: len,
        island_cols,
        far_run,
        class,
    })
}

fn classify_break(input: &PairSlice<'_>) -> (BreakKind, usize, usize) {
    let profile = internal_profile(input);
    let class = if profile.qualifies {
        match benign_region(
            input.left_key,
            input.right_key,
            input.left_start + input.prefix_len,
            input.right_start + input.prefix_len,
        ) {
            Some(region) => BreakKind::Benign(region),
            None => BreakKind::InternalCandidate,
        }
    } else {
        BreakKind::Boundary
    };
    (class, profile.island_cols, profile.far_run)
}

#[derive(Clone, Copy)]
struct Profile {
    qualifies: bool,
    island_cols: usize,
    far_run: usize,
}

fn internal_profile(input: &PairSlice<'_>) -> Profile {
    if input.prefix_len < MIN_TWO_SIDED_FLANK {
        return Profile {
            qualifies: false,
            island_cols: 0,
            far_run: 0,
        };
    }
    let mut best = Profile {
        qualifies: false,
        island_cols: 0,
        far_run: 0,
    };
    for island_cols in 1..=MAX_ISLAND_COLS {
        let far_run = far_run_after_island(input, island_cols);
        if far_run > best.far_run {
            best.island_cols = island_cols;
            best.far_run = far_run;
        }
        if far_run >= POST_MIN && has_cross_island_back_reference(input, island_cols, far_run) {
            return Profile {
                qualifies: true,
                island_cols,
                far_run,
            };
        }
    }
    best
}

fn far_run_after_island(input: &PairSlice<'_>, island_cols: usize) -> usize {
    let mut far_run = 0usize;
    let left_after = input.prefix_len.saturating_add(island_cols);
    while signature_eq(
        input.left,
        input.left_start + left_after,
        input.right,
        input.right_start + left_after,
        far_run + 1,
    ) {
        far_run += 1;
    }
    far_run
}

fn has_cross_island_back_reference(
    input: &PairSlice<'_>,
    island_cols: usize,
    far_run: usize,
) -> bool {
    let total_len = input
        .prefix_len
        .saturating_add(island_cols)
        .saturating_add(far_run);
    let Some(left_window) = input
        .left
        .get(input.left_start..input.left_start.saturating_add(total_len))
    else {
        return false;
    };
    let Some(right_window) = input
        .right
        .get(input.right_start..input.right_start.saturating_add(total_len))
    else {
        return false;
    };
    let left_signature = PatternSignature::from_window(left_window);
    let right_signature = PatternSignature::from_window(right_window);
    let suffix_start = input.prefix_len.saturating_add(island_cols);
    for relative in suffix_start..total_len {
        if has_shared_pre_island_source(
            left_signature.values(),
            right_signature.values(),
            relative,
            input.prefix_len,
        ) {
            return true;
        }
    }
    false
}

fn has_shared_pre_island_source(
    left_values: &[usize],
    right_values: &[usize],
    relative: usize,
    prefix_len: usize,
) -> bool {
    let Some(left_target) = left_values.get(relative).copied() else {
        return false;
    };
    let Some(right_target) = right_values.get(relative).copied() else {
        return false;
    };
    left_values
        .iter()
        .zip(right_values)
        .take(prefix_len)
        .any(|(left_prior, right_prior)| *left_prior == left_target && *right_prior == right_target)
}

fn benign_region(
    left_key: &str,
    right_key: &str,
    left_break: usize,
    right_break: usize,
) -> Option<BenignRegion> {
    if is_pair(left_key, right_key, "east1", "west1")
        && range_overlap(left_break, right_break, 1, 30)
    {
        return Some(BenignRegion::FunnyLookingObstacle);
    }
    if is_pair(left_key, right_key, "west1", "east2")
        && range_overlap(left_break, right_break, 35, 95)
    {
        return Some(BenignRegion::Caboose);
    }
    if all_in_stutter_family(left_key, right_key) && range_overlap(left_break, right_break, 35, 80)
    {
        return Some(BenignRegion::StutterSection);
    }
    None
}

fn is_pair(left: &str, right: &str, first: &str, second: &str) -> bool {
    (left == first && right == second) || (left == second && right == first)
}

fn all_in_stutter_family(left: &str, right: &str) -> bool {
    ["east4", "west4", "east5"].contains(&left) && ["east4", "west4", "east5"].contains(&right)
}

fn range_overlap(left: usize, right: usize, start: usize, end: usize) -> bool {
    (start..=end).contains(&left) || (start..=end).contains(&right)
}

fn signature_eq(
    left: &[u32],
    left_start: usize,
    right: &[u32],
    right_start: usize,
    len: usize,
) -> bool {
    let Some(left_window) = left.get(left_start..left_start.saturating_add(len)) else {
        return false;
    };
    let Some(right_window) = right.get(right_start..right_start.saturating_add(len)) else {
        return false;
    };
    PatternSignature::from_window(left_window) == PatternSignature::from_window(right_window)
}

fn repeated_symbol_count(signature: &PatternSignature) -> usize {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for value in signature.values() {
        *counts.entry(*value).or_insert(0) += 1;
    }
    counts.values().filter(|count| **count > 1).count()
}

// ===========================================================================
// Matched nulls and the east4/west4 chase.
// ===========================================================================

/// Computes the loose-candidate-class null and the robust-internal-violation
/// null from a single within-message shuffle pass (shared draws), so each
/// matched null costs one full-corpus scan per trial rather than two.
fn matched_nulls(
    keys: &[&str],
    messages: &[Vec<u32>],
    observed: ScanCounts,
    config: IsomorphImperfectionConfig,
) -> Result<(NullOutcome, NullOutcome), IsomorphImperfectionError> {
    let mut loose_samples = Vec::with_capacity(config.null_trials);
    let mut robust_samples = Vec::with_capacity(config.null_trials);
    for trial in 0..config.null_trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            LOOSE_NULL_TAG ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffle_messages(messages, &mut rng)?;
        let counts = scan_counts(keys, &shuffled, &EXTENDED_WINDOWS);
        loose_samples.push(counts.loose_candidates);
        robust_samples.push(counts.robust_internal_violations);
    }
    let loose = null_outcome(
        observed.loose_candidates,
        &loose_samples,
        config.null_trials,
    );
    let robust = null_outcome(
        observed.robust_internal_violations,
        &robust_samples,
        config.null_trials,
    );
    Ok((loose, robust))
}

fn shuffle_messages(
    messages: &[Vec<u32>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<u32>>, RandomBoundError> {
    let mut shuffled = messages.to_vec();
    for message in &mut shuffled {
        fisher_yates(message, rng)?;
    }
    Ok(shuffled)
}

fn null_outcome(observed: usize, samples: &[usize], trials: usize) -> NullOutcome {
    let upper_tail_count = samples.iter().filter(|count| **count >= observed).count();
    NullOutcome {
        observed,
        band: usize_band(samples),
        upper_tail_count,
        p: add_one_p_value(upper_tail_count, trials),
    }
}

fn collect_loose_candidates(
    keys: &[&'static str],
    breaks: &[LocalizedBreak],
) -> Vec<LooseCandidate> {
    breaks
        .iter()
        .filter(|break_row| break_row.is_loose_candidate())
        .map(|break_row| LooseCandidate {
            left_key: keys.get(break_row.left_index).copied().unwrap_or(""),
            right_key: keys.get(break_row.right_index).copied().unwrap_or(""),
            left_offset: break_row.left_offset(),
            right_offset: break_row.right_offset(),
            island_cols: break_row.island_cols,
            far_run: break_row.far_run,
            internalness: break_row.internalness(),
            benign_region: match break_row.class {
                BreakKind::Benign(region) => Some(benign_region_name(region)),
                BreakKind::Boundary | BreakKind::InternalCandidate => None,
            },
            promoted_to_violation: break_row.is_robust_violation(),
        })
        .collect()
}

fn benign_region_name(region: BenignRegion) -> &'static str {
    match region {
        BenignRegion::FunnyLookingObstacle => "FunnyObstacle",
        BenignRegion::Caboose => "Caboose",
        BenignRegion::StutterSection => "Stutter",
    }
}

fn locate_stutter_candidate(keys: &[&str], breaks: &[LocalizedBreak]) -> Option<StutterCandidate> {
    breaks
        .iter()
        .filter(|break_row| break_row.is_loose_candidate())
        .find(|break_row| {
            let left = keys.get(break_row.left_index).copied().unwrap_or("");
            let right = keys.get(break_row.right_index).copied().unwrap_or("");
            is_pair(left, right, "east4", "west4")
        })
        .map(|break_row| StutterCandidate {
            left_offset: break_row.left_offset(),
            right_offset: break_row.right_offset(),
            island_cols: break_row.island_cols,
            far_run: break_row.far_run,
            internalness: break_row.internalness(),
            benign_stutter: matches!(
                break_row.class,
                BreakKind::Benign(BenignRegion::StutterSection)
            ),
            promoted_to_violation: break_row.is_robust_violation(),
        })
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

#[cfg(test)]
mod tests {
    use super::{
        EXTENDED_WINDOWS, FAMILY_MESSAGES, HIGH_EPSILON, IsomorphImperfectionConfig, family_counts,
        generate_family, run_isomorph_imperfection, scan_counts,
    };
    use crate::report::Report;

    // The full-corpus shuffle null dominates cost, so the run()-driven tests use
    // small, cheap, deterministic trial counts. The public defaults stay large
    // and scientifically meaningful (exercised only by the ignored canonical
    // snapshot). The positive control still fires and the eyes still show zero
    // robust violations at this cheap config — that is the binding requirement.
    fn cheap_config() -> IsomorphImperfectionConfig {
        IsomorphImperfectionConfig {
            seed: 0x4242,
            null_trials: 64,
            family_trials: 12,
        }
    }

    fn tiny_config() -> IsomorphImperfectionConfig {
        IsomorphImperfectionConfig {
            seed: 0x4242,
            null_trials: 4,
            family_trials: 2,
        }
    }

    #[test]
    fn run_is_deterministic_for_fixed_config() {
        let config = tiny_config();
        let first = run_isomorph_imperfection(config).unwrap();
        let second = run_isomorph_imperfection(config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.order.name(), "standard36-u012-d012");
    }

    #[test]
    fn eyes_are_a_hardened_negative() {
        // One run() call covers the whole hardened-negative story so the slow
        // full-corpus null is paid only once.
        let report = run_isomorph_imperfection(cheap_config()).unwrap();

        // (a) Extending windows to {13,15,17} must not manufacture a robust
        // internal violation; the canonical scan reports zero and so must this.
        assert_eq!(report.base_counts.robust_internal_violations, 0);
        assert_eq!(report.extended_counts.robust_internal_violations, 0);
        assert_eq!(report.robust_null.observed, 0);
        assert_eq!(*report.extended_windows.last().unwrap(), 17);
        assert!(*report.extended_windows.last().unwrap() <= report.shortest_message);

        // (b) The robust (non-benign) count is the family-falsifier statistic.
        // Its BINDING calibration is the generative epsilon = 0 family (mean
        // robust 0), NOT this within-message shuffle: the shuffle is
        // structure-destroying, so the observed-0 add-one p = 1.0 is only the
        // trivial count floor (0 is the minimum). For the same reason the loose
        // candidates EXCEED the shuffle null (p small) — that is expected real
        // benign structure, not a violation.
        assert_eq!(
            report.robust_null.upper_tail_count,
            report.config.null_trials
        );
        assert!(report.robust_null.p > 0.05);
        assert!(report.extended_counts.loose_candidates > 0);
        assert!((report.loose_null.observed as f64) > report.loose_null.band.mean);

        // (c) The east4/west4 Stutter candidate stays benign and never promotes.
        let candidate = report
            .stutter_candidate
            .expect("east4/west4 loose candidate should be located");
        assert!(candidate.benign_stutter);
        assert!(!candidate.promoted_to_violation);

        // (c') EVERY loose candidate is surfaced (not only east4/west4) and the
        // surfaced list matches the loose count; each is benign-attributed and
        // none promotes, which is what the conditional negative rests on.
        assert_eq!(
            report.loose_candidates.len(),
            report.extended_counts.loose_candidates
        );
        for loose in &report.loose_candidates {
            assert!(loose.benign_region.is_some());
            assert!(!loose.promoted_to_violation);
        }

        // (d) The imperfect-family detector fires, and the eyes best-fit at the
        // perfect epsilon = 0.
        assert!(report.family.positive_control_fired);
        assert_eq!(report.family.observed_robust, 0);
        assert!((report.family.best_fit_epsilon - 0.0).abs() < f64::EPSILON);
        assert!((report.family.baseline_mean_robust - 0.0).abs() < f64::EPSILON);
        assert!(report.family.high_mean_robust > report.family.baseline_mean_robust);

        let rendered = report.render();
        assert!(rendered.contains("verdict"));
        assert!(rendered.contains("Claim ceiling"));
        assert!(rendered.contains("epsilon"));
        assert!(rendered.contains("GAK not falsified"));
        assert!(rendered.contains("all loose candidates"));
    }

    #[test]
    fn imperfect_family_positive_control_fires() {
        // The binding firing positive control (cheap synthetic scans, no eyes):
        // at epsilon = 0 the detector finds zero robust internal violations, and
        // at high epsilon it finds clearly elevated ones. Without this, "0
        // violations on the eyes" would be meaningless. Asserted across seeds.
        for seed in [0x11u64, 0x22, 0x33, 0x44] {
            let perfect = family_counts(0.0, seed, FAMILY_MESSAGES).robust_internal_violations;
            let imperfect =
                family_counts(HIGH_EPSILON, seed, FAMILY_MESSAGES).robust_internal_violations;
            assert_eq!(
                perfect, 0,
                "seed {seed} produced a false perfect-baseline violation"
            );
            assert!(
                imperfect >= FAMILY_MESSAGES - 1,
                "seed {seed} did not elevate robust violations at high epsilon ({imperfect})"
            );
        }
    }

    #[test]
    fn perfect_family_is_internally_clean() {
        // A directly generated perfect family (epsilon = 0) has zero robust and
        // zero loose candidates: its only breaks are trailing-edge boundaries.
        let family = generate_family(0.0, 0xfeed, FAMILY_MESSAGES);
        let keys = vec!["synthetic"; family.len()];
        let counts = scan_counts(&keys, &family, &EXTENDED_WINDOWS);
        assert_eq!(counts.robust_internal_violations, 0);
        assert_eq!(counts.loose_candidates, 0);
    }

    #[test]
    fn single_broken_instance_is_an_internal_violation() {
        // One broken non-reference instance against the perfect reference must
        // localize as exactly one robust internal violation at the designed
        // break (the irregular motif admits no misaligned spurious matches).
        let family = generate_family(HIGH_EPSILON, 0xabc, 2);
        let keys = vec!["synthetic"; family.len()];
        let counts = scan_counts(&keys, &family, &EXTENDED_WINDOWS);
        assert_eq!(counts.robust_internal_violations, 1);
        assert_eq!(counts.loose_candidates, 1);
    }

    #[test]
    fn zero_trials_are_rejected() {
        let config = IsomorphImperfectionConfig {
            seed: 1,
            null_trials: 0,
            family_trials: 1,
        };
        assert!(run_isomorph_imperfection(config).is_err());
    }

    #[test]
    #[ignore = "canonical full-trial run; capture headline numbers with cargo test -- --ignored --nocapture"]
    fn canonical_report_snapshot() {
        let report = run_isomorph_imperfection(IsomorphImperfectionConfig::default()).unwrap();
        println!("{}", report.render());
    }
}
