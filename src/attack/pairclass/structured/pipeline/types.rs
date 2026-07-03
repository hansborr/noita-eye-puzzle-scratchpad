//! Structured pipeline report and verdict types.

use crate::attack::pairclass::solve::Solution;
use crate::attack::pairclass::structured::confirm::StructuredConfirmRender;
use crate::attack::pairclass::structured::enumerate::{
    StructuredCandidateMeta, StructuredGenerationReport,
};

/// One structured oracle-decode attempt.
#[derive(Clone, Debug)]
pub struct StructuredDecodedCandidate {
    /// Candidate metadata.
    pub meta: StructuredCandidateMeta,
    /// Best rank-beam solution under this candidate, if any full segmentation exists.
    pub solution: Option<Solution>,
    /// Optional full-beam rendering for human review. Display-only; verdicts
    /// and gate statistics stay on the rank-beam solution.
    pub confirm: Option<StructuredConfirmRender>,
    /// Candidates offered during the rank-beam solve.
    pub expanded: u64,
    /// Feasible final states during the rank-beam solve.
    pub feasible_final: usize,
}

impl StructuredDecodedCandidate {
    /// Best score from this attempt.
    #[must_use]
    pub fn best_score(&self) -> Option<f32> {
        self.solution.as_ref().map(|solution| solution.score)
    }
}

/// Full structured run report.
#[derive(Clone, Debug)]
pub struct StructuredRunReport {
    /// Cheap-generation diagnostics.
    pub generation: StructuredGenerationReport,
    /// Every decoded candidate, in candidate-rank order.
    pub attempts: Vec<StructuredDecodedCandidate>,
    /// Best distinct successful solutions across all candidates.
    pub solutions: Vec<StructuredDecodedCandidate>,
    /// Total solver expansions across decoded candidates.
    pub total_expanded: u64,
}

impl StructuredRunReport {
    /// Best score across all structured candidates.
    #[must_use]
    pub fn best_score(&self) -> Option<f32> {
        self.solutions
            .first()
            .and_then(StructuredDecodedCandidate::best_score)
    }
}

/// One structured planted positive or random negative outcome.
#[derive(Clone, Debug)]
pub struct StructuredPlantOutcome {
    /// Best letter recovery against the plant truth.
    pub recovery: f64,
    /// One-based candidate rank of the true coloring, if enumerated.
    pub truth_candidate_rank: Option<usize>,
    /// One-based rank of the true coloring among successful rank-beam scores.
    pub truth_score_rank: Option<usize>,
    /// Rank-beam score of the true-coloring candidate.
    pub truth_score: Option<f32>,
    /// Best score from any structured candidate.
    pub best_score: Option<f32>,
    /// Whether the planted truth tied or beat every other successful family member.
    pub truth_is_family_best: bool,
    /// Matched Markov null for this same stream surface, when requested.
    pub null: Option<StructuredNullGate>,
}

/// Structured planted-positive control report.
#[derive(Clone, Debug)]
pub struct StructuredPowerReport {
    /// Per-plant outcomes.
    pub plants: Vec<StructuredPlantOutcome>,
    /// Mean recovery across plants.
    pub mean_recovery: f64,
    /// Whether every plant scored the truth at rank beam and the mean recovery bar cleared.
    pub cleared_bar: bool,
}

/// Random-coloring negative control report.
#[derive(Clone, Debug)]
pub struct StructuredNegativeReport {
    /// Per-plant outcomes.
    pub plants: Vec<StructuredPlantOutcome>,
    /// Number of random-coloring negatives meeting the configured candidate criterion.
    pub false_positive_like: usize,
    /// Whether every random-coloring negative stayed quiet under its own null.
    pub quiet: bool,
}

/// Structured control tier used by the matched-null verdict rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredVerdictProfile {
    /// Curated primary tier.
    Curated,
    /// Broad coverage tier.
    Broad,
}

/// Structured-mode verdict label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredVerdict {
    /// A rank-beam candidate cleared the stream's own matched null.
    Candidate,
    /// No candidate cleared and the measured controls were powered enough for a scoped negative.
    NoCandidate,
    /// No candidate cleared, but planted score power was too low for exclusion.
    LowPowerNoExclusion,
    /// Controls did not validate the scoring surface, so the real stream is not trusted.
    ControlsFailed,
}

/// Parameters for structured matched-null verdicting.
#[derive(Clone, Copy, Debug)]
pub struct StructuredVerdictCfg {
    /// Tier-specific rule set.
    pub profile: StructuredVerdictProfile,
    /// Required mean planted recovery bar.
    pub plant_bar: f64,
    /// Hard per-plant recovery floor.
    pub plant_floor: f64,
    /// Positive/null alpha for curated planted controls.
    pub positive_alpha: f64,
    /// Maximum truth score rank accepted by curated planted controls.
    pub curated_truth_top_rank: usize,
    /// Real-stream candidate alpha for curated mode.
    pub real_alpha: f64,
}

/// Null and threshold settings for structured random-negative controls.
#[derive(Clone, Copy, Debug)]
pub struct StructuredControlCfg {
    /// Matched Markov null resamples per control stream.
    pub null_trials: usize,
    /// Candidate threshold used to count false-positive-like negatives.
    pub candidate_alpha: f64,
}

/// Structured matched-null gate.
#[derive(Clone, Debug)]
pub struct StructuredNullGate {
    /// Observed best score for the stream surface being calibrated.
    pub observed_best: Option<f32>,
    /// Each null resample's best score.
    pub null_bests: Vec<Option<f32>>,
    /// Candidate-surface size decoded for each null resample.
    pub null_candidate_counts: Vec<usize>,
    /// Null scores reaching the observed best.
    pub null_ge: usize,
}

/// Configuration for structured Markov-null gates.
#[derive(Clone, Copy, Debug)]
pub struct StructuredNullCfg {
    /// Number of Markov resamples.
    pub null_trials: usize,
    /// Observed best score for the stream surface being calibrated.
    pub observed_best: Option<f32>,
    /// Deterministic null seed.
    pub seed: u64,
}

impl StructuredNullGate {
    /// Add-one empirical p-value for `null >= observed`.
    #[must_use]
    pub fn p_value(&self) -> f64 {
        if self.null_bests.is_empty() {
            return f64::NAN;
        }
        (self.null_ge as f64 + 1.0) / (self.null_bests.len() as f64 + 1.0)
    }

    /// Maximum null score.
    #[must_use]
    pub fn max_score(&self) -> Option<f32> {
        self.null_bests
            .iter()
            .filter_map(|score| *score)
            .max_by(f32::total_cmp)
    }

    /// Observed score minus the strongest matched-null score.
    #[must_use]
    pub fn null_margin(&self) -> Option<f32> {
        let observed = self.observed_best?;
        let null_max = self.max_score()?;
        Some(observed - null_max)
    }
}

impl StructuredPlantOutcome {
    /// Add-one empirical p-value from this plant's matched null, if available.
    #[must_use]
    pub fn p_emp(&self) -> Option<f64> {
        self.null.as_ref().map(StructuredNullGate::p_value)
    }

    /// Whether this stream meets a one-sided matched-null candidate threshold.
    #[must_use]
    pub fn null_significant(&self, alpha: f64) -> bool {
        self.null
            .as_ref()
            .is_some_and(|null| null.observed_best.is_some() && null.p_value() <= alpha)
    }
}

impl StructuredPowerReport {
    /// Whether every planted truth candidate was enumerated and scored.
    #[must_use]
    pub fn all_truth_decoded(&self) -> bool {
        !self.plants.is_empty() && self.plants.iter().all(|plant| plant.truth_score.is_some())
    }

    /// Number of planted truths that scored best of family.
    #[must_use]
    pub fn truth_best_count(&self) -> usize {
        self.plants
            .iter()
            .filter(|plant| plant.truth_is_family_best)
            .count()
    }

    /// Number of planted truths that ranked within `limit` by rank-beam score.
    #[must_use]
    pub fn truth_top_count(&self, limit: usize) -> usize {
        self.plants
            .iter()
            .filter(|plant| plant.truth_score_rank.is_some_and(|rank| rank <= limit))
            .count()
    }

    /// Whether every plant reached the configured recovery bar.
    #[must_use]
    pub fn all_recovery_at_bar(&self, recovery_bar: f64) -> bool {
        !self.plants.is_empty()
            && self
                .plants
                .iter()
                .all(|plant| plant.recovery >= recovery_bar)
    }

    /// Lowest per-plant recovery, if any plants were measured.
    #[must_use]
    pub fn min_recovery(&self) -> Option<f64> {
        self.plants
            .iter()
            .map(|plant| plant.recovery)
            .min_by(f64::total_cmp)
    }

    /// Whether any plant fell below the hard recovery floor.
    #[must_use]
    pub fn any_recovery_below(&self, recovery_floor: f64) -> bool {
        self.plants
            .iter()
            .any(|plant| plant.recovery < recovery_floor)
    }

    /// Shared recovery hard gate for structured controls.
    #[must_use]
    pub fn recovery_gate_cleared(&self, recovery_bar: f64, recovery_floor: f64) -> bool {
        !self.plants.is_empty()
            && self.mean_recovery >= recovery_bar
            && !self.any_recovery_below(recovery_floor)
    }

    /// Curated-tier per-plant power pass count.
    #[must_use]
    pub fn curated_pass_count(&self, recovery_bar: f64, alpha: f64, top_limit: usize) -> usize {
        self.plants
            .iter()
            .filter(|plant| {
                plant.recovery >= recovery_bar
                    && plant.truth_score_rank.is_some_and(|rank| rank <= top_limit)
                    && plant.null_significant(alpha)
            })
            .count()
    }
}

impl StructuredNegativeReport {
    /// Counts random negatives that meet a one-sided matched-null threshold.
    #[must_use]
    pub fn false_positive_count(&self, alpha: f64) -> usize {
        self.plants
            .iter()
            .filter(|plant| plant.null_significant(alpha))
            .count()
    }
}

/// Applies the structured matched-null verdict rules.
#[must_use]
pub fn structured_verdict(
    report: &StructuredRunReport,
    positive: &StructuredPowerReport,
    negative: &StructuredNegativeReport,
    real_null: &StructuredNullGate,
    cfg: &StructuredVerdictCfg,
) -> StructuredVerdict {
    if hard_positive_controls_failed(positive, cfg) {
        return StructuredVerdict::ControlsFailed;
    }
    match cfg.profile {
        StructuredVerdictProfile::Curated => {
            let powered = curated_controls_powered(positive, negative, cfg);
            if powered && real_candidate(report, real_null, cfg.real_alpha) {
                StructuredVerdict::Candidate
            } else if powered {
                StructuredVerdict::NoCandidate
            } else {
                StructuredVerdict::LowPowerNoExclusion
            }
        }
        StructuredVerdictProfile::Broad => {
            if real_candidate_by_zero_null(report, real_null) {
                return StructuredVerdict::Candidate;
            }
            if positive.truth_best_count() == positive.plants.len() {
                StructuredVerdict::NoCandidate
            } else {
                StructuredVerdict::LowPowerNoExclusion
            }
        }
    }
}

fn hard_positive_controls_failed(
    positive: &StructuredPowerReport,
    cfg: &StructuredVerdictCfg,
) -> bool {
    if !positive.all_truth_decoded() {
        return true;
    }
    !positive.recovery_gate_cleared(cfg.plant_bar, cfg.plant_floor)
}

fn curated_controls_powered(
    positive: &StructuredPowerReport,
    negative: &StructuredNegativeReport,
    cfg: &StructuredVerdictCfg,
) -> bool {
    positive.curated_pass_count(
        cfg.plant_bar,
        cfg.positive_alpha,
        cfg.curated_truth_top_rank,
    ) == positive.plants.len()
        && negative.quiet
}

fn real_candidate(
    report: &StructuredRunReport,
    real_null: &StructuredNullGate,
    alpha: f64,
) -> bool {
    report.best_score().is_some()
        && real_null.observed_best.is_some()
        && real_null.p_value() <= alpha
}

fn real_candidate_by_zero_null(
    report: &StructuredRunReport,
    real_null: &StructuredNullGate,
) -> bool {
    report.best_score().is_some() && real_null.observed_best.is_some() && real_null.null_ge == 0
}
