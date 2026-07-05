//! Public DTOs for the ns=3 Phase-0 arc-provenance instrument.

use std::time::Duration;

use super::SwapRecoveryStats;
use super::target_reason::ArcLiteral;

/// Pre-registered Phase-0 default: sample at most this many deterministic rejections.
pub const DEFAULT_ARC_PHASE0_REJECTION_CAP: usize = 60;
/// Pre-registered Phase-0 default wall-clock cap in seconds.
pub const DEFAULT_ARC_PHASE0_WALL_SECS: u64 = 3600;
/// Pre-registered Phase-0 default broad replay cap per rejection.
pub const DEFAULT_ARC_PHASE0_REPLAY_CAP: usize = 32;
/// Default sampled tuple spot-checks for the tuple-kill estimate.
pub const DEFAULT_ARC_PHASE0_SPOT_CHECKS: usize = 256;

pub(super) const PROJECTION_LETTERS: [char; 5] = ['E', 'H', 'S', 'T', 'Y'];
pub(super) const SHORT_CONFLICT_LIMIT: usize = 3;

/// Budget knobs for the ns=3 arc-provenance measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakSwapArcPhase0Config {
    /// Maximum deterministic target rejections to sample.
    pub max_rejections: usize,
    /// Maximum wall-clock budget for the measurement loop.
    pub wall_time: Duration,
    /// Maximum broad replays spent minimizing one rejection.
    pub replays_per_rejection: usize,
    /// Number of projected tuples to spot-check for each tuple-kill estimate.
    pub spot_check_samples: usize,
}

impl Default for GakSwapArcPhase0Config {
    fn default() -> Self {
        Self {
            max_rejections: DEFAULT_ARC_PHASE0_REJECTION_CAP,
            wall_time: Duration::from_secs(DEFAULT_ARC_PHASE0_WALL_SECS),
            replays_per_rejection: DEFAULT_ARC_PHASE0_REPLAY_CAP,
            spot_check_samples: DEFAULT_ARC_PHASE0_SPOT_CHECKS,
        }
    }
}

/// Public representation of a letter-local transition-arc literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GakSwapArcLiteral {
    /// Plaintext letter whose candidate domain is restricted.
    pub letter: char,
    /// Post-transition deck position read by `perm[post_position]`.
    pub post_position: usize,
    /// Pre-transition deck position required at that post position.
    pub pre_position: usize,
}

impl From<ArcLiteral> for GakSwapArcLiteral {
    fn from(value: ArcLiteral) -> Self {
        Self {
            letter: value.letter,
            post_position: value.post_position,
            pre_position: value.pre_position,
        }
    }
}

impl From<GakSwapArcLiteral> for ArcLiteral {
    fn from(value: GakSwapArcLiteral) -> Self {
        Self {
            letter: value.letter,
            post_position: value.post_position,
            pre_position: value.pre_position,
        }
    }
}

/// Phase-0 context bin for one minimized rejection reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GakSwapArcContextBin {
    /// The arc literals alone reproduced the rejection under broad replay.
    ContextFree,
    /// Arc literals plus expressible target context reproduced the rejection.
    ContextExpressible,
    /// The rejection did not reproduce with expressible context within budget.
    ContextOpaque,
}

impl GakSwapArcContextBin {
    /// Returns the label used by the pre-registered Phase-0 plan.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextFree => "context-free",
            Self::ContextExpressible => "context-expressible",
            Self::ContextOpaque => "context-opaque",
        }
    }

    pub(super) const fn counts_for_go_rule(self) -> bool {
        matches!(self, Self::ContextFree | Self::ContextExpressible)
    }
}

/// Tuple-kill estimate for a minimized context-free/context-expressible reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapArcTupleKillEstimate {
    /// Fixed `T` target slab used for the projection, when present.
    pub projected_t: Option<usize>,
    /// Total projected `E/H/S/T/Y` tuples in that slab before applying the reason.
    pub projected_total_for_t: usize,
    /// Estimated projected tuples covered by the minimized nogood.
    pub estimated_killed_tuples: usize,
    /// Sampled tuples checked by deterministic propagation.
    pub spot_checked_samples: usize,
    /// Sampled tuples that reproduced a deterministic rejection.
    pub spot_checked_rejections: usize,
    /// Short construction label for reports.
    pub construction: &'static str,
}

/// One sampled deterministic target rejection and its minimized arc reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapArcRejection {
    /// Target solver node number that produced this rejected assignment.
    pub node: usize,
    /// Full target assignment proposed at this node.
    pub targets: Vec<(char, usize)>,
    /// Raw tracked transition-arc literals before minimization.
    pub raw_arc_literals: Vec<GakSwapArcLiteral>,
    /// Raw expressible target context before minimization.
    pub raw_context_targets: Vec<(char, usize)>,
    /// Minimized transition-arc literals.
    pub minimized_arc_literals: Vec<GakSwapArcLiteral>,
    /// Minimized expressible target context.
    pub minimized_context_targets: Vec<(char, usize)>,
    /// Context bin assigned after broad replay.
    pub bin: GakSwapArcContextBin,
    /// Literal count after minimization, or the current upper bound if capped.
    pub literal_count: usize,
    /// True when `literal_count` is an upper bound because the replay cap fired.
    pub literal_count_is_upper_bound: bool,
    /// Broad replay checks spent on this rejection.
    pub replay_checks: usize,
    /// Tuple-kill estimate for bins that count toward the go rule.
    pub tuple_kill_estimate: Option<GakSwapArcTupleKillEstimate>,
}

impl GakSwapArcRejection {
    /// Returns true if this rejection is short and in a bin counted by the go rule.
    #[must_use]
    pub fn counts_as_short_go_conflict(&self) -> bool {
        self.bin.counts_for_go_rule() && self.literal_count <= SHORT_CONFLICT_LIMIT
    }
}

/// Why a Phase-0 measurement loop stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GakSwapArcPhase0Stop {
    /// The configured rejection cap was reached.
    RejectionCap,
    /// The configured wall-clock cap was reached.
    TimeBudget,
    /// The target SAT pre-solver exhausted every assignment.
    TargetExhausted,
    /// The first accepted target slice was not a deterministic rejection.
    NonDeterministicTargetSlice,
}

impl GakSwapArcPhase0Stop {
    /// Stable report label for the stop reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RejectionCap => "rejection-cap",
            Self::TimeBudget => "time-budget",
            Self::TargetExhausted => "target-exhausted",
            Self::NonDeterministicTargetSlice => "non-deterministic-target-slice",
        }
    }
}

/// Aggregate Phase-0 measurement report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapArcPhase0Report {
    /// Measurement budget used.
    pub config: GakSwapArcPhase0Config,
    /// Number of candidates enumerated in the broad ns=3 residual.
    pub enumerated_candidates: usize,
    /// Broad propagation stats before target sampling.
    pub broad_stats: SwapRecoveryStats,
    /// Number of target assignments considered.
    pub target_nodes: usize,
    /// Stop reason.
    pub stop: GakSwapArcPhase0Stop,
    /// Sampled deterministic rejection reports.
    pub rejections: Vec<GakSwapArcRejection>,
}

impl GakSwapArcPhase0Report {
    /// Number of sampled short conflicts in bins (a)/(b).
    #[must_use]
    pub fn short_go_conflicts(&self) -> usize {
        self.rejections
            .iter()
            .filter(|rejection| rejection.counts_as_short_go_conflict())
            .count()
    }

    /// Median tuple-kill estimate among short bins (a)/(b), when any exist.
    #[must_use]
    pub fn median_short_tuple_kill_estimate(&self) -> Option<usize> {
        let mut values = self
            .rejections
            .iter()
            .filter(|rejection| rejection.counts_as_short_go_conflict())
            .filter_map(|rejection| {
                rejection
                    .tuple_kill_estimate
                    .as_ref()
                    .map(|estimate| estimate.estimated_killed_tuples)
            })
            .collect::<Vec<_>>();
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        values.get(values.len() / 2).copied()
    }
}

/// One Phase-0 self-control leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapArcControlLeg {
    /// Human-readable control label.
    pub label: &'static str,
    /// Whether the control passed.
    pub passed: bool,
    /// Short diagnostic string.
    pub detail: String,
}

/// Built-in Phase-0 instrument controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapArcPhase0ControlsReport {
    /// Positive control: known short arc conflict.
    pub positive: GakSwapArcControlLeg,
    /// Matched null: known-long minimal conflict.
    pub matched_null: GakSwapArcControlLeg,
    /// Matched null: short bare arcs require target context and must not fake a go conflict.
    pub matched_null_context: GakSwapArcControlLeg,
}

impl GakSwapArcPhase0ControlsReport {
    /// Returns true when every instrument control passes.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.positive.passed && self.matched_null.passed && self.matched_null_context.passed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InternalMinimizedReason {
    pub(super) arcs: Vec<ArcLiteral>,
    pub(super) context_targets: Vec<(char, usize)>,
    pub(super) bin: GakSwapArcContextBin,
    pub(super) literal_count: usize,
    pub(super) literal_count_is_upper_bound: bool,
    pub(super) replay_checks: usize,
}
