//! Shared defaults and public option enums for hidden-base local recovery.

pub(super) const DEFAULT_ATTEMPTS: usize = 96;
pub(super) const DEFAULT_ROUNDS: usize = 18;
pub(super) const DEFAULT_TOP_SOURCE_BEAM_WIDTH: usize = 96;
pub(super) const DEFAULT_JOINT_MOVE_EVALUATION_CAP: usize = 4_096;
pub(super) const DEFAULT_JOINT_MOVE_TOTAL_EVALUATION_CAP: usize = 393_216;
pub(super) const DEFAULT_TRIPLE_MOVE_EVALUATION_CAP: usize = 0;
pub(super) const DEFAULT_TRIPLE_MOVE_TOTAL_EVALUATION_CAP: usize = 0;
pub(super) const DEFAULT_PREFIX_CEGAR_CAPS: (usize, usize) = (0, 0);
pub(super) const DEFAULT_STATE_SAT_HYPOTHESIS_CAP: usize = 96;
pub(super) const DEFAULT_SEED: u64 = 0x6761_6b5f_6862_6c73;

/// Generator family admitted by the hidden-base local solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseLocalGeneratorFamily {
    /// The top-card transposition family `{(0,k)}`.
    TopCardSwaps,
}

/// Candidate order for stalled two-letter sigma moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseLocalJointMoveOrder {
    /// Exhaust each letter-pair product before visiting the next pair.
    PairMajor,
    /// Visit one candidate from every letter pair in repeated strata.
    PairRoundRobin,
    /// Spend half of each pass round-robin, then continue pair-major without
    /// repeating candidates.
    Hybrid,
}
