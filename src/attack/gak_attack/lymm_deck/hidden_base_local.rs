//! Bounded local search for hidden-base `s = 2..3` top-swap keys.
//!
//! This solver does not enumerate hidden bases. It searches over per-letter
//! generator words, infers the shared base from identity-restart first-symbol
//! anchors, and accepts a key only when replaying the known plaintext reproduces
//! the compressed ciphertext exactly.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::ciphers::validate_permutation;

use super::{
    HiddenBaseRoundTrip, HiddenBaseSurfaceReport, KnownPlaintextPair, LymmDeckError, LymmDeckSpec,
    lymm_default_ct_alphabet,
};

#[path = "hidden_base_local/controls.rs"]
mod controls;
#[path = "hidden_base_local/corpus.rs"]
mod corpus;
#[path = "hidden_base_local/joint.rs"]
mod joint;
#[path = "hidden_base_local/output.rs"]
mod output;
#[path = "hidden_base_local/prefix_cegar.rs"]
mod prefix_cegar;
#[path = "hidden_base_local/report.rs"]
mod report;
#[path = "hidden_base_local/score.rs"]
mod score;
#[path = "hidden_base_local/search.rs"]
mod search;
#[path = "hidden_base_local/state_sat.rs"]
mod state_sat;
#[path = "hidden_base_local/top_source.rs"]
mod top_source;
#[path = "hidden_base_local/triple.rs"]
mod triple;

pub use controls::{
    HiddenBaseLocalControlExpectation, HiddenBaseLocalControlReport, HiddenBaseLocalSelfTestReport,
    hidden_base_local_self_test, post_anchor_ciphertext_label_swap,
};
use report::{classify_recovery, factorial_u128, representative_audit};
use search::run_local_search;

const DEFAULT_ATTEMPTS: usize = 96;
const DEFAULT_ROUNDS: usize = 18;
const DEFAULT_TOP_SOURCE_BEAM_WIDTH: usize = 96;
const DEFAULT_JOINT_MOVE_EVALUATION_CAP: usize = 4_096;
const DEFAULT_JOINT_MOVE_TOTAL_EVALUATION_CAP: usize = 393_216;
const DEFAULT_TRIPLE_MOVE_EVALUATION_CAP: usize = 0;
const DEFAULT_TRIPLE_MOVE_TOTAL_EVALUATION_CAP: usize = 0;
const DEFAULT_PREFIX_CEGAR_CAPS: (usize, usize) = (0, 0);
const DEFAULT_STATE_SAT_HYPOTHESIS_CAP: usize = 96;
const DEFAULT_SEED: u64 = 0x6761_6b5f_6862_6c73;

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

/// Search configuration for [`recover_hidden_base_local_known_plaintext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseLocalSolverConfig {
    /// Deck size.
    pub n: usize,
    /// Plaintext alphabet in key order.
    pub pt_alphabet: String,
    /// Ciphertext alphabet indexed by emitted deck value.
    pub ct_alphabet: String,
    /// Generator family used for each per-letter perturbation.
    pub generator_family: HiddenBaseLocalGeneratorFamily,
    /// Maximum top-card-swap budget admitted into each per-letter domain.
    pub swap_budget: usize,
    /// Deterministic seed for random restarts.
    pub seed: u64,
    /// Number of independent local-search restarts.
    pub attempts: usize,
    /// Maximum coordinate-descent rounds per restart.
    pub max_rounds: usize,
    /// Maximum top-source hypotheses retained for bounded recovery.
    pub top_source_beam_width: usize,
    /// Whether to rank complete top-source states with third-symbol restart
    /// compatibility before applying the beam cap.
    pub rank_top_sources_with_third_symbol: bool,
    /// Candidate order used by stalled two-letter sigma moves.
    pub joint_move_order: HiddenBaseLocalJointMoveOrder,
    /// Maximum two-letter sigma assignments scored per stalled `s=3` restart.
    /// Zero disables joint moves.
    pub joint_move_evaluation_cap: usize,
    /// Maximum two-letter sigma assignments scored over the complete run,
    /// allocated by cumulative fair share across configured restarts.
    pub joint_move_total_evaluation_cap: usize,
    /// Per-restart fourth-prefix triple cap; zero disables triple repair.
    pub triple_move_evaluation_cap: usize,
    /// Maximum fourth-prefix triple assignments checked over the complete run,
    /// allocated by cumulative fair share across configured restarts.
    pub triple_move_total_evaluation_cap: usize,
    /// Per-hypothesis prefix-CEGAR SAT-model cap; zero disables the fallback.
    pub prefix_cegar_node_cap: usize,
    /// Maximum SAT models replayed over the complete prefix-CEGAR fallback.
    pub prefix_cegar_total_node_cap: usize,
    /// Maximum retained top-source hypotheses solved by exact state SAT.
    pub state_sat_hypothesis_cap: usize,
}

impl HiddenBaseLocalSolverConfig {
    /// Builds the default top-card-swap configuration for this rung.
    #[must_use]
    pub fn top_card_swaps(n: usize, pt_alphabet: impl Into<String>, swap_budget: usize) -> Self {
        Self {
            n,
            pt_alphabet: pt_alphabet.into(),
            ct_alphabet: lymm_default_ct_alphabet(n),
            generator_family: HiddenBaseLocalGeneratorFamily::TopCardSwaps,
            swap_budget,
            seed: DEFAULT_SEED,
            attempts: DEFAULT_ATTEMPTS,
            max_rounds: DEFAULT_ROUNDS,
            top_source_beam_width: DEFAULT_TOP_SOURCE_BEAM_WIDTH,
            rank_top_sources_with_third_symbol: true,
            joint_move_order: HiddenBaseLocalJointMoveOrder::Hybrid,
            joint_move_evaluation_cap: DEFAULT_JOINT_MOVE_EVALUATION_CAP,
            joint_move_total_evaluation_cap: DEFAULT_JOINT_MOVE_TOTAL_EVALUATION_CAP,
            triple_move_evaluation_cap: DEFAULT_TRIPLE_MOVE_EVALUATION_CAP,
            triple_move_total_evaluation_cap: DEFAULT_TRIPLE_MOVE_TOTAL_EVALUATION_CAP,
            prefix_cegar_node_cap: DEFAULT_PREFIX_CEGAR_CAPS.0,
            prefix_cegar_total_node_cap: DEFAULT_PREFIX_CEGAR_CAPS.1,
            state_sat_hypothesis_cap: DEFAULT_STATE_SAT_HYPOTHESIS_CAP,
        }
    }

    /// Replaces the ciphertext alphabet.
    #[must_use]
    pub fn with_ct_alphabet(mut self, ct_alphabet: impl Into<String>) -> Self {
        self.ct_alphabet = ct_alphabet.into();
        self
    }

    /// Replaces the deterministic restart seed.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Replaces the restart count.
    #[must_use]
    pub const fn with_attempts(mut self, attempts: usize) -> Self {
        self.attempts = attempts;
        self
    }

    /// Replaces the coordinate-descent round cap.
    #[must_use]
    pub const fn with_max_rounds(mut self, max_rounds: usize) -> Self {
        self.max_rounds = max_rounds;
        self
    }

    /// Replaces the top-source hypothesis retention width independently of the
    /// local-search restart count.
    #[must_use]
    pub const fn with_top_source_beam_width(mut self, width: usize) -> Self {
        self.top_source_beam_width = width;
        self
    }

    /// Enables or disables third-symbol top-source ranking.
    #[must_use]
    pub const fn with_third_symbol_top_source_ranking(mut self, enabled: bool) -> Self {
        self.rank_top_sources_with_third_symbol = enabled;
        self
    }

    /// Replaces the stalled two-letter candidate order.
    #[must_use]
    pub const fn with_joint_move_order(mut self, order: HiddenBaseLocalJointMoveOrder) -> Self {
        self.joint_move_order = order;
        self
    }

    /// Replaces the per-restart two-letter sigma evaluation cap.
    #[must_use]
    pub const fn with_joint_move_evaluation_cap(mut self, cap: usize) -> Self {
        self.joint_move_evaluation_cap = cap;
        self
    }

    /// Replaces the fairly allocated total-run two-letter sigma evaluation cap.
    #[must_use]
    pub const fn with_joint_move_total_evaluation_cap(mut self, cap: usize) -> Self {
        self.joint_move_total_evaluation_cap = cap;
        self
    }

    /// Replaces the per-restart fourth-prefix triple-repair evaluation cap.
    #[must_use]
    pub const fn with_triple_move_evaluation_cap(mut self, cap: usize) -> Self {
        self.triple_move_evaluation_cap = cap;
        self
    }

    /// Replaces the fairly allocated total-run triple-repair evaluation cap.
    #[must_use]
    pub const fn with_triple_move_total_evaluation_cap(mut self, cap: usize) -> Self {
        self.triple_move_total_evaluation_cap = cap;
        self
    }

    /// Replaces the per-hypothesis prefix-CEGAR SAT-model cap.
    #[must_use]
    pub const fn with_prefix_cegar_node_cap(mut self, cap: usize) -> Self {
        self.prefix_cegar_node_cap = cap;
        self
    }

    /// Replaces the total-run prefix-CEGAR SAT-model cap.
    #[must_use]
    pub const fn with_prefix_cegar_total_node_cap(mut self, cap: usize) -> Self {
        self.prefix_cegar_total_node_cap = cap;
        self
    }

    /// Replaces the retained-hypothesis cap for exact state SAT.
    #[must_use]
    pub const fn with_state_sat_hypothesis_cap(mut self, cap: usize) -> Self {
        self.state_sat_hypothesis_cap = cap;
        self
    }
}

/// Final state of a hidden-base local recovery run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseLocalRecoveryState {
    /// The planted base was supplied for post-search audit and was recovered.
    RecoveredPlantedBase,
    /// An exact re-encrypting key was found, but the planted base was not
    /// supplied or was not the representative base.
    RecoveredEquivalentKey,
    /// An exact key was found, but the representative mapping admits a larger
    /// hidden-base decomposition class.
    AmbiguousEquivalentClass,
    /// The searched surface was exhaustive and no candidate exists.
    NoCandidate,
    /// The bounded local-search budget ended without an exact key.
    SearchCapExceeded,
}

impl HiddenBaseLocalRecoveryState {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecoveredPlantedBase => "recovered-planted-base",
            Self::RecoveredEquivalentKey => "recovered-equivalent-key",
            Self::AmbiguousEquivalentClass => "ambiguous-equivalent-class",
            Self::NoCandidate => "no-candidate",
            Self::SearchCapExceeded => "search-cap-exceeded",
        }
    }
}

/// One exact re-encrypting hidden-base/key representative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseLocalRecoveredKey {
    /// Candidate hidden base `B`.
    pub base: Vec<usize>,
    /// Complete per-letter mapping used for exact re-encryption.
    pub pt_mapping: BTreeMap<char, Vec<usize>>,
    /// Canonical top-swap word selected for each plaintext letter.
    pub letter_swaps: BTreeMap<char, Vec<usize>>,
}

/// Measurement and classification report for a hidden-base local recovery run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseLocalRecoveryReport {
    /// Final recovery state.
    pub state: HiddenBaseLocalRecoveryState,
    /// Configuration used for the run.
    pub config: HiddenBaseLocalSolverConfig,
    /// `n!` brute-force hidden-base count when it fits in `u128`.
    pub brute_force_base_count: Option<u128>,
    /// De-duplicated per-letter sigma domain size.
    pub sigma_domain_size: usize,
    /// Local-search restarts actually run.
    pub attempts_run: usize,
    /// Candidate letter assignments scored by the local search.
    pub candidate_evaluations: usize,
    /// Ciphertext events replayed across all candidate evaluations.
    pub replay_event_evaluations: usize,
    /// Candidate evaluations spent on stalled two-letter sigma moves.
    pub joint_move_candidate_evaluations: usize,
    /// Ciphertext events replayed inside stalled two-letter sigma moves.
    pub joint_move_replay_event_evaluations: usize,
    /// Whether the total-run two-letter sigma evaluation budget was exhausted.
    pub joint_move_total_budget_exhausted: bool,
    /// Improving two-letter sigma moves accepted by the local search.
    pub joint_moves_accepted: usize,
    /// Eligible letter pairs seen by at least one two-letter move pass.
    pub joint_move_letter_pairs_eligible: usize,
    /// Eligible letter pairs that received at least one candidate evaluation.
    pub joint_move_letter_pairs_evaluated: usize,
    /// Minimum candidate evaluations assigned to an eligible letter pair.
    pub joint_move_pair_evaluations_min: usize,
    /// Maximum candidate evaluations assigned to an eligible letter pair.
    pub joint_move_pair_evaluations_max: usize,
    /// Fourth-prefix triple assignments checked by stalled triple repair.
    pub triple_move_candidate_evaluations: usize,
    /// Exact fourth-prefix equations checked by stalled triple repair.
    pub triple_move_constraint_evaluations: usize,
    /// Ciphertext events replayed for constraint-surviving triple proposals.
    pub triple_move_replay_event_evaluations: usize,
    /// Whether the total-run triple-repair budget was exhausted.
    pub triple_move_total_budget_exhausted: bool,
    /// Improving fourth-prefix triple moves accepted by the local search.
    pub triple_moves_accepted: usize,
    /// Distinct violated fourth-prefix triples eligible for repair.
    pub triple_move_prefixes_eligible: usize,
    /// Eligible fourth-prefix triples receiving at least one assignment check.
    pub triple_move_prefixes_evaluated: usize,
    /// Retained top-source hypotheses opened by prefix CEGAR.
    pub prefix_cegar_hypotheses_attempted: usize,
    /// Retained hypotheses proved unsatisfiable within the admitted sigma CSP.
    pub prefix_cegar_hypotheses_unsat: usize,
    /// Retained hypotheses stopped at their SAT-model cap.
    pub prefix_cegar_hypotheses_capped: usize,
    /// SAT models replayed by prefix CEGAR.
    pub prefix_cegar_models: usize,
    /// Sound replay-derived prefix clauses learned by CEGAR.
    pub prefix_cegar_clauses: usize,
    /// Ciphertext events replayed by prefix CEGAR.
    pub prefix_cegar_replay_event_evaluations: usize,
    /// Exact complete-replay SAT models found by prefix CEGAR.
    pub prefix_cegar_exact_models: usize,
    /// Smallest learned prefix core; zero means no clause was learned.
    pub prefix_cegar_core_size_min: usize,
    /// Largest learned prefix-clause core.
    pub prefix_cegar_core_size_max: usize,
    /// Whether the total prefix-CEGAR SAT-model budget was exhausted.
    pub prefix_cegar_total_budget_exhausted: bool,
    /// Retained top-source hypotheses opened by exact state SAT.
    pub state_sat_hypotheses_attempted: usize,
    /// Retained fixed-base hypotheses proved unsatisfiable by state SAT.
    pub state_sat_hypotheses_unsat: usize,
    /// Exact state-SAT models accepted after complete replay.
    pub state_sat_exact_models: usize,
    /// SAT variables allocated across attempted fixed-base hypotheses.
    pub state_sat_variables: usize,
    /// SAT clauses allocated across attempted fixed-base hypotheses.
    pub state_sat_clauses: usize,
    /// Ciphertext events replayed to verify satisfying state-SAT models.
    pub state_sat_replay_event_evaluations: usize,
    /// Wall-clock time spent constructing and solving exact state SAT.
    pub state_sat_elapsed: Duration,
    /// Complete top-source hypotheses retained for bounded recovery.
    pub top_source_hypotheses_retained: usize,
    /// One-based pre-truncation rank of the planted top-source hypothesis when
    /// a planted base was supplied for audit.
    pub planted_top_source_hypothesis_rank: Option<usize>,
    /// Whether the planted top-source hypothesis survived the configured beam
    /// when a planted base was supplied for audit.
    pub planted_top_source_hypothesis_retained: Option<bool>,
    /// Partial top-source states expanded by the CSP stage.
    pub top_source_states_expanded: usize,
    /// Partial top-source states rejected by injectivity or second-symbol constraints.
    pub top_source_states_pruned: usize,
    /// Compatible complete states dropped at the configured beam/restart cap.
    pub top_source_states_dropped: usize,
    /// Sigma candidates checked while applying second-symbol constraints.
    pub top_source_constraint_evaluations: usize,
    /// Sigma pairs checked by the third-symbol top-source ranker.
    pub top_source_third_symbol_evaluations: usize,
    /// Wall-clock time spent constructing the top-source beam.
    pub top_source_elapsed: Duration,
    /// Distinct exact hidden bases found by the bounded search.
    pub exact_candidate_count: usize,
    /// Whether a planted base supplied for audit was recovered.
    pub planted_base_recovered: Option<bool>,
    /// Observed plaintext letters in alphabet order.
    pub observed_letters: Vec<char>,
    /// Plaintext letters seen as the first alphabet symbol of an identity-restart
    /// message, and therefore usable as base anchors.
    pub anchored_letters: Vec<char>,
    /// Total known-plaintext alphabet events checked.
    pub event_count: usize,
    /// Best mismatch count observed under compressed replay.
    pub best_mismatches: usize,
    /// Best compressed round-trip observed by the search.
    pub best_round_trip: HiddenBaseRoundTrip,
    /// Wall-clock time spent in the bounded search and post-search audit.
    pub elapsed: Duration,
    /// First exact re-encrypting representative, when one was found.
    pub representative_key: Option<HiddenBaseLocalRecoveredKey>,
    /// Hidden-base decomposition audit for the representative exact mapping.
    pub representative_audit: Option<HiddenBaseSurfaceReport>,
}

impl HiddenBaseLocalRecoveryReport {
    /// Returns true when the run found at least one exact key.
    #[must_use]
    pub const fn has_exact_recovery(&self) -> bool {
        matches!(
            self.state,
            HiddenBaseLocalRecoveryState::RecoveredPlantedBase
                | HiddenBaseLocalRecoveryState::RecoveredEquivalentKey
                | HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass
        )
    }
}

/// Recovers an exact hidden-base `s = 2..3` key from known plaintext/ciphertext
/// pairs without receiving the hidden base or planted per-letter mapping.
///
/// # Errors
/// Returns [`LymmDeckError`] if the configuration or corpus is malformed.
pub fn recover_hidden_base_local_known_plaintext(
    config: &HiddenBaseLocalSolverConfig,
    pairs: &[KnownPlaintextPair],
) -> Result<HiddenBaseLocalRecoveryReport, LymmDeckError> {
    recover_hidden_base_local_known_plaintext_inner(config, pairs, None)
}

/// Runs the same no-base local solver, then uses an optional planted base only
/// for post-search classification on synthetic controls.
///
/// # Errors
/// Returns [`LymmDeckError`] if the configuration, corpus, or planted base is
/// malformed.
pub fn recover_hidden_base_local_known_plaintext_with_audit(
    config: &HiddenBaseLocalSolverConfig,
    pairs: &[KnownPlaintextPair],
    planted_base: Option<&[usize]>,
) -> Result<HiddenBaseLocalRecoveryReport, LymmDeckError> {
    recover_hidden_base_local_known_plaintext_inner(config, pairs, planted_base)
}

fn recover_hidden_base_local_known_plaintext_inner(
    config: &HiddenBaseLocalSolverConfig,
    pairs: &[KnownPlaintextPair],
    planted_base: Option<&[usize]>,
) -> Result<HiddenBaseLocalRecoveryReport, LymmDeckError> {
    let started = Instant::now();
    validate_solver_config(config)?;
    if let Some(base) = planted_base {
        validate_permutation("hidden-base local planted base", base, config.n)?;
    }
    let spec = solver_spec(config)?;
    let search = run_local_search(config, &spec, pairs, planted_base)?;
    let representative_audit = representative_audit(
        &spec,
        pairs,
        search.representative_key.as_ref(),
        config.swap_budget,
        planted_base,
    )?;
    let state = classify_recovery(
        search.exact_candidate_count,
        search.planted_base_recovered,
        representative_audit.as_ref(),
    );

    Ok(HiddenBaseLocalRecoveryReport {
        state,
        config: config.clone(),
        brute_force_base_count: factorial_u128(config.n),
        sigma_domain_size: search.sigma_domain_size,
        attempts_run: search.attempts_run,
        candidate_evaluations: search.candidate_evaluations,
        replay_event_evaluations: search.replay_event_evaluations,
        joint_move_candidate_evaluations: search.joint_move_candidate_evaluations,
        joint_move_replay_event_evaluations: search.joint_move_replay_event_evaluations,
        joint_move_total_budget_exhausted: search.joint_move_total_budget_exhausted,
        joint_moves_accepted: search.joint_moves_accepted,
        joint_move_letter_pairs_eligible: search.joint_move_letter_pairs_eligible,
        joint_move_letter_pairs_evaluated: search.joint_move_letter_pairs_evaluated,
        joint_move_pair_evaluations_min: search.joint_move_pair_evaluations_min,
        joint_move_pair_evaluations_max: search.joint_move_pair_evaluations_max,
        triple_move_candidate_evaluations: search.triple_move_candidate_evaluations,
        triple_move_constraint_evaluations: search.triple_move_constraint_evaluations,
        triple_move_replay_event_evaluations: search.triple_move_replay_event_evaluations,
        triple_move_total_budget_exhausted: search.triple_move_total_budget_exhausted,
        triple_moves_accepted: search.triple_moves_accepted,
        triple_move_prefixes_eligible: search.triple_move_prefixes_eligible,
        triple_move_prefixes_evaluated: search.triple_move_prefixes_evaluated,
        prefix_cegar_hypotheses_attempted: search.prefix_cegar_hypotheses_attempted,
        prefix_cegar_hypotheses_unsat: search.prefix_cegar_hypotheses_unsat,
        prefix_cegar_hypotheses_capped: search.prefix_cegar_hypotheses_capped,
        prefix_cegar_models: search.prefix_cegar_models,
        prefix_cegar_clauses: search.prefix_cegar_clauses,
        prefix_cegar_replay_event_evaluations: search.prefix_cegar_replay_event_evaluations,
        prefix_cegar_exact_models: search.prefix_cegar_exact_models,
        prefix_cegar_core_size_min: search.prefix_cegar_core_size_min,
        prefix_cegar_core_size_max: search.prefix_cegar_core_size_max,
        prefix_cegar_total_budget_exhausted: search.prefix_cegar_total_budget_exhausted,
        state_sat_hypotheses_attempted: search.state_sat_hypotheses_attempted,
        state_sat_hypotheses_unsat: search.state_sat_hypotheses_unsat,
        state_sat_exact_models: search.state_sat_exact_models,
        state_sat_variables: search.state_sat_variables,
        state_sat_clauses: search.state_sat_clauses,
        state_sat_replay_event_evaluations: search.state_sat_replay_event_evaluations,
        state_sat_elapsed: search.state_sat_elapsed,
        top_source_hypotheses_retained: search.top_source_hypotheses_retained,
        planted_top_source_hypothesis_rank: search.planted_top_source_hypothesis_rank,
        planted_top_source_hypothesis_retained: search.planted_top_source_hypothesis_retained,
        top_source_states_expanded: search.top_source_states_expanded,
        top_source_states_pruned: search.top_source_states_pruned,
        top_source_states_dropped: search.top_source_states_dropped,
        top_source_constraint_evaluations: search.top_source_constraint_evaluations,
        top_source_third_symbol_evaluations: search.top_source_third_symbol_evaluations,
        top_source_elapsed: search.top_source_elapsed,
        exact_candidate_count: search.exact_candidate_count,
        planted_base_recovered: search.planted_base_recovered,
        observed_letters: search.observed_letters,
        anchored_letters: search.anchored_letters,
        event_count: search.event_count,
        best_mismatches: search.best_mismatches,
        best_round_trip: search.best_round_trip,
        elapsed: started.elapsed(),
        representative_key: search.representative_key,
        representative_audit,
    })
}

fn validate_solver_config(config: &HiddenBaseLocalSolverConfig) -> Result<(), LymmDeckError> {
    if config.n < 2 {
        return Err(LymmDeckError::DeckTooSmall { n: config.n });
    }
    if config.pt_alphabet.is_empty() {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "plaintext alphabet must not be empty",
        });
    }
    if !(2..=3).contains(&config.swap_budget) {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "hidden-base local solver currently requires s=2 or s=3",
        });
    }
    if config.attempts == 0 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "local solver attempts must be at least one",
        });
    }
    if config.max_rounds == 0 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "local solver max rounds must be at least one",
        });
    }
    if config.top_source_beam_width == 0 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "top-source beam width must be at least one",
        });
    }
    match config.generator_family {
        HiddenBaseLocalGeneratorFamily::TopCardSwaps => {}
    }
    Ok(())
}

fn solver_spec(config: &HiddenBaseLocalSolverConfig) -> Result<LymmDeckSpec, LymmDeckError> {
    let identity_base = (0..config.n).collect::<Vec<_>>();
    LymmDeckSpec::from_base(
        config.n,
        &config.pt_alphabet,
        &config.ct_alphabet,
        identity_base,
    )
}
