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
    audit_hidden_base_mapping, lymm_default_ct_alphabet,
};

#[path = "hidden_base_local/controls.rs"]
mod controls;
#[path = "hidden_base_local/corpus.rs"]
mod corpus;
#[path = "hidden_base_local/joint.rs"]
mod joint;
#[path = "hidden_base_local/search.rs"]
mod search;
#[path = "hidden_base_local/top_source.rs"]
mod top_source;

pub use controls::{
    HiddenBaseLocalControlExpectation, HiddenBaseLocalControlReport, HiddenBaseLocalSelfTestReport,
    hidden_base_local_self_test,
};
use search::run_local_search;

const DEFAULT_ATTEMPTS: usize = 96;
const DEFAULT_ROUNDS: usize = 18;
const DEFAULT_TOP_SOURCE_BEAM_WIDTH: usize = 96;
const DEFAULT_JOINT_MOVE_EVALUATION_CAP: usize = 4_096;
const DEFAULT_SEED: u64 = 0x6761_6b5f_6862_6c73;

/// Generator family admitted by the hidden-base local solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseLocalGeneratorFamily {
    /// The top-card transposition family `{(0,k)}`.
    TopCardSwaps,
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
    /// Maximum top-source hypotheses retained for sigma refinement.
    pub top_source_beam_width: usize,
    /// Maximum two-letter sigma assignments scored per stalled `s=3` restart.
    /// Zero disables joint moves.
    pub joint_move_evaluation_cap: usize,
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
            joint_move_evaluation_cap: DEFAULT_JOINT_MOVE_EVALUATION_CAP,
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

    /// Replaces the top-source hypothesis beam width.
    #[must_use]
    pub const fn with_top_source_beam_width(mut self, width: usize) -> Self {
        self.top_source_beam_width = width;
        self
    }

    /// Replaces the per-restart two-letter sigma evaluation cap.
    #[must_use]
    pub const fn with_joint_move_evaluation_cap(mut self, cap: usize) -> Self {
        self.joint_move_evaluation_cap = cap;
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
    /// Improving two-letter sigma moves accepted by the local search.
    pub joint_moves_accepted: usize,
    /// Complete top-source hypotheses retained for sigma refinement.
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
        joint_moves_accepted: search.joint_moves_accepted,
        top_source_hypotheses_retained: search.top_source_hypotheses_retained,
        planted_top_source_hypothesis_rank: search.planted_top_source_hypothesis_rank,
        planted_top_source_hypothesis_retained: search.planted_top_source_hypothesis_retained,
        top_source_states_expanded: search.top_source_states_expanded,
        top_source_states_pruned: search.top_source_states_pruned,
        top_source_states_dropped: search.top_source_states_dropped,
        top_source_constraint_evaluations: search.top_source_constraint_evaluations,
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

fn representative_audit(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    key: Option<&HiddenBaseLocalRecoveredKey>,
    swap_budget: usize,
    planted_base: Option<&[usize]>,
) -> Result<Option<HiddenBaseSurfaceReport>, LymmDeckError> {
    let Some(key) = key else {
        return Ok(None);
    };
    let audit_spec = LymmDeckSpec::from_base(
        spec.n,
        &spec.pt_alphabet.iter().collect::<String>(),
        &spec.ct_alphabet.iter().collect::<String>(),
        key.base.clone(),
    )?;
    audit_hidden_base_mapping(
        &audit_spec,
        pairs,
        &key.pt_mapping,
        swap_budget,
        planted_base,
    )
    .map(Some)
}

fn classify_recovery(
    exact_candidate_count: usize,
    planted_base_recovered: Option<bool>,
    representative_audit: Option<&HiddenBaseSurfaceReport>,
) -> HiddenBaseLocalRecoveryState {
    if exact_candidate_count == 0 {
        return HiddenBaseLocalRecoveryState::SearchCapExceeded;
    }
    if exact_candidate_count > 1
        || representative_audit.is_some_and(|audit| audit.base_candidate_count > 1)
    {
        return HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass;
    }
    if planted_base_recovered == Some(true) {
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    } else {
        HiddenBaseLocalRecoveryState::RecoveredEquivalentKey
    }
}

fn factorial_u128(n: usize) -> Option<u128> {
    let mut value = 1u128;
    for factor in 2..=n {
        value = value.checked_mul(u128::try_from(factor).ok()?)?;
    }
    Some(value)
}
