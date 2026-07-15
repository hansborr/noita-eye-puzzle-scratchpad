//! Lymm's deck-cipher convention for the community GAK swap-recovery corpus.
//!
//! This module is the Task-01 foundation for the known-plaintext swap-recovery
//! instrument described in `research/handoff/gak-swap-recovery/`: an exact
//! parameterized oracle, planted top-swap key generation, top-swap domain
//! enumeration, and the labeled known-plaintext corpus parser. It deliberately
//! implements Lymm's `state = state[perm[i]]` update directly instead of routing
//! through [`crate::ciphers::GakKey`], whose readout convention is different.

mod corpus;
mod domain;
mod error;
mod generators;
mod hidden_base;
mod hidden_base_controls;
mod hidden_base_fixture;
mod hidden_base_local;
mod hidden_base_s1;
mod hidden_base_s1_core;
mod oracle;
mod plant;
mod recovery;
mod share;
mod spec;

#[cfg(test)]
mod generator_tests;
#[cfg(test)]
mod hidden_base_tests;
#[cfg(test)]
mod ns3_probe;
#[cfg(test)]
mod share_tests;
#[cfg(test)]
mod tests;

pub use corpus::{KnownPlaintextPair, parse_known_plaintext_pairs};
pub use domain::{
    GeneratorBranchStrategy, TopSwapCandidate, TopSwapConstraints, TopSwapDomains,
    enumerate_top_swap_domains,
};
pub use error::LymmDeckError;
pub use generators::{LymmGeneratorSet, enumerate_generator_domains};
pub use hidden_base::{
    DEFAULT_HIDDEN_BASE_AUDIT_SEED, HiddenBaseAuditConfig, HiddenBaseAuditReport,
    HiddenBaseFixture, HiddenBaseFixtureConfig, HiddenBaseIdentifiabilityStatus, HiddenBaseKind,
    HiddenBaseRoundTrip, HiddenBaseSurfaceReport, HiddenBaseTrialReport, audit_hidden_base_mapping,
    run_hidden_base_identifiability_audit,
};
pub use hidden_base_controls::{
    HiddenBaseAuditSelfTestReport, HiddenBaseControlExpectation, HiddenBaseControlReport,
    hidden_base_audit_self_test,
};
pub use hidden_base_fixture::plant_hidden_base_fixture;
pub use hidden_base_local::{
    HiddenBaseLocalControlExpectation, HiddenBaseLocalControlReport,
    HiddenBaseLocalGeneratorFamily, HiddenBaseLocalJointMoveOrder, HiddenBaseLocalRecoveredKey,
    HiddenBaseLocalRecoveryReport, HiddenBaseLocalRecoveryState, HiddenBaseLocalSelfTestReport,
    HiddenBaseLocalSolverConfig, hidden_base_local_self_test,
    recover_hidden_base_local_known_plaintext,
    recover_hidden_base_local_known_plaintext_with_audit,
};
pub use hidden_base_s1::{
    HiddenBaseS1GeneratorFamily, HiddenBaseS1RecoveredKey, HiddenBaseS1RecoveryReport,
    HiddenBaseS1RecoveryState, HiddenBaseS1SolverConfig, recover_hidden_base_s1_known_plaintext,
    recover_hidden_base_s1_known_plaintext_with_audit,
};
pub use oracle::encrypt_lymm_deck;
pub use plant::{PlantedLymmMapping, generate_random_pt_mapping};
pub use recovery::{
    DEFAULT_ARC_PHASE0_REJECTION_CAP, DEFAULT_ARC_PHASE0_REPLAY_CAP,
    DEFAULT_ARC_PHASE0_SPOT_CHECKS, DEFAULT_ARC_PHASE0_WALL_SECS, DEFAULT_SWAP_RECOVERY_SEED,
    GakSwapArcContextBin, GakSwapArcControlLeg, GakSwapArcLiteral, GakSwapArcPhase0Config,
    GakSwapArcPhase0ControlsReport, GakSwapArcPhase0Report, GakSwapArcPhase0Stop,
    GakSwapArcRejection, GakSwapArcTupleKillEstimate, GakSwapReachStressCase,
    GakSwapReachStressConfig, GakSwapReachStressReport, GakSwapSelfTestConfig,
    GakSwapSelfTestReport, LetterRecoveryVerdict, NullControlOutcome, NullControlReport,
    PositiveControlReport, RecoveredLetter, RecoveryGeneratorSet, RecoveryReport, RoundTripReport,
    SUPPORTED_SWAP_RECOVERY_FRONTIER, SWAP_RECOVERY_FRONTIER_MESSAGE, SwapInferenceAttempt,
    SwapInferenceOutcome, SwapInferenceRange, SwapInferenceReport, SwapRecoveryConfig,
    SwapRecoveryError, SwapRecoveryStats, SwapRecoveryStrategy, gak_swap_arc_phase0_controls,
    gak_swap_reach_stress_self_test, gak_swap_self_test, infer_known_plaintext_swap_budget,
    measure_ns3_arc_provenance, measure_ns3_arc_provenance_with_sink,
    recover_known_plaintext_swaps, round_trip_check,
};
pub use share::python_pt_mapping_literal;
pub use spec::{
    LYMM_DEFAULT_DECIMATION, LYMM_DEFAULT_N, LYMM_DEFAULT_PT_ALPHABET, LYMM_DEFAULT_SHIFT,
    LymmComposeDirection, LymmDeckSpec, lymm_default_ct_alphabet,
};

pub(crate) use oracle::compose_lymm;
