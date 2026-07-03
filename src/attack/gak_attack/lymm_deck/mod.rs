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
mod oracle;
mod plant;
mod recovery;
mod spec;

#[cfg(test)]
mod tests;

pub use corpus::{KnownPlaintextPair, parse_known_plaintext_pairs};
pub use domain::{
    TopSwapCandidate, TopSwapConstraints, TopSwapDomains, enumerate_top_swap_domains,
};
pub use error::LymmDeckError;
pub use oracle::encrypt_lymm_deck;
pub use plant::{PlantedLymmMapping, generate_random_pt_mapping};
pub use recovery::{
    DEFAULT_SWAP_RECOVERY_SEED, GakSwapSelfTestConfig, GakSwapSelfTestReport,
    LetterRecoveryVerdict, NullControlOutcome, NullControlReport, PositiveControlReport,
    RecoveredLetter, RecoveryReport, RoundTripReport, SwapRecoveryConfig, SwapRecoveryError,
    SwapRecoveryStats, gak_swap_self_test, recover_known_plaintext_swaps, round_trip_check,
};
pub use spec::{
    LYMM_DEFAULT_DECIMATION, LYMM_DEFAULT_N, LYMM_DEFAULT_PT_ALPHABET, LYMM_DEFAULT_SHIFT,
    LymmComposeDirection, LymmDeckSpec, lymm_default_ct_alphabet,
};

pub(crate) use oracle::compose_lymm;
