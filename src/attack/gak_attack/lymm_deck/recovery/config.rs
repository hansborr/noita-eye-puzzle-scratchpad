//! Configuration types for Lymm swap recovery.

use std::collections::BTreeMap;
use std::time::Duration;

use super::super::LymmGeneratorSet;

/// Generator family admitted by `recover_known_plaintext_swaps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryGeneratorSet {
    /// Lymm's original top-swap generator family `{(0 k)}`.
    TopSwaps,
    /// Explicit generator-file family. Words are reported as generator row
    /// indexes rather than top-swap positions.
    Explicit(LymmGeneratorSet),
}

/// Recovery backend selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapRecoveryStrategy {
    /// Use the complete systematic path where it is cheap, and the local-search
    /// path for the measured ns=3 top-swap practice-puzzle surface.
    Auto,
    /// Force the propagation/SAT residual machinery.
    Systematic,
    /// Force substitution-first local search.
    LocalSearch,
}

impl RecoveryGeneratorSet {
    /// Returns true for the specialized top-swap family.
    #[must_use]
    pub const fn is_top_swaps(&self) -> bool {
        matches!(self, Self::TopSwaps)
    }
}

/// Search controls for `recover_known_plaintext_swaps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapRecoveryConfig {
    /// Maximum generator-word budget to admit into each per-letter domain.
    pub max_swaps: usize,
    /// Generator family used to build per-letter domains.
    pub generator_set: RecoveryGeneratorSet,
    /// Optional cap for residual-solver candidate models.
    pub max_nodes: Option<usize>,
    /// Optional wall-clock budget for the residual solver.
    pub time_budget: Option<Duration>,
    /// Recovery backend selection.
    pub strategy: SwapRecoveryStrategy,
    pub(super) planted_truth: Option<BTreeMap<char, Vec<usize>>>,
}

impl SwapRecoveryConfig {
    /// Builds a config with only the top-swap budget set.
    #[must_use]
    pub const fn with_max_swaps(max_swaps: usize) -> Self {
        Self {
            max_swaps,
            generator_set: RecoveryGeneratorSet::TopSwaps,
            max_nodes: None,
            time_budget: None,
            strategy: SwapRecoveryStrategy::Auto,
            planted_truth: None,
        }
    }

    /// Replaces the generator family.
    #[must_use]
    pub fn with_generator_set(mut self, generator_set: RecoveryGeneratorSet) -> Self {
        self.generator_set = generator_set;
        self
    }

    /// Replaces the recovery backend strategy.
    #[must_use]
    pub const fn with_strategy(mut self, strategy: SwapRecoveryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Adds observational planted truth for production-path soundness controls.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_planted_truth(mut self, planted_truth: BTreeMap<char, Vec<usize>>) -> Self {
        self.planted_truth = Some(planted_truth);
        self
    }

    /// Returns observational planted truth for internal controls.
    pub(super) fn planted_truth(&self) -> Option<&BTreeMap<char, Vec<usize>>> {
        self.planted_truth.as_ref()
    }
}
