//! Controls for hidden-base local recovery.

use crate::nulls::null::mix_seed;

use super::super::{
    HiddenBaseFixture, HiddenBaseFixtureConfig, HiddenBaseKind, KnownPlaintextPair, LymmDeckError,
    plant_hidden_base_fixture,
};
use super::{
    HiddenBaseLocalRecoveryState, HiddenBaseLocalSolverConfig,
    recover_hidden_base_local_known_plaintext_with_audit,
};

/// Swaps two ciphertext labels after each message's first emitted symbol.
///
/// Preserving the first emission keeps identity-restart anchor constraints
/// intact, so the transformed corpus exercises downstream recovery rather than
/// being rejected at top-source construction. The returned count is the number
/// of changed ciphertext symbols.
#[must_use]
pub fn post_anchor_ciphertext_label_swap(
    pairs: &[KnownPlaintextPair],
    first: char,
    second: char,
) -> (Vec<KnownPlaintextPair>, usize) {
    if first == second {
        return (pairs.to_vec(), 0);
    }
    let mut changed = 0usize;
    let mut transformed = pairs.to_vec();
    for pair in &mut transformed {
        pair.ciphertext = pair
            .ciphertext
            .chars()
            .enumerate()
            .map(|(index, ch)| match (index, ch) {
                (0, _) => ch,
                (_, current) if current == first => {
                    changed = changed.saturating_add(1);
                    second
                }
                (_, current) if current == second => {
                    changed = changed.saturating_add(1);
                    first
                }
                (_, current) => current,
            })
            .collect();
    }
    (transformed, changed)
}

/// Runs deterministic planted-positive and matched-null controls for the local
/// hidden-base solver.
///
/// # Errors
/// Returns [`LymmDeckError`] if a control fixture cannot be generated or scored.
pub fn hidden_base_local_self_test(
    seed: u64,
) -> Result<HiddenBaseLocalSelfTestReport, LymmDeckError> {
    let s2_fixture = plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 2,
        message_count: 8,
        message_len: 48,
        seed: mix_seed(seed, 0x6c6f_6361_6c73_3200),
        base_kind: HiddenBaseKind::Random,
    })?;
    let s2_positive = run_control(
        "planted-s2-positive",
        HiddenBaseLocalControlExpectation::ExactRecovery,
        &s2_fixture,
        2,
        seed,
    )?;

    let s3_fixture = plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 5,
        pt_alphabet: "ABCD".to_owned(),
        swap_budget: 3,
        message_count: 6,
        message_len: 48,
        seed: mix_seed(seed, 0x6c6f_6361_6c73_3300),
        base_kind: HiddenBaseKind::Random,
    })?;
    let s3_positive = run_control(
        "planted-s3-positive",
        HiddenBaseLocalControlExpectation::ExactRecovery,
        &s3_fixture,
        3,
        seed,
    )?;

    let mut shuffled_fixture = s2_fixture.clone();
    for pair in &mut shuffled_fixture.pairs {
        pair.ciphertext = pair
            .ciphertext
            .chars()
            .map(|ch| match ch {
                '!' => '"',
                '"' => '!',
                other => other,
            })
            .collect();
    }
    let label_shuffle = run_control(
        "ciphertext-label-shuffle-null",
        HiddenBaseLocalControlExpectation::NoExactWithinBudget,
        &shuffled_fixture,
        2,
        seed,
    )?;

    let over_budget_fixture = plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 3,
        message_count: 8,
        message_len: 48,
        seed: mix_seed(seed, 0x6c6f_6361_6c6f_7600),
        base_kind: HiddenBaseKind::Random,
    })?;
    let over_budget = run_control(
        "over-budget-s3-as-s2-null",
        HiddenBaseLocalControlExpectation::NoExactWithinBudget,
        &over_budget_fixture,
        2,
        seed,
    )?;

    Ok(HiddenBaseLocalSelfTestReport {
        s2_positive,
        s3_positive,
        label_shuffle,
        over_budget,
    })
}

fn run_control(
    name: &'static str,
    expectation: HiddenBaseLocalControlExpectation,
    fixture: &HiddenBaseFixture,
    swap_budget: usize,
    seed: u64,
) -> Result<HiddenBaseLocalControlReport, LymmDeckError> {
    let config = HiddenBaseLocalSolverConfig::top_card_swaps(
        fixture.spec.n,
        fixture.spec.pt_alphabet.iter().collect::<String>(),
        swap_budget,
    )
    .with_ct_alphabet(fixture.spec.ct_alphabet.iter().collect::<String>())
    .with_seed(mix_seed(
        seed,
        0x6c6f_6361_6c63_7472 ^ u64::try_from(swap_budget).unwrap_or(0),
    ))
    .with_attempts(96)
    .with_max_rounds(18);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )?;
    Ok(HiddenBaseLocalControlReport {
        name,
        expectation,
        observed: report.state,
        exact: report.has_exact_recovery(),
        best_mismatches: report.best_mismatches,
        attempts_run: report.attempts_run,
    })
}

/// Expected result for one local-solver control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseLocalControlExpectation {
    /// A planted exact key must be recovered.
    ExactRecovery,
    /// No exact key should be found within the bounded local-search budget.
    NoExactWithinBudget,
}

impl HiddenBaseLocalControlExpectation {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactRecovery => "exact-recovery",
            Self::NoExactWithinBudget => "no-exact-within-budget",
        }
    }
}

/// One deterministic local-solver control result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseLocalControlReport {
    /// Control name.
    pub name: &'static str,
    /// Expected outcome.
    pub expectation: HiddenBaseLocalControlExpectation,
    /// Observed recovery state.
    pub observed: HiddenBaseLocalRecoveryState,
    /// Whether an exact key was found.
    pub exact: bool,
    /// Best mismatch count observed.
    pub best_mismatches: usize,
    /// Number of local-search restarts run.
    pub attempts_run: usize,
}

impl HiddenBaseLocalControlReport {
    /// Returns true when the control matched its expected exact/non-exact
    /// outcome.
    #[must_use]
    pub fn passed(&self) -> bool {
        match self.expectation {
            HiddenBaseLocalControlExpectation::ExactRecovery => self.exact,
            HiddenBaseLocalControlExpectation::NoExactWithinBudget => !self.exact,
        }
    }
}

/// Aggregate deterministic control report for the local hidden-base solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseLocalSelfTestReport {
    /// Planted `s=2` positive control.
    pub s2_positive: HiddenBaseLocalControlReport,
    /// Planted `s=3` positive control.
    pub s3_positive: HiddenBaseLocalControlReport,
    /// Ciphertext-label shuffle matched null.
    pub label_shuffle: HiddenBaseLocalControlReport,
    /// `s=3` fixture attacked as `s=2` over-budget null.
    pub over_budget: HiddenBaseLocalControlReport,
}

impl HiddenBaseLocalSelfTestReport {
    /// Returns true when every control passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.s2_positive.passed()
            && self.s3_positive.passed()
            && self.label_shuffle.passed()
            && self.over_budget.passed()
    }
}
