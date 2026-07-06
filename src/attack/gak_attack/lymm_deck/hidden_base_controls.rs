//! Controls for hidden-base GAK/deck identifiability audits.

use std::collections::BTreeMap;

use crate::nulls::null::{SplitMix64, mix_seed, shuffled_permutation};

use super::{
    HiddenBaseFixture, HiddenBaseFixtureConfig, HiddenBaseIdentifiabilityStatus, HiddenBaseKind,
    HiddenBaseSurfaceReport, LymmDeckError, LymmDeckSpec, audit_hidden_base_mapping,
    encrypt_lymm_deck, plant_hidden_base_fixture,
};

const NULL_SEED_TAG: u64 = 0x6862_6e75_6c6c_0004;

/// Expected outcome for a hidden-base audit control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseControlExpectation {
    /// The control should be accepted by exact re-encryption plus decomposition.
    Accept,
    /// The control should be rejected by the same surface.
    Reject,
}

/// One planted-positive or matched-null control leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseControlReport {
    /// Stable control name.
    pub name: &'static str,
    /// Expected accept/reject outcome.
    pub expectation: HiddenBaseControlExpectation,
    /// Observed accept/reject outcome.
    pub accepted: bool,
    /// Exact re-encryption flag.
    pub exact_round_trip: bool,
    /// Compatible hidden-base count.
    pub base_candidate_count: usize,
    /// Surface status.
    pub status: HiddenBaseIdentifiabilityStatus,
}

impl HiddenBaseControlReport {
    /// Whether the control matched its expectation.
    #[must_use]
    pub fn passed(&self) -> bool {
        match self.expectation {
            HiddenBaseControlExpectation::Accept => self.accepted,
            HiddenBaseControlExpectation::Reject => !self.accepted,
        }
    }
}

/// Self-test report for the hidden-base audit instrument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseAuditSelfTestReport {
    /// Planted in-model positive control.
    pub planted_positive: HiddenBaseControlReport,
    /// Random full-permutation key null.
    pub random_full_key_null: HiddenBaseControlReport,
    /// Over-budget key attacked below its planted budget.
    pub over_budget_low_null: HiddenBaseControlReport,
    /// The same over-budget key at its true budget.
    pub over_budget_positive: HiddenBaseControlReport,
    /// Ciphertext-label-shuffle null.
    pub ciphertext_label_shuffle_null: HiddenBaseControlReport,
}

impl HiddenBaseAuditSelfTestReport {
    /// Returns true when the positive controls accept and all matched nulls
    /// reject under the same audit surface.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.planted_positive.passed()
            && self.random_full_key_null.passed()
            && self.over_budget_low_null.passed()
            && self.over_budget_positive.passed()
            && self.ciphertext_label_shuffle_null.passed()
    }
}

/// Runs the hidden-base planted-positive and matched-null controls.
///
/// # Errors
/// Returns [`LymmDeckError`] if a control fixture cannot be constructed.
pub fn hidden_base_audit_self_test(
    seed: u64,
) -> Result<HiddenBaseAuditSelfTestReport, LymmDeckError> {
    let positive_config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 2,
        message_count: 8,
        message_len: 48,
        seed,
        base_kind: HiddenBaseKind::Random,
    };
    let positive_fixture = plant_hidden_base_fixture(&positive_config)?;
    let positive_surface = audit_hidden_base_mapping(
        &positive_fixture.spec,
        &positive_fixture.pairs,
        &positive_fixture.planted.pt_mapping,
        positive_config.swap_budget,
        Some(&positive_fixture.spec.base),
    )?;
    let planted_positive = control_report(
        "planted-positive",
        HiddenBaseControlExpectation::Accept,
        &positive_surface,
    );

    let random_full_key_null = random_full_key_control(&positive_fixture, seed)?;
    let (over_budget_low_null, over_budget_positive) = over_budget_controls(seed)?;
    let ciphertext_label_shuffle_null = label_shuffle_control(&positive_fixture)?;

    Ok(HiddenBaseAuditSelfTestReport {
        planted_positive,
        random_full_key_null,
        over_budget_low_null,
        over_budget_positive,
        ciphertext_label_shuffle_null,
    })
}

fn random_full_key_control(
    fixture: &HiddenBaseFixture,
    seed: u64,
) -> Result<HiddenBaseControlReport, LymmDeckError> {
    for attempt in 0..32usize {
        let mapping_seed = mix_seed(seed, NULL_SEED_TAG ^ u64::try_from(attempt).unwrap_or(0));
        let mapping = random_full_mapping(&fixture.spec, mapping_seed)?;
        let pairs = pairs_for_mapping(&fixture.spec, &fixture.pairs, &mapping)?;
        let surface = audit_hidden_base_mapping(
            &fixture.spec,
            &pairs,
            &mapping,
            fixture.config.swap_budget,
            Some(&fixture.spec.base),
        )?;
        if !surface.accepted() {
            return Ok(control_report(
                "random-full-permutation-key-null",
                HiddenBaseControlExpectation::Reject,
                &surface,
            ));
        }
    }
    Err(LymmDeckError::HiddenBaseConfig {
        reason: "random full-key null did not produce a rejecting fixture",
    })
}

fn random_full_mapping(
    spec: &LymmDeckSpec,
    seed: u64,
) -> Result<BTreeMap<char, Vec<usize>>, LymmDeckError> {
    let mut rng = SplitMix64::new(seed);
    let mut mapping = BTreeMap::new();
    for &letter in &spec.pt_alphabet {
        let perm = shuffled_permutation(spec.n, &mut rng)?;
        let _old = mapping.insert(letter, perm);
    }
    Ok(mapping)
}

fn pairs_for_mapping(
    spec: &LymmDeckSpec,
    shape_pairs: &[super::KnownPlaintextPair],
    mapping: &BTreeMap<char, Vec<usize>>,
) -> Result<Vec<super::KnownPlaintextPair>, LymmDeckError> {
    shape_pairs
        .iter()
        .map(|pair| {
            Ok(super::KnownPlaintextPair {
                label: pair.label.clone(),
                plaintext: pair.plaintext.clone(),
                ciphertext: encrypt_lymm_deck(spec, mapping, &pair.plaintext)?,
            })
        })
        .collect()
}

fn over_budget_controls(
    seed: u64,
) -> Result<(HiddenBaseControlReport, HiddenBaseControlReport), LymmDeckError> {
    for attempt in 0..64usize {
        let fixture_seed = mix_seed(
            seed,
            0x6862_6f76_6572_0000 ^ u64::try_from(attempt).unwrap_or(0),
        );
        let config = HiddenBaseFixtureConfig {
            n: 7,
            pt_alphabet: "ABCDEF".to_owned(),
            swap_budget: 2,
            message_count: 8,
            message_len: 48,
            seed: fixture_seed,
            base_kind: HiddenBaseKind::Random,
        };
        let fixture = plant_hidden_base_fixture(&config)?;
        let low_surface = audit_hidden_base_mapping(
            &fixture.spec,
            &fixture.pairs,
            &fixture.planted.pt_mapping,
            1,
            Some(&fixture.spec.base),
        )?;
        let high_surface = audit_hidden_base_mapping(
            &fixture.spec,
            &fixture.pairs,
            &fixture.planted.pt_mapping,
            2,
            Some(&fixture.spec.base),
        )?;
        if !low_surface.accepted() && high_surface.accepted() {
            return Ok((
                control_report(
                    "over-budget-key-null",
                    HiddenBaseControlExpectation::Reject,
                    &low_surface,
                ),
                control_report(
                    "over-budget-true-budget-positive",
                    HiddenBaseControlExpectation::Accept,
                    &high_surface,
                ),
            ));
        }
    }
    Err(LymmDeckError::HiddenBaseConfig {
        reason: "over-budget null did not produce a rejecting lower-budget fixture",
    })
}

fn label_shuffle_control(
    fixture: &HiddenBaseFixture,
) -> Result<HiddenBaseControlReport, LymmDeckError> {
    let mut shuffled_pairs = fixture.pairs.clone();
    let mut alphabet = fixture.spec.ct_alphabet.clone();
    if alphabet.len() > 1 {
        alphabet.swap(0, 1);
    }
    let substitution = fixture
        .spec
        .ct_alphabet
        .iter()
        .copied()
        .zip(alphabet)
        .collect::<BTreeMap<_, _>>();
    for pair in &mut shuffled_pairs {
        pair.ciphertext = pair
            .ciphertext
            .chars()
            .map(|ch| substitution.get(&ch).copied().unwrap_or(ch))
            .collect();
    }
    let surface = audit_hidden_base_mapping(
        &fixture.spec,
        &shuffled_pairs,
        &fixture.planted.pt_mapping,
        fixture.config.swap_budget,
        Some(&fixture.spec.base),
    )?;
    Ok(control_report(
        "ciphertext-label-shuffle-null",
        HiddenBaseControlExpectation::Reject,
        &surface,
    ))
}

fn control_report(
    name: &'static str,
    expectation: HiddenBaseControlExpectation,
    surface: &HiddenBaseSurfaceReport,
) -> HiddenBaseControlReport {
    HiddenBaseControlReport {
        name,
        expectation,
        accepted: surface.accepted(),
        exact_round_trip: surface.round_trip.exact,
        base_candidate_count: surface.base_candidate_count,
        status: surface.status,
    }
}
