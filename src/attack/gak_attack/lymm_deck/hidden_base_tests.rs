//! Tests for hidden-base fixture and identifiability audit plumbing.

use super::{
    DEFAULT_HIDDEN_BASE_AUDIT_SEED, HiddenBaseAuditConfig, HiddenBaseFixtureConfig,
    HiddenBaseIdentifiabilityStatus, HiddenBaseKind, audit_hidden_base_mapping,
    hidden_base_audit_self_test, plant_hidden_base_fixture, run_hidden_base_identifiability_audit,
};

#[test]
fn hidden_base_fixture_positive_retains_planted_base() {
    let config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 1,
        message_count: 6,
        message_len: 32,
        seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let report = audit_hidden_base_mapping(
        &fixture.spec,
        &fixture.pairs,
        &fixture.planted.pt_mapping,
        config.swap_budget,
        Some(&fixture.spec.base),
    )
    .expect("audit");

    assert!(report.round_trip.exact);
    assert_eq!(report.planted_base_in_candidates, Some(true));
    assert!(matches!(
        report.status,
        HiddenBaseIdentifiabilityStatus::PlantedBaseUnique
            | HiddenBaseIdentifiabilityStatus::EquivalentBaseClass
    ));
}

#[test]
fn hidden_base_audit_batch_runs_deterministic_trials() {
    let config = HiddenBaseAuditConfig {
        fixture: HiddenBaseFixtureConfig {
            n: 7,
            pt_alphabet: "ABCDEF".to_owned(),
            swap_budget: 2,
            message_count: 8,
            message_len: 48,
            seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
            base_kind: HiddenBaseKind::Random,
        },
        trials: 3,
    };
    let report = run_hidden_base_identifiability_audit(&config).expect("audit");

    assert_eq!(report.trials.len(), 3);
    assert!(report.passed());
    assert_eq!(
        report.status_count(HiddenBaseIdentifiabilityStatus::NoCompatibleBase),
        0
    );
}

#[test]
fn hidden_base_controls_fire_positive_and_matched_nulls() {
    let report = hidden_base_audit_self_test(DEFAULT_HIDDEN_BASE_AUDIT_SEED).expect("controls");

    assert!(report.planted_positive.accepted);
    assert!(!report.random_full_key_null.accepted);
    assert!(!report.over_budget_low_null.accepted);
    assert!(report.over_budget_positive.accepted);
    assert!(!report.ciphertext_label_shuffle_null.accepted);
    assert!(report.passed());
}
