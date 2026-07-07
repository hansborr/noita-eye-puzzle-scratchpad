//! Tests for hidden-base fixture and identifiability audit plumbing.

use std::collections::BTreeMap;

use super::{
    DEFAULT_HIDDEN_BASE_AUDIT_SEED, HiddenBaseAuditConfig, HiddenBaseFixtureConfig,
    HiddenBaseIdentifiabilityStatus, HiddenBaseKind, HiddenBaseS1RecoveryState,
    HiddenBaseS1SolverConfig, KnownPlaintextPair, LymmDeckSpec, audit_hidden_base_mapping,
    encrypt_lymm_deck, hidden_base_audit_self_test, plant_hidden_base_fixture,
    recover_hidden_base_s1_known_plaintext, recover_hidden_base_s1_known_plaintext_with_audit,
    run_hidden_base_identifiability_audit,
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

#[test]
fn hidden_base_acceptance_requires_compatible_base_without_planted_base() {
    let spec = LymmDeckSpec::from_base(5, "AB", "abcde", vec![0, 1, 2, 3, 4]).expect("spec");
    let mut mapping = BTreeMap::new();
    let _old = mapping.insert('A', vec![0, 1, 2, 3, 4]);
    let _old = mapping.insert('B', vec![0, 2, 1, 3, 4]);
    let plaintext = "ABBA".to_owned();
    let ciphertext = encrypt_lymm_deck(&spec, &mapping, &plaintext).expect("encrypt");
    let pairs = vec![KnownPlaintextPair {
        label: "fixture".to_owned(),
        plaintext,
        ciphertext,
    }];

    let report = audit_hidden_base_mapping(&spec, &pairs, &mapping, 1, None).expect("audit");

    assert!(report.round_trip.exact);
    assert_eq!(report.base_candidate_count, 0);
    assert_eq!(
        report.status,
        HiddenBaseIdentifiabilityStatus::NoCompatibleBase
    );
    assert!(!report.accepted());
}

#[test]
fn hidden_base_s1_solver_recovers_planted_positive() {
    let config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 1,
        message_count: 8,
        message_len: 48,
        seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let solver_config = s1_solver_config(&fixture.spec);
    let report = recover_hidden_base_s1_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("s1 recovery");

    assert_eq!(
        report.state,
        HiddenBaseS1RecoveryState::RecoveredPlantedBase
    );
    assert!(report.has_exact_recovery());
    assert_eq!(report.brute_force_base_count, Some(5_040));
    assert_eq!(report.base_candidates_tested, 5_040);
    assert_eq!(report.exact_candidate_count, 1);
    assert_eq!(report.planted_base_recovered, Some(true));
    assert_eq!(report.event_count, 384);
    assert!(report.representative_key.is_some());
    let audit = report.representative_audit.expect("audit");
    assert!(audit.round_trip.exact);
    assert_eq!(audit.base_candidate_count, 1);
}

#[test]
fn hidden_base_s1_solver_rejects_ciphertext_label_shuffle_null() {
    let config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 1,
        message_count: 8,
        message_len: 48,
        seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let mut shuffled_pairs = fixture.pairs.clone();
    for pair in &mut shuffled_pairs {
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
    let solver_config = s1_solver_config(&fixture.spec);
    let report = recover_hidden_base_s1_known_plaintext_with_audit(
        &solver_config,
        &shuffled_pairs,
        Some(&fixture.spec.base),
    )
    .expect("s1 recovery");

    assert_eq!(report.state, HiddenBaseS1RecoveryState::NoCandidate);
    assert!(!report.has_exact_recovery());
    assert_eq!(report.base_candidates_tested, 5_040);
    assert_eq!(report.exact_candidate_count, 0);
}

#[test]
fn hidden_base_s1_solver_rejects_over_budget_null() {
    let fixture = (0..64usize)
        .find_map(|attempt| {
            let config = HiddenBaseFixtureConfig {
                n: 7,
                pt_alphabet: "ABCDEF".to_owned(),
                swap_budget: 2,
                message_count: 8,
                message_len: 48,
                seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED ^ u64::try_from(attempt).ok()?,
                base_kind: HiddenBaseKind::Random,
            };
            let fixture = plant_hidden_base_fixture(&config).ok()?;
            let solver_config = s1_solver_config(&fixture.spec);
            let report = recover_hidden_base_s1_known_plaintext_with_audit(
                &solver_config,
                &fixture.pairs,
                Some(&fixture.spec.base),
            )
            .ok()?;
            (report.state == HiddenBaseS1RecoveryState::NoCandidate).then_some(fixture)
        })
        .expect("rejecting over-budget fixture");
    let solver_config = s1_solver_config(&fixture.spec);
    let report = recover_hidden_base_s1_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("s1 recovery");

    assert_eq!(report.state, HiddenBaseS1RecoveryState::NoCandidate);
    assert_eq!(report.exact_candidate_count, 0);
}

#[test]
fn hidden_base_s1_solver_reports_ambiguous_equivalent_class() {
    let config = HiddenBaseFixtureConfig {
        n: 5,
        pt_alphabet: "A".to_owned(),
        swap_budget: 1,
        message_count: 1,
        message_len: 1,
        seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let solver_config = s1_solver_config(&fixture.spec);
    let report = recover_hidden_base_s1_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("s1 recovery");

    assert_eq!(
        report.state,
        HiddenBaseS1RecoveryState::AmbiguousEquivalentClass
    );
    assert_eq!(report.brute_force_base_count, Some(120));
    assert_eq!(report.base_candidates_tested, 120);
    assert_eq!(report.exact_candidate_count, 120);
    assert_eq!(report.planted_base_recovered, Some(true));
}

#[test]
fn hidden_base_s1_solver_reports_search_cap() {
    let config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 1,
        message_count: 8,
        message_len: 48,
        seed: DEFAULT_HIDDEN_BASE_AUDIT_SEED,
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let solver_config = s1_solver_config(&fixture.spec).with_max_base_candidates(Some(10));
    let report = recover_hidden_base_s1_known_plaintext(&solver_config, &fixture.pairs)
        .expect("s1 recovery");

    assert_eq!(report.state, HiddenBaseS1RecoveryState::SearchCapExceeded);
    assert_eq!(report.base_candidates_tested, 10);
    assert_eq!(report.brute_force_base_count, Some(5_040));
}

fn s1_solver_config(spec: &LymmDeckSpec) -> HiddenBaseS1SolverConfig {
    HiddenBaseS1SolverConfig::top_card_swaps(spec.n, spec.pt_alphabet.iter().collect::<String>())
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
}
