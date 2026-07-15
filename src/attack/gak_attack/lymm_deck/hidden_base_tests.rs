//! Tests for hidden-base fixture and identifiability audit plumbing.

use std::collections::BTreeMap;

use super::{
    DEFAULT_HIDDEN_BASE_AUDIT_SEED, HiddenBaseAuditConfig, HiddenBaseFixtureConfig,
    HiddenBaseIdentifiabilityStatus, HiddenBaseKind, HiddenBaseLocalJointMoveOrder,
    HiddenBaseLocalRecoveryState, HiddenBaseLocalSolverConfig, HiddenBaseS1RecoveryState,
    HiddenBaseS1SolverConfig, KnownPlaintextPair, LymmDeckSpec, audit_hidden_base_mapping,
    encrypt_lymm_deck, hidden_base_audit_self_test, hidden_base_local_self_test,
    plant_hidden_base_fixture, recover_hidden_base_local_known_plaintext_with_audit,
    recover_hidden_base_s1_known_plaintext, recover_hidden_base_s1_known_plaintext_with_audit,
    run_hidden_base_identifiability_audit,
};
use crate::nulls::null::mix_seed;

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

#[test]
fn hidden_base_local_controls_fire_positive_and_matched_nulls() {
    let report = hidden_base_local_self_test(DEFAULT_HIDDEN_BASE_AUDIT_SEED).expect("controls");

    assert!(report.s2_positive.passed());
    assert!(report.s2_positive.exact);
    assert!(report.s3_positive.passed());
    assert!(report.s3_positive.exact);
    assert!(report.label_shuffle.passed());
    assert!(!report.label_shuffle.exact);
    assert!(report.over_budget.passed());
    assert!(!report.over_budget.exact);
    assert!(report.passed());
}

#[test]
fn hidden_base_local_solver_recovers_small_s3_equivalent_class() {
    let config = HiddenBaseFixtureConfig {
        n: 5,
        pt_alphabet: "ABCD".to_owned(),
        swap_budget: 3,
        message_count: 6,
        message_len: 48,
        seed: mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c6f_6361_6c73_3300),
        base_kind: HiddenBaseKind::Random,
    };
    let fixture = plant_hidden_base_fixture(&config).expect("fixture");
    let solver_config = HiddenBaseLocalSolverConfig::top_card_swaps(5, "ABCD", 3)
        .with_ct_alphabet(fixture.spec.ct_alphabet.iter().collect::<String>())
        .with_seed(mix_seed(
            DEFAULT_HIDDEN_BASE_AUDIT_SEED,
            0x6c6f_6361_6c63_7472 ^ 3,
        ))
        .with_attempts(96)
        .with_max_rounds(18);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("local recovery");

    assert!(report.has_exact_recovery());
    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass
    );
    assert_eq!(report.best_mismatches, 0);
    assert_eq!(report.best_round_trip.matched, report.best_round_trip.total);
    assert_eq!(report.planted_base_recovered, Some(true));
    assert!(report.attempts_run < 120);
    let audit = report.representative_audit.expect("audit");
    assert!(audit.round_trip.exact);
    assert!(audit.base_candidate_count > 1);
}

#[test]
fn hidden_base_local_solver_recovers_previous_n7_s2_search_cap_fixture() {
    let fixture_seed = mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c73_7265_636f_7600);
    let fixture = local_s2_fixture(fixture_seed);
    let solver_config = local_s2_solver_config(&fixture.spec, fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("local recovery");

    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert!(report.best_round_trip.exact);
    assert_eq!(report.best_round_trip.matched, 384);
    assert_eq!(report.planted_base_recovered, Some(true));
    assert!(report.top_source_hypotheses_retained <= 96);
    assert!(report.top_source_states_expanded > 0);
    assert!(report.top_source_constraint_evaluations > 0);
}

#[test]
fn hidden_base_local_solver_recovers_five_seed_n7_s2_benchmark() {
    let mut exact = 0usize;
    for trial_index in 0..5usize {
        let fixture_seed = mix_seed(
            DEFAULT_HIDDEN_BASE_AUDIT_SEED,
            0x6c73_7265_636f_7600 ^ u64::try_from(trial_index).expect("small index"),
        );
        let fixture = local_s2_fixture(fixture_seed);
        let solver_config = local_s2_solver_config(&fixture.spec, fixture_seed);
        let report = recover_hidden_base_local_known_plaintext_with_audit(
            &solver_config,
            &fixture.pairs,
            Some(&fixture.spec.base),
        )
        .expect("local recovery");
        exact = exact.saturating_add(usize::from(report.has_exact_recovery()));
        assert_eq!(report.best_mismatches, 0, "trial {trial_index}");
        assert!(
            report.top_source_hypotheses_retained <= solver_config.top_source_beam_width,
            "trial {trial_index}"
        );
    }

    assert_eq!(exact, 5);
}

#[test]
fn hidden_base_local_joint_move_recovers_stalled_n7_s3_fixture() {
    let fixture_seed = mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c73_7265_636f_7600 ^ 3);
    let fixture = local_s3_fixture(fixture_seed);
    let without_joint = recover_hidden_base_local_known_plaintext_with_audit(
        &local_s3_solver_config(&fixture.spec, fixture_seed)
            .with_joint_move_evaluation_cap(0)
            .with_triple_move_evaluation_cap(0),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("coordinate-only local recovery");
    let with_joint = recover_hidden_base_local_known_plaintext_with_audit(
        &local_s3_solver_config(&fixture.spec, fixture_seed),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("joint local recovery");

    assert_eq!(
        without_joint.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert_eq!(without_joint.triple_move_candidate_evaluations, 0);
    assert_eq!(
        with_joint.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert!(with_joint.best_round_trip.exact);
    assert_eq!(with_joint.planted_top_source_hypothesis_rank, Some(1));
    assert_eq!(
        with_joint.planted_top_source_hypothesis_retained,
        Some(true)
    );
    assert!(with_joint.joint_move_candidate_evaluations > 0);
    assert!(with_joint.replay_event_evaluations > 0);
    assert!(with_joint.joint_move_replay_event_evaluations > 0);
    assert!(with_joint.joint_move_replay_event_evaluations <= with_joint.replay_event_evaluations);
    assert!(
        with_joint.joint_move_replay_event_evaluations
            < with_joint
                .joint_move_candidate_evaluations
                .saturating_mul(with_joint.event_count)
    );
    assert!(with_joint.joint_moves_accepted > 0);
    assert!(with_joint.top_source_third_symbol_evaluations > 0);
}

#[test]
fn hidden_base_local_joint_move_obeys_total_run_cap() {
    let fixture_seed = mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c73_7265_636f_7600 ^ 3);
    let fixture = local_s3_fixture(fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &local_s3_solver_config(&fixture.spec, fixture_seed)
            .with_attempts(4)
            .with_triple_move_evaluation_cap(0)
            .with_joint_move_total_evaluation_cap(100),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("total-capped local recovery");

    assert_eq!(report.joint_move_candidate_evaluations, 100);
    assert!(report.joint_move_total_budget_exhausted);

    let ablation = recover_hidden_base_local_known_plaintext_with_audit(
        &local_s3_solver_config(&fixture.spec, fixture_seed)
            .with_attempts(1)
            .with_joint_move_evaluation_cap(0)
            .with_triple_move_evaluation_cap(0)
            .with_third_symbol_top_source_ranking(false),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("ranking ablation");
    assert_eq!(ablation.top_source_third_symbol_evaluations, 0);
}

#[test]
fn hidden_base_local_round_robin_spreads_a_tight_cap_across_pairs() {
    let fixture_seed = mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c73_7265_636f_7600 ^ 3);
    let fixture = local_s3_fixture(fixture_seed);
    let base_config = local_s3_solver_config(&fixture.spec, fixture_seed)
        .with_attempts(1)
        .with_joint_move_evaluation_cap(10)
        .with_joint_move_total_evaluation_cap(10);
    let pair_major = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config
            .clone()
            .with_joint_move_order(HiddenBaseLocalJointMoveOrder::PairMajor),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("pair-major local recovery");
    let fair = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config.with_joint_move_order(HiddenBaseLocalJointMoveOrder::PairRoundRobin),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("pair-fair local recovery");

    assert_eq!(pair_major.joint_move_candidate_evaluations, 10);
    assert_eq!(fair.joint_move_candidate_evaluations, 10);
    assert_eq!(pair_major.joint_move_letter_pairs_eligible, 15);
    assert_eq!(fair.joint_move_letter_pairs_eligible, 15);
    assert!(fair.joint_move_letter_pairs_evaluated > pair_major.joint_move_letter_pairs_evaluated);
    assert!(fair.joint_move_pair_evaluations_max < pair_major.joint_move_pair_evaluations_max);
    assert_eq!(pair_major.joint_move_pair_evaluations_min, 0);
    assert_eq!(fair.joint_move_pair_evaluations_min, 0);
}

#[test]
fn hidden_base_local_triple_repair_obeys_its_separate_cap() {
    let fixture_seed = mix_seed(DEFAULT_HIDDEN_BASE_AUDIT_SEED, 0x6c73_7265_636f_7600 ^ 3);
    let fixture = local_s3_fixture(fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &local_s3_solver_config(&fixture.spec, fixture_seed)
            .with_attempts(1)
            .with_joint_move_evaluation_cap(0)
            .with_triple_move_evaluation_cap(10)
            .with_triple_move_total_evaluation_cap(10),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("triple-capped local recovery");

    assert_eq!(report.joint_move_candidate_evaluations, 0);
    assert_eq!(report.triple_move_candidate_evaluations, 10);
    assert!(report.triple_move_constraint_evaluations >= 10);
    assert!(report.triple_move_prefixes_eligible > 0);
    assert!(report.triple_move_prefixes_evaluated > 0);
    assert!(report.triple_move_total_budget_exhausted);
}

fn local_s2_fixture(seed: u64) -> super::HiddenBaseFixture {
    plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 2,
        message_count: 8,
        message_len: 48,
        seed,
        base_kind: HiddenBaseKind::Random,
    })
    .expect("fixture")
}

fn local_s2_solver_config(spec: &LymmDeckSpec, fixture_seed: u64) -> HiddenBaseLocalSolverConfig {
    HiddenBaseLocalSolverConfig::top_card_swaps(7, "ABCDEF", 2)
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
        .with_seed(mix_seed(fixture_seed, 0x6c73_736f_6c76_6572))
        .with_attempts(96)
        .with_max_rounds(18)
        .with_top_source_beam_width(96)
        .with_state_sat_hypothesis_cap(0)
}

fn local_s3_fixture(seed: u64) -> super::HiddenBaseFixture {
    plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 3,
        message_count: 8,
        message_len: 48,
        seed,
        base_kind: HiddenBaseKind::Random,
    })
    .expect("fixture")
}

fn local_s3_solver_config(spec: &LymmDeckSpec, fixture_seed: u64) -> HiddenBaseLocalSolverConfig {
    HiddenBaseLocalSolverConfig::top_card_swaps(7, "ABCDEF", 3)
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
        .with_seed(mix_seed(fixture_seed, 0x6c73_736f_6c76_6572))
        .with_attempts(96)
        .with_max_rounds(18)
        .with_top_source_beam_width(96)
        .with_state_sat_hypothesis_cap(0)
}

fn s1_solver_config(spec: &LymmDeckSpec) -> HiddenBaseS1SolverConfig {
    HiddenBaseS1SolverConfig::top_card_swaps(spec.n, spec.pt_alphabet.iter().collect::<String>())
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
}
