//! Focused regression tests for hidden-base local-search neighborhoods.

use super::{
    HiddenBaseFixtureConfig, HiddenBaseKind, HiddenBaseLocalRecoveryState,
    HiddenBaseLocalSolverConfig, LymmDeckSpec, plant_hidden_base_fixture,
    recover_hidden_base_local_known_plaintext_with_audit,
};
use crate::nulls::null::mix_seed;

#[test]
fn triple_repair_recovers_retained_weak_restart_stall() {
    let fixture_seed = mix_seed(0x7769_6465_5f74_3301, 0x6c73_7265_636f_7600 ^ 2);
    let fixture = weak_restart_fixture(fixture_seed);
    let base_config = solver_config(&fixture.spec, fixture_seed);
    let pair_only = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config.clone().with_triple_move_evaluation_cap(0),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("pair-only weak-restart recovery");
    let with_triple = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config
            .with_triple_move_evaluation_cap(4_096)
            .with_triple_move_total_evaluation_cap(393_216),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("triple-repair weak-restart recovery");

    assert_eq!(
        pair_only.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert_eq!(pair_only.planted_top_source_hypothesis_rank, Some(3));
    assert_eq!(
        with_triple.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert!(with_triple.best_round_trip.exact);
    assert!(with_triple.triple_move_candidate_evaluations > 0);
    assert!(with_triple.triple_move_replay_event_evaluations > 0);
    assert!(with_triple.triple_moves_accepted > 0);
}

#[test]
fn prefix_cegar_obeys_its_separate_total_cap() {
    let fixture_seed = mix_seed(0x7769_6465_5f74_3301, 0x6c73_7265_636f_7600 ^ 2);
    let fixture = weak_restart_fixture(fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config(&fixture.spec, fixture_seed)
            .with_prefix_cegar_node_cap(1)
            .with_prefix_cegar_total_node_cap(1),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("prefix-CEGAR-capped recovery");

    assert_eq!(report.prefix_cegar_hypotheses_attempted, 1);
    assert_eq!(report.prefix_cegar_hypotheses_capped, 1);
    assert_eq!(report.prefix_cegar_models, 1);
    assert_eq!(report.prefix_cegar_clauses, 1);
    assert!(report.prefix_cegar_replay_event_evaluations > 0);
    assert!((1..=6).contains(&report.prefix_cegar_core_size_min));
    assert!(report.prefix_cegar_total_budget_exhausted);
}

#[test]
fn prefix_cegar_recovers_preregistered_weak_restart_positive() {
    let fixture_seed = mix_seed(0x7769_6465_5f73_3301, 0x6c73_7265_636f_7600 ^ 7);
    let fixture = weak_restart_fixture(fixture_seed);
    let base_config = solver_config(&fixture.spec, fixture_seed);
    let pair_only = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("pair-only weak-restart recovery");
    let with_cegar = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config
            .with_prefix_cegar_node_cap(4_096)
            .with_prefix_cegar_total_node_cap(393_216),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("prefix-CEGAR weak-restart recovery");

    assert_eq!(
        pair_only.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert_eq!(pair_only.planted_top_source_hypothesis_rank, Some(1));
    assert_eq!(
        with_cegar.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert!(with_cegar.best_round_trip.exact);
    assert_eq!(with_cegar.prefix_cegar_exact_models, 1);
    assert_eq!(with_cegar.prefix_cegar_models, 163);
    assert_eq!(with_cegar.prefix_cegar_clauses, 162);
    assert!(with_cegar.prefix_cegar_replay_event_evaluations > 0);
    assert!((1..=6).contains(&with_cegar.prefix_cegar_core_size_min));
    assert!(with_cegar.prefix_cegar_core_size_max <= 6);
    assert!(!with_cegar.prefix_cegar_total_budget_exhausted);
}

#[test]
fn prefix_cegar_rejects_matched_ciphertext_label_shuffle() {
    let fixture_seed = mix_seed(0x7769_6465_5f73_3301, 0x6c73_7265_636f_7600 ^ 7);
    let fixture = weak_restart_fixture(fixture_seed);
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
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config(&fixture.spec, fixture_seed)
            .with_prefix_cegar_node_cap(4_096)
            .with_prefix_cegar_total_node_cap(393_216),
        &shuffled_pairs,
        Some(&fixture.spec.base),
    )
    .expect("prefix-CEGAR ciphertext-label shuffle null");

    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert!(!report.has_exact_recovery());
    assert_eq!(report.prefix_cegar_exact_models, 0);
    assert!(report.prefix_cegar_models > 0);
    assert!(report.prefix_cegar_replay_event_evaluations > 0);
}

fn weak_restart_fixture(seed: u64) -> super::HiddenBaseFixture {
    plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 3,
        message_count: 6,
        message_len: 64,
        seed,
        base_kind: HiddenBaseKind::Random,
    })
    .expect("fixture")
}

fn solver_config(spec: &LymmDeckSpec, fixture_seed: u64) -> HiddenBaseLocalSolverConfig {
    HiddenBaseLocalSolverConfig::top_card_swaps(7, "ABCDEF", 3)
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
        .with_seed(mix_seed(fixture_seed, 0x6c73_736f_6c76_6572))
        .with_attempts(96)
        .with_max_rounds(18)
        .with_top_source_beam_width(96)
}
