//! Focused regression tests for hidden-base local-search neighborhoods.

use super::{
    HiddenBaseFixtureConfig, HiddenBaseKind, HiddenBaseLocalRecoveryState,
    HiddenBaseLocalSolverConfig, KnownPlaintextPair, LymmDeckSpec, plant_hidden_base_fixture,
    post_anchor_ciphertext_label_swap, recover_hidden_base_local_known_plaintext_with_audit,
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

#[test]
fn state_sat_recovers_retained_weak_restart_positive() {
    let fixture_seed = mix_seed(0x7769_6465_5f73_3301, 0x6c73_7265_636f_7600 ^ 7);
    let fixture = weak_restart_fixture(fixture_seed);
    let base_config = solver_config(&fixture.spec, fixture_seed);
    let pair_only = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("pair-only weak-restart recovery");
    let with_state_sat = recover_hidden_base_local_known_plaintext_with_audit(
        &base_config.with_state_sat_hypothesis_cap(96),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("state-SAT weak-restart recovery");

    assert_eq!(
        pair_only.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert_eq!(pair_only.planted_top_source_hypothesis_rank, Some(1));
    assert_eq!(
        with_state_sat.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert!(with_state_sat.best_round_trip.exact);
    assert_eq!(with_state_sat.state_sat_hypotheses_attempted, 1);
    assert_eq!(with_state_sat.state_sat_base_completions_attempted, 1);
    assert_eq!(with_state_sat.state_sat_base_completions_unsat, 0);
    assert_eq!(with_state_sat.state_sat_base_completion_cap_exhausted, 0);
    assert_eq!(with_state_sat.state_sat_exact_models, 1);
    assert!(with_state_sat.state_sat_variables > 0);
    assert!(with_state_sat.state_sat_clauses > 0);
    assert_eq!(
        with_state_sat.state_sat_replay_event_evaluations,
        with_state_sat.event_count
    );
}

#[test]
fn state_sat_recovers_widened_rank_242_positive() {
    let fixture_seed = mix_seed(0x7769_6465_5f74_3301, 0x6c73_7265_636f_7600);
    let fixture = weak_restart_fixture(fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config(&fixture.spec, fixture_seed)
            .with_top_source_beam_width(256)
            .with_state_sat_hypothesis_cap(256),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("widened state-SAT weak-restart recovery");

    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert_eq!(report.planted_top_source_hypothesis_rank, Some(242));
    assert_eq!(report.planted_top_source_hypothesis_retained, Some(true));
    assert_eq!(report.state_sat_hypotheses_attempted, 242);
    assert_eq!(report.state_sat_hypotheses_unsat, 241);
    assert_eq!(report.state_sat_exact_models, 1);
    assert!(report.best_round_trip.exact);
}

#[test]
fn top_source_retention_is_independent_of_local_attempts() {
    let fixture_seed = mix_seed(0x7769_6465_5f73_3301, 0x6c73_7265_636f_7600 ^ 7);
    let fixture = weak_restart_fixture(fixture_seed);
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config(&fixture.spec, fixture_seed)
            .with_attempts(1)
            .with_max_rounds(1)
            .with_top_source_beam_width(2)
            .with_joint_move_evaluation_cap(0)
            .with_joint_move_total_evaluation_cap(0),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("independently retained top-source hypotheses");

    assert_eq!(report.attempts_run, 1);
    assert_eq!(report.top_source_hypotheses_retained, 2);
}

#[test]
fn state_sat_rejects_matched_ciphertext_label_shuffle() {
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
        &solver_config(&fixture.spec, fixture_seed).with_state_sat_hypothesis_cap(96),
        &shuffled_pairs,
        Some(&fixture.spec.base),
    )
    .expect("state-SAT ciphertext-label shuffle null");

    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert!(!report.has_exact_recovery());
    assert_eq!(report.state_sat_hypotheses_attempted, 96);
    assert_eq!(report.state_sat_hypotheses_unsat, 96);
    assert_eq!(report.state_sat_exact_models, 0);
    assert!(report.state_sat_variables > 0);
    assert!(report.state_sat_clauses > 0);
}

#[test]
fn widened_state_sat_rejects_matched_ciphertext_label_shuffle() {
    let fixture_seed = mix_seed(0x7769_6465_5f74_3301, 0x6c73_7265_636f_7600);
    let fixture = weak_restart_fixture(fixture_seed);
    let mut shuffled_pairs = fixture.pairs.clone();
    for pair in &mut shuffled_pairs {
        pair.ciphertext = pair
            .ciphertext
            .chars()
            .enumerate()
            .map(|(index, ch)| match (index, ch) {
                (0, _) => ch,
                (_, '!') => '"',
                (_, '"') => '!',
                (_, other) => other,
            })
            .collect();
    }
    let report = recover_hidden_base_local_known_plaintext_with_audit(
        &solver_config(&fixture.spec, fixture_seed)
            .with_top_source_beam_width(256)
            .with_state_sat_hypothesis_cap(256),
        &shuffled_pairs,
        Some(&fixture.spec.base),
    )
    .expect("widened state-SAT post-anchor label-shuffle null");

    assert_eq!(
        report.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert!(!report.has_exact_recovery());
    assert_eq!(report.state_sat_hypotheses_attempted, 256);
    assert_eq!(report.state_sat_hypotheses_unsat, 256);
    assert_eq!(report.state_sat_exact_models, 0);
}

#[test]
fn state_sat_second_base_completion_recovers_n8_positive() {
    let fixture_seed = mix_seed(0x7363_616c_696e_6701, 0x6c73_7265_636f_7600);
    let fixture = plant_hidden_base_fixture(&HiddenBaseFixtureConfig {
        n: 8,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 3,
        message_count: 6,
        message_len: 64,
        seed: fixture_seed,
        base_kind: HiddenBaseKind::Random,
    })
    .expect("n=8 completion-sensitive fixture");
    let config = HiddenBaseLocalSolverConfig::top_card_swaps(8, "ABCDEF", 3)
        .with_ct_alphabet(fixture.spec.ct_alphabet.iter().collect::<String>())
        .with_seed(mix_seed(fixture_seed, 0x6c73_736f_6c76_6572))
        .with_attempts(1)
        .with_max_rounds(1)
        .with_top_source_beam_width(96)
        .with_joint_move_evaluation_cap(0)
        .with_joint_move_total_evaluation_cap(0)
        .with_state_sat_hypothesis_cap(96);

    let cap_one = recover_hidden_base_local_known_plaintext_with_audit(
        &config.clone().with_state_sat_base_completion_cap(1),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("single representative completion");
    let cap_two = recover_hidden_base_local_known_plaintext_with_audit(
        &config.with_state_sat_base_completion_cap(2),
        &fixture.pairs,
        Some(&fixture.spec.base),
    )
    .expect("complete n=8 base marginalization");

    assert_eq!(
        cap_one.state,
        HiddenBaseLocalRecoveryState::SearchCapExceeded
    );
    assert_eq!(cap_one.planted_top_source_hypothesis_rank, Some(47));
    assert_eq!(cap_one.state_sat_base_completion_cap_exhausted, 96);
    assert_eq!(cap_one.state_sat_hypotheses_unsat, 0);
    assert_eq!(
        cap_two.state,
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    );
    assert_eq!(cap_two.state_sat_hypotheses_attempted, 47);
    assert_eq!(cap_two.state_sat_hypotheses_unsat, 46);
    assert_eq!(cap_two.state_sat_base_completions_attempted, 94);
    assert_eq!(cap_two.state_sat_base_completions_unsat, 93);
    assert_eq!(cap_two.state_sat_base_completion_cap_exhausted, 0);
    assert_eq!(cap_two.state_sat_exact_models, 1);
    assert!(cap_two.best_round_trip.exact);
}

#[test]
fn post_anchor_label_swap_preserves_each_restart_anchor() {
    let pairs = vec![
        KnownPlaintextPair {
            label: "first".to_owned(),
            plaintext: "ABCD".to_owned(),
            ciphertext: "!\"!#".to_owned(),
        },
        KnownPlaintextPair {
            label: "second".to_owned(),
            plaintext: "ABCD".to_owned(),
            ciphertext: "\"!!\"".to_owned(),
        },
    ];

    let (transformed, changed) = post_anchor_ciphertext_label_swap(&pairs, '!', '"');

    assert_eq!(changed, 5);
    assert_eq!(
        transformed
            .iter()
            .map(|pair| pair.ciphertext.as_str())
            .collect::<Vec<_>>(),
        vec!["!!\"#", "\"\"\"!"]
    );
    assert_eq!(
        pairs.first().map(|pair| pair.ciphertext.as_str()),
        Some("!\"!#")
    );
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
        .with_state_sat_hypothesis_cap(0)
}
