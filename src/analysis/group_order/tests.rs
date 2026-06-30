//! Tests for the element-order discriminator. They exercise the same library
//! functions the `groupscan` CLI calls: the permutation algebra, the group
//! constructions and their cycle-length spectra (the discriminating fact itself,
//! validated non-circularly), the per-anchor induced-map reading, the orchestration
//! error paths, and the full self-test (planted controls + matched null).

use super::control::{a4, d4, s4};
use super::scan::{compose, cycle_lengths, invert, is_even, read_context};
use super::{DEFAULT_SEED, GroupScanError, GroupVerdict, group_scan, group_scan_self_test};

#[test]
fn compose_follows_repo_convention() {
    // (p ∘ q)[i] = p[q[i]].
    let p = [1, 2, 3, 0];
    let q = [3, 2, 1, 0];
    assert_eq!(compose(&p, &q), vec![0, 3, 2, 1]);
}

#[test]
fn invert_is_a_left_and_right_inverse() {
    let p = vec![2, 0, 3, 1];
    let inv = invert(&p);
    assert_eq!(compose(&p, &inv), vec![0, 1, 2, 3]);
    assert_eq!(compose(&inv, &p), vec![0, 1, 2, 3]);
}

#[test]
fn cycle_lengths_decomposes_correctly() {
    assert_eq!(cycle_lengths(&[0, 1, 2, 3]), vec![1, 1, 1, 1]); // identity
    assert_eq!(cycle_lengths(&[1, 0, 2, 3]), vec![1, 1, 2]); // (01)
    assert_eq!(cycle_lengths(&[1, 0, 3, 2]), vec![2, 2]); // (01)(23)
    assert_eq!(cycle_lengths(&[1, 2, 0, 3]), vec![1, 3]); // (012)
    assert_eq!(cycle_lengths(&[1, 2, 3, 0]), vec![4]); // (0123)
}

#[test]
fn is_even_matches_parity() {
    assert!(is_even(&[0, 1, 2, 3])); // identity, 0 transpositions
    assert!(!is_even(&[1, 0, 2, 3])); // single transposition, odd
    assert!(is_even(&[1, 0, 3, 2])); // two transpositions, even
    assert!(is_even(&[1, 2, 0, 3])); // 3-cycle = two transpositions, even
    assert!(!is_even(&[1, 2, 3, 0])); // 4-cycle = three transpositions, odd
}

#[test]
fn group_orders_are_correct() {
    assert_eq!(s4().len(), 24);
    assert_eq!(a4().len(), 12);
    assert_eq!(d4().len(), 8);
}

/// The discriminating fact, validated directly against the group element lists:
/// `D4` has no 3-cycle, `A4` has no 4-cycle, `S4` has both. This is what makes a
/// single observed 3-cycle rule out `D4` and a single 4-cycle rule out `A4`.
#[test]
fn group_cycle_spectra_are_the_discriminator() {
    let has_len =
        |group: &[Vec<usize>], len: usize| group.iter().any(|p| cycle_lengths(p).contains(&len));

    // D4: 4-cycles present, no 3-cycle.
    assert!(has_len(&d4(), 4));
    assert!(!has_len(&d4(), 3));
    // A4: 3-cycles present, no 4-cycle.
    assert!(has_len(&a4(), 3));
    assert!(!has_len(&a4(), 4));
    // S4: both present.
    assert!(has_len(&s4(), 3));
    assert!(has_len(&s4(), 4));
}

#[test]
fn read_context_recovers_a_clean_permutation() {
    // q_a walks 0,1,2,3,...; q_b = g(q_a) with g = (0123).
    let q = [0, 1, 2, 3, 0, 1, 2, 3, 1, 2, 3, 0, 1, 2, 3, 0];
    let outcome = read_context(&q, 4, 0, 8, 7);
    assert_eq!(outcome.prefix_len, 8);
    assert_eq!(outcome.coverage, 4);
    assert_eq!(outcome.permutation, Some(vec![1, 2, 3, 0]));
}

#[test]
fn read_context_completes_from_three_of_four() {
    // Only sources {0,1,2} observed; the fourth image is forced.
    // q_a = 0,1,2,0,1,2; q_b = g(q_a), g = (012) so 0->1,1->2,2->0, and 3->3.
    let q = [0, 1, 2, 0, 1, 2, 1, 2, 0, 1, 2, 0];
    let outcome = read_context(&q, 4, 0, 6, 5);
    assert_eq!(outcome.coverage, 3);
    assert_eq!(outcome.permutation, Some(vec![1, 2, 0, 3]));
}

#[test]
fn read_context_stops_at_a_collision() {
    // Source 0 maps to 2 then to 3: collision at the third position.
    let q = [0, 1, 0, 1, 2, 3, 3, 2];
    let outcome = read_context(&q, 4, 0, 4, 3);
    assert_eq!(outcome.prefix_len, 2);
    assert_eq!(outcome.permutation, None); // coverage 2 < deck_size - 1
}

#[test]
fn read_context_rejects_non_injective_low_coverage() {
    // Consistent but only two sources, never enough to fix a permutation.
    let q = [0, 1, 0, 1, 2, 3, 2, 3];
    let outcome = read_context(&q, 4, 0, 4, 3);
    assert_eq!(outcome.prefix_len, 4);
    assert_eq!(outcome.permutation, None);
}

#[test]
fn group_scan_rejects_invalid_configuration() {
    let stream = vec![0u16; 40];
    assert_eq!(
        group_scan(&stream, 0, 3, 8, 16, 16, DEFAULT_SEED),
        Err(GroupScanError::EmptyAlphabet)
    );
    assert_eq!(
        group_scan(&stream, 12, 0, 8, 16, 16, DEFAULT_SEED),
        Err(GroupScanError::ZeroRotorMod)
    );
    assert_eq!(
        group_scan(&stream, 12, 5, 8, 16, 16, DEFAULT_SEED),
        Err(GroupScanError::AlphabetNotDivisible {
            alphabet_size: 12,
            rotor_mod: 5,
        })
    );
    assert_eq!(
        group_scan(&stream, 3, 3, 8, 16, 16, DEFAULT_SEED),
        Err(GroupScanError::DeckTooSmall { deck_size: 1 })
    );
}

#[test]
fn group_scan_reports_no_deck_signal_without_anchors() {
    // A stream shorter than the anchor threshold yields no difference-channel
    // anchors (its difference channel has fewer symbols than min_anchor_len).
    let stream: Vec<u16> = vec![0, 4, 8, 1, 5, 9, 2, 6];
    let report = group_scan(&stream, 12, 3, 8, 16, 16, DEFAULT_SEED).expect("scan");
    assert_eq!(report.anchors_examined, 0);
    assert_eq!(report.consistent_contexts, 0);
    assert_eq!(report.verdict, GroupVerdict::NoDeckSignal);
}

#[test]
fn self_test_passes_on_all_planted_controls() {
    let result = group_scan_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(result.cycle_recovery_passed, "cycle-type recovery");
    assert!(result.d4_excludes_a4, "D4 stream rules out A4");
    assert!(result.a4_excludes_d4, "A4 stream rules out D4");
    assert!(result.s4_verdict, "S4 stream forces S4");
    assert!(result.null_rejected, "eps-only null rejected");
    assert!(result.passed);
}

#[test]
fn self_test_is_seed_robust() {
    for seed in [1u64, 0x1234_5678, DEFAULT_SEED, u64::MAX] {
        let result = group_scan_self_test(seed).expect("self-test runs");
        assert!(result.passed, "self-test failed for seed {seed:#x}");
    }
}
