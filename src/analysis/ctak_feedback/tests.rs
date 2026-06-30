//! Unit tests exercising the same library functions the `ctakscan` CLI calls.

use super::model::{
    Convention, CribAnchor, Perms, Readout, Side, crib_run_count, decode_into,
    encrypt_deck_channel, random_advance_map, search_best_map,
};
use super::{CtakError, CtakVerdict, DEFAULT_NULL_TRIALS, DEFAULT_SEED, ctak_scan, ctak_self_test};
use crate::nulls::null::SplitMix64;

#[test]
fn self_test_passes() {
    let result = ctak_self_test(0x0123_4567_89ab_cdef).expect("self-test runs");
    assert!(result.positive_recovered, "planted feedback deck recovered");
    assert!(
        result.positive_full_repeat,
        "recovered map reproduces the full planted repeat"
    );
    assert!(
        result.negative_rejected,
        "no-feedback control yields NoFeedbackSignal"
    );
    assert!(result.passed);
}

#[test]
fn encrypt_decode_round_trip() {
    // Encrypting a known plaintext deck stream under a known g and convention and
    // then decoding with the same g (D0 = identity) recovers the plaintext exactly.
    let perms = Perms::build(4);
    let mut rng = SplitMix64::new(0xfeed_face_dead_beef);
    let g = random_advance_map(&perms, &mut rng).expect("advance map");
    let t: Vec<usize> = (0..60).map(|_| (rng.next_u64() % 4) as usize).collect();
    for convention in Convention::all() {
        let q = encrypt_deck_channel(&perms, &t, &g, convention);
        let mut decoded = Vec::new();
        decode_into(&perms, &q, &g, convention, q.len(), &mut decoded);
        assert_eq!(decoded, t, "round trip under {convention:?}");
    }
}

#[test]
fn crib_run_count_basic() {
    let t = vec![1, 2, 3, 4, 9, 1, 2, 3, 7, 9];
    // anchor compares [0..4] with [5..9]: 1,2,3 match then 4 vs 7 differ.
    let (run, count) = crib_run_count(
        &t,
        CribAnchor {
            first: 0,
            second: 5,
            length: 4,
        },
    );
    assert_eq!(run, 3);
    assert_eq!(count, 3);
}

#[test]
fn search_recovers_planted_single_anchor() {
    // A planted feedback deck with one repeated word: the forward/right search
    // (D0 cancels) must reach a full-length crib run at the anchor.
    let perms = Perms::build(4);
    let convention = Convention {
        side: Side::Right,
        readout: Readout::Forward,
    };
    let mut rng = SplitMix64::new(0xabcd_0001);
    let g = random_advance_map(&perms, &mut rng).expect("advance map");
    let word_len = 20usize;
    let mut t: Vec<usize> = (0..80).map(|_| (rng.next_u64() % 4) as usize).collect();
    let (src, dst) = (5usize, 50usize);
    let word: Vec<usize> = (0..word_len)
        .filter_map(|s| t.get(src + s).copied())
        .collect();
    for (s, &v) in word.iter().enumerate() {
        if let Some(slot) = t.get_mut(dst + s) {
            *slot = v;
        }
    }
    let q = encrypt_deck_channel(&perms, &t, &g, convention);
    let anchor = CribAnchor {
        first: src,
        second: dst,
        length: word_len,
    };
    let best = search_best_map(&perms, &q, &[anchor], convention).expect("best map");
    assert_eq!(
        best.min_run, word_len,
        "search reproduces the full planted repeat"
    );
}

#[test]
fn rejects_oversized_deck() {
    // alphabet 15, rotor 3 -> deck 5 -> 120^5 search space, refused.
    let err = ctak_scan(&[0, 1, 2], 15, 3, 8, 6, 4, DEFAULT_SEED).unwrap_err();
    assert!(matches!(err, CtakError::DeckTooLarge { deck_size: 5, .. }));
}

#[test]
fn rejects_non_divisible_alphabet() {
    let err = ctak_scan(&[0, 1], 13, 3, 8, 6, 4, DEFAULT_SEED).unwrap_err();
    assert!(matches!(
        err,
        CtakError::AlphabetNotDivisible {
            alphabet_size: 13,
            rotor_mod: 3
        }
    ));
}

#[test]
fn no_anchors_yields_no_signal() {
    // A short structureless stream has no significant rotor anchor -> NoFeedbackSignal.
    let values: Vec<u16> = (0..30u16).map(|i| i % 12).collect();
    let report =
        ctak_scan(&values, 12, 3, 8, 6, DEFAULT_NULL_TRIALS, DEFAULT_SEED).expect("scan runs");
    assert!(matches!(report.verdict, CtakVerdict::NoFeedbackSignal));
}
