use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    KnownPlaintextPair, LymmDeckSpec, TopSwapConstraints, encrypt_lymm_deck,
    enumerate_top_swap_domains, generate_random_pt_mapping, lymm_default_ct_alphabet,
    parse_known_plaintext_pairs,
};
use super::{
    LetterRecoveryVerdict, SwapInferenceOutcome, SwapInferenceRange, SwapRecoveryConfig,
    SwapRecoveryStrategy, infer_known_plaintext_swap_budget, recover_known_plaintext_swaps,
};

#[test]
fn ns3_top_swap_candidate_count_matches_verified_frontier() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let domains = enumerate_top_swap_domains(&spec, &TopSwapConstraints::up_to(3))
        .expect("ns=3 top-swap domains");
    let mut independent = independent_top_swap_permutations(&spec, 3);
    let mut top_images = BTreeSet::new();

    assert_eq!(domains.candidates.len(), 541_406);
    assert_eq!(independent.len(), 541_406);
    for candidate in &domains.candidates {
        assert!(candidate.canonical_swaps.len() <= 3);
        assert!(
            candidate
                .canonical_swaps
                .iter()
                .all(|&index| index < spec.n)
        );
        let permutation = candidate.permutation(&spec);
        assert_eq!(
            replay_top_swaps(&spec.base, &candidate.canonical_swaps),
            permutation
        );
        assert_eq!(
            permutation.get(spec.emit_index).copied(),
            Some(candidate.top_image)
        );
        let _inserted = top_images.insert(candidate.top_image);
        assert!(
            independent.remove(&compact_permutation(&permutation)),
            "duplicate or unreachable top-swap candidate"
        );
    }
    assert!(independent.is_empty());
    assert_eq!(top_images.len(), spec.n);
}

#[test]
fn local_search_ns3_planted_control_recovers_exact_candidate() {
    let spec = LymmDeckSpec::from_shift_decimation(11, "ABCD", &lymm_default_ct_alphabet(11), 4, 3)
        .expect("spec");
    let planted = generate_random_pt_mapping(&spec, 3, 0x51a7_0300_0000_0003).expect("ns=3 plant");
    let pairs = encrypted_pairs(&spec, &planted.pt_mapping, &synthetic_rows());
    let report = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(3).with_strategy(SwapRecoveryStrategy::LocalSearch),
    )
    .expect("local-search ns=3 recovery");

    assert!(report.round_trip.exact(), "{:#?}", report.round_trip);
    assert_eq!(report.round_trip.matched, report.round_trip.total);
}

#[test]
fn unobserved_vendored_letters_are_not_serialized_as_recovered_swaps() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../../research/data/practice-puzzles/deck-swap/1_swap_ct.txt"),
    )
    .expect("known plaintext pairs");
    let report =
        recover_known_plaintext_swaps(&spec, &pairs, SwapRecoveryConfig::with_max_swaps(1))
            .expect("ns=1 recovery");

    assert!(report.round_trip.exact(), "{:#?}", report.round_trip);
    assert_eq!(report.pt_mapping.len(), 24);
    for letter in ['J', 'Z'] {
        assert!(!report.pt_mapping.contains_key(&letter));
        let found = report
            .letters
            .iter()
            .find(|entry| entry.letter == letter)
            .expect("letter report");
        assert_eq!(found.occurrences, 0);
        assert_eq!(found.verdict, LetterRecoveryVerdict::NoCandidate);
        assert!(found.target.is_none());
        assert!(found.support.is_empty());
        assert!(found.canonical_swaps.is_empty());
        assert!(found.permutation.is_none());
        assert!(found.candidate_permutations.is_empty());
        assert_eq!(found.equivalent_count, 0);
    }
}

#[test]
fn infer_swaps_reaches_ns3_local_search_frontier() {
    let spec = LymmDeckSpec::from_shift_decimation(11, "ABCD", &lymm_default_ct_alphabet(11), 4, 3)
        .expect("spec");
    let planted = generate_random_pt_mapping(&spec, 3, 0x51a7_0300_0000_0003).expect("ns=3 plant");
    let pairs = encrypted_pairs(&spec, &planted.pt_mapping, &synthetic_rows());
    let report = infer_known_plaintext_swap_budget(
        &spec,
        &pairs,
        SwapInferenceRange::new(1, 3),
        SwapRecoveryConfig::with_max_swaps(1),
    )
    .expect("ns=3 inference");

    assert_eq!(report.inferred_max_swaps(), Some(3));
    assert_eq!(
        report.attempts.last().map(|attempt| attempt.outcome),
        Some(SwapInferenceOutcome::ExactRoundTrip)
    );
    assert!(report.exact());
}

#[test]
#[ignore = "vendored S83 ns=3 local-search regression runs in about 132s in debug"]
fn ns3_recovery_recovers_vendored_key_and_reencrypts_exactly() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../../research/data/practice-puzzles/deck-swap/3_swap_ct.txt"),
    )
    .expect("known plaintext pairs");
    let report =
        recover_known_plaintext_swaps(&spec, &pairs, SwapRecoveryConfig::with_max_swaps(3))
            .expect("ns=3 local-search recovery");

    assert!(report.round_trip.exact(), "{:#?}", report.round_trip);
    assert_eq!(report.round_trip.matched, 2439);
    assert_eq!(report.round_trip.total, 2439);
}

fn encrypted_pairs(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
    rows: &[(String, String)],
) -> Vec<KnownPlaintextPair> {
    rows.iter()
        .map(|(label, plaintext)| {
            let ciphertext = encrypt_lymm_deck(spec, mapping, plaintext)
                .expect("planted ciphertext")
                .chars()
                .filter(|ch| spec.ct_alphabet.contains(ch))
                .collect();
            KnownPlaintextPair {
                label: label.clone(),
                plaintext: plaintext.clone(),
                ciphertext,
            }
        })
        .collect()
}

fn synthetic_rows() -> Vec<(String, String)> {
    ['A', 'B', 'C', 'D']
        .into_iter()
        .enumerate()
        .map(|(index, letter)| ((index + 1).to_string(), letter.to_string().repeat(96)))
        .collect()
}

fn independent_top_swap_permutations(spec: &LymmDeckSpec, max_depth: usize) -> BTreeSet<Vec<u16>> {
    let mut seen = BTreeSet::new();
    let mut permutation = spec.base.clone();
    enumerate_independent_top_swap_words(spec.n, max_depth, &mut permutation, &mut seen);
    seen
}

fn enumerate_independent_top_swap_words(
    n: usize,
    remaining_depth: usize,
    permutation: &mut [usize],
    seen: &mut BTreeSet<Vec<u16>>,
) {
    let _inserted = seen.insert(compact_permutation(permutation));
    if remaining_depth == 0 {
        return;
    }
    for swap_index in 0..n {
        permutation.swap(0, swap_index);
        enumerate_independent_top_swap_words(n, remaining_depth - 1, permutation, seen);
        permutation.swap(0, swap_index);
    }
}

fn replay_top_swaps(base: &[usize], swaps: &[usize]) -> Vec<usize> {
    let mut permutation = base.to_vec();
    for &swap_index in swaps {
        permutation.swap(0, swap_index);
    }
    permutation
}

fn compact_permutation(permutation: &[usize]) -> Vec<u16> {
    permutation
        .iter()
        .map(|&value| u16::try_from(value).expect("S83 deck fits in u16"))
        .collect()
}
