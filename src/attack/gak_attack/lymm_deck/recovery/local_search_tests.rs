use std::collections::BTreeMap;

use super::super::{
    KnownPlaintextPair, LymmDeckSpec, TopSwapConstraints, encrypt_lymm_deck,
    enumerate_top_swap_domains, generate_random_pt_mapping, lymm_default_ct_alphabet,
    parse_known_plaintext_pairs,
};
use super::{SwapRecoveryConfig, SwapRecoveryStrategy, recover_known_plaintext_swaps};

#[test]
fn ns3_top_swap_candidate_count_matches_verified_frontier() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let domains = enumerate_top_swap_domains(&spec, &TopSwapConstraints::up_to(3))
        .expect("ns=3 top-swap domains");

    assert_eq!(domains.candidates.len(), 541_406);
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
