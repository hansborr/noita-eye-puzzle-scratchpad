//! Differential and parser tests for Lymm's deck-cipher oracle.

use std::collections::BTreeMap;

use super::{
    KnownPlaintextPair, LetterRecoveryVerdict, LymmDeckSpec, SwapRecoveryConfig,
    TopSwapConstraints, encrypt_lymm_deck, enumerate_top_swap_domains, generate_random_pt_mapping,
    parse_known_plaintext_pairs, recover_known_plaintext_swaps,
};

#[test]
fn hand_verified_oracle_vector_documents_orientation_and_passthrough() {
    let spec = LymmDeckSpec::from_base(5, "AB", "abcde", vec![0, 1, 2, 3, 4]).expect("spec");
    let mut mapping = BTreeMap::new();
    let _old = mapping.insert('A', vec![2, 1, 0, 3, 4]);
    let _old = mapping.insert('B', vec![3, 1, 2, 0, 4]);

    let ciphertext = encrypt_lymm_deck(&spec, &mapping, "A!B").expect("encrypt");

    assert_eq!(
        ciphertext, "c!d",
        "A emits state[(0 2)[0]]=2 -> 'c'; '!' does not advance; B then emits 3 -> 'd'"
    );
}

#[test]
fn planted_mapping_is_reproducible_and_reversible() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let first = generate_random_pt_mapping(&spec, 3, 0x51a7_0000_0000_0003).expect("first plant");
    let second = generate_random_pt_mapping(&spec, 3, 0x51a7_0000_0000_0003).expect("second plant");
    assert_eq!(first, second);

    let mut tops = first
        .pt_mapping
        .values()
        .map(|perm| perm.first().copied().expect("permutation is nonempty"))
        .collect::<Vec<_>>();
    tops.sort_unstable();
    tops.dedup();
    assert_eq!(tops.len(), spec.pt_alphabet.len());
    assert!(!tops.contains(&0));
}

#[test]
fn top_swap_domain_deduplicates_identity_and_repeats() {
    let spec = LymmDeckSpec::from_base(5, "AB", "abcde", vec![0, 1, 2, 3, 4]).expect("spec");
    let domains = enumerate_top_swap_domains(&spec, &TopSwapConstraints::up_to(3))
        .expect("domain enumeration");

    assert!(
        domains.candidates.iter().any(|candidate| {
            candidate.support.is_empty() && candidate.canonical_swaps.is_empty()
        })
    );
    assert_eq!(
        domains
            .candidates_with_top_image(2)
            .into_iter()
            .filter(|candidate| candidate.support == vec![0, 2])
            .count(),
        1
    );
    assert!(domains.candidates.iter().any(|candidate| {
        candidate.support == vec![1, 2] && candidate.sigma_permutation(5) == vec![0, 2, 1, 3, 4]
    }));
}

#[test]
fn parser_aligns_vendored_known_plaintext_pairs() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    for ciphertexts in [
        include_str!("../../../../research/data/practice-puzzles/deck-swap/1_swap_ct.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/2_swap_ct.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/3_swap_ct.txt"),
    ] {
        let pairs = parse_known_plaintext_pairs(
            &spec,
            include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
            ciphertexts,
        )
        .expect("known plaintext pairs");
        assert_eq!(pairs.len(), 8);
        assert_equal_message_5_and_8(&pairs);
    }
}

#[test]
fn rust_oracle_matches_python_reference_vectors_byte_for_byte() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let plaintexts = parse_plaintext_rows(include_str!(
        "../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"
    ));
    let vectors = parse_reference_vectors(include_str!(
        "../../../../research/data/practice-puzzles/deck-swap/python-reference-vectors.txt"
    ));
    let mut by_num_swaps: BTreeMap<usize, usize> = BTreeMap::new();

    for vector in vectors {
        *by_num_swaps.entry(vector.num_swaps).or_default() += 1;
        let planted = generate_random_pt_mapping(&spec, vector.num_swaps, vector.seed)
            .expect("Rust planted mapping");
        assert_eq!(
            planted.pt_mapping, vector.mapping,
            "Rust SplitMix64 plant must match the mapping injected into Python for ns={} seed=0x{:016x}",
            vector.num_swaps, vector.seed
        );

        for (label, expected) in &vector.ciphertexts {
            let plaintext = plaintexts
                .get(label)
                .unwrap_or_else(|| panic!("missing plaintext label {label}"));
            let actual =
                encrypt_lymm_deck(&spec, &vector.mapping, plaintext).expect("Rust encrypt");
            assert_eq!(
                actual.as_bytes(),
                expected.as_bytes(),
                "Python differential mismatch for ns={} seed=0x{:016x} label {label}",
                vector.num_swaps,
                vector.seed
            );
        }
    }

    assert_eq!(
        by_num_swaps,
        BTreeMap::from([(1, 2), (2, 2), (3, 2)]),
        "reference vectors must cover two seeds at each num_swaps level"
    );
}

#[test]
fn ns1_recovery_recovers_vendored_key_and_reencrypts_exactly() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/1_swap_ct.txt"),
    )
    .expect("known plaintext pairs");

    let report =
        recover_known_plaintext_swaps(&spec, &pairs, SwapRecoveryConfig::with_max_swaps(1))
            .expect("ns=1 recovery");

    assert_eq!(report.verdict, LetterRecoveryVerdict::RecoveredUnique);
    assert!(report.round_trip.exact());
    assert_eq!(report.round_trip.matched, report.round_trip.total);
    assert_eq!(
        report
            .letters
            .iter()
            .filter(|letter| letter.occurrences > 0)
            .filter(|letter| letter.verdict == LetterRecoveryVerdict::RecoveredUnique)
            .count(),
        24
    );
}

#[test]
fn ns2_recovery_recovers_vendored_key_and_reencrypts_exactly() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/2_swap_ct.txt"),
    )
    .expect("known plaintext pairs");

    let mut config = SwapRecoveryConfig::with_max_swaps(2);
    config.max_nodes = Some(50_000);
    let report = recover_known_plaintext_swaps(&spec, &pairs, config).expect("ns=2 recovery");

    assert!(report.round_trip.exact());
    assert_eq!(report.round_trip.matched, report.round_trip.total);
}

fn assert_equal_message_5_and_8(pairs: &[KnownPlaintextPair]) {
    let five = pairs
        .iter()
        .find(|pair| pair.label == "5")
        .expect("label 5");
    let eight = pairs
        .iter()
        .find(|pair| pair.label == "8")
        .expect("label 8");
    assert_eq!(five.plaintext, eight.plaintext);
    assert_eq!(five.ciphertext, eight.ciphertext);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceVector {
    num_swaps: usize,
    seed: u64,
    mapping: BTreeMap<char, Vec<usize>>,
    ciphertexts: BTreeMap<String, String>,
}

fn parse_reference_vectors(raw: &str) -> Vec<ReferenceVector> {
    let mut vectors = Vec::new();
    let mut current: Option<ReferenceVector> = None;
    let mut section = "";
    for line in raw.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("vector ns=") {
            if let Some(vector) = current.take() {
                vectors.push(vector);
            }
            let (num_swaps, seed) = rest.split_once(" seed=").expect("vector header");
            current = Some(ReferenceVector {
                num_swaps: num_swaps.parse().expect("num_swaps"),
                seed: u64::from_str_radix(seed.trim_start_matches("0x"), 16).expect("seed"),
                mapping: BTreeMap::new(),
                ciphertexts: BTreeMap::new(),
            });
            section = "";
            continue;
        }
        match line {
            "[mapping]" => {
                section = "mapping";
                continue;
            }
            "[ciphertexts]" => {
                section = "ciphertexts";
                continue;
            }
            "end" => {
                if let Some(vector) = current.take() {
                    vectors.push(vector);
                }
                section = "";
                continue;
            }
            _ => {}
        }

        let vector = current.as_mut().expect("section inside vector");
        match section {
            "mapping" => {
                let (left, values) = line.split_once(": ").expect("mapping separator");
                let letter = left.chars().next().expect("mapping letter");
                let _old = vector.mapping.insert(letter, parse_usize_list(values));
            }
            "ciphertexts" => {
                let (label, ciphertext) = line.split_once(": ").expect("ciphertext separator");
                let _old = vector
                    .ciphertexts
                    .insert(label.to_owned(), ciphertext.to_owned());
            }
            _ => panic!("line outside fixture section: {line}"),
        }
    }
    if let Some(vector) = current {
        vectors.push(vector);
    }
    vectors
}

fn parse_usize_list(raw: &str) -> Vec<usize> {
    raw.split(',')
        .map(|value| value.parse().expect("usize value"))
        .collect()
}

fn parse_plaintext_rows(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (label, plaintext) = line.split_once(':').expect("plaintext separator");
            (
                label.trim().to_owned(),
                plaintext.strip_prefix(' ').unwrap_or(plaintext).to_owned(),
            )
        })
        .collect()
}
