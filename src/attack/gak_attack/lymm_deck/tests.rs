//! Differential and parser tests for Lymm's deck-cipher oracle.

use std::collections::BTreeMap;

use super::{
    GakSwapSelfTestConfig, KnownPlaintextPair, LYMM_DEFAULT_PT_ALPHABET, LetterRecoveryVerdict,
    LymmDeckSpec, NullControlOutcome, SwapInferenceOutcome, SwapInferenceRange, SwapRecoveryConfig,
    SwapRecoveryError, TopSwapConstraints, encrypt_lymm_deck, enumerate_top_swap_domains,
    gak_swap_self_test, generate_random_pt_mapping, infer_known_plaintext_swap_budget,
    lymm_default_ct_alphabet, parse_known_plaintext_pairs, python_pt_mapping_literal,
    recover_known_plaintext_swaps,
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

#[test]
fn python_pt_mapping_literal_round_trips_recovered_candidate_and_null_breaks() {
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

    let literal = python_pt_mapping_literal(&report.pt_mapping);
    assert!(literal.starts_with("pt_mapping = {\n"));
    assert!(literal.contains("\"A\": np.array(["));
    let parsed = parse_python_pt_mapping_literal(&literal);
    assert_eq!(parsed, report.pt_mapping);

    let first = pairs.first().expect("first pair");
    assert_eq!(
        compressed_encrypt(&spec, &parsed, &first.plaintext),
        first.ciphertext
    );

    let mut null_mapping = parsed;
    null_mapping
        .get_mut(&'T')
        .expect("T appears in the planted control plaintext")
        .rotate_left(1);
    assert_ne!(
        compressed_encrypt(&spec, &null_mapping, &first.plaintext),
        first.ciphertext,
        "a mutated exported mapping must not pass the matched round-trip null"
    );
}

#[test]
fn infer_swaps_ns1_reports_final_support_not_swap_word_length() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/1_swap_ct.txt"),
    )
    .expect("known plaintext pairs");

    let report = infer_known_plaintext_swap_budget(
        &spec,
        &pairs,
        SwapInferenceRange::new(1, 2),
        SwapRecoveryConfig::with_max_swaps(1),
    )
    .expect("swap inference");
    let selected = report.selected.as_ref().expect("selected budget");

    assert_eq!(report.inferred_max_swaps(), Some(1));
    assert_eq!(report.inferred_support_size(), Some(2));
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(
        report.attempts.first().map(|attempt| attempt.outcome),
        Some(SwapInferenceOutcome::ExactRoundTrip)
    );
    assert_eq!(
        selected
            .letters
            .iter()
            .filter(|letter| letter.occurrences > 0)
            .map(|letter| letter.canonical_swaps.len())
            .max(),
        Some(1),
        "the inferred summary must report support size 2, not one-swap word length"
    );
}

#[test]
fn infer_swaps_planted_budget_two_closes_at_upper_bound() {
    let spec = LymmDeckSpec::from_shift_decimation(
        29,
        LYMM_DEFAULT_PT_ALPHABET,
        &lymm_default_ct_alphabet(29),
        7,
        3,
    )
    .expect("spec");
    let planted =
        generate_random_pt_mapping(&spec, 2, 0x51a7_0000_0000_0002).expect("planted mapping");
    let pairs = encrypted_plaintext_pairs(&spec, &planted.pt_mapping);
    let mut config = SwapRecoveryConfig::with_max_swaps(1);
    config.max_nodes = Some(50_000);

    let report = infer_known_plaintext_swap_budget(
        &spec,
        &pairs,
        SwapInferenceRange::new(1, 2),
        config.clone(),
    )
    .expect("swap inference");

    assert_eq!(report.inferred_max_swaps(), Some(2));
    assert_eq!(report.attempts.len(), 2);
    assert_ne!(
        report.attempts.first().map(|attempt| attempt.outcome),
        Some(SwapInferenceOutcome::ExactRoundTrip)
    );
    assert_eq!(
        report.attempts.get(1).map(|attempt| attempt.outcome),
        Some(SwapInferenceOutcome::ExactRoundTrip)
    );
    assert!(report.exact());

    let under_budget =
        infer_known_plaintext_swap_budget(&spec, &pairs, SwapInferenceRange::new(1, 1), config)
            .expect("under-budget inference");
    assert!(under_budget.selected.is_none());
    assert_ne!(
        under_budget.attempts.first().map(|attempt| attempt.outcome),
        Some(SwapInferenceOutcome::ExactRoundTrip)
    );
}

#[test]
fn infer_swaps_caps_requested_range_at_measured_frontier() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/1_swap_ct.txt"),
    )
    .expect("known plaintext pairs");

    let report = infer_known_plaintext_swap_budget(
        &spec,
        &pairs,
        SwapInferenceRange::new(1, 3),
        SwapRecoveryConfig::with_max_swaps(1),
    )
    .expect("frontier-capped inference");
    assert!(report.frontier_capped);
    assert_eq!(report.attempted, SwapInferenceRange::new(1, 2));
    assert_eq!(report.inferred_max_swaps(), Some(1));

    let unsupported = infer_known_plaintext_swap_budget(
        &spec,
        &pairs,
        SwapInferenceRange::new(3, 4),
        SwapRecoveryConfig::with_max_swaps(3),
    )
    .expect_err("range starting past the frontier must not run");
    assert!(matches!(
        unsupported,
        SwapRecoveryError::UnsupportedBudget { max_swaps: 3 }
    ));
}

#[test]
fn swap_recovery_self_test_passes_supported_frontier_controls() {
    let report =
        gak_swap_self_test(GakSwapSelfTestConfig::default()).expect("self-test should run");

    assert!(report.passed(), "{report:#?}");
    assert!(report.positive_ns1.exact);
    assert_eq!(
        report.positive_ns1.matched_observed_letters,
        report.positive_ns1.observed_letters
    );
    assert_eq!(report.positive_ns1.ambiguous_observed_letters, 0);
    assert_eq!(report.positive_ns1.ambiguous_missing_planted_letters, 0);
    assert_eq!(report.positive_ns1.mismatched_unique_letters, 0);
    assert!(report.positive_ns2.exact);
    assert_eq!(report.positive_ns2.mismatched_unique_letters, 0);
    assert_eq!(report.positive_ns2.ambiguous_missing_planted_letters, 0);
    assert_eq!(
        report.positive_ns2.matched_observed_letters
            + report.positive_ns2.ambiguous_observed_letters,
        report.positive_ns2.observed_letters
    );
    assert!(report.full_permutation_null.failed);
    assert_eq!(
        report.full_permutation_null.outcome,
        NullControlOutcome::CleanFailure
    );
    assert!(report.over_budget_null.failed);
    assert_eq!(
        report.over_budget_null.outcome,
        NullControlOutcome::CleanFailure
    );
    assert!(report.over_budget_recovery_exact);
    assert!(report.label_shuffle_null.failed);
    assert_eq!(
        report.label_shuffle_null.outcome,
        NullControlOutcome::CleanFailure
    );
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

fn encrypted_plaintext_pairs(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
) -> Vec<KnownPlaintextPair> {
    parse_plaintext_rows(include_str!(
        "../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"
    ))
    .into_iter()
    .map(|(label, plaintext)| {
        let ciphertext = encrypt_lymm_deck(spec, mapping, &plaintext)
            .expect("planted ciphertext")
            .chars()
            .filter(|ch| spec.ct_alphabet.contains(ch))
            .collect();
        KnownPlaintextPair {
            label,
            plaintext,
            ciphertext,
        }
    })
    .collect()
}

fn compressed_encrypt(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
    plaintext: &str,
) -> String {
    encrypt_lymm_deck(spec, mapping, plaintext)
        .expect("encrypt")
        .chars()
        .filter(|ch| spec.ct_alphabet.contains(ch))
        .collect()
}

fn parse_python_pt_mapping_literal(raw: &str) -> BTreeMap<char, Vec<usize>> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == "pt_mapping = {" || trimmed == "}" {
                return None;
            }
            let (key, rest) = trimmed.split_once(": np.array([").expect("mapping row");
            let values = rest
                .strip_suffix("], dtype=int),")
                .expect("numpy row suffix");
            let letter = key
                .trim_matches('"')
                .chars()
                .next()
                .expect("single-character key");
            let permutation = values
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.parse::<usize>().expect("permutation value"))
                .collect::<Vec<_>>();
            Some((letter, permutation))
        })
        .collect()
}
