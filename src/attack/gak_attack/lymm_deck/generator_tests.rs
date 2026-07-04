//! Generator-set recovery controls for the Lymm deck attack.

use std::collections::BTreeMap;

use super::{
    GeneratorBranchStrategy, KnownPlaintextPair, LymmComposeDirection, LymmDeckSpec,
    LymmGeneratorSet, RecoveryGeneratorSet, SwapRecoveryConfig, SwapRecoveryError,
    TopSwapConstraints, encrypt_lymm_deck, enumerate_generator_domains, lymm_default_ct_alphabet,
    recover_known_plaintext_swaps,
};

#[test]
fn explicit_transposition_generators_recover_control_and_reject_null() {
    let spec = identity_spec(7, "AB");
    let generator_set = LymmGeneratorSet::parse_permutation_file(
        spec.n,
        "\
swap01: 1 0 2 3 4 5 6
swap02: 2 1 0 3 4 5 6
",
    )
    .expect("generator file");
    let domains = enumerate_generator_domains(&spec, &generator_set, &TopSwapConstraints::up_to(1))
        .expect("generator domains");
    assert_eq!(
        domains.branch_strategy,
        GeneratorBranchStrategy::SmallTranspositionSupport
    );

    let planted = BTreeMap::from([('A', transposition(7, 0, 1)), ('B', transposition(7, 0, 2))]);
    let pairs = encrypted_pairs(&spec, &planted, &[("a", "ABABBA"), ("b", "BAABAB")]);
    let report = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set)),
    )
    .expect("explicit transposition recovery");

    assert!(report.round_trip.exact());
    assert_eq!(report.stats.enumerated_candidates, 2);
    assert_eq!(report.pt_mapping.get(&'A'), planted.get(&'A'));
    assert_eq!(report.pt_mapping.get(&'B'), planted.get(&'B'));

    let bad_generator_set =
        LymmGeneratorSet::parse_permutation_file(spec.n, "swap01: 1 0 2 3 4 5 6\n")
            .expect("bad generator file");
    let err = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(bad_generator_set)),
    )
    .expect_err("matched null must fail when the generator surface lacks no-doubles targets");
    assert!(matches!(
        err,
        SwapRecoveryError::TargetAssumptionViolated { .. }
    ));
}

#[test]
fn emit_index_and_initial_state_recover_control_and_reject_null() {
    let spec = identity_spec(7, "AB")
        .with_emit_index(1)
        .expect("emit index")
        .with_initial_state(rotation(7, 3))
        .expect("initial state");
    let generator_set = rotation_generator_set(spec.n);
    let planted = BTreeMap::from([('A', rotation(7, 1)), ('B', rotation(7, 2))]);
    let pairs = encrypted_pairs(&spec, &planted, &[("a", "ABBAAB"), ("b", "BABAAB")]);

    let report = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set.clone())),
    )
    .expect("emit-index recovery");

    assert!(report.round_trip.exact());
    assert_eq!(report.pt_mapping.get(&'A'), planted.get(&'A'));
    assert_eq!(report.pt_mapping.get(&'B'), planted.get(&'B'));

    let err = recover_known_plaintext_swaps(
        &spec,
        &relabel_ciphertext(&spec, &pairs),
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set)),
    )
    .expect_err("ciphertext-label null must not recover");
    assert!(matched_null_error(&err));
}

#[test]
fn right_compose_recover_control_and_reject_null() {
    let spec = identity_spec(7, "AB")
        .with_compose_dir(LymmComposeDirection::Right)
        .with_emit_index(1)
        .expect("emit index");
    let generator_set = rotation_generator_set(spec.n);
    let planted = BTreeMap::from([('A', rotation(7, 1)), ('B', rotation(7, 2))]);
    let pairs = encrypted_pairs(&spec, &planted, &[("a", "ABBAAB"), ("b", "BABAAB")]);

    let report = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set.clone())),
    )
    .expect("right-compose recovery");

    assert!(report.round_trip.exact());
    assert_eq!(report.pt_mapping.get(&'A'), planted.get(&'A'));
    assert_eq!(report.pt_mapping.get(&'B'), planted.get(&'B'));

    let err = recover_known_plaintext_swaps(
        &spec,
        &relabel_ciphertext(&spec, &pairs),
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set)),
    )
    .expect_err("ciphertext-label null must not recover");
    assert!(matched_null_error(&err));
}

#[test]
fn full_support_generators_use_word_mitm_and_forced_top_prune() {
    let spec = identity_spec(7, "AB");
    let generator_set = LymmGeneratorSet::parse_permutation_file(
        spec.n,
        "\
rot1: 1 2 3 4 5 6 0
rot2: 2 3 4 5 6 0 1
",
    )
    .expect("generator file");
    let domains = enumerate_generator_domains(&spec, &generator_set, &TopSwapConstraints::up_to(1))
        .expect("generator domains");
    assert_eq!(
        domains.branch_strategy,
        GeneratorBranchStrategy::WordMitm { split: 0 }
    );

    let planted = BTreeMap::from([('A', rotation(7, 1)), ('B', rotation(7, 2))]);
    let pairs = encrypted_pairs(&spec, &planted, &[("a", "ABBAAB"), ("b", "BABAAB")]);
    let report = recover_known_plaintext_swaps(
        &spec,
        &pairs,
        SwapRecoveryConfig::with_max_swaps(1)
            .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set)),
    )
    .expect("word generator recovery");

    assert!(report.round_trip.exact());
    assert_eq!(
        report.stats.enumerated_candidates, 2,
        "identity should be dropped by the forced-top prune when every observed letter has an identity restart"
    );
    assert_eq!(report.pt_mapping.get(&'A'), planted.get(&'A'));
    assert_eq!(report.pt_mapping.get(&'B'), planted.get(&'B'));

    let shifted_pairs = relabel_ciphertext(&spec, &pairs);
    let err = recover_known_plaintext_swaps(
        &spec,
        &shifted_pairs,
        SwapRecoveryConfig::with_max_swaps(1).with_generator_set(RecoveryGeneratorSet::Explicit(
            LymmGeneratorSet::parse_permutation_file(
                spec.n,
                "\
rot1: 1 2 3 4 5 6 0
rot2: 2 3 4 5 6 0 1
",
            )
            .expect("generator file"),
        )),
    )
    .expect_err("ciphertext-label null must not recover");
    assert!(matches!(
        err,
        SwapRecoveryError::NoCandidateForTarget { .. }
            | SwapRecoveryError::TargetAssumptionViolated { .. }
            | SwapRecoveryError::NoResidualCandidate
    ));
}

fn rotation_generator_set(n: usize) -> LymmGeneratorSet {
    LymmGeneratorSet::parse_permutation_file(
        n,
        "\
rot1: 1 2 3 4 5 6 0
rot2: 2 3 4 5 6 0 1
",
    )
    .expect("generator file")
}

fn matched_null_error(error: &SwapRecoveryError) -> bool {
    matches!(
        error,
        SwapRecoveryError::NoCandidateForTarget { .. }
            | SwapRecoveryError::TargetAssumptionViolated { .. }
            | SwapRecoveryError::NoResidualCandidate
            | SwapRecoveryError::InconsistentTarget { .. }
    )
}

fn identity_spec(n: usize, pt_alphabet: &str) -> LymmDeckSpec {
    LymmDeckSpec::from_base(
        n,
        pt_alphabet,
        &lymm_default_ct_alphabet(n),
        (0..n).collect(),
    )
    .expect("identity spec")
}

fn rotation(n: usize, shift: usize) -> Vec<usize> {
    (0..n).map(|index| (index + shift) % n).collect()
}

fn transposition(n: usize, left: usize, right: usize) -> Vec<usize> {
    let mut permutation = (0..n).collect::<Vec<_>>();
    permutation.swap(left, right);
    permutation
}

fn encrypted_pairs(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
    rows: &[(&str, &str)],
) -> Vec<KnownPlaintextPair> {
    rows.iter()
        .map(|&(label, plaintext)| KnownPlaintextPair {
            label: label.to_owned(),
            plaintext: plaintext.to_owned(),
            ciphertext: encrypt_lymm_deck(spec, mapping, plaintext).expect("encrypt"),
        })
        .collect()
}

fn relabel_ciphertext(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
) -> Vec<KnownPlaintextPair> {
    pairs
        .iter()
        .map(|pair| KnownPlaintextPair {
            label: pair.label.clone(),
            plaintext: pair.plaintext.clone(),
            ciphertext: pair
                .ciphertext
                .chars()
                .map(|ch| {
                    spec.ct_alphabet
                        .iter()
                        .position(|&candidate| candidate == ch)
                        .and_then(|index| {
                            spec.ct_alphabet
                                .get((index + 1) % spec.ct_alphabet.len())
                                .copied()
                        })
                        .unwrap_or(ch)
                })
                .collect(),
        })
        .collect()
}
