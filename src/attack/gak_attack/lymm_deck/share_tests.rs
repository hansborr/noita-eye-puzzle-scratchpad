//! Shareable-output tests for Lymm deck recovery.

use std::collections::BTreeMap;

use super::{
    LymmDeckSpec, SwapRecoveryConfig, encrypt_lymm_deck, parse_known_plaintext_pairs,
    python_pt_mapping_literal, recover_known_plaintext_swaps,
};

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
    assert_eq!(
        (
            parsed.len(),
            parsed.contains_key(&'J'),
            parsed.contains_key(&'Z')
        ),
        (24, false, false)
    );

    let first = pairs.first().expect("first pair");
    let completed = complete_mapping_for_oracle(&spec, &parsed);
    assert_eq!(
        compressed_encrypt(&spec, &completed, &first.plaintext),
        first.ciphertext
    );

    let mut null_mapping = parsed;
    null_mapping
        .get_mut(&'T')
        .expect("T appears in the planted control plaintext")
        .rotate_left(1);
    let completed_null = complete_mapping_for_oracle(&spec, &null_mapping);
    assert_ne!(
        compressed_encrypt(&spec, &completed_null, &first.plaintext),
        first.ciphertext,
        "a mutated exported mapping must not pass the matched round-trip null"
    );
}

fn complete_mapping_for_oracle(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
) -> BTreeMap<char, Vec<usize>> {
    let mut complete = mapping.clone();
    for &letter in &spec.pt_alphabet {
        let _existing = complete.entry(letter).or_insert_with(|| spec.base.clone());
    }
    complete
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
