//! Library-level regression tests for the first-trigram ("message start")
//! analysis. The module has no CLI subcommand by design, so these tests pin the
//! computed tabulation (both representations) and every hypothesis verdict.

use std::collections::BTreeSet;

use noita_eye_puzzle::analysis::first_trigram::{
    self, ChecksumRelation, ChecksumVerdict, DigitPositionSets, FirstTrigramAnalysis, IndexVerdict,
    base5_digits,
};
use noita_eye_puzzle::report::Report;

fn analysis() -> FirstTrigramAnalysis {
    first_trigram::analyze().expect("verified corpus tabulates")
}

#[test]
fn base5_digits_round_trip() {
    for value in 0u8..=124 {
        let [a, b, c] = base5_digits(value);
        assert!(a <= 4 && b <= 4 && c <= 4);
        assert_eq!(
            u16::from(a) * 25 + u16::from(b) * 5 + u16::from(c),
            u16::from(value)
        );
    }
}

#[test]
fn tabulation_matches_recomputed_corpus_values() {
    let analysis = analysis();
    assert_eq!(analysis.rows.len(), 9);

    // Storage-order base-5 forms, computed in code from corpus::trigrams().
    let expected_storage_digits = [
        [2, 0, 1],
        [3, 1, 1],
        [1, 2, 1],
        [3, 0, 1],
        [2, 2, 1],
        [1, 1, 1],
        [1, 0, 1],
        [3, 0, 1],
        [1, 1, 1],
    ];
    let expected_storage_values = [51u8, 81, 36, 76, 61, 31, 26, 76, 31];
    let expected_reading_values = [50u8, 80, 36, 76, 63, 34, 27, 77, 33];

    for (index, row) in analysis.rows.iter().enumerate() {
        assert_eq!(row.message_id as usize, index);
        assert_eq!(
            Some(&row.storage_digits),
            expected_storage_digits.get(index)
        );
        assert_eq!(Some(&row.storage_value), expected_storage_values.get(index));
        assert_eq!(Some(&row.reading_value), expected_reading_values.get(index));
        // The decomposition is internally consistent for both layers.
        assert_eq!(row.storage_digits, base5_digits(row.storage_value));
        assert_eq!(row.reading_digits, base5_digits(row.reading_value));
        // Ranges hold: storage 0..=124, reading 0..=82.
        assert!(row.storage_value <= 124);
        assert!(row.reading_value <= 82);
    }
}

#[test]
fn reading_layer_distinct_but_storage_forms_collide() {
    let analysis = analysis();
    // The wiki's "first trigram value in every message is different" holds in the
    // reading layer.
    assert!(analysis.reading_index.all_distinct);
    let reading: BTreeSet<u8> = analysis.reading_values().into_iter().collect();
    assert_eq!(reading.len(), 9);

    // But the raw base-5 storage forms collide: 76 (west2,west4) and 31
    // (west3,east5) each appear twice, so only 7 distinct values.
    assert!(!analysis.storage_index.all_distinct);
    let storage: BTreeSet<u8> = analysis.storage_values().into_iter().collect();
    assert_eq!(storage.len(), 7);
    // Sorted with duplicates: 76 and 31 each appear twice (only 7 distinct).
    let mut storage_values = analysis.storage_values();
    storage_values.sort_unstable();
    assert_eq!(storage_values, [26, 31, 31, 36, 51, 61, 76, 76, 81]);
}

#[test]
fn index_hypothesis_is_rejected_in_both_layers() {
    let analysis = analysis();
    assert!(!analysis.storage_index.is_supported());
    assert!(!analysis.reading_index.is_supported());
    // Values lie far outside any 1-9 / 0-8 / A-I index range.
    assert_eq!(
        (analysis.storage_index.min, analysis.storage_index.max),
        (26, 81)
    );
    assert_eq!(
        (analysis.reading_index.min, analysis.reading_index.max),
        (27, 80)
    );
}

#[test]
fn checksum_and_last_char_hypotheses_are_rejected() {
    let analysis = analysis();
    for verdict in [&analysis.storage_checksum, &analysis.reading_checksum] {
        assert!(!verdict.is_supported());
        assert!(verdict.holding.is_empty());
        for relation in ChecksumRelation::ALL {
            assert!(!verdict.holds(relation));
        }
    }
}

#[test]
fn storage_units_digit_is_constant_one_but_not_corpus_wide() {
    let analysis = analysis();
    // Every storage-order first trigram ends in base-5 digit 1.
    assert_eq!(analysis.storage_positions.constant_units(), Some(1));
    // Honest control: this is specific to the first trigram. Over all 1036
    // storage trigrams the units digit is not concentrated on 1.
    assert_eq!(analysis.storage_units_histogram, [263, 254, 238, 163, 118]);
    assert_eq!(analysis.storage_units_histogram.iter().sum::<usize>(), 1036);
    let units_one = analysis
        .storage_units_histogram
        .get(1)
        .copied()
        .unwrap_or(0);
    let total: usize = analysis.storage_units_histogram.iter().sum();
    // Far from the 9/9 = 100% seen at the first trigram.
    assert!((units_one as f64) / (total as f64) < 0.30);
}

#[test]
fn per_position_digit_sets_are_as_documented() {
    let analysis = analysis();
    let s = &analysis.storage_positions;
    assert_eq!(s.leading, BTreeSet::from([1, 2, 3]));
    assert_eq!(s.middle, BTreeSet::from([0, 1, 2]));
    assert_eq!(s.units, BTreeSet::from([1]));

    let r = &analysis.reading_positions;
    assert_eq!(r.leading, BTreeSet::from([1, 2, 3]));
    assert_eq!(r.middle, BTreeSet::from([0, 1, 2]));
    assert_eq!(r.units, BTreeSet::from([0, 1, 2, 3, 4]));
}

#[test]
fn predicates_fire_on_constructed_positive_cases() {
    // Index predicate detects a real 0..=8 permutation.
    let index = IndexVerdict::evaluate(&[8, 7, 6, 5, 4, 3, 2, 1, 0]);
    assert!(index.is_supported() && index.is_permutation_of_0_8 && index.all_distinct);
    // Checksum predicate detects first == last in every sequence.
    let checksum = ChecksumVerdict::evaluate(&[vec![5u8, 1, 2, 5], vec![9, 0, 9]], 83);
    assert!(checksum.holds(ChecksumRelation::EqualsLast) && checksum.is_supported());
    // Constant-units predicate distinguishes constant from varied units.
    assert_eq!(
        DigitPositionSets::from_digits(&[[2, 0, 1], [3, 1, 1]]).constant_units(),
        Some(1)
    );
    assert_eq!(
        DigitPositionSets::from_digits(&[[0, 0, 1], [0, 0, 2]]).constant_units(),
        None
    );
}

#[test]
fn render_contains_table_and_verdicts() {
    let rendered = analysis().render();
    assert!(rendered.contains("First-trigram"));
    assert!(rendered.contains("east1"));
    assert!(rendered.contains("units {1}"));
    assert!(rendered.contains("index hypothesis"));
}
