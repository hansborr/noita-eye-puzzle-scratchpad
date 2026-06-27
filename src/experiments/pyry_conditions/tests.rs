use super::{
    ALPHABET_SIZE, CandidateFamily, ConditionVector, PyryCondition, PyryConditionsConfig,
    evaluate_corpus, run_pyry_conditions,
};
use crate::core::trigram::TrigramValue;

fn values(rows: &[&[u8]]) -> Vec<Vec<TrigramValue>> {
    rows.iter()
        .map(|row| row.iter().copied().map(value).collect())
        .collect()
}

fn value(raw: u8) -> TrigramValue {
    TrigramValue::new(raw).unwrap()
}

fn full_support_prefix() -> Vec<TrigramValue> {
    (0..ALPHABET_SIZE).map(|raw| value(raw as u8)).collect()
}

fn assert_condition(corpus: &[Vec<TrigramValue>], condition: PyryCondition, expected: bool) {
    let evaluation = evaluate_corpus("fixture", corpus);
    assert_eq!(
        evaluation.vector.get(condition),
        expected,
        "{condition:?} metrics: {:?}",
        evaluation.metrics
    );
}

#[test]
fn condition_1_flat_ioc_discriminates() {
    let flat = values(&[&[0, 1, 2, 3, 4, 5, 6, 7], &[8, 9, 10, 11, 12, 13, 14, 15]]);
    let peaked = values(&[&[0, 0, 0, 0, 0, 0, 1, 2]]);
    assert_condition(&flat, PyryCondition::FlatIoc, true);
    assert_condition(&peaked, PyryCondition::FlatIoc, false);
}

#[test]
fn condition_2_contiguous_support_discriminates() {
    let complete = vec![full_support_prefix()];
    let missing = values(&[&[0, 1, 2, 3, 4, 82]]);
    assert_condition(&complete, PyryCondition::ContiguousAlphabet, true);
    assert_condition(&missing, PyryCondition::ContiguousAlphabet, false);
}

#[test]
fn condition_3_aligned_shared_runs_discriminates() {
    let positive = values(&[&[1, 7, 8, 2], &[3, 7, 8, 4]]);
    let negative = values(&[&[1, 7, 9, 2], &[3, 8, 7, 4]]);
    assert_condition(&positive, PyryCondition::AlignedSharedSections, true);
    assert_condition(&negative, PyryCondition::AlignedSharedSections, false);
}

#[test]
fn condition_4_isomorphs_discriminate() {
    let positive = values(&[&[1, 2, 1, 3, 4, 3]]);
    let negative = values(&[&[1, 2, 3, 4, 5, 6]]);
    assert_condition(&positive, PyryCondition::IsomorphsPresent, true);
    assert_condition(&negative, PyryCondition::IsomorphsPresent, false);
}

#[test]
fn condition_5_shared_after_varying_prefix_discriminates() {
    let positive = values(&[&[1, 7, 8, 9], &[2, 7, 8, 9]]);
    let negative = values(&[&[1, 7, 8, 9], &[1, 7, 8, 4]]);
    assert_condition(&positive, PyryCondition::SharedAfterVaryingPrefix, true);
    assert_condition(&negative, PyryCondition::SharedAfterVaryingPrefix, false);
}

#[test]
fn condition_6_near_isomorphs_discriminate() {
    let positive = values(&[&[1, 2, 1, 5, 3, 4, 4]]);
    let negative = values(&[&[1, 2, 3, 4, 5, 6, 7]]);
    assert_condition(&positive, PyryCondition::NearIsomorphsPresent, true);
    assert_condition(&negative, PyryCondition::NearIsomorphsPresent, false);
}

#[test]
fn condition_7_differing_first_shared_second_discriminates() {
    let positive = values(&[&[1, 66, 5], &[2, 66, 5]]);
    let negative = values(&[&[1, 66, 5], &[2, 67, 6]]);
    assert_condition(&positive, PyryCondition::DifferingFirstSharedSecond, true);
    assert_condition(&negative, PyryCondition::DifferingFirstSharedSecond, false);
}

#[test]
fn condition_8_no_doubled_trigrams_discriminates() {
    let positive = values(&[&[1, 2, 3], &[3, 2, 1]]);
    let negative = values(&[&[1, 1, 2]]);
    assert_condition(&positive, PyryCondition::NoDoubledTrigrams, true);
    assert_condition(&negative, PyryCondition::NoDoubledTrigrams, false);
}

#[test]
fn condition_9_non_shared_isomorphs_differ_discriminates() {
    let positive = values(&[&[1, 2, 3, 1, 4, 2, 9, 8, 7, 9, 6, 8]]);
    let negative = values(&[&[1, 2, 3, 1, 4, 2, 1, 2, 3, 1, 4, 2]]);
    assert_condition(&positive, PyryCondition::NonSharedIsomorphsDiffer, true);
    assert_condition(&negative, PyryCondition::NonSharedIsomorphsDiffer, false);
}

#[test]
fn eye_condition_vector_is_pinned() {
    let report = run_pyry_conditions(PyryConditionsConfig {
        seed: 123,
        fixture_draws: 2,
    })
    .unwrap();
    assert_eq!(
        report.eyes.vector.as_array(),
        [true, true, true, true, true, true, true, true, true]
    );
    assert_eq!(report.eyes.metrics.total_symbols, 1_036);
    assert_eq!(report.eyes.metrics.distinct_in_alphabet, 83);
    assert_eq!(report.eyes.metrics.adjacent_equal_count, 0);
}

#[test]
fn generated_family_rows_are_reproducible() {
    let config = PyryConditionsConfig {
        seed: 987,
        fixture_draws: 3,
    };
    let first = run_pyry_conditions(config).unwrap();
    let second = run_pyry_conditions(config).unwrap();
    assert_eq!(first.families, second.families);
    assert_eq!(first.families.len(), CandidateFamily::all().len());
    for family in &first.families {
        assert_eq!(family.draws.len(), config.fixture_draws);
    }
}

#[test]
fn condition_vector_counts_passes() {
    let vector = ConditionVector::new([true, false, true, false, true, false, true, false, true]);
    assert_eq!(vector.passed_count(), 5);
    assert!(!vector.all_pass());
}
