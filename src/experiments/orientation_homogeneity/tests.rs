use super::{
    HOMOGENEITY_DEGREES_OF_FREEDOM, HomogeneityNullComparison, ORIENTATION_BUCKETS,
    OrientationHomogeneityConfig, OrientationHomogeneityError, g_test_homogeneity_statistic,
    homogeneity_statistics, pearson_homogeneity_statistic, positive_control, repartition_table,
    run_orientation_homogeneity,
};
use crate::nulls::null::SplitMix64;

#[test]
fn homogeneity_statistics_match_toy_table() {
    let table = [[8, 2, 0, 0, 0], [2, 8, 0, 0, 0]];

    assert_close(pearson_homogeneity_statistic(&table), 7.2, 1e-12);
    assert_close(
        g_test_homogeneity_statistic(&table),
        7.709_790_280_870_3,
        1e-12,
    );

    let statistics = homogeneity_statistics(&table);
    assert_eq!(
        statistics.degrees_of_freedom,
        HOMOGENEITY_DEGREES_OF_FREEDOM
    );
}

#[test]
fn repartition_null_preserves_lengths_and_pooled_counts() {
    let pooled = vec![0, 0, 1, 2, 2, 3, 4, 4, 4];
    let lengths = vec![2, 3, 4];
    let mut rng = SplitMix64::new(0x5eed);

    let table = repartition_table(&pooled, &lengths, &mut rng).unwrap();

    let row_totals = table
        .iter()
        .map(|row| row.iter().sum::<usize>())
        .collect::<Vec<_>>();
    assert_eq!(row_totals, lengths);
    assert_eq!(pooled_counts_for_test(&table), [2, 1, 2, 1, 3]);
}

#[test]
fn repartition_rejects_length_mismatch() {
    let mut rng = SplitMix64::new(0x5eed);
    let error = repartition_table(&[0, 1, 2], &[1, 1], &mut rng).unwrap_err();
    assert_eq!(
        error,
        OrientationHomogeneityError::LengthTotalMismatch {
            lengths_total: 2,
            pooled_total: 3,
        }
    );
}

#[test]
fn heterogeneous_positive_control_lands_in_upper_tail() {
    let config = OrientationHomogeneityConfig {
        seed: 0x7070,
        trials_per_seed: 96,
        seed_count: 2,
    };
    let lengths = [60, 61, 62, 63, 64, 65, 66, 67, 68];

    let control = positive_control(config, &lengths).unwrap();

    assert_upper_tail_signal(control.pearson);
    assert_upper_tail_signal(control.g_test);
}

#[test]
fn real_eye_headline_counts_are_pinned() {
    let config = OrientationHomogeneityConfig {
        seed: 0x5151,
        trials_per_seed: 8,
        seed_count: 2,
    };

    let report = run_orientation_homogeneity(config).unwrap();
    let lengths = report
        .profiles
        .iter()
        .map(|profile| profile.length)
        .collect::<Vec<_>>();
    let counts = report
        .profiles
        .iter()
        .map(|profile| profile.counts)
        .collect::<Vec<_>>();

    assert_eq!(lengths, vec![297, 309, 354, 306, 411, 372, 357, 360, 342]);
    assert_eq!(
        counts,
        vec![
            [70, 76, 55, 50, 46],
            [70, 69, 72, 53, 45],
            [93, 83, 78, 53, 47],
            [75, 77, 77, 44, 33],
            [111, 89, 96, 65, 50],
            [85, 94, 86, 58, 49],
            [93, 72, 81, 69, 42],
            [93, 86, 80, 54, 47],
            [84, 93, 74, 44, 47],
        ]
    );
    assert_eq!(report.total_orientations, 3_108);
    assert_eq!(report.total_eye_count, 3_108);
    assert_eq!(report.pooled_uniform.counts, [774, 739, 699, 490, 406]);
    assert_close(
        report.pooled_uniform.chi_square_vs_uniform,
        171.816_602_316_602_3,
        1e-12,
    );
    assert_close(
        report.homogeneity.pearson_chi_square,
        21.916_794_741_888_925,
        1e-12,
    );
    assert_close(report.homogeneity.g_test, 21.999_082_968_340_836, 1e-12);
    assert_eq!(report.pooled_uniform.counts.len(), ORIENTATION_BUCKETS);
}

fn assert_upper_tail_signal(comparison: HomogeneityNullComparison) {
    assert!(
        comparison.observed > comparison.null.q975,
        "observed={} null={:?}",
        comparison.observed,
        comparison.null
    );
    assert!(
        comparison.upper_tail_add_one_p <= 0.01,
        "p={} comparison={:?}",
        comparison.upper_tail_add_one_p,
        comparison
    );
}

fn pooled_counts_for_test(table: &[[usize; ORIENTATION_BUCKETS]]) -> [usize; ORIENTATION_BUCKETS] {
    let mut counts = [0; ORIENTATION_BUCKETS];
    for row in table {
        for (slot, &count) in counts.iter_mut().zip(row) {
            *slot += count;
        }
    }
    counts
}

fn assert_close(observed: f64, expected: f64, tolerance: f64) {
    assert!(
        (observed - expected).abs() <= tolerance,
        "observed {observed}, expected {expected}"
    );
}
