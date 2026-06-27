use crate::analysis::orders::{corpus_grids, standard36_orders};
use crate::nulls::null::{
    NullConfig, NullConfigError, NullRunError, SplitMix64, add_one_p_value,
    analytic_headline_bounds, evaluate_trial, mix_seed, run_standard36_null, stateless_splitmix,
    wilson_95,
};

const STABILITY_SEEDS: [u64; 5] = [12_345, 67_890, 13_579, 24_680, 424_242];
const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

fn assert_relative_close(actual: f64, expected: f64, label: &str) {
    let tolerance = expected.abs() * FLOAT_RELATIVE_EPSILON;
    let difference = (actual - expected).abs();
    assert!(
        difference <= tolerance,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
    );
}

#[test]
fn splitmix64_seed_is_reproducible() {
    let mut first = SplitMix64::new(12_345);
    let mut second = SplitMix64::new(12_345);
    let first_values: Vec<u64> = (0..8).map(|_| first.next_u64()).collect();
    let second_values: Vec<u64> = (0..8).map(|_| second.next_u64()).collect();
    assert_eq!(first_values, second_values);
}

#[test]
fn add_one_p_value_uses_plus_one_estimator() {
    assert_eq!(
        add_one_p_value(0, 2_000).to_bits(),
        (1.0_f64 / 2_001.0_f64).to_bits()
    );
    assert_eq!(
        add_one_p_value(6, 1_000).to_bits(),
        (7.0_f64 / 1_001.0_f64).to_bits()
    );
}

#[test]
fn mix_seed_is_deterministic_splitmix_of_seed_xor_tag() {
    let seed = 0x1234_5678_9abc_def0;
    let tag = 0x0fed_cba9_8765_4321;
    let mixed = mix_seed(seed, tag);
    assert_eq!(mixed, mix_seed(seed, tag));
    assert_eq!(mixed, stateless_splitmix(seed ^ tag));
}

#[test]
fn null_run_rejects_zero_trials() {
    let config = NullConfig { seed: 1, trials: 0 };
    assert_eq!(
        run_standard36_null(config),
        Err(NullRunError::Config(NullConfigError::ZeroTrials))
    );
}

#[test]
fn null_run_is_reproducible_for_fixed_seed() {
    let config = NullConfig {
        seed: 0x5eed,
        trials: 3,
    };
    let first = run_standard36_null(config).unwrap();
    let second = run_standard36_null(config).unwrap();
    assert_eq!(first.headline_count, second.headline_count);
    assert_eq!(first.adjacent_zero_count, second.adjacent_zero_count);
    assert_eq!(first.min_distinct_histogram, second.min_distinct_histogram);
    assert_eq!(first.min_ceiling_histogram, second.min_ceiling_histogram);
    assert_eq!(
        first.distance4_ratio_min.to_bits(),
        second.distance4_ratio_min.to_bits()
    );
    assert_eq!(
        first.distance4_ratio_median.to_bits(),
        second.distance4_ratio_median.to_bits()
    );
    assert_eq!(
        first.distance4_ratio_max.to_bits(),
        second.distance4_ratio_max.to_bits()
    );
}

#[test]
fn analytic_bound_matches_stage_a_headline_scale() {
    let bounds = analytic_headline_bounds(36, 1036);

    assert_eq!(bounds.family_size, 36);
    assert_relative_close(
        bounds.per_order,
        5.836_200_792_956_83e-185,
        "per-order analytic headline probability",
    );
    assert_relative_close(
        bounds.bonferroni,
        2.101_032_285_464_46e-183,
        "Bonferroni analytic headline bound",
    );
    assert_relative_close(
        bounds.sidak,
        2.101_032_285_464_46e-183,
        "Sidak analytic headline bound",
    );
}

#[test]
fn standard36_fast_sweep_does_not_manufacture_contiguous_headline() {
    for seed in STABILITY_SEEDS {
        let report = run_standard36_null(NullConfig { seed, trials: 128 }).unwrap();

        assert_eq!(
            report.headline_count, 0,
            "seed {seed} reproduced the contiguous 0..=82 headline"
        );
    }
}

#[test]
#[ignore = "canonical 1000-trial Monte Carlo regression; run with cargo test -- --ignored"]
fn standard36_seed_12345_null_matches_headline_regression() {
    let report = run_standard36_null(NullConfig {
        seed: 12_345,
        trials: 1_000,
    })
    .unwrap();

    assert_eq!(report.family_size, 36);
    assert_eq!(report.headline_count, 0);
    assert_eq!(report.adjacent_zero_count, 2);
    assert_eq!(
        report.min_distinct_histogram,
        vec![(122, 1), (123, 2), (124, 136), (125, 861)]
    );
    assert_eq!(report.min_ceiling_histogram, vec![(124, 1_000)]);
    assert_relative_close(
        report.distance4_ratio_min,
        0.171_428_571_428_571,
        "minimum distance-4 ratio",
    );
    assert_relative_close(
        report.distance4_ratio_median,
        1.102_040_816_326_53,
        "median distance-4 ratio",
    );
    assert_relative_close(
        report.distance4_ratio_max,
        2.210_526_315_789_47,
        "maximum distance-4 ratio",
    );

    let adjacent_interval = wilson_95(report.adjacent_zero_count, report.config.trials);
    assert_eq!(adjacent_interval.count, 2);
    assert_eq!(adjacent_interval.trials, 1_000);
    assert_relative_close(
        adjacent_interval.estimate,
        0.002,
        "adjacent-zero Wilson point estimate",
    );

    let grids = corpus_grids().unwrap();
    let real_outcome = evaluate_trial(&grids, &standard36_orders()).unwrap();
    assert_relative_close(
        real_outcome.max_distance4_ratio,
        2.785_714_285_714_29,
        "real-corpus maximum distance-4 ratio",
    );
    assert!(real_outcome.max_distance4_ratio > report.distance4_ratio_max);
}

#[test]
#[ignore = "multi-seed 1000-trial stability sweep; run with cargo test -- --ignored"]
fn standard36_ignored_sweep_does_not_manufacture_contiguous_headline() {
    for seed in STABILITY_SEEDS {
        let report = run_standard36_null(NullConfig {
            seed,
            trials: 1_000,
        })
        .unwrap();

        assert_eq!(
            report.headline_count, 0,
            "seed {seed} reproduced the contiguous 0..=82 headline"
        );
    }
}

mod harness_tests {
    use crate::nulls::null::{
        F64Band, NullColumnError, NullSampler, SplitMix64, UsizeBand, WithinMessageShuffle,
        f64_band, median_f64, median_usize, run_null_test, run_null_test_columns,
        run_null_test_columns_streams, run_null_test_streams, scaled_quantile_index, usize_band,
    };
    use core::convert::Infallible;

    fn first_value(draw: &[Vec<usize>]) -> usize {
        draw.first()
            .and_then(|message| message.first())
            .copied()
            .unwrap_or_default()
    }

    fn last_value(draw: &[Vec<usize>]) -> usize {
        draw.first()
            .and_then(|message| message.last())
            .copied()
            .unwrap_or_default()
    }

    fn total_value(draw: &[Vec<usize>]) -> usize {
        draw.iter().flatten().copied().sum()
    }

    #[test]
    fn within_message_shuffle_preserves_each_message_multiset() {
        let messages = vec![vec![0usize, 0, 1, 1, 2, 2], vec![3, 4, 5]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let mut rng = SplitMix64::new(0x5151);

        let draw = sampler.sample(&mut rng).unwrap();

        assert_eq!(draw.len(), messages.len());
        for (original, shuffled) in messages.iter().zip(&draw) {
            assert_eq!(shuffled.len(), original.len());
            let mut original_sorted = original.clone();
            let mut shuffled_sorted = shuffled.clone();
            original_sorted.sort_unstable();
            shuffled_sorted.sort_unstable();
            assert_eq!(shuffled_sorted, original_sorted);
        }
    }

    #[test]
    fn run_null_test_with_invariant_statistic_is_hand_checkable() {
        let messages = vec![vec![0usize, 1, 2], vec![3, 4]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        // Sum is invariant under a within-message shuffle, so every sample is
        // exactly the observed total and the observed value sits in both tails.
        let result = run_null_test(
            |draw| Ok::<usize, Infallible>(total_value(draw)),
            10,
            &sampler,
            5,
            0xABCD,
        )
        .unwrap();

        assert_eq!(result.observed, 10);
        assert_eq!(result.samples, vec![10usize; 5]);
        assert_eq!(result.lower_tail_count, 5);
        assert_eq!(result.upper_tail_count, 5);
        assert_eq!(result.trials, 5);
    }

    #[test]
    fn run_null_test_is_deterministic_in_seed() {
        let messages = vec![vec![0usize, 1, 2, 3, 4]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        let first = run_null_test(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            0,
            &sampler,
            16,
            0x1234,
        )
        .unwrap();
        let second = run_null_test(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            0,
            &sampler,
            16,
            0x1234,
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn run_null_test_streams_concatenates_in_stream_order() {
        let messages = vec![vec![0usize, 1, 2, 3, 4, 5]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let seeds = [111u64, 222, 333];

        let streamed = run_null_test_streams(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            2,
            &sampler,
            3,
            4,
            |index| seeds.get(index).copied().unwrap_or_default(),
        )
        .unwrap();

        let mut expected_samples = Vec::new();
        let mut lower = 0usize;
        let mut upper = 0usize;
        for &seed in &seeds {
            let stream = run_null_test(
                |draw| Ok::<usize, Infallible>(first_value(draw)),
                2,
                &sampler,
                4,
                seed,
            )
            .unwrap();
            expected_samples.extend(stream.samples);
            lower += stream.lower_tail_count;
            upper += stream.upper_tail_count;
        }

        assert_eq!(streamed.samples, expected_samples);
        assert_eq!(streamed.trials, 12);
        assert_eq!(streamed.lower_tail_count, lower);
        assert_eq!(streamed.upper_tail_count, upper);
    }

    #[test]
    fn run_null_test_columns_reports_width_mismatch() {
        let messages = vec![vec![0usize, 1, 2]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        let result: Result<_, NullColumnError<Infallible>> = run_null_test_columns(
            |_draw| Ok(vec![1usize, 2]),
            vec![0usize, 0, 0],
            &sampler,
            4,
            7,
        );

        assert_eq!(
            result,
            Err(NullColumnError::WidthMismatch {
                expected: 3,
                observed: 2,
            })
        );
    }

    #[test]
    fn run_null_test_columns_streams_matches_per_stream_columns() {
        let messages = vec![vec![0usize, 1, 2, 3]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let seeds = [7u64, 9, 11];
        let observed = [1usize, 2];

        let columns = run_null_test_columns_streams(
            |draw| Ok::<Vec<usize>, Infallible>(vec![first_value(draw), last_value(draw)]),
            &observed,
            &sampler,
            3,
            5,
            |index| seeds.get(index).copied().unwrap_or_default(),
        )
        .unwrap();

        let mut expected: Vec<Vec<usize>> = vec![Vec::new(), Vec::new()];
        for &seed in &seeds {
            let per_stream = run_null_test_columns(
                |draw| Ok::<Vec<usize>, Infallible>(vec![first_value(draw), last_value(draw)]),
                observed.to_vec(),
                &sampler,
                5,
                seed,
            )
            .unwrap();
            for (slot, column) in expected.iter_mut().zip(&per_stream) {
                slot.extend(column.samples.iter().copied());
            }
        }

        assert_eq!(columns.len(), 2);
        for (column, expected_samples) in columns.iter().zip(&expected) {
            assert_eq!(&column.samples, expected_samples);
            assert_eq!(column.trials, 15);
        }
    }

    #[test]
    fn usize_band_matches_explicit_quantile_math() {
        let samples: Vec<usize> = vec![5, 3, 8, 1, 9, 2, 7, 4, 6, 0];
        let band: UsizeBand = usize_band(&samples);

        let mut sorted = samples.clone();
        sorted.sort_unstable();
        assert_eq!(band.trials, samples.len());
        assert_eq!(band.min, sorted.first().copied().unwrap());
        assert_eq!(band.max, sorted.last().copied().unwrap());
        assert_eq!(
            band.q025,
            sorted
                .get(scaled_quantile_index(sorted.len(), 25, 1_000))
                .copied()
                .unwrap()
        );
        assert_eq!(
            band.q975,
            sorted
                .get(scaled_quantile_index(sorted.len(), 975, 1_000))
                .copied()
                .unwrap()
        );
        assert_eq!(band.median.to_bits(), median_usize(&sorted).to_bits());
        let expected_mean = samples.iter().sum::<usize>() as f64 / samples.len() as f64;
        assert_eq!(band.mean.to_bits(), expected_mean.to_bits());
    }

    #[test]
    fn f64_band_matches_explicit_quantile_math() {
        let samples: Vec<f64> = vec![5.0, 3.0, 8.5, 1.0, 9.0, 2.0, 7.0, 4.0, 6.0, 0.5];
        let band: F64Band = f64_band(&samples);

        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        assert_eq!(band.trials, samples.len());
        assert_eq!(
            band.min.to_bits(),
            sorted.first().copied().unwrap().to_bits()
        );
        assert_eq!(
            band.max.to_bits(),
            sorted.last().copied().unwrap().to_bits()
        );
        assert_eq!(
            band.q025.to_bits(),
            sorted
                .get(scaled_quantile_index(sorted.len(), 25, 1_000))
                .copied()
                .unwrap()
                .to_bits()
        );
        assert_eq!(
            band.q975.to_bits(),
            sorted
                .get(scaled_quantile_index(sorted.len(), 975, 1_000))
                .copied()
                .unwrap()
                .to_bits()
        );
        assert_eq!(band.median.to_bits(), median_f64(&sorted).to_bits());
        let expected_mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert_eq!(band.mean.to_bits(), expected_mean.to_bits());
    }
}
