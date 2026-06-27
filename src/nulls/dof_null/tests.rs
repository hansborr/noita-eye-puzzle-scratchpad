use super::{
    DofNullConfig, DofSearchSpace, GroupingRule, HeadlineStatistic, run_dof_null,
    run_dof_null_for_grids, run_dof_null_with,
};
use crate::analysis::orders::{GlyphGrid, ReadingOrder};
use crate::core::glyph::Orientation;
use crate::nulls::null::{SplitMix64, random_orientation_grids_like};

const STABILITY_SEEDS: [u64; 5] = [12_345, 67_890, 13_579, 24_680, 424_242];
const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

fn row(digits: &[u8]) -> Vec<Orientation> {
    digits
        .iter()
        .copied()
        .map(|digit| Orientation::from_digit(digit).unwrap())
        .collect()
}

fn one_row_grid(digits: &[u8]) -> Vec<GlyphGrid> {
    vec![GlyphGrid::from_orientation_rows("toy", vec![row(digits)])]
}

fn one_cell_space(statistic: HeadlineStatistic) -> DofSearchSpace {
    DofSearchSpace {
        orders: vec![ReadingOrder::RawRows],
        groupings: vec![GroupingRule::OrientationBase5 { width: 1 }],
        statistics: vec![statistic],
    }
}

fn compact_adaptive_space() -> DofSearchSpace {
    DofSearchSpace {
        orders: vec![ReadingOrder::RawRows],
        groupings: vec![
            GroupingRule::OrientationBase5 { width: 1 },
            GroupingRule::OrientationBase5 { width: 2 },
            GroupingRule::OrientationBase5 { width: 3 },
            GroupingRule::OrientationBase5 { width: 4 },
        ],
        statistics: vec![
            HeadlineStatistic::DistinctCount,
            HeadlineStatistic::ContiguousBoundedAtMax,
            HeadlineStatistic::ZeroAdjacencyRate,
            HeadlineStatistic::BestRecurrenceRatio,
        ],
    }
}

fn is_floor_censored(value: f64, floor: f64) -> bool {
    (value - floor).abs() <= f64::EPSILON * 8.0
}

fn assert_relative_close(actual: f64, expected: f64, label: &str) {
    let tolerance = expected.abs() * FLOAT_RELATIVE_EPSILON;
    let difference = (actual - expected).abs();
    assert!(
        difference <= tolerance,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
    );
}

#[test]
fn planted_structure_positive_control_has_small_adaptive_p() {
    let real = one_row_grid(&[0; 60]);
    let config = DofNullConfig {
        seed: 0x51a1,
        calibration_trials: 64,
        trials: 64,
    };
    let report = run_dof_null_for_grids(
        config,
        &real,
        &one_cell_space(HeadlineStatistic::DistinctCount),
    )
    .unwrap();

    assert!(report.observed_min_p < 0.05);
    assert!(report.adaptive_interval.estimate < 0.05);
    assert_eq!(report.adaptive_extreme_count, 0);
}

#[test]
fn uniform_random_negative_control_is_not_significant() {
    let template = one_row_grid(&[0; 60]);
    let mut rng = SplitMix64::new(0xdecaf);
    let real = random_orientation_grids_like(&template, &mut rng);
    let config = DofNullConfig {
        seed: 0x000d_ecaf_0001,
        calibration_trials: 64,
        trials: 64,
    };
    let report = run_dof_null_for_grids(
        config,
        &real,
        &one_cell_space(HeadlineStatistic::DistinctCount),
    )
    .unwrap();

    assert!(report.observed_min_p > 0.50);
    assert!(report.adaptive_interval.estimate > 0.50);
}

#[test]
fn marginal_tails_are_probabilities_on_default_space() {
    let real = one_row_grid(&[0, 0, 0, 1, 1, 2, 3, 4]);
    let config = DofNullConfig {
        seed: 0x7072_6f62,
        calibration_trials: 16,
        trials: 16,
    };
    let space = DofSearchSpace {
        orders: vec![ReadingOrder::RawRows],
        groupings: vec![
            GroupingRule::OrientationBase5 { width: 1 },
            GroupingRule::OrientationBase5 { width: 2 },
        ],
        statistics: vec![
            HeadlineStatistic::DistinctCount,
            HeadlineStatistic::ContiguousBoundedAtMax,
            HeadlineStatistic::ZeroAdjacencyRate,
            HeadlineStatistic::BestRecurrenceRatio,
        ],
    };
    let report = run_dof_null_for_grids(config, &real, &space).unwrap();

    for cell in &report.cells {
        assert!((0.0..=1.0).contains(&cell.marginal_p));
    }
    assert!((0.0..=1.0).contains(&report.observed_min_p));
    assert!((0.0..=1.0).contains(&report.adaptive_interval.estimate));
}

#[test]
fn min_p_matches_hand_checked_toy_case() {
    let real = one_row_grid(&[0, 0, 0]);
    let calibration_nulls = [
        one_row_grid(&[0, 1, 2]),
        one_row_grid(&[0, 0, 1]),
        one_row_grid(&[2, 2, 2]),
    ];
    let resampling_nulls = [
        one_row_grid(&[0, 1, 2]),
        one_row_grid(&[0, 0, 1]),
        one_row_grid(&[2, 2, 2]),
    ];
    let mut draws = calibration_nulls
        .iter()
        .chain(resampling_nulls.iter())
        .cloned();
    let mut index = 0usize;
    let config = DofNullConfig {
        seed: 0,
        calibration_trials: calibration_nulls.len(),
        trials: resampling_nulls.len(),
    };
    let report = run_dof_null_with(
        config,
        &real,
        &one_cell_space(HeadlineStatistic::DistinctCount),
        |_templates, _rng| {
            let grids = draws.next().unwrap();
            index += 1;
            grids
        },
    )
    .unwrap();

    assert!((report.best_cell.real_value - 1.0).abs() < f64::EPSILON);
    assert_eq!(report.best_cell.marginal_extreme_count, 1);
    assert!((report.observed_min_p - 0.5).abs() < f64::EPSILON);
    assert_eq!(report.adaptive_extreme_count, 1);
    assert!((report.adaptive_interval.estimate - 0.5).abs() < f64::EPSILON);
    assert_eq!(index, config.calibration_trials + config.trials);
}

#[test]
fn fresh_null_observation_is_not_self_rank_pinned() {
    let template = one_row_grid(&[0; 48]);
    let space = compact_adaptive_space();
    let seeds = [0xa11c_e123, 0xa11c_e124, 0xa11c_e125, 0xa11c_e126];
    let mut seeds_with_resampling_hits = 0usize;

    for seed in seeds {
        let mut observed_rng = SplitMix64::new(seed ^ 0xffff_0000_aaaa_5555);
        let observed = random_orientation_grids_like(&template, &mut observed_rng);
        let config = DofNullConfig {
            seed,
            calibration_trials: 16,
            trials: 96,
        };
        let mut generated = Vec::new();
        let report = run_dof_null_with(config, &observed, &space, |templates, rng| {
            let grids = random_orientation_grids_like(templates, rng);
            generated.push(grids.clone());
            grids
        })
        .unwrap();

        assert_eq!(generated.len(), config.calibration_trials + config.trials);
        let (calibration, resampling) = generated.split_at(config.calibration_trials);
        assert!(
            calibration
                .iter()
                .all(|left| resampling.iter().all(|right| left != right))
        );
        if report.adaptive_extreme_count > 0 {
            seeds_with_resampling_hits += 1;
        }
    }

    assert!(seeds_with_resampling_hits >= 2);
}

#[test]
fn analytic_configured_dof_bound_is_astronomically_small_for_eyes() {
    let report = run_dof_null(DofNullConfig {
        seed: 0x4d55_0001,
        calibration_trials: 1,
        trials: 1,
    })
    .unwrap();
    let bounds = report.analytic_headline_bounds.unwrap();

    assert_eq!(bounds.trigrams, 1036);
    assert_eq!(bounds.total_configured_cells, 1_140);
    assert_relative_close(
        bounds.per_order,
        5.836_200_792_956_83e-185,
        "per-order analytic headline probability",
    );
    assert_relative_close(
        bounds.total_bonferroni,
        6.653_268_903_970_79e-182,
        "configured-cell Bonferroni headline bound",
    );
    assert_relative_close(
        bounds.total_sidak,
        6.653_268_903_970_79e-182,
        "configured-cell Sidak headline bound",
    );
}

#[test]
fn dof_null_floor_censoring_is_invariant_and_fast_sweep_stays_in_floor_regime() {
    let invariant_report = run_dof_null(DofNullConfig {
        seed: 12_345,
        calibration_trials: 8,
        trials: 8,
    })
    .unwrap();
    let invariant_bounds = invariant_report.analytic_headline_bounds.as_ref().unwrap();

    assert!(
        is_floor_censored(
            invariant_report.observed_min_p,
            invariant_report.empirical_marginal_floor
        ),
        "the eyes' min p moved off the calibration floor: {} vs {}",
        invariant_report.observed_min_p,
        invariant_report.empirical_marginal_floor
    );
    assert!(
        is_floor_censored(
            invariant_bounds.cell.marginal_p,
            invariant_report.empirical_marginal_floor
        ),
        "the headline cell moved off the calibration floor: {} vs {}",
        invariant_bounds.cell.marginal_p,
        invariant_report.empirical_marginal_floor
    );
    assert_eq!(invariant_bounds.cell.marginal_extreme_count, 0);

    for seed in STABILITY_SEEDS {
        let config = DofNullConfig {
            seed,
            calibration_trials: 8,
            trials: 8,
        };
        let report = run_dof_null(config).unwrap();

        assert!(
            (0.5..=1.0).contains(&report.adaptive_interval.estimate),
            "seed {seed} moved the coarse adaptive diagnostic out of the floor-hit regime: {}",
            report.adaptive_interval.estimate
        );
    }
}

#[test]
#[ignore = "canonical 1000+1000-trial adaptive null regression; run with cargo test -- --ignored"]
fn dof_null_seed_12345_matches_headline_regression() {
    let report = run_dof_null(DofNullConfig {
        seed: 12_345,
        calibration_trials: 1_000,
        trials: 1_000,
    })
    .unwrap();
    let bounds = report.analytic_headline_bounds.unwrap();

    assert_eq!(report.configured_orders, 57);
    assert_eq!(report.configured_groupings, 5);
    assert_eq!(report.configured_statistics, 4);
    assert_eq!(report.configured_cell_count, 1_140);
    assert_eq!(report.valid_cell_count, 916);
    assert_relative_close(
        report.observed_min_p,
        0.000_999_000_999_001,
        "observed minimum marginal p-value",
    );
    assert_relative_close(
        report.empirical_marginal_floor,
        0.000_999_000_999_001,
        "empirical marginal floor",
    );
    assert_relative_close(
        report.best_cell.marginal_p,
        0.000_999_000_999_001,
        "best-cell marginal p-value",
    );

    assert_eq!(
        bounds.cell.order,
        crate::analysis::orders::accepted_honeycomb_order()
    );
    assert_eq!(
        bounds.cell.grouping,
        GroupingRule::OrientationBase5 { width: 3 }
    );
    assert_eq!(
        bounds.cell.statistic,
        HeadlineStatistic::ContiguousBoundedAtMax
    );
    assert_eq!(bounds.cell.real_value.to_bits(), 82.0_f64.to_bits());
    assert_relative_close(
        bounds.cell.marginal_p,
        0.000_999_000_999_001,
        "analytic headline cell marginal p-value",
    );
    assert_eq!(bounds.cell.marginal_extreme_count, 0);

    assert_eq!(report.adaptive_extreme_count, 199);
    assert_eq!(report.adaptive_interval.count, 200);
    assert_eq!(report.adaptive_interval.trials, 1_001);
    assert_relative_close(
        report.adaptive_interval.estimate,
        0.199_800_199_800_2,
        "adaptive Wilson point estimate",
    );
    assert_relative_close(
        report.adaptive_interval.lower,
        0.176_198_491_593_545,
        "adaptive Wilson lower bound",
    );
    assert_relative_close(
        report.adaptive_interval.upper,
        0.225_697_205_758_206,
        "adaptive Wilson upper bound",
    );

    assert_eq!(bounds.trigrams, 1_036);
    assert_relative_close(
        bounds.per_order,
        5.836_200_792_956_83e-185,
        "per-order analytic headline probability",
    );
    assert_eq!(bounds.total_configured_cells, 1_140);
    assert_relative_close(
        bounds.total_bonferroni,
        6.653_268_903_970_79e-182,
        "configured-cell Bonferroni headline bound",
    );
    assert_relative_close(
        bounds.total_sidak,
        6.653_268_903_970_79e-182,
        "configured-cell Sidak headline bound",
    );
    assert_relative_close(
        bounds.effective_comparisons,
        173.113_277_064_259,
        "effective comparisons",
    );
    assert_relative_close(
        bounds.effective_bonferroni,
        1.010_323_844_873_78e-182,
        "effective Bonferroni headline bound",
    );
    assert_relative_close(
        bounds.effective_sidak,
        1.010_323_844_873_78e-182,
        "effective Sidak headline bound",
    );
}

#[test]
#[ignore = "multi-seed 256+128-trial adaptive stability sweep; run with cargo test -- --ignored"]
fn dof_null_floor_invariant_and_adaptive_regime_holds_in_ignored_sweep() {
    let invariant_report = run_dof_null(DofNullConfig {
        seed: 12_345,
        calibration_trials: 256,
        trials: 128,
    })
    .unwrap();
    let invariant_bounds = invariant_report.analytic_headline_bounds.as_ref().unwrap();

    assert!(
        is_floor_censored(
            invariant_report.observed_min_p,
            invariant_report.empirical_marginal_floor
        ),
        "the eyes' min p moved off the calibration floor: {} vs {}",
        invariant_report.observed_min_p,
        invariant_report.empirical_marginal_floor
    );
    assert!(
        is_floor_censored(
            invariant_bounds.cell.marginal_p,
            invariant_report.empirical_marginal_floor
        ),
        "the headline cell moved off the calibration floor: {} vs {}",
        invariant_bounds.cell.marginal_p,
        invariant_report.empirical_marginal_floor
    );
    assert_eq!(invariant_bounds.cell.marginal_extreme_count, 0);

    for seed in STABILITY_SEEDS {
        let config = DofNullConfig {
            seed,
            calibration_trials: 256,
            trials: 128,
        };
        let report = run_dof_null(config).unwrap();

        assert!(
            (0.35..=0.80).contains(&report.adaptive_interval.estimate),
            "seed {seed} moved the adaptive diagnostic out of the same broad regime: {}",
            report.adaptive_interval.estimate
        );
        assert!(
            report.adaptive_extreme_count > 0,
            "seed {seed} produced no resampling floor hits"
        );
    }
}
