use super::{
    ChainingClassification, ChainingConfig, SourceProfile, build_control_fixtures,
    chaining_signature, run_chaining,
};
use crate::analysis::orders;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::SplitMix64;

#[test]
fn known_succeed_and_fail_controls_are_distinct_and_separated() {
    let lengths = [99, 103, 118, 102, 137, 124, 119, 120, 114];
    let period = 7;
    let alphabet_size = orders::READING_LAYER_ALPHABET_SIZE;
    let source = SourceProfile::new(alphabet_size);
    let mut rng = SplitMix64::new(0x5eed);
    let controls =
        build_control_fixtures(&lengths, period, alphabet_size, &source, &mut rng).unwrap();

    assert_ne!(controls.succeed, controls.fail);
    assert_ne!(controls.fail, controls.shuffled_fail);

    let succeed = chaining_signature(&controls.succeed, period, alphabet_size).unwrap();
    let fail = chaining_signature(&controls.fail, period, alphabet_size).unwrap();
    let shuffled = chaining_signature(&controls.shuffled_fail, period, alphabet_size).unwrap();

    assert_eq!(succeed.cycle_residual_distance, 0);
    assert!(succeed.chain_score > fail.chain_score);
    assert!(succeed.chain_score > shuffled.chain_score);
    assert_eq!(
        fail.mean_alignment_quality.to_bits(),
        shuffled.mean_alignment_quality.to_bits()
    );
    assert_eq!(fail.chain_score.to_bits(), shuffled.chain_score.to_bits());
}

#[test]
fn multi_seed_calibration_bands_separate_for_candidate_periods() {
    let config = ChainingConfig {
        seed: 0x7171,
        trials: 64,
        min_period: 2,
        max_period: 10,
        alphabet_size: orders::READING_LAYER_ALPHABET_SIZE,
    };
    let report = run_chaining(config).unwrap();

    assert_eq!(report.rows.len(), 9);
    for row in &report.rows {
        assert!(
            row.score_bands_separated,
            "p={} succeed={:?} fail={:?} shuffled={:?}",
            row.period,
            row.succeed.chain_score,
            row.fail.chain_score,
            row.shuffled_fail.chain_score
        );
        assert!(row.fail.chain_score.q975 < row.succeed.chain_score.q025);
        assert!(row.shuffled_fail.chain_score.q975 < row.succeed.chain_score.q025);
    }
}

#[test]
fn period_calibration_is_independent_of_scan_range() {
    let wide_config = ChainingConfig {
        seed: 1,
        trials: 64,
        min_period: 2,
        max_period: 3,
        alphabet_size: orders::READING_LAYER_ALPHABET_SIZE,
    };
    let narrow_config = ChainingConfig {
        min_period: 3,
        ..wide_config
    };

    let wide = run_chaining(wide_config).unwrap();
    let narrow = run_chaining(narrow_config).unwrap();
    let wide_period = wide.rows.iter().find(|row| row.period == 3).unwrap();
    let narrow_period = narrow.rows.first().unwrap();

    assert_eq!(narrow_period.period, 3);
    assert_eq!(wide_period.succeed, narrow_period.succeed);
    assert_eq!(wide_period.fail, narrow_period.fail);
    assert_eq!(wide_period.shuffled_fail, narrow_period.shuffled_fail);
    assert_eq!(
        wide_period.score_bands_separated,
        narrow_period.score_bands_separated
    );
    assert_eq!(wide_period.classification, narrow_period.classification);
}

#[test]
fn real_eye_scores_are_measured_against_the_fail_band() {
    let config = ChainingConfig {
        seed: 0x8888,
        trials: 64,
        min_period: 2,
        max_period: 8,
        alphabet_size: orders::READING_LAYER_ALPHABET_SIZE,
    };
    let report = run_chaining(config).unwrap();

    assert_eq!(report.order.name(), "standard36-u012-d012");
    assert_eq!(report.total_length, 1036);
    assert!(
        report
            .rows
            .iter()
            .all(|row| row.classification == ChainingClassification::MatchesKnownFail),
        "{:?}",
        report
            .rows
            .iter()
            .map(|row| (row.period, row.real.chain_score, row.classification))
            .collect::<Vec<_>>()
    );
}

#[test]
fn out_of_alphabet_values_are_rejected() {
    let values = vec![vec![TrigramValue::new(83).unwrap(); 12]];
    let error = chaining_signature(&values, 2, 83).unwrap_err();
    assert!(matches!(
        error,
        super::ChainingError::ValueOutsideAlphabet {
            value: 83,
            alphabet_size: 83
        }
    ));
}
