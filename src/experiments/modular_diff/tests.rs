use super::calibration::{SourceSampler, build_control_fixture};
use super::diff::summarize_difference_stream;
use super::{
    BandSeparation, ControlFamily, FamilyPlacement, ModularDiffConfig, PRIMARY_MODULUS,
    modular_difference_messages, run_modular_diff,
};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::SplitMix64;

fn values(raw: &[u8]) -> Vec<TrigramValue> {
    raw.iter()
        .copied()
        .map(|value| TrigramValue::new(value).unwrap())
        .collect()
}

fn assert_close(label: &str, actual: f64, expected: f64, tolerance: f64) {
    let difference = (actual - expected).abs();
    assert!(
        difference <= tolerance,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
    );
}

#[test]
fn first_difference_resets_at_message_boundaries() {
    let messages = vec![values(&[1, 3, 0]), values(&[5, 2])];
    let differenced = modular_difference_messages(&messages, 1, 7).unwrap();

    assert_eq!(differenced, vec![values(&[2, 4]), values(&[4])]);
}

#[test]
fn higher_order_difference_math_is_modular() {
    let messages = vec![values(&[1, 3, 0, 4])];
    let differenced = modular_difference_messages(&messages, 2, 7).unwrap();

    assert_eq!(differenced, vec![values(&[2, 0])]);
}

#[test]
fn wheel_fixture_has_constant_first_difference() {
    let source = SourceSampler::new(PRIMARY_MODULUS);
    let mut rng = SplitMix64::new(0x5151);
    let fixture = build_control_fixture(
        ControlFamily::IncrementingWheel,
        &[12, 11],
        &source,
        &mut rng,
    )
    .unwrap();
    let differenced = modular_difference_messages(&fixture, 1, PRIMARY_MODULUS).unwrap();
    let stats = summarize_difference_stream(&differenced, 0.0, PRIMARY_MODULUS, 1, 8, 8).unwrap();

    assert_eq!(stats.top_difference.value, 17);
    assert_eq!(stats.top_difference.count, 21);
    assert_close("wheel top rate", stats.top_difference.rate, 1.0, 1e-12);
    assert_close("wheel IoC", stats.ioc, 1.0, 1e-12);
}

#[test]
fn calibration_controls_separate_before_eye_classification() {
    let report = run_modular_diff(ModularDiffConfig {
        seed: 0x2222,
        trials: 32,
        max_period: 12,
        max_lag: 12,
    })
    .unwrap();
    let first = report
        .controls
        .iter()
        .find(|row| row.difference_order == 1)
        .unwrap();

    assert_eq!(first.separation.wheel_top_rate, BandSeparation::Separated);
    assert_eq!(
        first.separation.vigenere_period_excess,
        BandSeparation::Separated
    );
    assert!(first.separation.is_calibrated());
}

#[test]
fn real_headline_statistics_are_stable() {
    let report = run_modular_diff(ModularDiffConfig {
        seed: 123,
        trials: 8,
        max_period: 8,
        max_lag: 8,
    })
    .unwrap();
    let first = report.primary.differences.first().unwrap();

    assert_eq!(report.total_length, 1036);
    assert_eq!(first.stats.length, 1027);
    assert_eq!(first.stats.distinct_support_size, 82);
    assert_eq!(first.stats.top_difference.value, 7);
    assert_eq!(first.stats.top_difference.count, 25);
    assert_close(
        "raw IoC",
        first.stats.raw_ioc,
        0.011_708_150_480_720_913,
        1e-15,
    );
    assert_close(
        "diff IoC",
        first.stats.ioc,
        0.012_151_682_999_573_924,
        1e-15,
    );
    assert_close(
        "delta IoC",
        first.stats.delta_ioc,
        0.000_443_532_518_853_010_86,
        1e-15,
    );
    assert_close(
        "top over uniform",
        first.stats.top_difference.over_uniform,
        2.020_447_906_523_856,
        1e-9,
    );
    assert_eq!(
        report.headline_placement,
        FamilyPlacement::StructurelessLike
    );
}
