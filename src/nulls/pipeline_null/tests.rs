use super::{
    BASE7_CEILING_DIGITS, OrientationSource, U64_DRAW_DOMAIN, input_randomness_report,
    no_minus_one_count_and_span, pow6_u128, pow7_u128, random_value_of_length, real_symbol_total,
    run_pipeline_null, value_span_for_length,
};
use crate::data::generator;
use crate::nulls::null::{NullConfig, NullConfigError, NullRunError, SplitMix64};

#[test]
fn pipeline_null_rejects_zero_trials() {
    let config = NullConfig { seed: 1, trials: 0 };
    assert_eq!(
        run_pipeline_null(config),
        Err(NullRunError::Config(NullConfigError::ZeroTrials))
    );
}

#[test]
fn random_value_decodes_to_requested_length() {
    let mut rng = SplitMix64::new(99);
    for &length in &[2usize, 9, 11, 16, 21, BASE7_CEILING_DIGITS as usize] {
        for _ in 0..64 {
            let value = random_value_of_length(length, &mut rng);
            assert_eq!(
                generator::decode_u64(value).len(),
                length,
                "length {length} not reproduced for value {value}"
            );
        }
    }
}

#[test]
fn value_span_for_length_rejects_unrepresentable_length() {
    // Every real engine per-pair length (0..=22) is representable in a u64,
    // so the sampler's `None`/`u64::MAX` fallback is unreachable for real
    // data. One length past the base-7 u64 ceiling has no representable span.
    for length in 0..=(BASE7_CEILING_DIGITS as usize) {
        assert!(
            value_span_for_length(length).is_some(),
            "length {length} should have a representable base-7 span"
        );
    }
    assert!(value_span_for_length(BASE7_CEILING_DIGITS as usize + 1).is_none());
}

#[test]
fn orientation_source_yields_only_orientations() {
    let lengths = vec![22usize, 21, 11];
    let mut source = OrientationSource::new(&lengths);
    let mut rng = SplitMix64::new(7);
    for _ in 0..5_000 {
        let orientation = source.next(&mut rng);
        assert!(orientation.digit() <= 4);
    }
}

#[test]
fn no_minus_one_probability_accounts_for_u64_cap() {
    let (sub_ceiling_count, sub_ceiling_span) =
        no_minus_one_count_and_span(21).expect("length 21 is representable");
    assert_eq!(sub_ceiling_span, 6 * pow7_u128(21));
    assert_eq!(sub_ceiling_count, 7 * pow6_u128(21));

    let (ceiling_count, ceiling_span) =
        no_minus_one_count_and_span(22).expect("length 22 is representable");
    assert_eq!(ceiling_span, U64_DRAW_DOMAIN - pow7_u128(22));
    assert_ne!(
        ceiling_count * 6 * pow7_u128(22),
        ceiling_span * 7 * pow6_u128(22),
        "length-22 no -1 rate must not use the uncapped independence ratio"
    );
}

#[test]
fn storage_histogram_formatter_is_stable() {
    assert_eq!(
        super::format_storage_histogram(&[0, 1, 2, 3, 4, 5, 6]),
        "-1:0, 0:1, 1:2, 2:3, 3:4, 4:5, 5:6"
    );
}

#[test]
fn pipeline_null_is_reproducible_and_finds_no_contiguity() {
    let config = NullConfig {
        seed: 0xabc_def,
        trials: 40,
    };
    let first = run_pipeline_null(config).unwrap();
    let second = run_pipeline_null(config).unwrap();
    assert_eq!(first.null.headline_count, second.null.headline_count);
    assert_eq!(
        first.null.min_distinct_histogram,
        second.null.min_distinct_histogram
    );

    // Like the uniform null, the base-7 pipeline never produces the bounded
    // 0..=82 range, and the minimum distinct count stays far above 83.
    assert_eq!(first.null.headline_count, 0);
    let reached_83 = first
        .null
        .min_distinct_histogram
        .iter()
        .any(|&(distinct, _count)| distinct <= 83);
    assert!(!reached_83, "pipeline null implausibly bounded near 83");
}

#[test]
fn real_inputs_are_not_random_integers() {
    let config = NullConfig {
        seed: 0x1234,
        trials: 20,
    };
    let report = input_randomness_report(config).unwrap();

    assert_eq!(report.pair_count, 150);
    assert_eq!(report.total_symbols, 3194);
    assert_eq!(report.total_symbols, real_symbol_total());
    assert_eq!(report.real_minus_one, 0);
    assert_eq!(report.real_delimiters, 86);
    assert_eq!(report.real_symbol_histogram.iter().sum::<usize>(), 3194);

    // Random matched-length integers flood the decode with control symbols
    // the real corpus never contains.
    assert!(report.mc_mean_minus_one > 300.0);
    assert!(report.mc_mean_delimiters > 300.0);
    assert_eq!(report.mc_corpora_with_zero_minus_one, 0);

    // The real histogram is astronomically far from the capped matched-length
    // random decode, and a random corpus essentially never reproduces the
    // no-`-1` property.
    assert!(report.real_chi_square_vs_uniform > 1_000.0);
    assert!(report.analytic_probability_no_minus_one < 1e-100);
    assert!(report.analytic_probability_no_minus_one > 0.0);
}
