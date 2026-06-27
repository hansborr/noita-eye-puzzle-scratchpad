use super::{
    PeriodicityConfig, PeriodicityError, accepted_honeycomb_order, report_from_message_values,
    run_periodicity,
};
use crate::core::trigram::TrigramValue;

#[test]
fn fixed_period_fixture_clears_null_band() {
    let mut values = Vec::new();
    for position in 0..260 {
        let value = u8::try_from(position % 7).unwrap();
        values.push(TrigramValue::new(value).unwrap());
    }
    let config = PeriodicityConfig {
        seed: 0x5a17,
        trials: 128,
        max_period: 12,
        max_lag: 16,
        min_ngram: 3,
        max_ngram: 3,
        alphabet_size: 83,
    };
    let report =
        report_from_message_values(config, accepted_honeycomb_order(), &["fixture"], &[values])
            .unwrap();

    let period_7 = report
        .pooled_ioc_by_period
        .iter()
        .find(|row| row.period == 7)
        .unwrap();
    assert!(period_7.above_null_envelope);
    assert!(period_7.normalized_ioc > 80.0);

    let lag_7 = report
        .pooled_autocorrelation
        .iter()
        .find(|row| row.lag == 7)
        .unwrap();
    assert!(lag_7.above_null_envelope);
    assert!((lag_7.rate - 1.0).abs() < f64::EPSILON);
}

#[test]
fn real_honeycomb_stream_has_no_familywise_period_or_lag_spike() {
    let report = run_periodicity(PeriodicityConfig {
        seed: 0x6579_652d_7465_7374,
        trials: 256,
        max_period: 32,
        max_lag: 64,
        min_ngram: 3,
        max_ngram: 5,
        alphabet_size: 83,
    })
    .unwrap();

    assert!(
        report
            .pooled_ioc_by_period
            .iter()
            .all(|row| !row.above_null_envelope)
    );
    assert!(
        report
            .pooled_autocorrelation
            .iter()
            .all(|row| !row.above_null_envelope)
    );
    assert!(report.messages.iter().all(|message| {
        message
            .ioc_by_period
            .iter()
            .all(|row| !row.above_null_envelope)
            && message
                .autocorrelation
                .iter()
                .all(|row| !row.above_null_envelope)
    }));
}

#[test]
fn kasiski_distances_record_pairwise_gcd_structure() {
    let values = [1, 2, 3, 1, 2, 4, 1, 2]
        .into_iter()
        .map(|value| TrigramValue::new(value).unwrap())
        .collect::<Vec<_>>();
    let report = super::kasiski_report_for_messages(&[values], 2, 8);

    assert_eq!(report.repeated_ngram_kinds, 1);
    assert_eq!(report.repeated_occurrences, 3);
    assert_eq!(report.distance_count, 3);
    assert_eq!(report.all_distance_gcd, 3);
    assert_eq!(report.top_distances, vec![(3, 2), (6, 1)]);
    assert!(report.factor_counts.contains(&(3, 3)));
    assert!(report.factor_counts.contains(&(6, 1)));
}

#[test]
fn invalid_config_is_rejected() {
    let config = PeriodicityConfig {
        trials: 0,
        ..PeriodicityConfig::default()
    };
    assert_eq!(run_periodicity(config), Err(PeriodicityError::ZeroTrials));
}
