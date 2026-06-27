use super::{
    PerseusConfig, SIGNIFICANCE_ALPHA, build_shared_partition, report_from_message_values,
    report_from_partition, run_perseus,
};
use crate::analysis::orders;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{NullSampler, SplitMix64, WithinMessageShuffle};

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
fn reconstructs_documented_perseus_partition_anchors() {
    let report = run_perseus(PerseusConfig { seed: 7, trials: 8 }).unwrap();

    let prefix = report.partition.global_prefix.as_ref().unwrap();
    assert_eq!(prefix.start, 1);
    assert_eq!(prefix.len, 2);
    assert_eq!(prefix.values, vec![66, 5]);

    let counterpart_runs = report
        .partition
        .counterpart_runs
        .iter()
        .map(|run| ((run.east_key, run.west_key), (run.start, run.len)))
        .collect::<std::collections::BTreeMap<_, _>>();

    assert_eq!(counterpart_runs.get(&("east1", "west1")), Some(&(1, 24)));
    assert_eq!(counterpart_runs.get(&("east2", "west2")), Some(&(1, 2)));
    assert_eq!(counterpart_runs.get(&("east3", "west3")), Some(&(1, 5)));
    assert_eq!(counterpart_runs.get(&("east4", "west4")), Some(&(1, 20)));
}

#[test]
fn planted_no_recurrence_fixture_is_significant() {
    let keys = ["east1", "west1"];
    let messages = planted_no_recurrence_fixture();
    let report = report_from_message_values(
        PerseusConfig {
            seed: 0x5150,
            trials: 512,
        },
        orders::accepted_honeycomb_order(),
        &keys,
        &messages,
    )
    .unwrap();

    assert_eq!(report.observed.recurrent_occurrences, 0);
    assert!(
        report.significant,
        "p={} null={:?}",
        report.empirical_p, report.null
    );
}

#[test]
fn shuffled_fixture_negative_control_is_not_significant() {
    let keys = ["east1", "west1"];
    let messages = planted_no_recurrence_fixture();
    let partition = build_shared_partition(&keys, &messages).unwrap();
    let sampler = WithinMessageShuffle {
        messages: &messages,
    };
    let mut rng = SplitMix64::new(0x5a5a);
    let shuffled = sampler.sample(&mut rng).unwrap();
    let report = report_from_partition(
        PerseusConfig {
            seed: 0x6161,
            trials: 512,
        },
        orders::accepted_honeycomb_order(),
        &keys,
        &shuffled,
        partition,
    )
    .unwrap();

    assert!(
        !report.significant,
        "unexpected lower-tail signal: observed={:?} p={} null={:?}",
        report.observed, report.empirical_p, report.null
    );
}

#[test]
fn perseus_observation_is_invariant_and_fast_sweep_stays_significant() {
    let invariant_report = run_perseus(PerseusConfig {
        seed: 12_345,
        trials: 128,
    })
    .unwrap();
    assert_eq!(invariant_report.observed.tested_shared_occurrences, 185);
    assert_eq!(invariant_report.observed.recurrent_occurrences, 0);

    for seed in STABILITY_SEEDS {
        let report = run_perseus(PerseusConfig { seed, trials: 128 }).unwrap();

        assert!(
            report.empirical_p < SIGNIFICANCE_ALPHA,
            "seed {seed} was not significant: p={}",
            report.empirical_p
        );
        assert!(
            report.significant,
            "seed {seed} lost the qualitative signal"
        );
    }
}

#[test]
#[ignore = "canonical 1000-trial within-message shuffle regression; run with cargo test -- --ignored"]
fn perseus_seed_12345_recurrence_null_matches_headline_regression() {
    let report = run_perseus(PerseusConfig {
        seed: 12_345,
        trials: 1_000,
    })
    .unwrap();

    assert_eq!(report.observed.non_shared_occurrences, 851);
    assert_eq!(report.observed.tested_shared_occurrences, 185);
    assert_eq!(report.observed.recurrent_occurrences, 0);
    assert_eq!(report.observed.rate.to_bits(), 0);
    assert!(report.observed.recurrent_symbols.is_empty());
    assert_eq!(report.empirical_p_count, 6);
    assert_relative_close(
        report.empirical_p,
        0.006_993_006_993_006_99,
        "empirical recurrence p-value",
    );
    assert!(report.significant);
}

#[test]
#[ignore = "multi-seed 1000-trial within-message shuffle stability sweep; run with cargo test -- --ignored"]
fn perseus_observation_is_invariant_and_ignored_sweep_stays_significant() {
    let invariant_report = run_perseus(PerseusConfig {
        seed: 12_345,
        trials: 1_000,
    })
    .unwrap();
    assert_eq!(invariant_report.observed.tested_shared_occurrences, 185);
    assert_eq!(invariant_report.observed.recurrent_occurrences, 0);

    for seed in STABILITY_SEEDS {
        let report = run_perseus(PerseusConfig {
            seed,
            trials: 1_000,
        })
        .unwrap();

        assert!(
            report.empirical_p <= 0.01,
            "seed {seed} moved the lower-tail p out of the small-p regime: p={}",
            report.empirical_p
        );
        assert!(
            report.significant,
            "seed {seed} lost the qualitative signal"
        );
    }
}

fn planted_no_recurrence_fixture() -> Vec<Vec<TrigramValue>> {
    let mut east = Vec::new();
    let mut west = Vec::new();
    east.push(value(80));
    west.push(value(81));

    for raw in 0..30 {
        east.push(value(raw));
        west.push(value(raw));
    }
    for raw in 0..30 {
        east.push(value(raw));
        west.push(value(29 - raw));
    }
    for raw in 30..60 {
        east.push(value(raw));
        west.push(value(raw));
    }
    for raw in 30..60 {
        east.push(value(raw));
        west.push(value(89 - raw));
    }

    vec![east, west]
}

fn value(raw: u8) -> TrigramValue {
    TrigramValue::new(raw).unwrap()
}
