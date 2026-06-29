use super::{
    IsomorphNullConfig, isomorph_null_for_stream, report_from_message_values, run_isomorph_null,
};
use crate::analysis::orders;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::SplitMix64;
use crate::report::Report;

#[test]
fn isomorph_null_is_reproducible_for_fixed_seed() {
    let config = IsomorphNullConfig {
        seed: 0x5eed,
        trials: 8,
        min_window: 3,
        max_window: 5,
    };

    let first = run_isomorph_null(config).unwrap();
    let second = run_isomorph_null(config).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.order.name(), "standard36-u012-d012");
    assert_eq!(first.rows.len(), 3);
}

#[test]
fn isomorph_rich_fixture_exceeds_its_shuffle_null() {
    let messages = vec![isomorph_rich_values()];
    let config = IsomorphNullConfig {
        seed: 0x7a,
        trials: 64,
        min_window: 12,
        max_window: 12,
    };
    let report = report_from_message_values(
        config,
        orders::accepted_honeycomb_order(),
        &["fixture"],
        &messages,
    )
    .unwrap();
    let row = report.rows.first().unwrap();

    assert!(
        row.real.repeated_signature_kinds > row.null.q975,
        "real={} null={:?}",
        row.real.repeated_signature_kinds,
        row.null
    );
    assert!(row.empirical_p <= 0.05, "p={}", row.empirical_p);
}

#[test]
fn for_stream_isomorph_rich_exceeds_its_shuffle_null_off_corpus() {
    // The fn the CLI handler calls, on an arbitrary single-message stream: a
    // genuinely isomorph-rich fixture clears its own within-message shuffle
    // null under the neutral raw-rows label, off the eye corpus.
    let values = isomorph_rich_values();
    let config = IsomorphNullConfig {
        seed: 0x7a,
        trials: 64,
        min_window: 12,
        max_window: 12,
    };
    let report = isomorph_null_for_stream(config, &values).unwrap();

    assert_eq!(report.order.name(), "raw-rows");
    assert_eq!(report.message_lengths, vec![("input", values.len())]);
    let row = report.rows.first().unwrap();
    assert!(
        row.real.repeated_signature_kinds > row.null.q975,
        "real={} null={:?}",
        row.real.repeated_signature_kinds,
        row.null
    );
    assert!(row.empirical_p <= 0.05, "p={}", row.empirical_p);

    // Honesty: an off-corpus stream report must not claim eye-corpus provenance.
    let rendered = report.render();
    assert!(!rendered.contains("eye"), "{rendered}");
    assert!(!rendered.contains("Experiment 0"), "{rendered}");
}

#[test]
fn uniform_random_fixture_stays_inside_its_shuffle_null() {
    let messages = vec![uniform_random_values(0x5151, 160, 83)];
    let config = IsomorphNullConfig {
        seed: 0x6161,
        trials: 128,
        min_window: 12,
        max_window: 12,
    };
    let report = report_from_message_values(
        config,
        orders::accepted_honeycomb_order(),
        &["uniform"],
        &messages,
    )
    .unwrap();
    let row = report.rows.first().unwrap();

    assert!(
        row.real.repeated_signature_kinds <= row.null.q975,
        "real={} null={:?}",
        row.real.repeated_signature_kinds,
        row.null
    );
}

fn isomorph_rich_values() -> Vec<TrigramValue> {
    let mut values = Vec::new();
    for block in 0u8..10 {
        let base = block * 12;
        for raw in [
            base,
            base + 1,
            base,
            base + 2,
            base + 3,
            base + 2,
            base + 4,
            base + 5,
            base + 6,
            base + 4,
            base + 7,
            base + 8,
            base + 9,
            base + 10,
            base + 11,
            base + 9,
        ] {
            values.push(value(raw));
        }
    }
    values
}

fn uniform_random_values(seed: u64, len: usize, alphabet_size: u8) -> Vec<TrigramValue> {
    let mut rng = SplitMix64::new(seed);
    let mut values = Vec::new();
    for _position in 0..len {
        let raw = (rng.next_u64() % u64::from(alphabet_size)) as u8;
        values.push(value(raw));
    }
    values
}

fn value(raw: u8) -> TrigramValue {
    TrigramValue::new(raw).unwrap()
}
