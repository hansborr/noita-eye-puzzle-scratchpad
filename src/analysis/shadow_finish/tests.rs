//! Tests for the shadow-finish residual instrument.

use super::control::shadow_finish_self_test_fast_for_test;
use super::{
    ShadowFinishConfig, ShadowFinishTable, ShadowFinishVerdict, builtin_tables, parse_table_file,
};

#[test]
fn self_test_controls_pass() {
    let report =
        shadow_finish_self_test_fast_for_test(0x7368_6164_6f77_6603).expect("self-test runs");
    assert!(report.positive_roundtrip, "{report:?}");
    assert!(report.positive_candidate_verdict, "{report:?}");
    assert!(report.positive_truth_best, "{report:?}");
    assert_eq!(report.positive_truth_rank, Some(1), "{report:?}");
    assert!(report.positive_truth_top_k, "{report:?}");
    assert!(report.positive_margin_vs_junk_max > 0.0, "{report:?}");
    assert!(report.dirty_boundary_anchor, "{report:?}");
    assert!(report.wrong_plaintext_no_roundtrip, "{report:?}");
    assert!(report.wrong_plaintext_inside_junk, "{report:?}");
    assert!(report.vacuity_both_roundtrip, "{report:?}");
    assert!(report.vacuity_distinct_plaintexts, "{report:?}");
    assert!(report.passed, "{report:?}");
}

#[test]
fn table_file_parser_accepts_escaped_space() {
    let tables = parse_table_file("toy=ab\\sc\n").expect("table parses");
    assert_eq!(tables.len(), 1);
    let table = tables.first().expect("one table");
    assert_eq!(table.name, "toy");
    assert_eq!(table.decode(2), Some(b' '));
}

#[test]
fn builtin_tables_are_injective() {
    let tables = builtin_tables().expect("builtins build");
    assert!(tables.iter().any(|table| table.name == "ascii32"));
    assert!(
        tables
            .iter()
            .any(|table| table.name == "sixbit-lower-space")
    );
    for table in tables {
        for value in 0..table.len() {
            let byte = table
                .decode(u8::try_from(value).expect("small table"))
                .unwrap();
            assert_eq!(table.encode(byte), Some(u8::try_from(value).unwrap()));
        }
    }
}

#[test]
fn config_defaults_are_powered_for_real_alpha() {
    let cfg = ShadowFinishConfig::default();
    assert_eq!(cfg.top_k_per_class, 512);
    assert_eq!(cfg.null_trials, 20);
    assert_eq!(ShadowFinishVerdict::NoCandidate.label(), "NoCandidate");
}

#[test]
fn duplicate_table_bytes_are_rejected() {
    assert!(ShadowFinishTable::new("bad", b"aa").is_err());
}
