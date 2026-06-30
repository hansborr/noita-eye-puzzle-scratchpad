use std::collections::BTreeSet;

use super::regression::synthetic_internal_violation_fires;
use super::{
    ALPHABET_SIZE, BreakClass, PerfectIsomorphismConfig, SIGNIFICANCE_ALPHA, WikiRegressionCheck,
    perfect_isomorphism_for_stream, report_from_message_values, run_perfect_isomorphism,
};
use crate::analysis::orders;
use crate::report::Report;

#[test]
fn perfect_isomorphism_run_is_deterministic_for_fixed_seed() {
    let config = PerfectIsomorphismConfig {
        seed: 0x1234,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };

    let first = run_perfect_isomorphism(config).unwrap();
    let second = run_perfect_isomorphism(config).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.order.name(), "standard36-u012-d012");
}

#[test]
fn real_eye_stream_pins_lengths_and_alphabet() {
    let config = PerfectIsomorphismConfig {
        seed: 0x5678,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };
    let report = run_perfect_isomorphism(config).unwrap();

    assert_eq!(report.total_length, 1_036);
    assert_eq!(
        report.message_lengths,
        vec![
            ("east1", 99),
            ("west1", 103),
            ("east2", 118),
            ("west2", 102),
            ("east3", 137),
            ("west3", 124),
            ("east4", 119),
            ("west4", 120),
            ("east5", 114),
        ]
    );

    let grids = orders::corpus_grids().unwrap();
    let messages =
        orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
    let distinct = messages
        .iter()
        .flatten()
        .map(|value| value.get())
        .collect::<BTreeSet<_>>();
    assert_eq!(distinct.len(), ALPHABET_SIZE);
}

#[test]
fn positive_control_and_regressions_fire() {
    let config = PerfectIsomorphismConfig {
        seed: 0x9999,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };
    let report = run_perfect_isomorphism(config).unwrap();

    assert!(report.positive_control_fired);
    assert_eq!(report.robust_internal_violations, 0);
    assert_eq!(report.safe_extents.len(), 16);
    assert!(report.regression.iter().all(|result| result.reproduced));
    assert!(report.regression.iter().any(|result| {
        result.check == WikiRegressionCheck::CorruptionTheoryBound
            && result.hypothesis_label.contains("conditional")
    }));
}

#[test]
fn synthetic_internal_violation_control_is_detected() {
    assert!(synthetic_internal_violation_fires().unwrap());
}

#[test]
fn for_stream_self_validates_and_is_neutral_off_corpus() {
    // The fn the CLI handler calls, on an arbitrary single-message stream. A single
    // stream has no cross-message aligned repeats, so the gap-pattern catalog is
    // empty by construction and no internal-violation test applies; the
    // stream-independent synthetic short-island control still self-validates the
    // detector, under the neutral raw-rows label with no eye-corpus provenance.
    let stream = neutral_stream();
    let len = stream.len();
    let config = PerfectIsomorphismConfig {
        seed: 0x7a,
        trials: 64,
        ..PerfectIsomorphismConfig::default()
    };
    let report = perfect_isomorphism_for_stream(config, &["input"], &[stream]).unwrap();

    assert!(report.positive_control_fired);
    assert!(report.regression.is_empty());
    assert!(report.catalog.is_empty());
    assert_eq!(report.robust_internal_violations, 0);
    assert_eq!(report.order.name(), "raw-rows");
    assert_eq!(report.message_lengths, vec![("input", len)]);
    assert_eq!(report.total_length, len);

    // Honesty: an off-corpus stream report must not claim eye / wiki / GAK
    // provenance, and must not assert "supports perfect isomorphism" for an input
    // that cannot be tested; it must say plainly that the test does not apply.
    let rendered = report.render();
    assert!(!rendered.contains("eye"), "{rendered}");
    assert!(!rendered.contains("wiki"), "{rendered}");
    assert!(!rendered.contains("GAK"), "{rendered}");
    assert!(!rendered.contains("Stutter"), "{rendered}");
    assert!(
        !rendered.contains("supports (does not prove) perfect isomorphism"),
        "{rendered}"
    );
    assert!(rendered.contains("does not apply"), "{rendered}");
}

#[test]
fn for_stream_multi_message_fires_cross_message_detector() {
    // Planted positive on USER input: two supplied messages that share an aligned
    // isomorph which diverges at a single fresh-singleton interior island and then
    // re-syncs for a long far run carrying a cross-island back-reference -- the
    // proven short-island internal-violation geometry, in disjoint symbol ranges
    // per message. The CROSS-MESSAGE detector must catch it on user data, not just
    // the synthetic-internal control. This is the multi-message report branch that
    // a single stream can never reach.
    let messages = planted_internal_violation_pair();
    let keys = ["m0", "m1"];
    let config = PerfectIsomorphismConfig {
        seed: 0x6d31,
        trials: 256,
        ..PerfectIsomorphismConfig::default()
    };
    let report = perfect_isomorphism_for_stream(config, &keys, &messages).unwrap();

    // (1) The cross-message detector actually fires: a non-empty cross-message
    // catalog and at least one robust internal violation localized across m0/m1.
    assert!(!report.catalog.is_empty(), "cross-message catalog is empty");
    assert!(
        report.robust_internal_violations >= 1,
        "no robust internal violation localized"
    );
    assert_eq!(report.order.name(), "raw-rows");
    // Both planted messages are 20 columns by construction.
    assert_eq!(report.message_lengths, vec![("m0", 20), ("m1", 20)]);

    // (2) Matched within-message null: this shuffle is structure-destroying for the
    // cross-message internal-violation statistic -- it scrambles the planted
    // cross-message alignment, so the null collapses toward zero and a non-zero
    // localized count clears it trivially. The p <= alpha / mean-below-observed checks
    // below are therefore a sanity floor (a non-zero count against a null that
    // degenerates to ~0), not a significance result -- the report itself now discloses
    // this add-one p as a near-trivial floor. The binding positive control is the
    // synthetic perfect-isomorphism-family check asserted in (3) below, not this null.
    assert!(
        report.empirical_p <= SIGNIFICANCE_ALPHA,
        "sanity floor: non-zero localized count did not clear the collapsed within-message null (p = {})",
        report.empirical_p
    );
    assert!(
        report.internal_violation_null.count_mean < report.robust_internal_violations as f64,
        "sanity floor: collapsed null mean {} is not below observed {}",
        report.internal_violation_null.count_mean,
        report.robust_internal_violations
    );

    // (3) The synthetic control still fires; the render is provenance-clean and
    // frames the hit as a structural candidate to recheck, not a recovery/decode.
    assert!(report.positive_control_fired);
    let rendered = report.render();
    for forbidden in [
        "eye",
        "wiki",
        "GAK",
        "Stutter",
        "CTAK",
        "Allomorphs",
        "Experiment 0",
        ".md",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "leaked {forbidden}: {rendered}"
        );
    }
    assert!(!rendered.contains("does not apply"), "{rendered}");
    assert!(rendered.contains("supplied streams"), "{rendered}");
    assert!(rendered.contains("not a recovery"), "{rendered}");
}

#[test]
fn for_stream_multi_message_repeats_zero_robust_makes_no_claim() {
    // The honesty-critical case: two supplied messages that DO share a cross-message
    // gap-pattern repeat (non-empty catalog) but are fully gap-aligned, so the strong
    // isomorph never breaks internally -- zero robust internal violations. This run
    // must make NO affirmation: it must not say "supports perfect isomorphism", and it
    // must not call zero violations a candidate signal. It must also not be mistaken
    // for the single-message "does not apply" degeneracy.
    let messages = aligned_no_violation_pair();
    let keys = ["m0", "m1"];
    let config = PerfectIsomorphismConfig {
        seed: 0x5a17,
        trials: 128,
        ..PerfectIsomorphismConfig::default()
    };
    let report = perfect_isomorphism_for_stream(config, &keys, &messages).unwrap();

    assert_eq!(report.message_lengths.len(), 2);
    assert!(
        !report.catalog.is_empty(),
        "cross-message catalog should be populated by the shared aligned repeat"
    );
    assert_eq!(
        report.robust_internal_violations, 0,
        "fully aligned pair should localize no internal violation"
    );
    assert!(report.positive_control_fired);

    let rendered = report.render();
    let lowered = rendered.to_lowercase();
    assert!(
        !lowered.contains("supports"),
        "zero-robust multi-message stream must not affirm support: {rendered}"
    );
    assert!(
        !rendered.contains("does not apply"),
        "must not be reported as the single-message degeneracy: {rendered}"
    );
    assert!(
        rendered.contains("no candidate and no claim"),
        "must state the honest no-candidate/no-claim outcome: {rendered}"
    );
    assert!(
        rendered.contains("no affirmation either way"),
        "interpretation must make no affirmation either way: {rendered}"
    );
    for forbidden in [
        "eye",
        "wiki",
        "GAK",
        "Stutter",
        "CTAK",
        "Allomorphs",
        "Experiment 0",
        ".md",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "leaked {forbidden}: {rendered}"
        );
    }
}

#[test]
fn for_stream_multi_message_no_repeats_is_a_tested_negative() {
    // Two supplied messages with no shared cross-message gap-pattern repeat at all
    // (empty catalog), count >= 2. This is a TESTED NEGATIVE, not the single-message
    // degeneracy and not support for any structure.
    let messages = disjoint_no_repeat_pair();
    let keys = ["m0", "m1"];
    let config = PerfectIsomorphismConfig {
        seed: 0x4e30,
        trials: 64,
        ..PerfectIsomorphismConfig::default()
    };
    let report = perfect_isomorphism_for_stream(config, &keys, &messages).unwrap();

    assert_eq!(report.message_lengths.len(), 2);
    assert!(report.catalog.is_empty(), "catalog should be empty");
    assert_eq!(report.robust_internal_violations, 0);
    assert!(report.positive_control_fired);

    let rendered = report.render();
    let lowered = rendered.to_lowercase();
    assert!(
        !lowered.contains("supports"),
        "multi-message no-repeat stream must not affirm support: {rendered}"
    );
    assert!(
        !rendered.contains("does not apply"),
        "must not be reported as the single-message degeneracy: {rendered}"
    );
    assert!(
        rendered.contains("tested negative"),
        "must state a tested negative: {rendered}"
    );
    for forbidden in [
        "eye",
        "wiki",
        "GAK",
        "Stutter",
        "CTAK",
        "Allomorphs",
        "Experiment 0",
        ".md",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "leaked {forbidden}: {rendered}"
        );
    }
}

#[test]
fn mismatched_keys_and_messages_are_rejected() {
    // The public stream fn must reject a caller that supplies a different number of
    // display keys than messages rather than silently zip-and-drop.
    let messages = disjoint_no_repeat_pair();
    let config = PerfectIsomorphismConfig {
        seed: 1,
        trials: 8,
        ..PerfectIsomorphismConfig::default()
    };
    let result = perfect_isomorphism_for_stream(config, &["only-one"], &messages);
    assert!(matches!(
        result,
        Err(super::PerfectIsomorphismError::MismatchedStreamKeys {
            keys: 1,
            messages: 2
        })
    ));
}

#[test]
fn invalid_window_range_is_rejected() {
    let config = PerfectIsomorphismConfig {
        seed: 1,
        trials: 1,
        min_window: 10,
        max_window: 10,
    };

    assert!(run_perfect_isomorphism(config).is_err());
}

#[test]
fn hand_built_boundary_negative_stays_boundary() {
    let left = values(&[1, 2, 1, 3, 4, 5, 6]);
    let right = values(&[9, 8, 9, 7, 6, 5, 4]);
    let break_row = super::breaks::classify_break(super::breaks::PairSlice {
        left_key: "left",
        right_key: "right",
        left_values: &left,
        right_values: &right,
        left_start: 0,
        right_start: 0,
        prefix_len: 3,
    });

    assert_eq!(break_row.class, BreakClass::Boundary);
}

#[test]
fn report_from_message_values_accepts_small_trial_fixture() {
    let grids = orders::corpus_grids().unwrap();
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = orders::read_corpus_message_values(&grids, order).unwrap();
    let config = PerfectIsomorphismConfig {
        seed: 0x4242,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };

    let report = report_from_message_values(config, order, &keys, &message_values).unwrap();

    assert_eq!(report.robust_internal_violations, 0);
}

fn neutral_stream() -> Vec<crate::core::trigram::TrigramValue> {
    // 16 symbols (>= the default max-window 11) with internal repeats; still a single
    // message, so it cannot populate the cross-message catalog regardless of content.
    values(&[0, 1, 0, 2, 3, 2, 4, 5, 6, 4, 7, 8, 9, 10, 11, 9])
}

fn planted_internal_violation_pair() -> Vec<Vec<crate::core::trigram::TrigramValue>> {
    // Two messages whose first nine columns share a gap pattern (a strong window-8
    // isomorph), diverge at exactly one interior column (a fresh-singleton island),
    // then re-sync for ten columns whose back-reference points across the island
    // into the shared prefix. The two messages use disjoint symbol ranges, so the
    // match is purely gap-structural -- the same short-island internal-violation
    // geometry the synthetic control validates, here split across two user messages.
    let left = values(&[
        1, 2, 3, 1, 4, 2, 5, 3, 6, 2, 7, 8, 1, 9, 10, 11, 12, 13, 14, 15,
    ]);
    let right = values(&[
        31, 32, 33, 31, 34, 32, 35, 33, 36, 37, 38, 39, 31, 40, 41, 42, 43, 44, 45, 46,
    ]);
    vec![left, right]
}

fn aligned_no_violation_pair() -> Vec<Vec<crate::core::trigram::TrigramValue>> {
    // Two messages with IDENTICAL gap structure in disjoint symbol ranges (right =
    // left + 30 throughout). The first columns carry repeated symbols, so a strong
    // cross-message window-8/9/11 signature is shared (the catalog is non-empty), but
    // because the structures are perfectly aligned the isomorph never breaks
    // internally -- there is no short-island desync, so zero robust internal
    // violations. This is the zero-robust multi-message case.
    let left = values(&[
        1, 2, 3, 1, 4, 2, 5, 3, 6, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]);
    let right = values(&[
        31, 32, 33, 31, 34, 32, 35, 33, 36, 32, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
    ]);
    vec![left, right]
}

fn disjoint_no_repeat_pair() -> Vec<Vec<crate::core::trigram::TrigramValue>> {
    // Two messages of all-distinct symbols: no window has a repeated symbol, so no
    // gap-pattern signature is recorded and the cross-message catalog is empty. Two
    // messages (count >= 2), so this is a tested negative, not single-message
    // degeneracy.
    let left = values(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let right = values(&[
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    ]);
    vec![left, right]
}

fn values(raw: &[u8]) -> Vec<crate::core::trigram::TrigramValue> {
    raw.iter()
        .copied()
        .map(crate::core::trigram::TrigramValue::new)
        .map(Result::unwrap)
        .collect()
}
