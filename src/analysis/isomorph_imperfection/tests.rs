use super::family::{family_counts, generate_family};
use super::{
    EXTENDED_WINDOWS, FAMILY_MESSAGES, HIGH_EPSILON, IsomorphImperfectionConfig,
    isomorph_imperfection_for_stream, run_isomorph_imperfection, scan_counts,
};
use crate::analysis::perfect_isomorphism::SIGNIFICANCE_ALPHA;
use crate::report::Report;

// The full-corpus shuffle null dominates cost, so the run()-driven tests use
// small, cheap, deterministic trial counts. The public defaults stay large
// and scientifically meaningful (exercised only by the ignored canonical
// snapshot). The positive control still fires and the eyes still show zero
// robust violations at this cheap config — that is the binding requirement.
fn cheap_config() -> IsomorphImperfectionConfig {
    IsomorphImperfectionConfig {
        seed: 0x4242,
        null_trials: 64,
        family_trials: 12,
    }
}

fn tiny_config() -> IsomorphImperfectionConfig {
    IsomorphImperfectionConfig {
        seed: 0x4242,
        null_trials: 4,
        family_trials: 2,
    }
}

#[test]
fn run_is_deterministic_for_fixed_config() {
    let config = tiny_config();
    let first = run_isomorph_imperfection(config).unwrap();
    let second = run_isomorph_imperfection(config).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.order.name(), "standard36-u012-d012");
}

#[test]
fn eyes_are_a_hardened_negative() {
    // One run() call covers the whole hardened-negative story so the slow
    // full-corpus null is paid only once.
    let report = run_isomorph_imperfection(cheap_config()).unwrap();

    // (a) Extending windows to {13,15,17} must not manufacture a robust
    // internal violation; the canonical scan reports zero and so must this.
    assert_eq!(report.base_counts.robust_internal_violations, 0);
    assert_eq!(report.extended_counts.robust_internal_violations, 0);
    assert_eq!(report.robust_null.observed, 0);
    assert_eq!(*report.extended_windows.last().unwrap(), 17);
    assert!(*report.extended_windows.last().unwrap() <= report.shortest_message);

    // (b) The robust (non-benign) count is the family-falsifier statistic.
    // Its binding calibration is the generative epsilon = 0 family (mean
    // robust 0), not this within-message shuffle: the shuffle is
    // structure-destroying, so the observed-0 add-one p = 1.0 is only the
    // trivial count floor (0 is the minimum). For the same reason the loose
    // candidates exceed the shuffle null (p small) — that is expected real
    // benign structure, not a violation.
    assert_eq!(
        report.robust_null.upper_tail_count,
        report.config.null_trials
    );
    assert!(report.robust_null.p > 0.05);
    assert!(report.extended_counts.loose_candidates > 0);
    assert!((report.loose_null.observed as f64) > report.loose_null.band.mean);

    // (c) The east4/west4 Stutter candidate stays benign and never promotes.
    let candidate = report
        .stutter_candidate
        .expect("east4/west4 loose candidate should be located");
    assert!(candidate.benign_stutter);
    assert!(!candidate.promoted_to_violation);

    // (c') every loose candidate is surfaced (not only east4/west4) and the
    // surfaced list matches the loose count; each is benign-attributed and
    // none promotes, which is what the conditional negative rests on.
    assert_eq!(
        report.loose_candidates.len(),
        report.extended_counts.loose_candidates
    );
    for loose in &report.loose_candidates {
        assert!(loose.benign_region.is_some());
        assert!(!loose.promoted_to_violation);
    }

    // (d) The imperfect-family detector fires, and the eyes best-fit at the
    // perfect epsilon = 0.
    assert!(report.family.positive_control_fired);
    assert_eq!(report.family.observed_robust, 0);
    assert!((report.family.best_fit_epsilon - 0.0).abs() < f64::EPSILON);
    assert!((report.family.baseline_mean_robust - 0.0).abs() < f64::EPSILON);
    assert!(report.family.high_mean_robust > report.family.baseline_mean_robust);

    let rendered = report.render();
    assert!(rendered.contains("verdict"));
    assert!(rendered.contains("epsilon"));
    assert!(rendered.contains("GAK not falsified"));
    assert!(rendered.contains("all loose candidates"));
}

#[test]
fn for_stream_does_not_apply_and_is_neutral_off_corpus() {
    // The fn the CLI handler calls, on an arbitrary single-message stream.
    // Isomorph imperfection is a cross-message test, so a single stream has an
    // empty cross-message break catalog by construction and no internal-violation
    // test applies; the stream-independent synthetic imperfect-family control still
    // self-validates the detector, under the neutral raw-rows label with no
    // eye-corpus provenance.
    let stream = neutral_stream();
    let len = stream.len();
    let report = isomorph_imperfection_for_stream(cheap_config(), &["input"], &[stream]).unwrap();

    assert_eq!(report.order.name(), "raw-rows");
    assert_eq!(report.message_lengths, vec![("input", len)]);
    assert_eq!(report.extended_counts.robust_internal_violations, 0);
    assert!(report.loose_candidates.is_empty());
    assert!(report.stutter_candidate.is_none());
    // The synthetic imperfect-family positive control self-validates the detector
    // independently of the supplied stream.
    assert!(report.family.positive_control_fired);

    // Honesty: an off-corpus stream report must not claim eye / wiki / GAK
    // provenance, and must say plainly that the cross-message test does not apply
    // rather than emit a vacuous verdict about the untestable input.
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
    assert!(!rendered.contains("GAK not falsified"), "{rendered}");
    assert!(rendered.contains("does not apply"), "{rendered}");
}

fn neutral_stream() -> Vec<crate::core::trigram::TrigramValue> {
    // >= the longest extended window (17) with internal repeats; still a single
    // message, so it cannot populate the cross-message break catalog regardless of
    // content.
    [0u8, 1, 2, 0, 3, 1, 4, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        .into_iter()
        .map(|raw| crate::core::trigram::TrigramValue::new(raw).unwrap())
        .collect()
}

#[test]
fn for_stream_multi_message_localizes_cross_message_violation() {
    // Planted positive on USER input: two supplied messages whose first nine
    // columns share a gap pattern (a strong window-8 isomorph), diverge at one
    // fresh-singleton interior island, then re-sync for a long far run carrying a
    // cross-island back-reference -- the proven short-island internal-violation
    // geometry, split across two user messages in disjoint symbol ranges. The
    // CROSS-MESSAGE break detector must localize it as a robust internal violation
    // on user data (the multi-message branch a single stream can never reach).
    let messages = planted_internal_violation_pair();
    let keys = ["m0", "m1"];
    let config = IsomorphImperfectionConfig {
        seed: 0x6d31,
        null_trials: 256,
        family_trials: 12,
    };
    let report = isomorph_imperfection_for_stream(config, &keys, &messages).unwrap();

    // (1) The cross-message detector actually fires on user input.
    assert!(report.extended_counts.robust_internal_violations >= 1);
    assert_eq!(report.order.name(), "raw-rows");
    assert_eq!(report.message_lengths, vec![("m0", 20), ("m1", 20)]);

    // (2) Matched null: the within-message multiset shuffle destroys the planted
    // alignment, so the localized violation exceeds its null (upper-tail p <= alpha
    // and the null mean stays below the observed count).
    assert!(report.robust_null.observed >= 1);
    assert!(
        report.robust_null.p <= SIGNIFICANCE_ALPHA,
        "planted signal did not exceed its null (p = {})",
        report.robust_null.p
    );
    assert!(
        report.robust_null.band.mean < report.robust_null.observed as f64,
        "null mean {} not below observed {}",
        report.robust_null.band.mean,
        report.robust_null.observed
    );

    // (3) The synthetic imperfect-family control still fires; the render is
    // provenance-clean and frames the hit as a structural candidate to recheck,
    // not a recovery/decode, and is no longer in the "does not apply" branch.
    assert!(report.family.positive_control_fired);
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
    assert!(rendered.contains("structural candidate"), "{rendered}");
    assert!(rendered.contains("not a recovery"), "{rendered}");
}

fn planted_internal_violation_pair() -> Vec<Vec<crate::core::trigram::TrigramValue>> {
    let to_values = |raw: &[u8]| -> Vec<crate::core::trigram::TrigramValue> {
        raw.iter()
            .copied()
            .map(|value| crate::core::trigram::TrigramValue::new(value).unwrap())
            .collect()
    };
    let left = to_values(&[
        1, 2, 3, 1, 4, 2, 5, 3, 6, 2, 7, 8, 1, 9, 10, 11, 12, 13, 14, 15,
    ]);
    let right = to_values(&[
        31, 32, 33, 31, 34, 32, 35, 33, 36, 37, 38, 39, 31, 40, 41, 42, 43, 44, 45, 46,
    ]);
    vec![left, right]
}

#[test]
fn imperfect_family_positive_control_fires() {
    // The binding firing positive control (cheap synthetic scans, no eyes):
    // at epsilon = 0 the detector finds zero robust internal violations, and
    // at high epsilon it finds clearly elevated ones. Without this, "0
    // violations on the eyes" would be meaningless. Asserted across seeds.
    for seed in [0x11u64, 0x22, 0x33, 0x44] {
        let perfect = family_counts(0.0, seed, FAMILY_MESSAGES).robust_internal_violations;
        let imperfect =
            family_counts(HIGH_EPSILON, seed, FAMILY_MESSAGES).robust_internal_violations;
        assert_eq!(
            perfect, 0,
            "seed {seed} produced a false perfect-baseline violation"
        );
        assert!(
            imperfect >= FAMILY_MESSAGES - 1,
            "seed {seed} did not elevate robust violations at high epsilon ({imperfect})"
        );
    }
}

#[test]
fn perfect_family_is_internally_clean() {
    // A directly generated perfect family (epsilon = 0) has zero robust and
    // zero loose candidates: its only breaks are trailing-edge boundaries.
    let family = generate_family(0.0, 0xfeed, FAMILY_MESSAGES);
    let keys = vec!["synthetic"; family.len()];
    let counts = scan_counts(&keys, &family, &EXTENDED_WINDOWS);
    assert_eq!(counts.robust_internal_violations, 0);
    assert_eq!(counts.loose_candidates, 0);
}

#[test]
fn single_broken_instance_is_an_internal_violation() {
    // One broken non-reference instance against the perfect reference must
    // localize as exactly one robust internal violation at the designed
    // break (the irregular motif admits no misaligned spurious matches).
    let family = generate_family(HIGH_EPSILON, 0xabc, 2);
    let keys = vec!["synthetic"; family.len()];
    let counts = scan_counts(&keys, &family, &EXTENDED_WINDOWS);
    assert_eq!(counts.robust_internal_violations, 1);
    assert_eq!(counts.loose_candidates, 1);
}

#[test]
fn zero_trials_are_rejected() {
    let config = IsomorphImperfectionConfig {
        seed: 1,
        null_trials: 0,
        family_trials: 1,
    };
    assert!(run_isomorph_imperfection(config).is_err());
}

#[test]
#[ignore = "canonical full-trial run; capture headline numbers with cargo test -- --ignored --nocapture"]
fn canonical_report_snapshot() {
    let report = run_isomorph_imperfection(IsomorphImperfectionConfig::default()).unwrap();
    println!("{}", report.render());
}
