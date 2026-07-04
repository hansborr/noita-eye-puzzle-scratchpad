//! Tests for the Avenue G pattern-crib scan.

use super::{
    PatternCribAnchor, PatternCribConfig, PatternCribVerdict, pattern_crib_span_fits,
    run_pattern_crib_scan, scan_pattern_crib_corpus,
};

fn letters(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_lowercase)
        .map(|byte| byte - b'a')
        .collect()
}

#[test]
fn pattern_crib_predicate_enforces_letter_to_class_consistency() {
    let pattern = [0, 1, 0, 2];
    let fits = pattern_crib_span_fits(&letters("abac"), &pattern)
        .expect("same letter keeps the same class");
    assert_eq!(
        fits.get(usize::from(b'a' - b'a')).copied().flatten(),
        Some(0)
    );
    assert_eq!(
        fits.get(usize::from(b'b' - b'a')).copied().flatten(),
        Some(1)
    );
    assert_eq!(
        fits.get(usize::from(b'c' - b'a')).copied().flatten(),
        Some(2)
    );

    assert!(
        pattern_crib_span_fits(&letters("abaa"), &pattern).is_none(),
        "a repeated plaintext letter cannot carry two observed classes"
    );
    assert!(
        pattern_crib_span_fits(&letters("abca"), &pattern).is_none(),
        "different observed classes force different plaintext letters"
    );
}

#[test]
fn corpus_scan_counts_surviving_spans_without_requiring_a_solver() {
    let scan = scan_pattern_crib_corpus("abac wwww abac", &[0, 1, 0, 2], 1).expect("scan runs");
    assert!(
        scan.hit_count > 1,
        "at least both literal abac spans survive"
    );
    assert_eq!(scan.hits.len(), 1, "display hits are capped");
    assert!(scan.capped());
    assert_eq!(scan.hits.first().map(|hit| hit.text.as_str()), Some("abac"));
}

#[test]
fn pattern_crib_run_controls_then_reports_a_real_candidate() {
    let corpus = "abracadabracadabra qqqqqqqqqqqqqqqqqqqqqqqqqq abracadabracadabra";
    let positive_text = "abracadabracadabra abracadabracadabra";
    let phrase = letters("abracadabracadabra");
    let coloring = [
        0, 1, 3, 2, 0, 0, 1, 1, 2, 2, 3, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1,
    ];
    let phrase_tokens: Vec<u8> = phrase
        .iter()
        .map(|&letter| coloring.get(usize::from(letter)).copied().unwrap_or(0))
        .collect();
    let mut tokens = vec![0, 1];
    tokens.extend_from_slice(&phrase_tokens);
    tokens.extend_from_slice(&[2, 3, 2, 1, 0, 3]);
    let second = tokens.len();
    tokens.extend_from_slice(&phrase_tokens);
    tokens.extend_from_slice(&[1, 0, 1]);

    let report = run_pattern_crib_scan(
        &tokens,
        4,
        PatternCribAnchor {
            first: 2,
            second,
            len: phrase_tokens.len(),
        },
        corpus,
        positive_text,
        PatternCribConfig {
            max_hits: 4,
            null_trials: 2,
            random_negatives: 1,
            seed: 0x1234,
        },
    )
    .expect("run completes");

    assert!(report.controls.positive.fired);
    assert!(report.controls.passed, "{:?}", report.controls);
    assert_eq!(report.verdict, PatternCribVerdict::Candidate);
    let real = report
        .real_scan
        .expect("controls passed, real stream scanned");
    assert!(real.hit_count >= 2);
    assert!(real.hits.iter().any(|hit| hit.text == "abracadabracadabra"));
}
