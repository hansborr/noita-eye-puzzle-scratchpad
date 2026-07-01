//! Library tests for `maskdecode`, exercising the same functions the CLI
//! calls: the sweep/verify pipeline, the round-trip encoder, the self-test
//! controls, and the recorded-`one` regression.

use crate::attack::rlcodec::one_practice_digits;
use crate::core::glyph::Glyph;

use super::{
    BitOrder, CellParams, DEFAULT_SEED, MaskAnalysis, MaskCfg, MaskError, MaskKind, MaskVerdict,
    ONE_BASE, ONE_CELL, ONE_DIGIT_COUNT, ONE_SOLUTION, Polarity, ReadDirection,
    analyze_embedded_one, analyze_mask_decode, mask_encode, mask_encode_trimmed,
    maskdecode_self_test,
};

#[test]
fn self_test_passes_with_the_default_seed() {
    let report = maskdecode_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(report.planted_alternating.passed(), "alternating plant leg");
    assert!(report.planted_static.passed(), "static plant leg");
    assert!(report.null_negative, "matched-null leg");
    assert!(report.not_a_walk_detected, "walk-gate leg");
    assert!(report.one_regression.passed(), "one regression leg");
    assert!(report.passed());
}

#[test]
fn embedded_one_is_the_recorded_verified_decode() {
    let analysis = analyze_embedded_one(&MaskCfg::default()).expect("embedded one analyzes");
    let MaskAnalysis::Walk(report) = analysis else {
        panic!("embedded one must be a clean walk");
    };
    assert_eq!(report.n_digits, ONE_DIGIT_COUNT);
    assert_eq!(report.n_bits, ONE_DIGIT_COUNT - 1);
    assert_eq!(report.start_digit, 4);
    assert_eq!(report.verdict, MaskVerdict::VerifiedDecode);

    let (candidate, completion) = report.verified().expect("a verified candidate exists");
    assert_eq!(candidate.readout.params, ONE_CELL);
    assert_eq!(completion.text, ONE_SOLUTION);
    assert_eq!(completion.matched, ONE_DIGIT_COUNT);
    assert_eq!(completion.total, ONE_DIGIT_COUNT);
    assert_eq!(completion.head_char, Some('P'));
    assert_eq!(completion.tail_char, None);
    assert_eq!(
        candidate.completions.len(),
        1,
        "the head completes uniquely"
    );
    assert_eq!(candidate.head_options, vec!['P']);
    assert_eq!(
        candidate.readout.rendered,
        "ermutation Representation Destination"
    );
}

#[test]
fn embedded_one_also_carries_the_mirror_twin() {
    let analysis = analyze_embedded_one(&MaskCfg::default()).expect("embedded one analyzes");
    let MaskAnalysis::Walk(report) = analysis else {
        panic!("embedded one must be a clean walk");
    };
    assert_eq!(
        report.candidates.len(),
        2,
        "exactly the forward cell and its mirror twin reach letter fraction 1.0"
    );
    let mirror = report.candidates.get(1).expect("mirror twin present");
    assert_eq!(mirror.readout.params.direction, ReadDirection::Reversed);
    assert_eq!(mirror.readout.params.order, BitOrder::LsbFirst);
    let mirror_completion = mirror.verified().expect("the mirror twin round-trips");
    let reversed: String = ONE_SOLUTION.chars().rev().collect();
    assert_eq!(mirror_completion.text, reversed);
    assert_eq!(mirror_completion.matched, ONE_DIGIT_COUNT);
}

#[test]
fn round_trip_encoder_reproduces_one_from_the_recorded_message() {
    // The decisive gate as a direct law: the 38-char message's 266 bits, with
    // the leading bit of `P` dropped (head_skip = 1), walk from digit 4 into
    // all 266 ciphertext digits.
    let encoded = mask_encode_trimmed(ONE_SOLUTION, &ONE_CELL, ONE_BASE, 4, 1, 0).expect("encodes");
    let digits = one_practice_digits().expect("embedded one parses");
    assert_eq!(encoded, digits);
}

#[test]
fn one_verifies_with_the_width_sweep_restricted_to_seven() {
    let cfg = MaskCfg {
        widths: vec![7],
        top_cells: 4,
    };
    let analysis = analyze_embedded_one(&cfg).expect("embedded one analyzes");
    let MaskAnalysis::Walk(report) = analysis else {
        panic!("embedded one must be a clean walk");
    };
    assert_eq!(report.verdict, MaskVerdict::VerifiedDecode);
    assert_eq!(report.cells_swept, 2 * 7 * 2 * 2 * 2);
}

#[test]
fn a_non_unit_step_yields_the_honest_not_a_walk_verdict() {
    let digits = [Glyph(0), Glyph(2), Glyph(4)];
    let analysis =
        analyze_mask_decode(&digits, ONE_BASE, &MaskCfg::default()).expect("analysis runs");
    let MaskAnalysis::NotAWalk(detail) = analysis else {
        panic!("a step of +2 must be NotAWalk, got {analysis:?}");
    };
    assert_eq!(detail.position, 0);
    assert_eq!(detail.from, 0);
    assert_eq!(detail.to, 2);
    assert_eq!(detail.diff, 2);
    assert_eq!(analysis_label(&digits), "NotAWalk");
}

fn analysis_label(digits: &[Glyph]) -> &'static str {
    analyze_mask_decode(digits, ONE_BASE, &MaskCfg::default())
        .expect("analysis runs")
        .verdict_label()
}

#[test]
fn configuration_and_input_errors_are_reported_not_panicked() {
    let digits = [Glyph(0), Glyph(1), Glyph(2)];
    let empty = MaskCfg {
        widths: Vec::new(),
        top_cells: 4,
    };
    assert_eq!(
        analyze_mask_decode(&digits, ONE_BASE, &empty),
        Err(MaskError::EmptyWidths)
    );
    let zero = MaskCfg {
        widths: vec![0],
        top_cells: 4,
    };
    assert_eq!(
        analyze_mask_decode(&digits, ONE_BASE, &zero),
        Err(MaskError::InvalidWidth { width: 0 })
    );
    let wide = MaskCfg {
        widths: vec![17],
        top_cells: 4,
    };
    assert_eq!(
        analyze_mask_decode(&digits, ONE_BASE, &wide),
        Err(MaskError::InvalidWidth { width: 17 })
    );
    assert_eq!(
        analyze_mask_decode(&digits, 2, &MaskCfg::default()),
        Err(MaskError::InvalidBase { base: 2 })
    );
    assert_eq!(
        analyze_mask_decode(&[Glyph(0)], ONE_BASE, &MaskCfg::default()),
        Err(MaskError::TooFewDigits { count: 1 })
    );
    assert_eq!(
        analyze_mask_decode(&[Glyph(0), Glyph(7)], ONE_BASE, &MaskCfg::default()),
        Err(MaskError::SymbolOutOfRange {
            value: 7,
            base: ONE_BASE
        })
    );
}

#[test]
fn encoder_rejects_bad_starts_and_unencodable_chars() {
    let params = CellParams {
        mask: MaskKind::Static,
        width: 5,
        offset: 0,
        order: BitOrder::MsbFirst,
        polarity: Polarity::Plain,
        direction: ReadDirection::Forward,
    };
    assert_eq!(
        mask_encode("z", &params, ONE_BASE, 0),
        Err(MaskError::UnencodableChar { ch: 'z', width: 5 })
    );
    assert_eq!(
        mask_encode("a", &params, ONE_BASE, 9),
        Err(MaskError::InvalidStartDigit {
            start: 9,
            base: ONE_BASE
        })
    );
}

#[test]
fn encoder_rejects_oversized_bases_and_consuming_trims() {
    let params = CellParams {
        mask: MaskKind::Static,
        width: 5,
        offset: 0,
        order: BitOrder::MsbFirst,
        polarity: Polarity::Plain,
        direction: ReadDirection::Forward,
    };
    let max_base = usize::from(u16::MAX) + 1;
    assert_eq!(
        mask_encode("a", &params, max_base + 1, 0),
        Err(MaskError::BaseTooLarge {
            base: max_base + 1,
            max: max_base
        })
    );
    // trims that consume the whole 7-bit message are an error, not an Ok walk
    let wide = CellParams { width: 7, ..params };
    assert_eq!(
        mask_encode_trimmed("a", &wide, ONE_BASE, 0, 4, 3),
        Err(MaskError::InvalidTrim {
            head_skip: 4,
            tail_skip: 3,
            available: 7
        })
    );
    assert_eq!(
        mask_encode_trimmed("a", &wide, ONE_BASE, 0, 0, 8),
        Err(MaskError::InvalidTrim {
            head_skip: 0,
            tail_skip: 8,
            available: 7
        })
    );
    assert_eq!(
        mask_encode("", &wide, ONE_BASE, 0),
        Err(MaskError::InvalidTrim {
            head_skip: 0,
            tail_skip: 0,
            available: 0
        })
    );
}

#[test]
fn planted_complemented_reversed_cell_is_recovered_too() {
    // Exercise the polarity and direction axes end-to-end: a plant encoded
    // with complemented polarity and reversed direction must still come back
    // as a verified decode recovering the phrase verbatim at its cell.
    let params = CellParams {
        mask: MaskKind::Alternating,
        width: 7,
        offset: 0,
        order: BitOrder::LsbFirst,
        polarity: Polarity::Complemented,
        direction: ReadDirection::Reversed,
    };
    let phrase = "Masked walks read as ascii";
    let digits = mask_encode(phrase, &params, ONE_BASE, 1).expect("plant encodes");
    let analysis =
        analyze_mask_decode(&digits, ONE_BASE, &MaskCfg::default()).expect("analysis runs");
    let MaskAnalysis::Walk(report) = analysis else {
        panic!("plant must be a clean walk");
    };
    assert_eq!(report.verdict, MaskVerdict::VerifiedDecode);
    let recovered = report.candidates.iter().find(|candidate| {
        candidate
            .completions
            .iter()
            .any(|completion| completion.exact() && completion.text == phrase)
    });
    let recovered = recovered.expect("phrase recovered verbatim");
    assert_eq!(recovered.readout.params, params);
}
