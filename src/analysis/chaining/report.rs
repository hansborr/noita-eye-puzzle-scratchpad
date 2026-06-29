use super::{ChainingClassification, ChainingReport, ResidualBand, ScalarBand};
use crate::analysis::orders::ReadingOrder;
use crate::report::{self, Report};

/// Whether this report is an arbitrary-stream run (file-driven path) rather than
/// the verified eye corpus. The eye path always uses the accepted honeycomb order;
/// only the `*_for_stream` entry labels its report with [`ReadingOrder::RawRows`].
/// Stream reports must not claim eye-corpus provenance.
fn is_stream(report: &ChainingReport) -> bool {
    report.order == ReadingOrder::RawRows
}

impl Report for ChainingReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_chaining_header(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_score_table(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_calibration_detail(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_interpretation(&mut out, self);
        out
    }
}

fn append_chaining_header(out: &mut String, report: &ChainingReport) {
    report::appendln!(out, "Experiment 7B alphabet-chaining structural control");
    report::appendln!(out, "order: {}", report.order.name());
    let alphabet_kind = if is_stream(report) {
        "values"
    } else {
        "reading-layer values"
    };
    report::appendln!(
        out,
        "alphabet: {alphabet_kind} 0..={}",
        report.config.alphabet_size.saturating_sub(1)
    );
    report::appendln!(out, "seed: {}", report.config.seed);
    report::appendln!(out, "trials per period/control: {}", report.config.trials);
    report::appendln!(
        out,
        "periods: {}..={}",
        report.config.min_period,
        report.config.max_period
    );
    report::appendln!(
        out,
        "message lengths: {}",
        report::format_message_lengths(&report.message_lengths)
    );
    report::appendln!(out, "pooled length: {}", report.total_length);
    report::appendln!(
        out,
        "boundary rule: columns reset at each message; no column evidence crosses message joins"
    );
    report::appendln!(
        out,
        "procedure: split by position mod p; estimate adjacent additive shifts by maximum circular distribution overlap"
    );
    report::appendln!(
        out,
        "quality: best overlap minus second-best overlap; score = mean quality * cycle closure"
    );
    report::appendln!(
        out,
        "controls: generated Vigenere known-succeed, independent per-column substitution known-fail, and within-column shuffled fail invariance check"
    );
}

fn append_chaining_score_table(out: &mut String, report: &ChainingReport) {
    let (score_label, qual_label) = if is_stream(report) {
        ("score", "quality")
    } else {
        ("eye score", "eye qual")
    };
    report::appendln!(
        out,
        "{:>2} {:>10} {:>9} {:>7} {:>15} {:>15} {:>15} {:>12}",
        "p",
        score_label,
        qual_label,
        "resid",
        "succeed 95%",
        "fail 95%",
        "shuf-fail 95%",
        "verdict"
    );
    for row in &report.rows {
        report::appendln!(
            out,
            "{:>2} {:>10.4} {:>9.4} {:>7} {:>15} {:>15} {:>15} {:>12}",
            row.period,
            row.real.chain_score,
            row.real.mean_alignment_quality,
            format_residual(row.real.cycle_residual_distance, row.real.alphabet_size),
            format_chaining_band(row.succeed.chain_score),
            format_chaining_band(row.fail.chain_score),
            format_chaining_band(row.shuffled_fail.chain_score),
            format_chaining_classification(row.classification)
        );
    }
}

fn append_chaining_calibration_detail(out: &mut String, report: &ChainingReport) {
    report::appendln!(out, "calibration detail");
    report::appendln!(
        out,
        "{:>2} {:>17} {:>17} {:>17} {:>17} {:>17} {:>17}",
        "p",
        "succ qual 95%",
        "fail qual 95%",
        "succ ovlp 95%",
        "fail ovlp 95%",
        "succ resid 95%",
        "fail resid 95%"
    );
    for row in &report.rows {
        report::appendln!(
            out,
            "{:>2} {:>17} {:>17} {:>17} {:>17} {:>17} {:>17}",
            row.period,
            format_chaining_band(row.succeed.mean_alignment_quality),
            format_chaining_band(row.fail.mean_alignment_quality),
            format_chaining_band(row.succeed.mean_best_overlap),
            format_chaining_band(row.fail.mean_best_overlap),
            format_residual_band(row.succeed.cycle_residual_distance),
            format_residual_band(row.fail.cycle_residual_distance)
        );
    }
}

fn append_chaining_interpretation(out: &mut String, report: &ChainingReport) {
    let mut fail_matches = 0usize;
    let mut succeed_matches = 0usize;
    let mut between = 0usize;
    let mut overlapping = 0usize;
    for row in &report.rows {
        match row.classification {
            ChainingClassification::MatchesKnownFail => fail_matches += 1,
            ChainingClassification::MatchesKnownSucceed => succeed_matches += 1,
            ChainingClassification::BetweenBands => between += 1,
            ChainingClassification::CalibrationOverlaps => overlapping += 1,
        }
    }
    if overlapping > 0 {
        report::appendln!(
            out,
            "Interpretation: {overlapping} candidate {} had overlapping succeed/fail control bands, so those periods are not calibrated well enough for a verdict.",
            report::counted_form(overlapping, "period", "periods")
        );
    }
    if fail_matches == report.rows.len() {
        if is_stream(report) {
            report::appendln!(
                out,
                "Interpretation: across the scanned periods, the input stream lands in the calibrated known-fail chaining band, not the known-succeed Vigenere band. Under this fixed-period additive alphabet model, the stream lacks chainable additive-related-alphabet structure."
            );
        } else {
            report::appendln!(
                out,
                "Interpretation: across the scanned periods, the eye stream lands in the calibrated known-fail chaining band, not the known-succeed Vigenere band. Under this honeycomb reading order and fixed-period additive alphabet model, the eyes lack chainable additive-related-alphabet structure."
            );
        }
    } else {
        report::appendln!(
            out,
            "Interpretation: period placement summary: {fail_matches} known-fail, {succeed_matches} known-succeed, {between} between separated bands, {overlapping} uncalibrated-overlap."
        );
    }
    if is_stream(report) {
        report::appendln!(
            out,
            "This is a structural null result only on the supplied stream. It does not rule out other encodings, period models, or non-additive alphabet relationships."
        );
    } else {
        report::appendln!(
            out,
            "This is a structural null result only. It does not prove the eyes are meaningless, and it does not rule out other encodings, period models, reading orders, transcription corrections, or non-additive alphabet relationships."
        );
    }
}

fn format_chaining_band(band: ScalarBand) -> String {
    format!("{:.4}..{:.4}", band.q025, band.q975)
}

fn format_residual_band(band: ResidualBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

fn format_residual(distance: usize, alphabet_size: usize) -> String {
    format!("{distance}/{}", alphabet_size / 2)
}

fn format_chaining_classification(classification: ChainingClassification) -> &'static str {
    match classification {
        ChainingClassification::CalibrationOverlaps => "overlap",
        ChainingClassification::MatchesKnownFail => "known-fail",
        ChainingClassification::MatchesKnownSucceed => "known-succeed",
        ChainingClassification::BetweenBands => "between",
    }
}
