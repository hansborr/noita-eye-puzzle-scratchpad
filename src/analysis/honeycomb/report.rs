//! Human-readable rendering for the honeycomb lattice report.

use crate::report::{self, Report};

use super::{HoneycombReport, NullBand, PairStats, TailReport};

impl Report for HoneycombReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 20 honeycomb 2D lattice structure");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.observed.total_trigrams);
        report::appendln!(&mut out, "band widths:");
        for (message_key, widths) in &self.band_widths {
            report::appendln!(
                &mut out,
                "  {message_key}: {}",
                report::format_widths(widths)
            );
        }
        report::appendln!(
            &mut out,
            "held fixed: accepted honeycomb traversal and trigram digit order; no standard36 re-selection"
        );
        report::appendln!(
            &mut out,
            "null: verified row-width structure with uniform orientation cells 0..=4, read under the same fixed order"
        );
        report::appendln!(
            &mut out,
            "boundary rule: vertical and same-distance sequence pairs are formed within messages only"
        );
        report::appendln!(&mut out);

        append_honeycomb_pair_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_position_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_parity_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_interpretation(&mut out, self);
        out
    }
}

fn append_honeycomb_pair_section(out: &mut String, report: &HoneycombReport) {
    report::appendln!(out, "vertical adjacency");
    append_pair_stats(out, "vertical same pos", report.observed.vertical);
    append_tail_line(out, "  equality null", report.null.vertical_equal_rate);
    append_tail_line(out, "  mean-diff null", report.null.vertical_mean_abs_diff);
    report::appendln!(out, "same-distance 1D control");
    append_pair_stats(
        out,
        "same lag sequence",
        report.observed.sequence_distance_control,
    );
    append_tail_line(
        out,
        "  equality null",
        report.null.sequence_control_equal_rate,
    );
    append_tail_line(
        out,
        "  mean-diff null",
        report.null.sequence_control_mean_abs_diff,
    );
    report::appendln!(
        out,
        "same-lag note: for the verified accepted honeycomb geometry, the sequence-distance-matched lag pool coincides with the vertical pool; this exposes the sequence-distance confound instead of treating it as independent evidence"
    );
    report::appendln!(
        out,
        "mean-diff caveat: value differences are range-sensitive because the accepted eye stream is bounded to 0..=82 while the uniform cell null can emit 0..=124"
    );
}

fn append_pair_stats(out: &mut String, label: &str, stats: PairStats) {
    report::appendln!(
        out,
        "  {label}: {}/{} = {:.6}; mean |diff| {:.3}",
        stats.exact_equal,
        stats.pairs,
        stats.exact_equal_rate,
        stats.mean_abs_diff
    );
}

fn append_honeycomb_position_section(out: &mut String, report: &HoneycombReport) {
    let stats = report.observed.position_conditioning;
    report::appendln!(out, "position-in-band conditioning");
    report::appendln!(
        out,
        "  trigrams: {}; positions: {}; value bands: {}; chi-square: {:.3}; df: {}",
        stats.total,
        stats.positions,
        stats.value_deciles,
        stats.chi_square,
        stats.degrees_of_freedom
    );
    report::appendln!(
        out,
        "  value-band note: only 7 of 10 decile buckets are reachable because reading-layer values are bounded to 0..=82"
    );
    append_tail_line(out, "  chi-square null", report.null.position_chi_square);
}

fn append_honeycomb_parity_section(out: &mut String, report: &HoneycombReport) {
    let stats = report.observed.parity_split;
    report::appendln!(out, "interlock-parity split");
    report::appendln!(
        out,
        "  upper/lower trigrams: {}/{}; chi-square: {:.3}; df: {}",
        stats.upper_total,
        stats.lower_total,
        stats.chi_square,
        stats.degrees_of_freedom
    );
    append_tail_line(out, "  chi-square null", report.null.parity_chi_square);
    report::appendln!(
        out,
        "  IoC upper/lower/diff: {:.6} / {:.6} / {:.6}",
        stats.upper_ioc,
        stats.lower_ioc,
        stats.ioc_abs_diff
    );
    append_tail_line(out, "  IoC-diff null", report.null.parity_ioc_abs_diff);
}

fn append_tail_line(out: &mut String, label: &str, tail: TailReport) {
    report::appendln!(
        out,
        "{label}: observed {:.6}; null 95% {}; {} {} ({}/{})",
        tail.observed,
        format_honeycomb_band(tail.band),
        tail.tail.label(),
        report::format_probability(tail.empirical_p),
        tail.extreme_count,
        tail.band.trials
    );
}

fn format_honeycomb_band(band: NullBand) -> String {
    format!("{:.6}..{:.6}", band.q025, band.q975)
}

fn append_honeycomb_interpretation(out: &mut String, report: &HoneycombReport) {
    const POINTWISE_ALPHA: f64 = 0.05;
    const BORDERLINE_MARGIN: f64 = 0.01;

    let isolated_2d_tails = [
        report.null.position_chi_square.empirical_p,
        report.null.parity_chi_square.empirical_p,
        report.null.parity_ioc_abs_diff.empirical_p,
    ];
    let strongest_isolated_2d_tail = isolated_2d_tails.iter().copied().fold(1.0, f64::min);
    let strongest_isolated_2d_tail_is_borderline =
        (strongest_isolated_2d_tail - POINTWISE_ALPHA).abs() <= BORDERLINE_MARGIN;
    let vertical_tail_is_small = report.null.vertical_equal_rate.empirical_p <= POINTWISE_ALPHA
        || report.null.vertical_mean_abs_diff.empirical_p <= POINTWISE_ALPHA;

    report::appendln!(
        out,
        "Multiplicity note: this experiment evaluates 7 one-sided 5% statistics (at least one pointwise hit is about 30% under the null), so a single p near 0.05 is expected and is not a finding."
    );
    if strongest_isolated_2d_tail_is_borderline {
        report::appendln!(
            out,
            "Interpretation: the strongest position/parity lattice statistic is a borderline pointwise marginal near the 5% threshold, seed-sensitive at the configured trial count. Recheck only after multiplicity adjustment; this is not a plaintext or decryption claim."
        );
    } else if strongest_isolated_2d_tail <= POINTWISE_ALPHA {
        report::appendln!(
            out,
            "Interpretation: at least one position/parity lattice statistic is outside a one-sided 5% Monte-Carlo tail. Treat that as a structural anomaly to recheck against transcription and configuration choices, not as a plaintext or decryption claim."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the position-in-band and parity statistics are inside the sampled fixed-order uniform-grid null at the configured resolution. Together with the same-distance control below, this is a negative isolated-2D spatial-layout result for this accepted honeycomb order, not proof that the glyphs are meaningless."
        );
    }
    if vertical_tail_is_small {
        report::appendln!(
            out,
            "Vertical caveat: the vertical adjacency tail is matched by the same-distance 1D control under this geometry, so it does not isolate physical vertical structure from sequence-distance proximity."
        );
    }
    report::appendln!(
        out,
        "The test is conditional on the accepted honeycomb reading order and deliberately avoids order circularity by not searching or reselecting an order for either eyes or null grids."
    );
}
