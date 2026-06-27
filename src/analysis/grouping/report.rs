//! Experiment 8 stdout rendering: the [`Report`] implementation and the
//! `append_*`/`format_*` helpers that lay out the grouping comparison,
//! language-compatibility flags, and state-count estimate tables.

use super::Experiment8Report;
use crate::analysis::orders;
use crate::report::{self, Report};

impl Report for Experiment8Report {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 8 base-N grouping reinterpretation");
        report::appendln!(&mut out, "order: {}", self.state_estimate.order.name());
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.state_estimate.message_lengths)
        );
        report::appendln!(
            &mut out,
            "boundary rule: rendered groups are non-overlapping within each message; incomplete tails are dropped and no group crosses a message join"
        );
        report::appendln!(
            &mut out,
            "storage axis: engine base-7 decoded symbols 0..=5, including delimiter 5, reported separately from rendered orientations"
        );
        report::appendln!(&mut out);
        append_grouping_summary(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_message_detail(&mut out, self);
        report::appendln!(&mut out);
        append_language_reference_rows(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_compatibility(&mut out, self);
        report::appendln!(&mut out);
        append_state_count_estimate(&mut out, self);
        report::appendln!(&mut out);
        append_state_count_calibration(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_interpretation(&mut out, self);
        out
    }
}

fn append_grouping_summary(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "grouping summary");
    report::appendln!(
        out,
        "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9} {:>8} {:>10} {:>9} {:>10}",
        "grouping",
        "base",
        "symbols",
        "drop",
        "used",
        "H bits",
        "H/log2k",
        "IoC pool",
        "H msg",
        "IoC msg"
    );
    for row in &experiment.groupings {
        report::appendln!(
            out,
            "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9.4} {:>8.4} {:>10.6} {:>9.4} {:>10.6}",
            row.axis.label(),
            row.axis.nominal_base(),
            row.pooled.symbols,
            row.dropped_source_symbols,
            row.pooled.used_alphabet,
            row.pooled.entropy_bits_per_symbol,
            row.pooled.normalized_entropy,
            row.pooled.ioc,
            row.message_weighted_entropy_bits_per_symbol,
            row.message_weighted_ioc
        );
    }
}

fn append_grouping_message_detail(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "per-message grouping detail");
    report::appendln!(
        out,
        "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9} {:>8} {:>10}",
        "grouping",
        "msg",
        "symbols",
        "drop",
        "used",
        "H bits",
        "H/log2k",
        "IoC"
    );
    for row in &experiment.groupings {
        for message in &row.messages {
            report::appendln!(
                out,
                "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9.4} {:>8.4} {:>10.6}",
                row.axis.label(),
                message.message_key,
                message.stats.symbols,
                message.dropped_source_symbols,
                message.stats.used_alphabet,
                message.stats.entropy_bits_per_symbol,
                message.stats.normalized_entropy,
                message.stats.ioc
            );
        }
    }
}

fn append_language_reference_rows(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(
        out,
        "natural-language unigram references from bundled language models"
    );
    report::appendln!(
        out,
        "{:<8} {:>7} {:>8} {:>7} {:>9} {:>8} {:>10} {:>9}",
        "lang",
        "nom k",
        "obs k",
        "letters",
        "H bits",
        "H/log2k",
        "IoC",
        "1/IoC"
    );
    for reference in &experiment.language_references {
        report::appendln!(
            out,
            "{:<8} {:>7} {:>8} {:>7} {:>9.4} {:>8.4} {:>10.6} {:>9.2}",
            reference.language,
            reference.nominal_alphabet,
            reference.observed_used_alphabet,
            reference.symbols,
            reference.entropy_bits_per_symbol,
            reference.normalized_entropy,
            reference.ioc,
            reference.collision_effective_alphabet
        );
    }
}

fn append_grouping_compatibility(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "language-compatibility flags");
    report::appendln!(
        out,
        "derived bands: alphabet {}..={}, entropy {:.4}..{:.4} bits",
        experiment.compatibility.alphabet_min,
        experiment.compatibility.alphabet_max,
        experiment.compatibility.entropy_min,
        experiment.compatibility.entropy_max
    );
    report::appendln!(
        out,
        "{:<24} {:>10} {:>10} {:>10}",
        "grouping",
        "alphabet",
        "entropy",
        "both"
    );
    for row in &experiment.compatibility.rows {
        let both = row.alphabet_compatible && row.entropy_compatible;
        report::appendln!(
            out,
            "{:<24} {:>10} {:>10} {:>10}",
            row.grouping_label,
            report::yes_no(row.alphabet_compatible),
            report::yes_no(row.entropy_compatible),
            report::yes_no(both)
        );
    }
    let compatible = experiment.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        report::appendln!(out, "fully compatible groupings: none");
    } else {
        report::appendln!(out, "fully compatible groupings: {}", compatible.join(", "));
    }
    report::appendln!(
        out,
        "nearest alphabet-size match: {}",
        experiment.compatibility.nearest_alphabet_grouping
    );
}

fn append_state_count_estimate(out: &mut String, experiment: &Experiment8Report) {
    let estimate = &experiment.state_estimate;
    let collision = estimate.collision;
    report::appendln!(out, "independent collision state-count estimate");
    report::appendln!(
        out,
        "pooled IoC: {:.6}; 1/IoC: {:.2}; collision entropy: {:.4} bits",
        collision.pooled_ioc,
        collision.pooled_effective_states,
        collision.collision_entropy_bits
    );
    report::appendln!(
        out,
        "message-weighted IoC: {:.6}; 1/IoC: {:.2}; pooled Shannon entropy: {:.4} bits",
        collision.message_weighted_ioc,
        collision.message_weighted_effective_states,
        collision.pooled_entropy_bits_per_symbol
    );
    report::appendln!(
        out,
        "calibrated range: {}..{} states; contains established reading-layer size {}: {}",
        estimate.range.lower,
        estimate.range.upper,
        orders::READING_LAYER_ALPHABET_SIZE,
        report::yes_no(estimate.range.includes_83)
    );
    report::appendln!(
        out,
        "calibration margin applied: {:.1}%",
        estimate.calibration_relative_margin * 100.0
    );
    report::appendln!(
        out,
        "longest repeated isomorph in scanned k={}..={}: {}",
        grouping_state_min_window(experiment),
        grouping_state_max_window(experiment),
        estimate
            .longest_repeated_isomorph
            .map_or_else(|| "none".to_owned(), |window| window.to_string())
    );
    report::appendln!(out);
    report::appendln!(out, "isomorph/window diagnostics");
    report::appendln!(
        out,
        "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
        "k",
        "windows",
        "inform",
        "rep kinds",
        "max rep",
        "birthday N"
    );
    for row in &estimate.isomorph_rows {
        report::appendln!(
            out,
            "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
            row.window,
            row.windows,
            row.informative_windows,
            row.repeated_signature_kinds,
            row.max_repeat_count,
            format_optional_f64(row.birthday_effective_states)
        );
    }
}

fn append_state_count_calibration(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "synthetic N-state positive-control calibration");
    report::appendln!(out, "seed: {}", experiment.calibration.seed);
    report::appendln!(
        out,
        "model: real message lengths, uniform N-symbol plaintext through N deterministic rotational alphabets"
    );
    report::appendln!(
        out,
        "{:>6} {:>5} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "true N",
        "used",
        "IoC pool",
        "N pool",
        "N msg",
        "rel err",
        "max iso"
    );
    for row in &experiment.calibration.rows {
        report::appendln!(
            out,
            "{:>6} {:>5} {:>10.6} {:>10.2} {:>10.2} {:>8.2}% {:>10}",
            row.true_states,
            row.used_alphabet,
            row.pooled_ioc,
            row.pooled_effective_states,
            row.message_weighted_effective_states,
            row.relative_error * 100.0,
            format_optional_usize(row.longest_repeated_isomorph)
        );
    }
    report::appendln!(
        out,
        "max sampled relative error: {:.2}%; applied margin: {:.2}%",
        experiment.calibration.max_relative_error * 100.0,
        experiment.calibration.applied_relative_margin * 100.0
    );
}

fn append_grouping_interpretation(out: &mut String, experiment: &Experiment8Report) {
    let compatible = experiment.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        report::appendln!(
            out,
            "Interpretation: no tested grouping matches both the bundled natural-language alphabet-size band and entropy band as raw plaintext. The nearest alphabet-size match is {}, but its entropy is measured separately above.",
            experiment.compatibility.nearest_alphabet_grouping
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: grouping(s) matching both measured language alphabet size and entropy: {}.",
            compatible.join(", ")
        );
    }

    let range = experiment.state_estimate.range;
    let relation = if range.includes_83 {
        "overlaps"
    } else if range.upper < orders::READING_LAYER_ALPHABET_SIZE {
        "falls below"
    } else {
        "sits above"
    };
    report::appendln!(
        out,
        "The independent collision estimate gives an approximate {}..{} state range, which {relation} the established 83-symbol reading layer. This agreement check does not assume 83, and it does not decode meaning.",
        range.lower,
        range.upper
    );
    report::appendln!(
        out,
        "Near-uniform high entropy remains consistent with a permutation or other structured transformation of data, as in Experiment 4; these numbers constrain plausible encodings only."
    );
}

fn grouping_state_min_window(experiment: &Experiment8Report) -> usize {
    experiment
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .min()
        .unwrap_or_default()
}

fn grouping_state_max_window(experiment: &Experiment8Report) -> usize {
    experiment
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .max()
        .unwrap_or_default()
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |number| format!("{number:.2}"))
}

fn format_optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "none".to_owned(), |number| number.to_string())
}
