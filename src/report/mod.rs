//! Report rendering for the Noita eye-puzzle command-line tools.
//!
//! The functions in this module intentionally keep presentation separate from
//! the experiment engines. They render already-computed domain reports and
//! convert domain errors into user-facing CLI text.

use crate::analysis::{analysis, orders};
use crate::core::glyph::Sequence;

/// A domain report that can render itself to user-facing CLI text.
pub trait Report {
    /// Renders this report as a complete, newline-terminated block of text.
    fn render(&self) -> String;
}

/// Appends formatted arguments followed by a newline to a rendered report.
pub(crate) fn append_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;

    let _write_result = out.write_fmt(args);
    out.push('\n');
}

/// Appends a blank newline to a rendered report.
pub(crate) fn append_blank_line(out: &mut String) {
    out.push('\n');
}

macro_rules! appendln {
    ($out:expr) => {
        $crate::report::append_blank_line($out)
    };
    ($out:expr, $($arg:tt)*) => {
        $crate::report::append_line($out, format_args!($($arg)*))
    };
}

pub(crate) use appendln;

/// Returns the singular or plural form for a report count.
pub(crate) fn counted_form(
    count: usize,
    singular: &'static str,
    plural: &'static str,
) -> &'static str {
    if count == 1 { singular } else { plural }
}

/// Formats keyed message lengths for report output.
pub(crate) fn format_message_lengths(lengths: &[(&'static str, usize)]) -> String {
    lengths
        .iter()
        .map(|(key, length)| format!("{key}:{length}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn format_null_flag(pointwise: bool, envelope: bool) -> &'static str {
    if envelope {
        "OUT"
    } else if pointwise {
        "pt95"
    } else {
        "inside"
    }
}

pub(crate) fn format_match_count(matches: usize, comparisons: usize) -> String {
    format!("{matches}/{comparisons}")
}

/// Returns `numerator / denominator`, with zero for an empty denominator.
pub(crate) fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Formats a fraction as a one-decimal percentage.
pub(crate) fn format_percent(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

/// Formats a probability for report output.
pub(crate) fn format_probability(value: f64) -> String {
    if value < 0.001 {
        format!("{value:.3e}")
    } else {
        format!("{value:.6}")
    }
}

/// Formats unsigned integer values as a comma-separated report list.
pub(crate) fn format_usize_values(values: &[usize]) -> String {
    if values.is_empty() {
        return "none".to_owned();
    }
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Returns a report-safe preview of `text`, truncating at a character boundary.
pub(crate) fn preview_text(text: &str, max_chars: usize) -> String {
    let mut preview = String::new();
    let mut omitted = false;
    for (index, symbol) in text.chars().enumerate() {
        if index >= max_chars {
            omitted = true;
            break;
        }
        preview.push(symbol);
    }
    if omitted {
        preview.push_str("...");
    }
    preview
}

pub(crate) fn format_positions(positions: &[usize]) -> String {
    let mut rendered = positions
        .iter()
        .take(12)
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if positions.len() > 12 {
        rendered.push_str(",...");
    }
    rendered
}

/// Renders the reading-order audit and Experiment 4 flatness report.
#[must_use]
pub fn render_orders_report(
    summary: &orders::GridSummary,
    stats: &[orders::NamedOrderStats],
    flatness: &[orders::NamedReadingLayerFlatnessStats],
) -> String {
    let mut out = String::new();
    appendln!(&mut out, "grid row widths:");
    for (key, widths) in &summary.row_widths {
        appendln!(&mut out, "  {key}: {}", format_widths(widths));
    }
    appendln!(&mut out, "max row width: {}", summary.max_width);
    appendln!(
        &mut out,
        "bottom two rows differ by <=1: {}",
        summary.bottom_two_rows_differ_by_at_most_one
    );
    appendln!(&mut out);
    appendln!(
        &mut out,
        "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
        "order",
        "total",
        "distinct",
        "contiguous",
        "span",
        ">82",
        "adj-eq",
        "recurrence d1..d6"
    );

    let mut winners = Vec::new();
    for item in stats {
        if item.stats.is_contiguous_0_to_82() {
            winners.push(item.order.name());
        }
        appendln!(
            &mut out,
            "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
            item.order.name(),
            item.stats.total,
            item.stats.distinct,
            item.stats.contiguous,
            format_span(item.stats.min, item.stats.max),
            item.stats.values_above_82,
            item.stats.adjacent_equal,
            format_recurrence(&item.stats.recurrence_distance_1_to_6)
        );
    }
    appendln!(&mut out);
    if winners.is_empty() {
        appendln!(&mut out, "contiguous 0..=82 orders: none");
    } else {
        appendln!(&mut out, "contiguous 0..=82 orders: {}", winners.join(", "));
    }

    append_experiment_4_flatness_report(&mut out, flatness);
    out
}

/// Renders frequency, entropy, and `IoC` statistics for one rendered sequence.
#[must_use]
pub fn render_sequence_report(label: &str, seq: &Sequence) -> String {
    let mut out = String::new();
    appendln!(&mut out, "{label}: {} glyphs", seq.len());
    appendln!(
        &mut out,
        "  entropy:               {:.4} bits/glyph",
        analysis::shannon_entropy(&seq.glyphs)
    );
    appendln!(
        &mut out,
        "  index of coincidence:  {:.4}",
        analysis::index_of_coincidence(&seq.glyphs)
    );
    appendln!(&mut out, "  frequencies:");
    for (glyph, count) in analysis::frequencies(&seq.glyphs) {
        appendln!(&mut out, "    {glyph}: {count}");
    }
    out
}

/// Formats row widths as a comma-separated report list.
pub(crate) fn format_widths(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_span(min: Option<u8>, max: Option<u8>) -> String {
    match min.zip(max) {
        Some((low, high)) => format!("{low}..{high}"),
        None => "empty".to_owned(),
    }
}

fn format_recurrence(recurrence: &[usize; 6]) -> String {
    let [d1, d2, d3, d4, d5, d6] = *recurrence;
    format!("{d1},{d2},{d3},{d4},{d5},{d6}")
}

fn append_experiment_4_flatness_report(
    out: &mut String,
    flatness: &[orders::NamedReadingLayerFlatnessStats],
) {
    appendln!(out);
    appendln!(out, "Experiment 4 reading-layer flatness");
    appendln!(out, "alphabet: 83 reading-layer symbols, values 0..=82");
    appendln!(
        out,
        "frequency counts are pooled across the nine messages; entropy and IoC p/msg are message-weighted"
    );
    appendln!(
        out,
        "IoC convention: probability form from analysis::index_of_coincidence; x83/all is the concatenated community-reference cross-check"
    );
    appendln!(
        out,
        "{:<24} {:>5} {:>5} {:>7} {:>7} {:>13} {:>17} {:>10} {:>10} {:>10} {:>12} {:>7} {:>12}",
        "order",
        "total",
        "in83",
        "outside",
        "mean",
        "freq min..max",
        "entropy/max",
        "IoC p/msg",
        "x83/msg",
        "x83/all",
        "chi2 83",
        "df",
        "p>=chi2"
    );
    for item in flatness
        .iter()
        .filter(|item| is_experiment_4_order(item.order))
    {
        appendln!(
            out,
            "{:<24} {:>5} {:>5} {:>7} {:>7.2} {:>13} {:>17} {:>10.6} {:>10.3} {:>10.3} {:>12} {:>7} {:>12}",
            item.order.name(),
            item.flatness.total,
            item.flatness.in_alphabet_total,
            item.flatness.outside_alphabet_occurrences,
            item.flatness.mean_frequency,
            format_frequency_range(&item.flatness),
            format_entropy_ratio(&item.flatness),
            item.flatness.ioc_probability,
            item.flatness.normalized_ioc,
            item.flatness.concatenated_normalized_ioc,
            format_chi_square(item.flatness.chi_square_vs_uniform),
            orders::ReadingLayerFlatnessStats::CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM,
            format_chi_square_p_value(item.flatness.chi_square_vs_uniform_upper_tail_p_value)
        );
    }
    appendln!(out);
    appendln!(
        out,
        "Interpretation: the df-aware chi-square tail tests exact iid uniformity over the 83 buckets, not whether the stream is meaningful. Flat-ish per-symbol frequency still RULES MONOALPHABETIC OUT; it does NOT rule a real message IN, and structured-but-meaningless data can also be near-uniform. Do not present flatness as evidence of encoding."
    );
}

fn is_experiment_4_order(order: orders::ReadingOrder) -> bool {
    matches!(
        order,
        orders::ReadingOrder::RawRows | orders::ReadingOrder::HoneycombStandard { .. }
    )
}

fn format_frequency_range(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{}..{} z{}",
        flatness.min_frequency, flatness.max_frequency, flatness.zero_frequency_symbols
    )
}

fn format_entropy_ratio(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{:.4}/{:.4}",
        flatness.entropy_bits_per_symbol, flatness.max_entropy_bits_per_symbol
    )
}

pub(crate) fn format_chi_square(value: f64) -> String {
    if value.is_infinite() {
        "inf(outside)".to_owned()
    } else {
        format!("{value:.3}")
    }
}

pub(crate) fn format_chi_square_p_value(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |p_value| format!("{p_value:.6e}"))
}

pub(crate) fn format_histogram<T: std::fmt::Display>(histogram: &[(T, usize)]) -> String {
    histogram
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{
        format_chi_square, format_chi_square_p_value, format_histogram, format_match_count,
        format_null_flag, format_probability, format_span,
    };

    #[test]
    fn representative_scalar_formatters_are_stable() {
        assert_eq!(format_probability(0.25), "0.250000");
        assert_eq!(format_probability(0.000_25), "2.500e-4");
        assert_eq!(format_chi_square(12.345_6), "12.346");
        assert_eq!(format_chi_square(f64::INFINITY), "inf(outside)");
        assert_eq!(format_chi_square_p_value(Some(0.125)), "1.250000e-1");
        assert_eq!(format_chi_square_p_value(None), "n/a");
    }

    #[test]
    fn representative_table_formatters_are_stable() {
        assert_eq!(format_span(Some(0), Some(82)), "0..82");
        assert_eq!(format_span(None, Some(82)), "empty");
        assert_eq!(format_match_count(3, 99), "3/99");
        assert_eq!(format_null_flag(false, false), "inside");
        assert_eq!(format_null_flag(true, false), "pt95");
        assert_eq!(format_null_flag(true, true), "OUT");
    }

    #[test]
    fn representative_histogram_formatters_are_stable() {
        assert_eq!(
            format_histogram(&[(82_usize, 1), (83_usize, 2)]),
            "82:1, 83:2"
        );
        assert_eq!(format_histogram(&[(0_u8, 5), (4_u8, 7)]), "0:5, 4:7");
    }
}
