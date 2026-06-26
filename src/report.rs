//! Report rendering for the Noita eye-puzzle command-line tools.
//!
//! The functions in this module intentionally keep presentation separate from
//! the experiment engines. They render already-computed domain reports and
//! convert domain errors into user-facing CLI text.

use crate::glyph::Sequence;
use crate::{analysis, gak_attack, orders};

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

/// Prints the Thread 4 EYES Step-3 report: the ONLY unit touching the real eyes.
///
/// This is the highest honesty-risk surface in the project. Every line preserves
/// the claim ceiling, states the expected outcome is NO surviving candidate, reports
/// the held-out + Thread-3 verdicts, labels everything HYPOTHESIS-not-decode, and
/// NEVER implies a decode.
pub fn print_gak_attack_eyes_report(report: &gak_attack::EyesAttackReport) {
    println!("Thread 4 EYES Step 3 (the ONLY unit that touches the real eye corpus)");
    println!(
        "Claim ceiling: the eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Nothing here is stronger."
    );
    println!(
        "Expected outcome: NO surviving candidate. The standing conclusion is the eye decode remains BLOCKED on the unknown symbol->meaning mapping; a clean honest negative is a SUCCESS, not a failure."
    );
    println!(
        "What is recovered: STRUCTURE (visible-coset / chain-link constraints), NOT cleartext. A full structural recovery still yields abstract plaintext-letter INDICES, not readable text, because symbol->letter mapping needs an external ANCHOR (the standing blocker). Any candidate is a HYPOTHESIS, never a decode."
    );
    println!(
        "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)"
    );
    println!(
        "  reading order `{}`; {} reading-layer symbols; {} distinct (the 83-symbol reading layer); {} messages",
        report.order_name,
        report.total_symbols,
        report.distinct_symbols,
        report.per_message.len()
    );
    println!();
    print_eyes_gate1(report);
    println!();
    print_eyes_gates_2_3_verdict(report);
}

/// Prints the EYES Step-3 Gate-1 (held-out isomorphs) section.
fn print_eyes_gate1(report: &gak_attack::EyesAttackReport) {
    // GATE 1: held-out isomorphs (embargoed-consensus coverage-weighted score).
    println!("GATE 1 -- held-out isomorphs vs matched within-message shuffle null");
    println!(
        "  statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The recovered model is a LIBRARY of context-colored partial permutations (one per TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out edge scores only when >=2 train contexts from DISTINCT signature groups -- with NO physical span overlap/adjacency with the held-out context -- AGREE on it; that embargo kills the nested/overlapping-window leak a within-message shuffle mimics, so only genuinely TRANSFERABLE structure scores. score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83, with a per-message COVERAGE CLAMP that zeroes any message with < 4 confident decisions (an explicit part of the statistic, applied identically to real and null). Gate-1 chaining is ENFORCED to stay within the Thread-3 safe isomorph extents (F2). A shuffle has no transferable structure detected by this gate, so it scores ~0."
    );
    println!(
        "  held-out POSITIVE CONTROL on a synthetic isomorph-rich eye-shaped fixture: real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={} (the predictor must fire on KNOWN signal AND clear its OWN population's material-effect bar, or the gate is not trusted)",
        report.held_out_positive_control.real_score,
        report.held_out_positive_control.null_score,
        report.held_out_positive_control.scoreable_edges,
        yes_no(report.held_out_positive_control.fired)
    );
    println!(
        "  real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}",
        report.real_held_out_hits_total,
        report.real_held_out_misses_total,
        report.real_held_out_ambiguous_total,
        report.real_score
    );
    println!(
        "  matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}",
        report.trials,
        report.null_at_least_real,
        report.null_mean_score,
        report.matched_null_p_value
    );
    println!(
        "  material-effect bar (p-value is NECESSARY, NOT sufficient), POPULATION-RELATIVE and FAIR to the eyes: the real-vs-null excess must reach {:.0}% of the eyes' OWN max achievable score = scoreable_edges*(A-1) = {}*{} = {:.0}, so threshold = {:.1} (BELOW the eyes' max, so genuine signal COULD clear it); met={} (the detector is validated: the positive control clears its own population's bar by the identical rule)",
        gak_attack::EYES_MATERIAL_EFFECT_FRACTION * 100.0,
        report.scoreable_edges,
        gak_attack::EYE_READING_ALPHABET_SIZE - 1,
        report.max_achievable_score,
        report.material_effect_threshold,
        yes_no(report.material_effect_met)
    );
    println!(
        "  GATE 1 VERDICT (held-out beats matched null AND clears the calibrated material-effect bar): {}",
        yes_no(report.held_out_beats_null)
    );
    println!("  per-message (boundaries kept; never concatenated):");
    println!(
        "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
        "msg", "len", "iso-groups", "pairs", "touched", "aborts", "hits", "miss", "amb", "score"
    );
    for m in &report.per_message {
        println!(
            "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
            m.message_key,
            m.length,
            m.isomorph_groups,
            m.aligned_pairs,
            m.symbols_touched,
            m.true_conflict_aborts,
            m.real_held_out_hits,
            m.real_held_out_misses,
            m.real_held_out_ambiguous,
            m.real_score
        );
    }
}

/// Prints the EYES Step-3 Gate-2 / Gate-3 sections, the verdict, and the
/// candidate-logging protocol (the honesty-lock tail).
fn print_eyes_gates_2_3_verdict(report: &gak_attack::EyesAttackReport) {
    // GATE 2: Thread-3 consistency.
    println!(
        "GATE 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API REUSED, never re-derived)"
    );
    println!(
        "  robust internal violations: {} (must be 0 -- a non-zero count is a manufactured TRUE conflict that would disqualify the model)",
        report.three_consistency.robust_internal_violations
    );
    println!(
        "  safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within these per-message safe spans (F2): an occurrence window is admitted only inside a Thread-3 safe span, so chaining never over-extends past them)",
        report.three_consistency.safe_extents
    );
    println!(
        "  Thread-3 positive control fired: {}",
        yes_no(report.three_consistency.positive_control_fired)
    );
    println!(
        "  GATE 2 VERDICT (model consistent with Thread 3): {}",
        yes_no(report.three_consistency.consistent)
    );
    println!();

    // GATE 3: speculative cleartext.
    println!(
        "GATE 3 -- SPECULATIVE cleartext plausibility (LAST, Finnish-weighted, NEVER primary)"
    );
    match &report.speculative_cleartext {
        None => {
            println!(
                "  NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the SPECULATIVE cleartext path is correctly NOT executed and NO candidate cleartext is reported."
            );
        }
        Some(s) => {
            println!(
                "  RAN (both structural gates passed). The symbol->letter mapping is a HYPOTHESIS, never recovered; this is NEVER primary evidence. Implied plaintext logged VERBATIM to the candidate record for human review (Finnish weighted highly -- Noita is Finnish)."
            );
            println!(
                "  Finnish bigram {:.4} vs matched-mapping null {:.4} -> beats={}; English bigram {:.4} vs null {:.4} -> beats={}",
                s.finnish_score,
                s.finnish_null_mean,
                yes_no(s.beats_finnish_null),
                s.english_score,
                s.english_null_mean,
                yes_no(s.beats_english_null)
            );
        }
    }
    println!();

    // The verdict + interpretation (honesty lock).
    println!(
        "THE VERDICT: candidate survived BOTH structural gates: {}",
        yes_no(report.candidate_survived)
    );
    if report.candidate_survived {
        println!(
            "Interpretation: a candidate survived the held-out + Thread-3 checks. It is logged as a HYPOTHESIS for human review, NOT a decode. The claim ceiling still binds: this is NOT a recovered eye plaintext. FLAGGED LOUDLY for human review."
        );
    } else {
        println!(
            "Interpretation: no candidate surfaced. This is the EXPECTED, reportable outcome -- with a near-S_83 group and very little eye text, recovered structure does not predict held-out isomorphs above the matched null (no transferable structure DETECTED BY THIS GATE). The eye decode REMAINS BLOCKED on the unknown symbol->meaning mapping. This is a HYPOTHESIS-free honest negative, NOT a decode."
        );
    }
    println!(
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/ capturing the attempt, the recovered-structure amount, the held-out verdict + matched-null p-value, the Thread-3 verdict, and the explicit HYPOTHESIS-not-decode label; any candidate cleartext (English OR Finnish) is logged VERBATIM for human review. This run's record: {}",
        report.record_path.display()
    );
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

/// Prints the reading-order audit and Experiment 4 flatness report.
pub fn print_orders_report(
    summary: &orders::GridSummary,
    stats: &[orders::NamedOrderStats],
    flatness: &[orders::NamedReadingLayerFlatnessStats],
) {
    println!("grid row widths:");
    for (key, widths) in &summary.row_widths {
        println!("  {key}: {}", format_widths(widths));
    }
    println!("max row width: {}", summary.max_width);
    println!(
        "bottom two rows differ by <=1: {}",
        summary.bottom_two_rows_differ_by_at_most_one
    );
    println!();
    println!(
        "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
        "order", "total", "distinct", "contiguous", "span", ">82", "adj-eq", "recurrence d1..d6"
    );

    let mut winners = Vec::new();
    for item in stats {
        if item.stats.is_contiguous_0_to_82() {
            winners.push(item.order.name());
        }
        println!(
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
    println!();
    if winners.is_empty() {
        println!("contiguous 0..=82 orders: none");
    } else {
        println!("contiguous 0..=82 orders: {}", winners.join(", "));
    }

    print_experiment_4_flatness_report(flatness);
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

fn print_experiment_4_flatness_report(flatness: &[orders::NamedReadingLayerFlatnessStats]) {
    println!();
    println!("Experiment 4 reading-layer flatness");
    println!("alphabet: 83 reading-layer symbols, values 0..=82");
    println!(
        "frequency counts are pooled across the nine messages; entropy and IoC p/msg are message-weighted"
    );
    println!(
        "IoC convention: probability form from analysis::index_of_coincidence; x83/all is the concatenated community-reference cross-check"
    );
    println!(
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
        println!(
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
    println!();
    println!(
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
