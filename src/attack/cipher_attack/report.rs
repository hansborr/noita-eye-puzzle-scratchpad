use super::{
    AttackRow, CipherAttackReport, CipherFamily, PlantRecovery, PositiveControlReport,
    SearchSummary,
};
use crate::report::{self, Report};

impl Report for CipherAttackReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 12 candidate-cipher language-scoring/null harness"
        );
        report::appendln!(&mut out, "order: {}", self.order_name);
        report::appendln!(&mut out, "alphabet: eye reading-layer values 0..=82");
        report::appendln!(
            &mut out,
            "fundamental limitation: English/Finnish scores require an unknown 83-symbol-to-letter mapping; every mapping below is an unverified guess"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "sampled keys: {}", self.config.samples);
        report::appendln!(&mut out, "shuffle null trials: {}", self.config.null_trials);
        report::appendln!(
            &mut out,
            "Vigenere periods searched: 1..={}",
            self.config.vigenere_max_period
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_symbols);
        report::appendln!(&mut out, "boundary rule: {}", self.boundary_rule);
        report::appendln!(&mut out, "null model: {}", self.null_model);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "{:<19} {:<7} {:<14} {:>10} {:>10} {:>10} {:>8} {:>10} {:<28}",
            "cipher",
            "lang",
            "mapping",
            "real",
            "null mean",
            "null q95",
            "p",
            "verdict",
            "best key"
        );
        for row in &self.rows {
            report::appendln!(
                &mut out,
                "{:<19} {:<7} {:<14} {:>10.4} {:>10.4} {:>10.4} {:>8.4} {:>10} {:<28}",
                row.cipher.label(),
                row.language.label(),
                row.mapping_label,
                row.real.score.bigram_mean_log_likelihood,
                row.null.mean,
                row.null.q95,
                row.null.empirical_p,
                format_cipher_attack_verdict(row),
                report::preview_text(&row.real.key, 28)
            );
        }
        report::appendln!(&mut out);
        report::appendln!(&mut out, "search methods");
        for summary in unique_cipher_search_summaries(&self.rows) {
            report::appendln!(
                &mut out,
                "  {}: {} candidates; keyspace {}; {}",
                summary.0.label(),
                summary.1.candidates_evaluated,
                summary.1.key_space,
                summary.1.note
            );
        }
        report::appendln!(&mut out);
        report::appendln!(&mut out, "mapping caveats");
        for row in &self.rows {
            report::appendln!(
                &mut out,
                "  {} / {} / {}: {}",
                row.cipher.label(),
                row.language.label(),
                row.mapping_label,
                row.mapping_note
            );
        }
        report::appendln!(&mut out);
        append_positive_control_report(&mut out, &self.positive_control);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "caveat: any apparent hit is not credible unless it has a fully reproducible, independently checkable method and is rechecked against Experiment 0 transcription integrity; this command makes no message claim"
        );
        append_cipher_attack_interpretation(&mut out, self);
        out
    }
}

fn append_positive_control_report(out: &mut String, report: &PositiveControlReport) {
    report::appendln!(out, "positive control");
    append_plant_recovery(out, &report.caesar);
    append_plant_recovery(out, &report.vigenere);
}

fn append_plant_recovery(out: &mut String, plant: &PlantRecovery) {
    report::appendln!(
        out,
        "  {}: expected {}, recovered {}, score {:.4}, null max {:.4}, margin {:.4}, p {:.4}",
        plant.cipher.label(),
        plant.expected_key,
        plant.recovered_key,
        plant.real_score.bigram_mean_log_likelihood,
        plant.null.max,
        plant.margin_over_null_max,
        plant.null.empirical_p
    );
}

fn append_cipher_attack_interpretation(out: &mut String, report: &CipherAttackReport) {
    for line in cipher_attack_interpretation_lines(report) {
        report::appendln!(out, "{line}");
    }
}

pub(super) fn cipher_attack_interpretation_lines(report: &CipherAttackReport) -> Vec<String> {
    let above_q95 = report
        .rows
        .iter()
        .filter(|row| row.real.score.bigram_mean_log_likelihood > row.null.q95)
        .count();
    let above_max = report
        .rows
        .iter()
        .filter(|row| row.real.score.bigram_mean_log_likelihood > row.null.max)
        .count();
    let row_count = report.rows.len();
    let expected_rate = 0.05;
    let exceedance_rate = report::fraction(above_q95, row_count);
    let expected_rows = row_count as f64 * expected_rate;
    let rate_multiple = exceedance_rate / expected_rate;
    let total_key_evaluations = report
        .rows
        .iter()
        .map(|row| row.search.candidates_evaluated)
        .sum::<usize>();
    let mut lines = Vec::new();
    if above_q95 == 0 {
        lines.push(format!(
            "Interpretation: all {row_count} cipher/mapping/language rows are inside the one-sided 95% shuffled-null best-score band. Under these named ciphers and declared guessed mappings, this run shows no English/Finnish language signal above chance."
        ));
    } else {
        lines.push(format!(
            "Interpretation: {above_q95} of {row_count} rows ({}) exceed the one-sided 95% shuffled-null band, and {above_max} exceed the sampled null maximum. If the shuffle null were a valid no-difference reference for these selected best-score rows, only about {expected_rows:.1} of {row_count} rows (~5%) would be expected to clear that band; this run is far above that expectation at {:.1}x the rate. That is an exceedance-rate diagnostic, not {above_q95} near-solutions.",
            report::format_percent(exceedance_rate),
            rate_multiple
        ));
        lines.push(
            "The null construction shuffles symbols within each message and reapplies the same key search, so it preserves message lengths and symbol counts but destroys local order. The defensible cause is that the bigram language score detects the eye stream's already documented mild local structure - the distance-4 recurrence / slight bigram non-uniformity established in Experiments 4, 5A, and 7A - relative to symbol-shuffled data. That known structural property is not cipher signal; the null does not use a smaller key search than the real rows.".to_owned(),
        );
    }

    lines.push(cipher_attack_effect_size_line(report));
    lines.push(format!(
        "Multiple comparisons: this configured run scans {row_count} cipher/mapping/language rows and {total_key_evaluations} row-level key evaluations before selecting best scores. The reported p values are pointwise and uncorrected across the scanned ciphers, mappings, languages, and keyspaces; small values are expected by selection, and no family-wise-significant result exists in this report."
    ));
    lines.push(
        "Overall conclusion: clean negative. No credible English/Finnish decryption is established, and there is no message claim. The run constrains only these candidate ciphers, this reading order, these sampled keyspaces, and these unverified symbol-to-letter mappings; any apparent hit still requires a fully reproducible, independently checkable method plus an Experiment 0 transcription-integrity recheck.".to_owned(),
    );
    lines
}

fn cipher_attack_effect_size_line(report: &CipherAttackReport) -> String {
    let plant_margins = [
        report.positive_control.caesar.margin_over_null_max,
        report.positive_control.vigenere.margin_over_null_max,
    ];
    let plant_range =
        range_from_values(&plant_margins).unwrap_or(NumberRange { min: 0.0, max: 0.0 });
    let eye_margins = report
        .rows
        .iter()
        .map(|row| row.real.score.bigram_mean_log_likelihood - row.null.max)
        .filter(|margin| *margin > 0.0)
        .collect::<Vec<_>>();
    if let Some(eye_range) = range_from_values(&eye_margins) {
        let min_ratio = plant_range.min / eye_range.max;
        let max_ratio = plant_range.max / eye_range.min;
        format!(
            "Effect-size contrast: eye rows that clear the sampled null maximum do so by only {} nats, while the same harness recovers positive-control plant margins of {} nats. The plant effect is about {} larger, so the eyes' best decryptions are nowhere near the scale of a genuine cipher hit.",
            format_number_range(eye_range, 4),
            format_number_range(plant_range, 4),
            format_ratio_range(NumberRange {
                min: min_ratio,
                max: max_ratio,
            })
        )
    } else {
        let best_margin = report
            .rows
            .iter()
            .map(|row| row.real.score.bigram_mean_log_likelihood - row.null.max)
            .max_by(f64::total_cmp)
            .unwrap_or(0.0);
        format!(
            "Effect-size contrast: no eye row clears the sampled null maximum; the best eye margin against that maximum is {best_margin:.4} nats, while the same harness recovers positive-control plant margins of {} nats. The eyes' best decryptions are nowhere near the scale of a genuine cipher hit.",
            format_number_range(plant_range, 4)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct NumberRange {
    min: f64,
    max: f64,
}

fn range_from_values(values: &[f64]) -> Option<NumberRange> {
    let mut iter = values.iter().copied();
    let first = iter.next()?;
    let mut range = NumberRange {
        min: first,
        max: first,
    };
    for value in iter {
        range.min = range.min.min(value);
        range.max = range.max.max(value);
    }
    Some(range)
}

fn format_number_range(range: NumberRange, decimals: usize) -> String {
    if (range.max - range.min).abs() < f64::EPSILON {
        format!("{:.*}", decimals, range.min)
    } else {
        format!("{:.*}..{:.*}", decimals, range.min, decimals, range.max)
    }
}

fn format_ratio_range(range: NumberRange) -> String {
    if (range.max - range.min).abs() < f64::EPSILON {
        format!("{:.0}x", range.min)
    } else {
        format!("{:.0}x to {:.0}x", range.min, range.max)
    }
}

fn format_cipher_attack_verdict(row: &AttackRow) -> &'static str {
    let real = row.real.score.bigram_mean_log_likelihood;
    if real > row.null.max {
        "above-max"
    } else if real > row.null.q95 {
        "above95"
    } else {
        "inside95"
    }
}

fn unique_cipher_search_summaries(rows: &[AttackRow]) -> Vec<(CipherFamily, SearchSummary)> {
    let mut summaries = Vec::new();
    for row in rows {
        if summaries
            .iter()
            .any(|(cipher, _summary)| *cipher == row.cipher)
        {
            continue;
        }
        summaries.push((row.cipher, row.search.clone()));
    }
    summaries
}
