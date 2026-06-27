//! Experiment 5A report rendering for [`PeriodicityReport`].
//!
//! Holds the `Report` implementation and its `append_*`/`format_*` helpers,
//! split out of the periodicity battery body so the compute lives separately.

use crate::report::{self, Report};

use super::{
    AutocorrelationRow, KasiskiReport, MessagePeriodicityReport, NullBand, PeriodIocRow,
    PeriodicityReport,
};

const MIN_RELIABLE_PERIODICITY_NULL_TRIALS: usize = 50;

impl Report for PeriodicityReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 5A periodicity/autocorrelation battery"
        );
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "alphabet: reading-layer values 0..=82");
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "periods: 1..={} ; lags: 1..={} ; Kasiski n-grams: {}..={}",
            self.config.max_period,
            self.config.max_lag,
            self.config.min_ngram,
            self.config.max_ngram
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.pooled_length);
        report::appendln!(
            &mut out,
            "boundary rule: pooled statistics aggregate within-message evidence only; no lag pairs, period columns, or n-grams cross message joins"
        );
        report::appendln!(
            &mut out,
            "IoC convention: analysis::index_of_coincidence probability form; x83 normalizes to the uniform 83-symbol baseline"
        );
        report::appendln!(
            &mut out,
            "sampled report-wide null envelopes: period x83 <= {:.3}; autocorrelation rate <= {:.6}",
            self.period_null_envelope_max,
            self.autocorrelation_null_envelope_max
        );
        report::appendln!(&mut out);
        append_period_ioc_table(&mut out, "pooled IoC-by-period", &self.pooled_ioc_by_period);
        report::appendln!(&mut out);
        append_autocorrelation_table(
            &mut out,
            "pooled autocorrelation profile",
            &self.pooled_autocorrelation,
        );
        report::appendln!(&mut out);
        append_message_periodicity_summary(&mut out, &self.messages);
        report::appendln!(&mut out);
        append_kasiski_table(&mut out, "pooled Kasiski distances", &self.pooled_kasiski);
        report::appendln!(&mut out);
        append_message_kasiski_summary(&mut out, &self.messages);
        report::appendln!(&mut out);
        append_periodicity_interpretation(&mut out, self);
        out
    }
}

fn append_periodicity_interpretation(out: &mut String, report: &PeriodicityReport) {
    let exceedance_labels = null_envelope_exceedance_labels(report);
    if report.config.trials < MIN_RELIABLE_PERIODICITY_NULL_TRIALS {
        report::appendln!(
            out,
            "Caveat: only {} Monte-Carlo trial(s) were sampled (< {}); the report-wide null envelope is undersampled and the OUT/inside verdict is not reliable.",
            report.config.trials,
            MIN_RELIABLE_PERIODICITY_NULL_TRIALS
        );
    }

    if exceedance_labels.is_empty() {
        report::appendln!(
            out,
            "Interpretation: no pooled or per-message period/lag row exceeds the sampled report-wide random-null envelope (no OUT flags). That rules out a simple fixed-period polyalphabetic cipher under this honeycomb reading order; it does not prove the data is meaningless, and it says nothing about other reading orders or encodings."
        );
    } else {
        let count = exceedance_labels.len();
        report::appendln!(
            out,
            "Interpretation: {count} pooled/per-message period/lag {} {} the sampled report-wide random-null envelope (OUT): {}. Because at least one row is OUT, this run does not support the no-exceedance verdict and does not rule out a simple fixed-period polyalphabetic cipher under this honeycomb reading order.",
            report::counted_form(count, "row", "rows"),
            report::counted_form(count, "exceeds", "exceed"),
            exceedance_labels.join(", ")
        );
    }

    report::appendln!(
        out,
        "Near-uniform IoC-by-period is also exactly what a fixed permutation of structured data can produce. Pointwise pt95 rows are shown as noise candidates only; a peak inside the sampled envelope is not a period claim."
    );
    append_distance4_reconciliation(out, report, !exceedance_labels.is_empty());
    report::appendln!(
        out,
        "Any future striking period must be rechecked against Experiment 0 transcription integrity before interpretation."
    );
}

fn null_envelope_exceedance_labels(report: &PeriodicityReport) -> Vec<String> {
    let mut labels = Vec::new();
    append_period_exceedance_labels("pooled", &report.pooled_ioc_by_period, &mut labels);
    append_autocorrelation_exceedance_labels("pooled", &report.pooled_autocorrelation, &mut labels);
    for message in &report.messages {
        append_period_exceedance_labels(message.message_key, &message.ioc_by_period, &mut labels);
        append_autocorrelation_exceedance_labels(
            message.message_key,
            &message.autocorrelation,
            &mut labels,
        );
    }
    labels
}

fn append_period_exceedance_labels(scope: &str, rows: &[PeriodIocRow], labels: &mut Vec<String>) {
    for row in rows.iter().filter(|row| row.above_null_envelope) {
        let period = row.period;
        labels.push(format!("{scope} period p={period}"));
    }
}

fn append_autocorrelation_exceedance_labels(
    scope: &str,
    rows: &[AutocorrelationRow],
    labels: &mut Vec<String>,
) {
    for row in rows.iter().filter(|row| row.above_null_envelope) {
        let lag = row.lag;
        labels.push(format!("{scope} lag={lag}"));
    }
}

fn append_distance4_reconciliation(
    out: &mut String,
    report: &PeriodicityReport,
    has_envelope_exceedance: bool,
) {
    let lag4 = report
        .pooled_autocorrelation
        .iter()
        .find(|row| row.lag == 4);
    let strongest = strongest_autocorrelation_row(&report.pooled_autocorrelation);
    let lag4_is_dominant = matches!((lag4, strongest), (Some(_), Some(row)) if row.lag == 4);

    match (lag4, strongest) {
        (Some(row), Some(strongest_row)) if strongest_row.lag == 4 => {
            report::appendln!(
                out,
                "Distance-4 reconciliation: lag 4 is the dominant pooled autocorrelation peak under this honeycomb order, consistent with Experiment 1B's distance-4 spike."
            );
            append_lag4_band_reconciliation(out, row);
        }
        (Some(row), Some(strongest_row)) => {
            report::appendln!(
                out,
                "Distance-4 reconciliation: lag 4 is included in this scan, but the strongest pooled autocorrelation peak in the configured range is lag {}. The usual lag-4-dominant wording therefore does not apply to this run.",
                strongest_row.lag
            );
            append_lag4_band_reconciliation(out, row);
        }
        _ => report::appendln!(
            out,
            "Distance-4 reconciliation: this configured lag range does not include lag 4, so this run cannot evaluate Experiment 1B's distance-4 spike."
        ),
    }

    report::appendln!(
        out,
        "Experiment 1B's targeted distance-4 test, appropriate for a pre-identified distance under the best-over-36 null, found d4 significant; this broad conservative sweep does not contradict it."
    );
    if has_envelope_exceedance {
        report::appendln!(
            out,
            "Because OUT rows are present in this configured run, the broad scan should not be summarized as showing no new family-wise period/lag signal. The d4 structure itself is order-contingent and is not a message claim."
        );
    } else if lag4_is_dominant {
        report::appendln!(
            out,
            "The broad scan still shows no new dominant period beyond the known d4 structure. The d4 structure itself is order-contingent and is not a message claim."
        );
    } else {
        report::appendln!(
            out,
            "This configured scan should not be used for a broad no-new-period statement beyond its scanned range. The d4 structure itself is order-contingent and is not a message claim."
        );
    }
}

fn append_lag4_band_reconciliation(out: &mut String, row: &AutocorrelationRow) {
    if row.above_null_envelope {
        report::appendln!(
            out,
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is OUT against that envelope in this configured run, and it exceeds its own per-lag band (pt95). Treat that as an envelope exceedance, not as a plaintext claim by itself."
        );
    } else if row.above_pointwise_band {
        report::appendln!(
            out,
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is inside that envelope, but it still exceeds its own per-lag band (pt95). Therefore, no family-wise exceedance is not evidence that the d4 structure is absent."
        );
    } else {
        report::appendln!(
            out,
            "The report-wide envelope is a family-wise verdict over all scanned lags; lag 4 is inside that envelope and does not exceed its own per-lag band in this configured run."
        );
    }
}

fn append_period_ioc_table(out: &mut String, label: &str, rows: &[PeriodIocRow]) {
    report::appendln!(out, "{label}");
    report::appendln!(
        out,
        "{:>3} {:>10} {:>10} {:>19} {:>10} {:>7}",
        "p",
        "IoC",
        "x83",
        "null x83 95%",
        "null max",
        "flag"
    );
    for row in rows {
        report::appendln!(
            out,
            "{:>3} {:>10.6} {:>10.3} {:>19} {:>10.3} {:>7}",
            row.period,
            row.mean_ioc,
            row.normalized_ioc,
            format_null_band(row.null_band),
            row.null_band.max,
            report::format_null_flag(row.above_pointwise_band, row.above_null_envelope)
        );
    }
}

fn append_autocorrelation_table(out: &mut String, label: &str, rows: &[AutocorrelationRow]) {
    report::appendln!(out, "{label}");
    report::appendln!(
        out,
        "{:>3} {:>11} {:>10} {:>10} {:>19} {:>10} {:>7}",
        "lag",
        "matches",
        "rate",
        "x83",
        "null rate 95%",
        "null max",
        "flag"
    );
    for row in rows {
        report::appendln!(
            out,
            "{:>3} {:>11} {:>10.6} {:>10.3} {:>19} {:>10.6} {:>7}",
            row.lag,
            report::format_match_count(row.matches, row.comparisons),
            row.rate,
            row.normalized_rate,
            format_null_band(row.null_band),
            row.null_band.max,
            report::format_null_flag(row.above_pointwise_band, row.above_null_envelope)
        );
    }
}

fn append_message_periodicity_summary(out: &mut String, messages: &[MessagePeriodicityReport]) {
    report::appendln!(out, "per-message strongest apparent rows");
    report::appendln!(
        out,
        "{:<6} {:>5} {:>8} {:>9} {:>7} {:>8} {:>11} {:>7}",
        "msg",
        "len",
        "best p",
        "p x83",
        "p flag",
        "best lag",
        "lag rate",
        "lag flag"
    );
    for message in messages {
        let period = strongest_period_row(&message.ioc_by_period);
        let lag = strongest_autocorrelation_row(&message.autocorrelation);
        report::appendln!(
            out,
            "{:<6} {:>5} {:>8} {:>9} {:>7} {:>8} {:>11} {:>7}",
            message.message_key,
            message.length,
            period.map_or_else(|| "none".to_owned(), |row| row.period.to_string()),
            period.map_or_else(
                || "n/a".to_owned(),
                |row| format!("{:.3}", row.normalized_ioc)
            ),
            period.map_or("n/a", |row| {
                report::format_null_flag(row.above_pointwise_band, row.above_null_envelope)
            }),
            lag.map_or_else(|| "none".to_owned(), |row| row.lag.to_string()),
            lag.map_or_else(|| "n/a".to_owned(), |row| format!("{:.6}", row.rate)),
            lag.map_or("n/a", |row| {
                report::format_null_flag(row.above_pointwise_band, row.above_null_envelope)
            })
        );
    }
}

fn append_kasiski_table(out: &mut String, label: &str, rows: &[KasiskiReport]) {
    report::appendln!(out, "{label}");
    report::appendln!(
        out,
        "{:>3} {:>9} {:>9} {:>9} {:>5} {:<28} {:<28} {:<28}",
        "n",
        "repeat",
        "occurs",
        "dist",
        "gcd",
        "top distances",
        "per-ngram gcds",
        "top factors"
    );
    for row in rows {
        report::appendln!(
            out,
            "{:>3} {:>9} {:>9} {:>9} {:>5} {:<28} {:<28} {:<28}",
            row.n,
            row.repeated_ngram_kinds,
            row.repeated_occurrences,
            row.distance_count,
            row.all_distance_gcd,
            format_pair_counts(&row.top_distances),
            format_pair_counts(&row.ngram_gcd_histogram),
            format_top_factor_counts(&row.factor_counts)
        );
    }
}

fn append_message_kasiski_summary(out: &mut String, messages: &[MessagePeriodicityReport]) {
    report::appendln!(out, "per-message Kasiski summaries");
    report::appendln!(
        out,
        "{:<6} {:>3} {:>9} {:>9} {:>9} {:>5} {:<28}",
        "msg",
        "n",
        "repeat",
        "occurs",
        "dist",
        "gcd",
        "top factors"
    );
    for message in messages {
        for row in &message.kasiski {
            report::appendln!(
                out,
                "{:<6} {:>3} {:>9} {:>9} {:>9} {:>5} {:<28}",
                message.message_key,
                row.n,
                row.repeated_ngram_kinds,
                row.repeated_occurrences,
                row.distance_count,
                row.all_distance_gcd,
                format_top_factor_counts(&row.factor_counts)
            );
        }
    }
}

fn strongest_period_row(rows: &[PeriodIocRow]) -> Option<&PeriodIocRow> {
    rows.iter()
        .max_by(|left, right| left.normalized_ioc.total_cmp(&right.normalized_ioc))
}

fn strongest_autocorrelation_row(rows: &[AutocorrelationRow]) -> Option<&AutocorrelationRow> {
    rows.iter()
        .max_by(|left, right| left.rate.total_cmp(&right.rate))
}

fn format_null_band(band: NullBand) -> String {
    format!("{:.3}..{:.3}", band.q025, band.q975)
}

fn format_pair_counts(pairs: &[(usize, usize)]) -> String {
    if pairs.is_empty() {
        return "none".to_owned();
    }
    pairs
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_top_factor_counts(pairs: &[(usize, usize)]) -> String {
    let mut sorted = pairs
        .iter()
        .copied()
        .filter(|(_factor, count)| *count > 0)
        .collect::<Vec<_>>();
    sorted.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    sorted.truncate(8);
    format_pair_counts(&sorted)
}
