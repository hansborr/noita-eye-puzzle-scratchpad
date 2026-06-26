//! Experiment 5A periodicity and autocorrelation battery.
//!
//! The battery runs over the accepted honeycomb reading-layer stream
//! (`standard36-u012-d012`) and compares apparent period/lag peaks with
//! deterministic same-shape uniform-random streams over the `0..=82`
//! reading-layer alphabet.
//!
//! Message boundaries are preserved throughout. Pooled period columns reset
//! the column counter at the start of each message, autocorrelation never forms
//! cross-message lag pairs, and Kasiski distances are aggregated only from
//! repeats found within individual messages.

use std::collections::BTreeMap;
use std::fmt;

use crate::analysis;
use crate::glyph::Glyph;
use crate::null::{F64Band, SplitMix64, f64_band};
use crate::orders::{
    self, GlyphGrid, GridError, ReadingOrder, count_message_lag_comparisons,
    count_message_lag_matches, glyph_messages_from_values, read_corpus_message_values,
};
use crate::report::{self, Report};
use crate::trigram::TrigramValue;

/// Default maximum candidate Friedman period.
pub const DEFAULT_MAX_PERIOD: usize = 32;
/// Default maximum autocorrelation lag.
pub const DEFAULT_MAX_LAG: usize = 64;
/// Default minimum Kasiski n-gram length.
pub const DEFAULT_MIN_NGRAM: usize = 2;
/// Default maximum Kasiski n-gram length.
pub const DEFAULT_MAX_NGRAM: usize = 5;
/// Default deterministic Monte-Carlo seed.
pub const DEFAULT_SEED: u64 = 0x6579_652d_7065_7235;
/// Default Monte-Carlo trial count.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Accepted reading-layer alphabet size for the honeycomb winner.
pub const DEFAULT_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

const TOP_KASISKI_ITEMS: usize = 12;
const MIN_RELIABLE_PERIODICITY_NULL_TRIALS: usize = 50;

/// Error returned by the periodicity battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeriodicityError {
    /// The verified corpus could not be reconstructed as grids.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required for a null band.
    ZeroTrials,
    /// Candidate period range was empty.
    ZeroMaxPeriod,
    /// Candidate lag range was empty.
    ZeroMaxLag,
    /// Kasiski n-gram range was invalid.
    InvalidNgramRange {
        /// Requested minimum n-gram length.
        min: usize,
        /// Requested maximum n-gram length.
        max: usize,
    },
    /// The null alphabet must fit in the base-5 trigram value type.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
}

impl fmt::Display for PeriodicityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::ZeroMaxPeriod => write!(f, "max period must be at least 1"),
            Self::ZeroMaxLag => write!(f, "max lag must be at least 1"),
            Self::InvalidNgramRange { min, max } => {
                write!(f, "invalid n-gram range {min}..={max}")
            }
            Self::InvalidAlphabetSize { alphabet_size } => {
                write!(
                    f,
                    "invalid null alphabet size {alphabet_size}; expected 1..=125"
                )
            }
        }
    }
}

impl std::error::Error for PeriodicityError {}

impl From<GridError> for PeriodicityError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

/// Configuration for Experiment 5A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodicityConfig {
    /// Explicit deterministic PRNG seed for the same-shape random null.
    pub seed: u64,
    /// Number of same-shape random streams to sample.
    pub trials: usize,
    /// Largest candidate Friedman period to test, inclusive.
    pub max_period: usize,
    /// Largest autocorrelation lag to test, inclusive.
    pub max_lag: usize,
    /// Smallest Kasiski repeated n-gram length.
    pub min_ngram: usize,
    /// Largest Kasiski repeated n-gram length.
    pub max_ngram: usize,
    /// Uniform null alphabet size. The accepted stream uses `83`.
    pub alphabet_size: usize,
}

impl Default for PeriodicityConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            max_period: DEFAULT_MAX_PERIOD,
            max_lag: DEFAULT_MAX_LAG,
            min_ngram: DEFAULT_MIN_NGRAM,
            max_ngram: DEFAULT_MAX_NGRAM,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        }
    }
}

/// Monte-Carlo band for one statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullBand {
    /// Number of same-shape random streams sampled.
    pub trials: usize,
    /// Smallest sampled value.
    pub min: f64,
    /// Lower pointwise 95% band edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% band edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

impl From<F64Band> for NullBand {
    fn from(band: F64Band) -> Self {
        // `NullBand` carries no `mean` field; the rest map directly.
        Self {
            trials: band.trials,
            min: band.min,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// One IoC-by-period row.
#[derive(Clone, Debug, PartialEq)]
pub struct PeriodIocRow {
    /// Candidate period.
    pub period: usize,
    /// Arithmetic mean of per-column `IoC` probabilities.
    pub mean_ioc: f64,
    /// `mean_ioc * alphabet_size`; a uniform stream is expected near `1.0`.
    pub normalized_ioc: f64,
    /// Pointwise null band for `normalized_ioc`.
    pub null_band: NullBand,
    /// Whether the row is above its pointwise null band.
    pub above_pointwise_band: bool,
    /// Whether the row is above the sampled report-wide null envelope.
    pub above_null_envelope: bool,
}

/// One autocorrelation lag row.
#[derive(Clone, Debug, PartialEq)]
pub struct AutocorrelationRow {
    /// Tested lag.
    pub lag: usize,
    /// Count of equality pairs `symbol[i] == symbol[i + lag]`.
    pub matches: usize,
    /// Count of comparable within-message pairs at this lag.
    pub comparisons: usize,
    /// Equality-pair rate.
    pub rate: f64,
    /// `rate * alphabet_size`; a uniform stream is expected near `1.0`.
    pub normalized_rate: f64,
    /// Pointwise null band for `rate`.
    pub null_band: NullBand,
    /// Whether the row is above its pointwise null band.
    pub above_pointwise_band: bool,
    /// Whether the row is above the sampled report-wide null envelope.
    pub above_null_envelope: bool,
}

/// Kasiski repeated-segment summary for one n-gram size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KasiskiReport {
    /// N-gram length in reading-layer symbols.
    pub n: usize,
    /// Number of distinct n-grams seen more than once.
    pub repeated_ngram_kinds: usize,
    /// Total occurrences belonging to repeated n-gram kinds.
    pub repeated_occurrences: usize,
    /// Number of pairwise within-message distances between repeated n-grams.
    pub distance_count: usize,
    /// Greatest common divisor across all collected distances, or zero when
    /// no distances were collected.
    pub all_distance_gcd: usize,
    /// Most common exact repeated-segment distances, sorted by count then distance.
    pub top_distances: Vec<(usize, usize)>,
    /// GCDs computed per repeated n-gram kind from its own distances.
    pub ngram_gcd_histogram: Vec<(usize, usize)>,
    /// Candidate factors `2..=max_period` and their divisible-distance counts.
    pub factor_counts: Vec<(usize, usize)>,
}

/// Periodicity battery for one message.
#[derive(Clone, Debug, PartialEq)]
pub struct MessagePeriodicityReport {
    /// Message key, such as `east1`.
    pub message_key: &'static str,
    /// Number of reading-layer symbols in this message.
    pub length: usize,
    /// Sampled report-wide null envelope for the IoC-by-period profile.
    pub period_null_envelope_max: f64,
    /// Sampled report-wide null envelope for the autocorrelation profile.
    pub autocorrelation_null_envelope_max: f64,
    /// IoC-by-period profile.
    pub ioc_by_period: Vec<PeriodIocRow>,
    /// Autocorrelation lag profile.
    pub autocorrelation: Vec<AutocorrelationRow>,
    /// Kasiski repeated-segment summaries.
    pub kasiski: Vec<KasiskiReport>,
}

/// Experiment 5A report for the accepted reading stream.
#[derive(Clone, Debug, PartialEq)]
pub struct PeriodicityReport {
    /// Configuration used for the run.
    pub config: PeriodicityConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total pooled length.
    pub pooled_length: usize,
    /// Sampled report-wide null envelope for the IoC-by-period battery.
    pub period_null_envelope_max: f64,
    /// Sampled report-wide null envelope for the autocorrelation battery.
    pub autocorrelation_null_envelope_max: f64,
    /// Pooled IoC-by-period profile.
    pub pooled_ioc_by_period: Vec<PeriodIocRow>,
    /// Pooled autocorrelation lag profile.
    pub pooled_autocorrelation: Vec<AutocorrelationRow>,
    /// Pooled Kasiski summaries, aggregating within-message distances only.
    pub pooled_kasiski: Vec<KasiskiReport>,
    /// Per-message reports.
    pub messages: Vec<MessagePeriodicityReport>,
}

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

/// Returns the accepted honeycomb reading order for the real stream.
#[must_use]
pub const fn accepted_honeycomb_order() -> ReadingOrder {
    orders::accepted_honeycomb_order()
}

/// Runs Experiment 5A on the verified corpus.
///
/// # Errors
/// Returns [`PeriodicityError`] when the corpus grids cannot be reconstructed
/// or the configuration is invalid.
pub fn run_periodicity(config: PeriodicityConfig) -> Result<PeriodicityReport, PeriodicityError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids.iter().map(GlyphGrid::message_key).collect();
    let order = accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

fn report_from_message_values(
    config: PeriodicityConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<PeriodicityReport, PeriodicityError> {
    validate_config(config)?;

    let lengths: Vec<usize> = message_values.iter().map(Vec::len).collect();
    let null = build_null_summary(config, &lengths)?;

    let pooled_length = lengths.iter().sum();
    let pooled_period_values =
        normalized_ioc_by_period_values(message_values, config.max_period, config.alphabet_size);
    let pooled_ioc_by_period = build_period_rows(
        &pooled_period_values,
        &null.pooled_ioc,
        null.global_ioc_envelope_max,
        config.alphabet_size,
    );
    let pooled_autocorrelation_values = autocorrelation_values(message_values, config.max_lag);
    let pooled_autocorrelation = build_autocorrelation_rows(
        message_values,
        &pooled_autocorrelation_values,
        &null.pooled_autocorrelation,
        null.global_autocorrelation_envelope_max,
        config.alphabet_size,
    );
    let pooled_kasiski = kasiski_reports_for_messages(
        message_values,
        config.min_ngram,
        config.max_ngram,
        config.max_period,
    );

    let mut messages = Vec::new();
    for ((key, values), message_null) in keys
        .iter()
        .copied()
        .zip(message_values)
        .zip(null.messages.iter())
    {
        let one_message = [values.clone()];
        let period_values =
            normalized_ioc_by_period_values(&one_message, config.max_period, config.alphabet_size);
        let ioc_by_period = build_period_rows(
            &period_values,
            &message_null.ioc,
            null.global_ioc_envelope_max,
            config.alphabet_size,
        );
        let autocorrelation_values = autocorrelation_values(&one_message, config.max_lag);
        let autocorrelation = build_autocorrelation_rows(
            &one_message,
            &autocorrelation_values,
            &message_null.autocorrelation,
            null.global_autocorrelation_envelope_max,
            config.alphabet_size,
        );
        let kasiski = kasiski_reports_for_messages(
            &one_message,
            config.min_ngram,
            config.max_ngram,
            config.max_period,
        );
        messages.push(MessagePeriodicityReport {
            message_key: key,
            length: values.len(),
            period_null_envelope_max: null.global_ioc_envelope_max,
            autocorrelation_null_envelope_max: null.global_autocorrelation_envelope_max,
            ioc_by_period,
            autocorrelation,
            kasiski,
        });
    }

    Ok(PeriodicityReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        pooled_length,
        period_null_envelope_max: null.global_ioc_envelope_max,
        autocorrelation_null_envelope_max: null.global_autocorrelation_envelope_max,
        pooled_ioc_by_period,
        pooled_autocorrelation,
        pooled_kasiski,
        messages,
    })
}

fn validate_config(config: PeriodicityConfig) -> Result<(), PeriodicityError> {
    if config.trials == 0 {
        return Err(PeriodicityError::ZeroTrials);
    }
    if config.max_period == 0 {
        return Err(PeriodicityError::ZeroMaxPeriod);
    }
    if config.max_lag == 0 {
        return Err(PeriodicityError::ZeroMaxLag);
    }
    if config.min_ngram == 0 || config.min_ngram > config.max_ngram {
        return Err(PeriodicityError::InvalidNgramRange {
            min: config.min_ngram,
            max: config.max_ngram,
        });
    }
    if config.alphabet_size == 0 || config.alphabet_size > 125 {
        return Err(PeriodicityError::InvalidAlphabetSize {
            alphabet_size: config.alphabet_size,
        });
    }
    Ok(())
}

#[derive(Debug)]
struct NullSummary {
    pooled_ioc: Vec<NullBand>,
    pooled_autocorrelation: Vec<NullBand>,
    global_ioc_envelope_max: f64,
    global_autocorrelation_envelope_max: f64,
    messages: Vec<MessageNullSummary>,
}

#[derive(Debug)]
struct MessageNullSummary {
    ioc: Vec<NullBand>,
    autocorrelation: Vec<NullBand>,
}

fn build_null_summary(
    config: PeriodicityConfig,
    lengths: &[usize],
) -> Result<NullSummary, PeriodicityError> {
    let mut rng = SplitMix64::new(config.seed);
    let mut pooled_ioc_samples = ProfileSamples::new(config.max_period);
    let mut pooled_autocorrelation_samples = ProfileSamples::new(config.max_lag);
    let mut global_ioc_maxima = Vec::new();
    let mut global_autocorrelation_maxima = Vec::new();
    let mut message_ioc_samples: Vec<ProfileSamples> = lengths
        .iter()
        .map(|_length| ProfileSamples::new(config.max_period))
        .collect();
    let mut message_autocorrelation_samples: Vec<ProfileSamples> = lengths
        .iter()
        .map(|_length| ProfileSamples::new(config.max_lag))
        .collect();

    for _trial in 0..config.trials {
        let generated = random_message_values_like(lengths, &mut rng, config.alphabet_size)?;
        let pooled_ioc_profile =
            normalized_ioc_by_period_values(&generated, config.max_period, config.alphabet_size);
        let pooled_autocorrelation_profile = autocorrelation_values(&generated, config.max_lag);
        let mut global_ioc_maximum = profile_maximum(&pooled_ioc_profile);
        let mut global_autocorrelation_maximum = profile_maximum(&pooled_autocorrelation_profile);

        pooled_ioc_samples.push_profile(&pooled_ioc_profile);
        pooled_autocorrelation_samples.push_profile(&pooled_autocorrelation_profile);

        for ((values, ioc_samples), autocorrelation_samples) in generated
            .iter()
            .zip(message_ioc_samples.iter_mut())
            .zip(message_autocorrelation_samples.iter_mut())
        {
            let one_message = [values.clone()];
            let ioc_profile = normalized_ioc_by_period_values(
                &one_message,
                config.max_period,
                config.alphabet_size,
            );
            let autocorrelation_profile = autocorrelation_values(&one_message, config.max_lag);
            global_ioc_maximum = global_ioc_maximum.max(profile_maximum(&ioc_profile));
            global_autocorrelation_maximum =
                global_autocorrelation_maximum.max(profile_maximum(&autocorrelation_profile));
            ioc_samples.push_profile(&ioc_profile);
            autocorrelation_samples.push_profile(&autocorrelation_profile);
        }
        global_ioc_maxima.push(global_ioc_maximum);
        global_autocorrelation_maxima.push(global_autocorrelation_maximum);
    }

    let messages = message_ioc_samples
        .into_iter()
        .zip(message_autocorrelation_samples)
        .map(|(ioc, autocorrelation)| MessageNullSummary {
            ioc: ioc.bands(),
            autocorrelation: autocorrelation.bands(),
        })
        .collect();

    Ok(NullSummary {
        pooled_ioc: pooled_ioc_samples.bands(),
        pooled_autocorrelation: pooled_autocorrelation_samples.bands(),
        global_ioc_envelope_max: sample_maximum(&global_ioc_maxima),
        global_autocorrelation_envelope_max: sample_maximum(&global_autocorrelation_maxima),
        messages,
    })
}

/// Largest value in `samples` under a [`f64::total_cmp`] sort (`0.0` when empty).
///
/// Reproduces the `max` quantile that the removed `quantile_from_samples` used
/// for the report-wide null envelope.
fn sample_maximum(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted.last().copied().unwrap_or(0.0)
}

fn profile_maximum(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}

#[derive(Debug)]
struct ProfileSamples {
    per_row: Vec<Vec<f64>>,
}

impl ProfileSamples {
    fn new(rows: usize) -> Self {
        Self {
            per_row: vec![Vec::new(); rows],
        }
    }

    fn push_profile(&mut self, values: &[f64]) {
        for (slot, &value) in self.per_row.iter_mut().zip(values) {
            slot.push(value);
        }
    }

    fn bands(&self) -> Vec<NullBand> {
        self.per_row
            .iter()
            .map(|samples| NullBand::from(f64_band(samples)))
            .collect()
    }
}

fn random_message_values_like(
    lengths: &[usize],
    rng: &mut SplitMix64,
    alphabet_size: usize,
) -> Result<Vec<Vec<TrigramValue>>, PeriodicityError> {
    let mut messages = Vec::new();
    let alphabet_size_u64 = alphabet_size as u64;
    for &length in lengths {
        let mut values = Vec::with_capacity(length);
        for _position in 0..length {
            let raw = rng.next_u64() % alphabet_size_u64;
            let value = TrigramValue::new(raw as u8)
                .map_err(|_raw| PeriodicityError::InvalidAlphabetSize { alphabet_size })?;
            values.push(value);
        }
        messages.push(values);
    }
    Ok(messages)
}

fn build_period_rows(
    normalized_ioc_values: &[f64],
    null_bands: &[NullBand],
    null_envelope_max: f64,
    alphabet_size: usize,
) -> Vec<PeriodIocRow> {
    normalized_ioc_values
        .iter()
        .copied()
        .enumerate()
        .zip(null_bands.iter().copied())
        .map(|((index, normalized_ioc), null_band)| {
            let period = index + 1;
            PeriodIocRow {
                period,
                mean_ioc: normalized_ioc / alphabet_size as f64,
                normalized_ioc,
                null_band,
                above_pointwise_band: normalized_ioc > null_band.q975,
                above_null_envelope: normalized_ioc > null_envelope_max,
            }
        })
        .collect()
}

fn build_autocorrelation_rows(
    message_values: &[Vec<TrigramValue>],
    rates: &[f64],
    null_bands: &[NullBand],
    null_envelope_max: f64,
    alphabet_size: usize,
) -> Vec<AutocorrelationRow> {
    rates
        .iter()
        .copied()
        .enumerate()
        .zip(null_bands.iter().copied())
        .map(|((index, rate), null_band)| {
            let lag = index + 1;
            let matches = count_message_lag_matches(message_values, lag);
            let comparisons = count_message_lag_comparisons(message_values, lag);
            AutocorrelationRow {
                lag,
                matches,
                comparisons,
                rate,
                normalized_rate: rate * alphabet_size as f64,
                null_band,
                above_pointwise_band: rate > null_band.q975,
                above_null_envelope: rate > null_envelope_max,
            }
        })
        .collect()
}

/// Computes normalized mean column `IoC` values for candidate periods.
///
/// Message boundaries reset the period column counter: column `0` in one
/// message is never joined to column `0` in another before computing a column
/// `IoC`. Each returned value is multiplied by `alphabet_size`, so an
/// independent uniform stream is expected near `1.0`.
#[must_use]
pub fn normalized_ioc_by_period_values(
    message_values: &[Vec<TrigramValue>],
    max_period: usize,
    alphabet_size: usize,
) -> Vec<f64> {
    let message_glyphs = glyph_messages_from_values(message_values);
    (1..=max_period)
        .map(|period| mean_column_ioc(&message_glyphs, period) * alphabet_size as f64)
        .collect()
}

fn mean_column_ioc(message_glyphs: &[Vec<Glyph>], period: usize) -> f64 {
    if period == 0 {
        return 0.0;
    }
    let mut ioc_total = 0.0;
    let mut column_count = 0usize;
    for glyphs in message_glyphs {
        let mut columns = vec![Vec::new(); period];
        for (position, &glyph) in glyphs.iter().enumerate() {
            let column = position % period;
            if let Some(values) = columns.get_mut(column) {
                values.push(glyph);
            }
        }
        ioc_total += columns
            .iter()
            .map(|column| analysis::index_of_coincidence(column))
            .sum::<f64>();
        column_count += period;
    }
    if column_count == 0 {
        0.0
    } else {
        ioc_total / column_count as f64
    }
}

/// Computes exact-symbol autocorrelation rates for lags `1..=max_lag`.
///
/// Message boundaries are preserved: a lag pair is counted only when both
/// positions are inside the same message.
#[must_use]
pub fn autocorrelation_values(message_values: &[Vec<TrigramValue>], max_lag: usize) -> Vec<f64> {
    (1..=max_lag)
        .map(|lag| {
            let comparisons = count_message_lag_comparisons(message_values, lag);
            if comparisons == 0 {
                0.0
            } else {
                count_message_lag_matches(message_values, lag) as f64 / comparisons as f64
            }
        })
        .collect()
}

fn kasiski_reports_for_messages(
    message_values: &[Vec<TrigramValue>],
    min_ngram: usize,
    max_ngram: usize,
    max_factor: usize,
) -> Vec<KasiskiReport> {
    (min_ngram..=max_ngram)
        .map(|n| kasiski_report_for_messages(message_values, n, max_factor))
        .collect()
}

fn kasiski_report_for_messages(
    message_values: &[Vec<TrigramValue>],
    n: usize,
    max_factor: usize,
) -> KasiskiReport {
    let mut repeated_ngram_kinds = 0;
    let mut repeated_occurrences = 0;
    let mut distances = Vec::new();
    let mut ngram_gcd_counts = BTreeMap::new();

    for values in message_values {
        let partial = kasiski_distances_for_values(values, n);
        repeated_ngram_kinds += partial.repeated_ngram_kinds;
        repeated_occurrences += partial.repeated_occurrences;
        for gcd in partial.ngram_gcds {
            *ngram_gcd_counts.entry(gcd).or_default() += 1;
        }
        distances.extend(partial.distances);
    }

    let distance_count = distances.len();
    let all_distance_gcd = gcd_all(distances.iter().copied());
    let top_distances = top_histogram_items(&histogram_usize(&distances), TOP_KASISKI_ITEMS);
    let ngram_gcd_histogram = top_histogram_items(&ngram_gcd_counts, TOP_KASISKI_ITEMS);
    let factor_counts = factor_counts(&distances, max_factor);

    KasiskiReport {
        n,
        repeated_ngram_kinds,
        repeated_occurrences,
        distance_count,
        all_distance_gcd,
        top_distances,
        ngram_gcd_histogram,
        factor_counts,
    }
}

#[derive(Debug)]
struct KasiskiDistances {
    repeated_ngram_kinds: usize,
    repeated_occurrences: usize,
    distances: Vec<usize>,
    ngram_gcds: Vec<usize>,
}

fn kasiski_distances_for_values(values: &[TrigramValue], n: usize) -> KasiskiDistances {
    let mut occurrences: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    if n == 0 || n > values.len() {
        return KasiskiDistances {
            repeated_ngram_kinds: 0,
            repeated_occurrences: 0,
            distances: Vec::new(),
            ngram_gcds: Vec::new(),
        };
    }

    for (position, window) in values.windows(n).enumerate() {
        let key = window.iter().map(|value| value.get()).collect();
        occurrences.entry(key).or_default().push(position);
    }

    let mut repeated_ngram_kinds = 0;
    let mut repeated_occurrences = 0;
    let mut distances = Vec::new();
    let mut ngram_gcds = Vec::new();

    for positions in occurrences.values() {
        if positions.len() < 2 {
            continue;
        }
        repeated_ngram_kinds += 1;
        repeated_occurrences += positions.len();

        let mut local_distances = Vec::new();
        for (left_index, &left) in positions.iter().enumerate() {
            for &right in positions.iter().skip(left_index + 1) {
                let distance = right.saturating_sub(left);
                if distance > 0 {
                    distances.push(distance);
                    local_distances.push(distance);
                }
            }
        }
        let local_gcd = gcd_all(local_distances);
        if local_gcd > 0 {
            ngram_gcds.push(local_gcd);
        }
    }

    KasiskiDistances {
        repeated_ngram_kinds,
        repeated_occurrences,
        distances,
        ngram_gcds,
    }
}

fn factor_counts(distances: &[usize], max_factor: usize) -> Vec<(usize, usize)> {
    (2..=max_factor)
        .map(|factor| {
            let count = distances
                .iter()
                .filter(|&&distance| distance.is_multiple_of(factor))
                .count();
            (factor, count)
        })
        .collect()
}

fn histogram_usize(values: &[usize]) -> BTreeMap<usize, usize> {
    let mut counts = BTreeMap::new();
    for &value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn top_histogram_items(histogram: &BTreeMap<usize, usize>, limit: usize) -> Vec<(usize, usize)> {
    let mut items: Vec<(usize, usize)> = histogram
        .iter()
        .map(|(&value, &count)| (value, count))
        .collect();
    items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    items.truncate(limit);
    items
}

fn gcd_all(values: impl IntoIterator<Item = usize>) -> usize {
    let mut current = 0;
    for value in values {
        current = if current == 0 {
            value
        } else {
            gcd(current, value)
        };
    }
    current
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::{
        PeriodicityConfig, PeriodicityError, accepted_honeycomb_order, report_from_message_values,
        run_periodicity,
    };
    use crate::trigram::TrigramValue;

    #[test]
    fn fixed_period_fixture_clears_null_band() {
        let mut values = Vec::new();
        for position in 0..260 {
            let value = u8::try_from(position % 7).unwrap();
            values.push(TrigramValue::new(value).unwrap());
        }
        let config = PeriodicityConfig {
            seed: 0x5a17,
            trials: 128,
            max_period: 12,
            max_lag: 16,
            min_ngram: 3,
            max_ngram: 3,
            alphabet_size: 83,
        };
        let report =
            report_from_message_values(config, accepted_honeycomb_order(), &["fixture"], &[values])
                .unwrap();

        let period_7 = report
            .pooled_ioc_by_period
            .iter()
            .find(|row| row.period == 7)
            .unwrap();
        assert!(period_7.above_null_envelope);
        assert!(period_7.normalized_ioc > 80.0);

        let lag_7 = report
            .pooled_autocorrelation
            .iter()
            .find(|row| row.lag == 7)
            .unwrap();
        assert!(lag_7.above_null_envelope);
        assert!((lag_7.rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn real_honeycomb_stream_has_no_familywise_period_or_lag_spike() {
        let report = run_periodicity(PeriodicityConfig {
            seed: 0x6579_652d_7465_7374,
            trials: 256,
            max_period: 32,
            max_lag: 64,
            min_ngram: 3,
            max_ngram: 5,
            alphabet_size: 83,
        })
        .unwrap();

        assert!(
            report
                .pooled_ioc_by_period
                .iter()
                .all(|row| !row.above_null_envelope)
        );
        assert!(
            report
                .pooled_autocorrelation
                .iter()
                .all(|row| !row.above_null_envelope)
        );
        assert!(report.messages.iter().all(|message| {
            message
                .ioc_by_period
                .iter()
                .all(|row| !row.above_null_envelope)
                && message
                    .autocorrelation
                    .iter()
                    .all(|row| !row.above_null_envelope)
        }));
    }

    #[test]
    fn kasiski_distances_record_pairwise_gcd_structure() {
        let values = [1, 2, 3, 1, 2, 4, 1, 2]
            .into_iter()
            .map(|value| TrigramValue::new(value).unwrap())
            .collect::<Vec<_>>();
        let report = super::kasiski_report_for_messages(&[values], 2, 8);

        assert_eq!(report.repeated_ngram_kinds, 1);
        assert_eq!(report.repeated_occurrences, 3);
        assert_eq!(report.distance_count, 3);
        assert_eq!(report.all_distance_gcd, 3);
        assert_eq!(report.top_distances, vec![(3, 2), (6, 1)]);
        assert!(report.factor_counts.contains(&(3, 3)));
        assert!(report.factor_counts.contains(&(6, 1)));
    }

    #[test]
    fn invalid_config_is_rejected() {
        let config = PeriodicityConfig {
            trials: 0,
            ..PeriodicityConfig::default()
        };
        assert_eq!(run_periodicity(config), Err(PeriodicityError::ZeroTrials));
    }
}
