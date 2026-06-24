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

use crate::analysis;
use crate::glyph::Glyph;
use crate::null::SplitMix64;
use crate::orders::{
    self, GlyphGrid, GridError, ReadingOrder, count_message_lag_comparisons,
    count_message_lag_matches, glyph_messages_from_values, read_corpus_message_values,
};
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
        global_ioc_envelope_max: quantile_from_samples(&global_ioc_maxima, Quantile::Max),
        global_autocorrelation_envelope_max: quantile_from_samples(
            &global_autocorrelation_maxima,
            Quantile::Max,
        ),
        messages,
    })
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
            .map(|samples| null_band(samples))
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

fn null_band(samples: &[f64]) -> NullBand {
    NullBand {
        trials: samples.len(),
        min: quantile_from_samples(samples, Quantile::Min),
        q025: quantile_from_samples(samples, Quantile::Q025),
        median: quantile_from_samples(samples, Quantile::Median),
        q975: quantile_from_samples(samples, Quantile::Q975),
        max: quantile_from_samples(samples, Quantile::Max),
    }
}

#[derive(Clone, Copy)]
enum Quantile {
    Min,
    Q025,
    Median,
    Q975,
    Max,
}

fn quantile_from_samples(samples: &[f64], quantile: Quantile) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    quantile_from_sorted(&sorted, quantile)
}

fn quantile_from_sorted(sorted: &[f64], quantile: Quantile) -> f64 {
    match quantile {
        Quantile::Min => sorted.first().copied().unwrap_or(0.0),
        Quantile::Q025 => sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or(0.0),
        Quantile::Median => median(sorted),
        Quantile::Q975 => sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or(0.0),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

fn median(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left, right),
            _ => 0.0,
        }
    } else {
        sorted.get(middle).copied().unwrap_or(0.0)
    }
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
