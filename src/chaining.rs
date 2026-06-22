//! Experiment 7B: alphabet-chaining as a calibrated structural signature.
//!
//! The procedure here is intentionally narrow. For a candidate period `p`, each
//! message is split into columns by `position % p`, resetting the column counter
//! at message boundaries. For every adjacent column pair, including the last
//! column back to column zero, the code chooses the additive alphabet shift that
//! maximizes circular distribution overlap between the two column histograms.
//!
//! The measured signature is:
//!
//! - mean best shifted distribution overlap;
//! - mean pairwise alignment quality, defined as the margin between the best
//!   and second-best shifted overlaps;
//! - the around-cycle residual, `sum(shifts) mod alphabet_size`; and
//! - `chain_score = mean_alignment_quality * cycle_closure`, where
//!   `cycle_closure` is `1.0` at zero residual and decreases linearly to zero at
//!   the maximum circular residual distance.
//!
//! A high score therefore requires both identifiable pairwise shifts and a
//! closed additive cycle. Uniform columns, or columns whose best shifts are not
//! distinguishable from nearby alternatives, have low quality even when some
//! shift can always be chosen.
//!
//! The calibration controls are generated, not reverse-engineered from the eye
//! data. The known-succeed fixture is a Vigenere stream over the same 83-symbol
//! reading alphabet with period `p`; its columns are additive shifts of the same
//! irregular source distribution. The known-fail fixture applies an independent
//! random substitution to each period column, so the columns share the source
//! frequency multiset without being circular shifts of one another. A
//! within-column shuffled copy of the failure fixture is also measured; because
//! this chaining signature uses only column distributions, that shuffle is an
//! invariance check rather than a separate order-sensitive signal.

use crate::null::SplitMix64;
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::trigram::TrigramValue;

/// Default deterministic Monte-Carlo seed for Experiment 7B.
pub const DEFAULT_SEED: u64 = 0x6368_6169_6e37_6221;
/// Default Monte-Carlo trial count for CLI calibration.
pub const DEFAULT_TRIALS: usize = 256;
/// Default minimum candidate period.
pub const DEFAULT_MIN_PERIOD: usize = 2;
/// Default maximum candidate period.
pub const DEFAULT_MAX_PERIOD: usize = 16;
/// Alphabet size for the accepted honeycomb reading-layer stream (`0..=82`).
pub const DEFAULT_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Configuration for Experiment 7B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of generated control fixtures sampled per candidate period.
    pub trials: usize,
    /// Smallest candidate period to test, inclusive.
    pub min_period: usize,
    /// Largest candidate period to test, inclusive.
    pub max_period: usize,
    /// Additive alphabet size used by the chaining procedure.
    pub alphabet_size: usize,
}

impl Default for ChainingConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            min_period: DEFAULT_MIN_PERIOD,
            max_period: DEFAULT_MAX_PERIOD,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        }
    }
}

/// Error returned by the Experiment 7B chaining battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainingError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// Candidate period range was empty or included the degenerate period one.
    InvalidPeriodRange {
        /// Requested minimum period.
        min_period: usize,
        /// Requested maximum period.
        max_period: usize,
    },
    /// The additive alphabet must fit in the base-5 trigram value type.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
    /// A measured stream contained a value outside the configured alphabet.
    ValueOutsideAlphabet {
        /// Offending reading-layer value.
        value: u8,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A deterministic control fixture could not be generated.
    ControlConstructionFailed,
    /// A random draw bound did not fit the PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for ChainingError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

/// Best additive alignment found for one adjacent period-column pair.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairAlignment {
    /// Source column index.
    pub from_column: usize,
    /// Destination column index.
    pub to_column: usize,
    /// Additive shift relating the source distribution to the destination:
    /// `source[x]` is compared with `destination[x + shift]`.
    pub shift: usize,
    /// Best circular distribution overlap, in `0.0..=1.0`.
    pub best_overlap: f64,
    /// Second-best circular distribution overlap, in `0.0..=1.0`.
    pub second_overlap: f64,
    /// Alignment quality: `best_overlap - second_overlap`.
    pub quality: f64,
}

/// Complete chaining-consistency signature for one period.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingSignature {
    /// Candidate period.
    pub period: usize,
    /// Additive alphabet size.
    pub alphabet_size: usize,
    /// Total symbols measured.
    pub total_symbols: usize,
    /// Number of symbols assigned to each period column.
    pub column_lengths: Vec<usize>,
    /// Mean of best shifted distribution overlaps across adjacent pairs.
    pub mean_best_overlap: f64,
    /// Mean pairwise alignment quality across adjacent pairs.
    pub mean_alignment_quality: f64,
    /// Raw around-cycle residual, `sum(shifts) mod alphabet_size`.
    pub cycle_residual: usize,
    /// Circular distance from residual to identity.
    pub cycle_residual_distance: usize,
    /// Linear closure factor in `0.0..=1.0`.
    pub cycle_closure: f64,
    /// Scalar signature combining quality and cycle closure.
    pub chain_score: f64,
    /// Pairwise alignments around the full period cycle.
    pub pair_alignments: Vec<PairAlignment>,
}

/// Monte-Carlo band for a floating-point statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalarBand {
    /// Number of samples in the band.
    pub trials: usize,
    /// Smallest sampled value.
    pub min: f64,
    /// Mean sampled value.
    pub mean: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

/// Monte-Carlo band for the integer cycle-residual distance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResidualBand {
    /// Number of samples in the band.
    pub trials: usize,
    /// Smallest sampled residual distance.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled residual distance.
    pub max: usize,
}

/// Calibration bands for one generated fixture family.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationBands {
    /// Mean best shifted-overlap band.
    pub mean_best_overlap: ScalarBand,
    /// Mean alignment-quality band.
    pub mean_alignment_quality: ScalarBand,
    /// Around-cycle residual-distance band.
    pub cycle_residual_distance: ResidualBand,
    /// Composite chain-score band.
    pub chain_score: ScalarBand,
}

/// Where the real eye signature falls relative to the calibrated controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainingClassification {
    /// Succeed/fail control bands overlap, so no calibrated comparison is valid.
    CalibrationOverlaps,
    /// The real score lands inside the known-fail control band.
    MatchesKnownFail,
    /// The real score lands inside the known-succeed control band.
    MatchesKnownSucceed,
    /// The real score lies between the separated fail and succeed bands.
    BetweenBands,
}

/// Real-vs-control row for one candidate period.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingPeriodReport {
    /// Candidate period.
    pub period: usize,
    /// Real eye signature under the accepted honeycomb order.
    pub real: ChainingSignature,
    /// Known-succeed Vigenere calibration bands.
    pub succeed: CalibrationBands,
    /// Known-fail independent substitution calibration bands.
    pub fail: CalibrationBands,
    /// Within-column shuffled known-fail calibration bands.
    pub shuffled_fail: CalibrationBands,
    /// Whether the fail and succeed score bands are separated.
    pub score_bands_separated: bool,
    /// Real-eye placement relative to the calibrated score bands.
    pub classification: ChainingClassification,
}

/// Complete Experiment 7B report for the accepted eye stream.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingReport {
    /// Configuration used for the run.
    pub config: ChainingConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of reading-layer symbols across messages.
    pub total_length: usize,
    /// Per-period rows.
    pub rows: Vec<ChainingPeriodReport>,
}

/// Runs Experiment 7B on the verified eye corpus.
///
/// # Errors
/// Returns [`ChainingError`] when the corpus cannot be reconstructed, when the
/// accepted reading order is incompatible with a grid, or when the
/// configuration is invalid.
pub fn run_chaining(config: ChainingConfig) -> Result<ChainingReport, ChainingError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::orders::GlyphGrid::message_key)
        .collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

/// Computes the chaining signature for caller-supplied message values.
///
/// This is the single procedure used by the real-eye stream and every control
/// fixture: split by period within each message, compare adjacent column
/// distributions by circular additive shifts, and close the shift cycle.
///
/// # Errors
/// Returns [`ChainingError`] if the period or alphabet is invalid, or if any
/// stream value is outside the configured alphabet.
pub fn chaining_signature(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    alphabet_size: usize,
) -> Result<ChainingSignature, ChainingError> {
    validate_period_and_alphabet(period, alphabet_size)?;
    let columns = split_columns(message_values, period, alphabet_size)?;
    let column_lengths = columns
        .iter()
        .map(|column| column.total)
        .collect::<Vec<_>>();
    let total_symbols = column_lengths.iter().sum();

    let mut pair_alignments = Vec::with_capacity(period);
    for from_column in 0..period {
        let to_column = (from_column + 1) % period;
        let Some(left) = columns.get(from_column) else {
            return Err(ChainingError::ControlConstructionFailed);
        };
        let Some(right) = columns.get(to_column) else {
            return Err(ChainingError::ControlConstructionFailed);
        };
        pair_alignments.push(best_pair_alignment(
            from_column,
            to_column,
            left,
            right,
            alphabet_size,
        ));
    }

    let pair_count = pair_alignments.len();
    let mean_best_overlap = mean_f64(pair_alignments.iter().map(|pair| pair.best_overlap));
    let mean_alignment_quality = mean_f64(pair_alignments.iter().map(|pair| pair.quality));
    let shift_sum = pair_alignments
        .iter()
        .map(|pair| pair.shift)
        .fold(0usize, |sum, shift| (sum + shift) % alphabet_size);
    let cycle_residual = shift_sum % alphabet_size;
    let cycle_residual_distance = cycle_distance(cycle_residual, alphabet_size);
    let cycle_closure = cycle_closure(cycle_residual_distance, alphabet_size);
    let chain_score = mean_alignment_quality * cycle_closure;

    if pair_count == 0 {
        return Err(ChainingError::InvalidPeriodRange {
            min_period: period,
            max_period: period,
        });
    }

    Ok(ChainingSignature {
        period,
        alphabet_size,
        total_symbols,
        column_lengths,
        mean_best_overlap,
        mean_alignment_quality,
        cycle_residual,
        cycle_residual_distance,
        cycle_closure,
        chain_score,
        pair_alignments,
    })
}

fn report_from_message_values(
    config: ChainingConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ChainingReport, ChainingError> {
    validate_config(config)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let mut rng = SplitMix64::new(config.seed);
    let source_profile = SourceProfile::new(config.alphabet_size);

    let mut rows = Vec::new();
    for period in config.min_period..=config.max_period {
        let real = chaining_signature(message_values, period, config.alphabet_size)?;
        let calibration = calibrate_period(config, period, &lengths, &source_profile, &mut rng)?;
        let score_bands_separated = calibration.fail.chain_score.q975
            < calibration.succeed.chain_score.q025
            && calibration.shuffled_fail.chain_score.q975 < calibration.succeed.chain_score.q025;
        let classification = classify_real_score(
            real.chain_score,
            &calibration.succeed.chain_score,
            &calibration.fail.chain_score,
            &calibration.shuffled_fail.chain_score,
            score_bands_separated,
        );
        rows.push(ChainingPeriodReport {
            period,
            real,
            succeed: calibration.succeed,
            fail: calibration.fail,
            shuffled_fail: calibration.shuffled_fail,
            score_bands_separated,
            classification,
        });
    }

    Ok(ChainingReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        rows,
    })
}

fn validate_config(config: ChainingConfig) -> Result<(), ChainingError> {
    if config.trials == 0 {
        return Err(ChainingError::ZeroTrials);
    }
    validate_period_range(config.min_period, config.max_period)?;
    validate_alphabet(config.alphabet_size)
}

fn validate_period_range(min_period: usize, max_period: usize) -> Result<(), ChainingError> {
    if min_period < 2 || min_period > max_period {
        return Err(ChainingError::InvalidPeriodRange {
            min_period,
            max_period,
        });
    }
    Ok(())
}

fn validate_period_and_alphabet(period: usize, alphabet_size: usize) -> Result<(), ChainingError> {
    validate_period_range(period, period)?;
    validate_alphabet(alphabet_size)
}

fn validate_alphabet(alphabet_size: usize) -> Result<(), ChainingError> {
    if alphabet_size == 0 || alphabet_size > 125 {
        return Err(ChainingError::InvalidAlphabetSize { alphabet_size });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ColumnCounts {
    counts: Vec<usize>,
    total: usize,
}

fn split_columns(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    alphabet_size: usize,
) -> Result<Vec<ColumnCounts>, ChainingError> {
    let mut columns = (0..period)
        .map(|_column| ColumnCounts {
            counts: vec![0; alphabet_size],
            total: 0,
        })
        .collect::<Vec<_>>();

    for values in message_values {
        for (position, value) in values.iter().copied().enumerate() {
            let raw = usize::from(value.get());
            if raw >= alphabet_size {
                return Err(ChainingError::ValueOutsideAlphabet {
                    value: value.get(),
                    alphabet_size,
                });
            }
            let column_index = position % period;
            let Some(column) = columns.get_mut(column_index) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(count) = column.counts.get_mut(raw) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            *count += 1;
            column.total += 1;
        }
    }

    Ok(columns)
}

fn best_pair_alignment(
    from_column: usize,
    to_column: usize,
    left: &ColumnCounts,
    right: &ColumnCounts,
    alphabet_size: usize,
) -> PairAlignment {
    let mut best_shift = 0usize;
    let mut best_overlap = f64::NEG_INFINITY;
    let mut second_overlap = f64::NEG_INFINITY;

    for shift in 0..alphabet_size {
        let overlap = shifted_overlap(left, right, shift, alphabet_size);
        if overlap > best_overlap {
            second_overlap = best_overlap;
            best_overlap = overlap;
            best_shift = shift;
        } else if overlap > second_overlap {
            second_overlap = overlap;
        }
    }

    if !second_overlap.is_finite() {
        second_overlap = best_overlap.max(0.0);
    }
    let best_overlap = best_overlap.max(0.0);
    let second_overlap = second_overlap.max(0.0);
    PairAlignment {
        from_column,
        to_column,
        shift: best_shift,
        best_overlap,
        second_overlap,
        quality: (best_overlap - second_overlap).max(0.0),
    }
}

fn shifted_overlap(
    left: &ColumnCounts,
    right: &ColumnCounts,
    shift: usize,
    alphabet_size: usize,
) -> f64 {
    if left.total == 0 || right.total == 0 {
        return 0.0;
    }
    let left_total = left.total as f64;
    let right_total = right.total as f64;
    let mut overlap = 0.0;
    for (symbol, &left_count) in left.counts.iter().enumerate() {
        let right_index = (symbol + shift) % alphabet_size;
        if let Some(&right_count) = right.counts.get(right_index) {
            let left_probability = left_count as f64 / left_total;
            let right_probability = right_count as f64 / right_total;
            overlap += left_probability.min(right_probability);
        }
    }
    overlap
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceProfile {
    population: Vec<usize>,
    stride: usize,
}

impl SourceProfile {
    fn new(alphabet_size: usize) -> Self {
        let weights = source_weights(alphabet_size);
        let max_weight = weights.iter().copied().max().unwrap_or(1);
        let mut population = Vec::new();
        for rank in 0..max_weight {
            for (symbol, &weight) in weights.iter().enumerate() {
                if rank < weight {
                    population.push(symbol);
                }
            }
        }
        let stride = coprime_stride(population.len(), alphabet_size);
        Self { population, stride }
    }

    fn symbol_at(&self, row: usize, offset: usize) -> Result<usize, ChainingError> {
        if self.population.is_empty() {
            return Err(ChainingError::ControlConstructionFailed);
        }
        let index = (row.wrapping_mul(self.stride).wrapping_add(offset)) % self.population.len();
        self.population
            .get(index)
            .copied()
            .ok_or(ChainingError::ControlConstructionFailed)
    }
}

fn source_weights(alphabet_size: usize) -> Vec<usize> {
    (0..alphabet_size)
        .map(|symbol| {
            let mixed = stateless_splitmix(symbol as u64 ^ 0x9f6d_62f1_4d35_24ab);
            3 + (mixed % 47) as usize
        })
        .collect()
}

fn stateless_splitmix(seed: u64) -> u64 {
    let mut value = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn coprime_stride(total: usize, alphabet_size: usize) -> usize {
    let mut stride = alphabet_size.max(3);
    if stride.is_multiple_of(2) {
        stride += 1;
    }
    while gcd(stride, total) != 1 {
        stride += 2;
    }
    stride
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Debug, PartialEq)]
struct CalibrationSamples {
    succeed: Vec<ChainingSignature>,
    fail: Vec<ChainingSignature>,
    shuffled_fail: Vec<ChainingSignature>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct PeriodCalibration {
    succeed: CalibrationBands,
    fail: CalibrationBands,
    shuffled_fail: CalibrationBands,
}

fn calibrate_period(
    config: ChainingConfig,
    period: usize,
    lengths: &[usize],
    source_profile: &SourceProfile,
    rng: &mut SplitMix64,
) -> Result<PeriodCalibration, ChainingError> {
    let mut samples = CalibrationSamples {
        succeed: Vec::with_capacity(config.trials),
        fail: Vec::with_capacity(config.trials),
        shuffled_fail: Vec::with_capacity(config.trials),
    };

    for _trial in 0..config.trials {
        let controls =
            build_control_fixtures(lengths, period, config.alphabet_size, source_profile, rng)?;
        samples.succeed.push(chaining_signature(
            &controls.succeed,
            period,
            config.alphabet_size,
        )?);
        samples.fail.push(chaining_signature(
            &controls.fail,
            period,
            config.alphabet_size,
        )?);
        samples.shuffled_fail.push(chaining_signature(
            &controls.shuffled_fail,
            period,
            config.alphabet_size,
        )?);
    }

    Ok(PeriodCalibration {
        succeed: calibration_bands(&samples.succeed),
        fail: calibration_bands(&samples.fail),
        shuffled_fail: calibration_bands(&samples.shuffled_fail),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlFixtures {
    succeed: Vec<Vec<TrigramValue>>,
    fail: Vec<Vec<TrigramValue>>,
    shuffled_fail: Vec<Vec<TrigramValue>>,
}

fn build_control_fixtures(
    lengths: &[usize],
    period: usize,
    alphabet_size: usize,
    source_profile: &SourceProfile,
    rng: &mut SplitMix64,
) -> Result<ControlFixtures, ChainingError> {
    let key = random_key(period, alphabet_size, rng)?;
    let substitutions = random_column_substitutions(period, alphabet_size, rng)?;
    let source_offset = random_index_below(source_profile.population.len(), rng)?;
    let mut column_rows = vec![0usize; period];
    let mut succeed = Vec::new();
    let mut fail = Vec::new();

    for &length in lengths {
        let mut succeed_message = Vec::with_capacity(length);
        let mut fail_message = Vec::with_capacity(length);
        for position in 0..length {
            let column = position % period;
            let Some(row) = column_rows.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let plain = source_profile.symbol_at(*row, source_offset)?;
            *row += 1;

            let Some(&shift) = key.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let succeed_raw = (plain + shift) % alphabet_size;
            succeed_message.push(trigram_from_usize(succeed_raw, alphabet_size)?);

            let Some(substitution) = substitutions.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(&fail_raw) = substitution.get(plain) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            fail_message.push(trigram_from_usize(fail_raw, alphabet_size)?);
        }
        succeed.push(succeed_message);
        fail.push(fail_message);
    }

    let shuffled_fail = shuffle_within_period_columns(&fail, period, rng)?;
    Ok(ControlFixtures {
        succeed,
        fail,
        shuffled_fail,
    })
}

fn random_key(
    period: usize,
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, ChainingError> {
    let mut key = Vec::with_capacity(period);
    for _column in 0..period {
        key.push(random_index_below(alphabet_size, rng)?);
    }
    Ok(key)
}

fn random_column_substitutions(
    period: usize,
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<usize>>, ChainingError> {
    let mut substitutions = Vec::with_capacity(period);
    for _column in 0..period {
        let mut substitution = (0..alphabet_size).collect::<Vec<_>>();
        fisher_yates_usize(&mut substitution, rng)?;
        substitutions.push(substitution);
    }
    Ok(substitutions)
}

fn shuffle_within_period_columns(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ChainingError> {
    let mut columns = vec![Vec::new(); period];
    for values in message_values {
        for (position, value) in values.iter().copied().enumerate() {
            let column = position % period;
            let Some(slot) = columns.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            slot.push(value);
        }
    }
    for column in &mut columns {
        fisher_yates_trigram(column, rng)?;
    }

    let mut column_offsets = vec![0usize; period];
    let mut shuffled = Vec::with_capacity(message_values.len());
    for values in message_values {
        let mut message = Vec::with_capacity(values.len());
        for position in 0..values.len() {
            let column = position % period;
            let Some(offset) = column_offsets.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(column_values) = columns.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(value) = column_values.get(*offset).copied() else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            *offset += 1;
            message.push(value);
        }
        shuffled.push(message);
    }
    Ok(shuffled)
}

fn fisher_yates_usize(values: &mut [usize], rng: &mut SplitMix64) -> Result<(), ChainingError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

fn fisher_yates_trigram(
    values: &mut [TrigramValue],
    rng: &mut SplitMix64,
) -> Result<(), ChainingError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

fn random_index_below(bound: usize, rng: &mut SplitMix64) -> Result<usize, ChainingError> {
    let bound_u64 =
        u64::try_from(bound).map_err(|_error| ChainingError::RandomBoundTooLarge { bound })?;
    if bound_u64 == 0 {
        return Err(ChainingError::RandomBoundTooLarge { bound });
    }
    let rejection_threshold = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let draw = rng.next_u64();
        if draw < rejection_threshold {
            let index_u64 = draw % bound_u64;
            return usize::try_from(index_u64)
                .map_err(|_error| ChainingError::RandomBoundTooLarge { bound });
        }
    }
}

fn trigram_from_usize(value: usize, alphabet_size: usize) -> Result<TrigramValue, ChainingError> {
    let raw = u8::try_from(value)
        .map_err(|_error| ChainingError::InvalidAlphabetSize { alphabet_size })?;
    TrigramValue::new(raw).map_err(|_raw| ChainingError::InvalidAlphabetSize { alphabet_size })
}

fn calibration_bands(samples: &[ChainingSignature]) -> CalibrationBands {
    CalibrationBands {
        mean_best_overlap: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.mean_best_overlap)
                .collect::<Vec<_>>(),
        ),
        mean_alignment_quality: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.mean_alignment_quality)
                .collect::<Vec<_>>(),
        ),
        cycle_residual_distance: residual_band(
            &samples
                .iter()
                .map(|signature| signature.cycle_residual_distance)
                .collect::<Vec<_>>(),
        ),
        chain_score: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.chain_score)
                .collect::<Vec<_>>(),
        ),
    }
}

fn scalar_band(samples: &[f64]) -> ScalarBand {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    ScalarBand {
        trials: samples.len(),
        min: sorted.first().copied().unwrap_or(0.0),
        mean: mean_f64(samples.iter().copied()),
        q025: quantile_f64(&sorted, 25, 1_000),
        median: median_f64(&sorted),
        q975: quantile_f64(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or(0.0),
    }
}

fn residual_band(samples: &[usize]) -> ResidualBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    ResidualBand {
        trials: samples.len(),
        min: sorted.first().copied().unwrap_or_default(),
        q025: quantile_usize(&sorted, 25, 1_000),
        median: median_usize(&sorted),
        q975: quantile_usize(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn classify_real_score(
    real_score: f64,
    succeed: &ScalarBand,
    fail: &ScalarBand,
    shuffled_fail: &ScalarBand,
    bands_separated: bool,
) -> ChainingClassification {
    if !bands_separated {
        return ChainingClassification::CalibrationOverlaps;
    }
    let fail_ceiling = fail.q975.max(shuffled_fail.q975);
    if real_score <= fail_ceiling {
        ChainingClassification::MatchesKnownFail
    } else if real_score >= succeed.q025 {
        ChainingClassification::MatchesKnownSucceed
    } else {
        ChainingClassification::BetweenBands
    }
}

fn mean_f64(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut total = 0.0;
    let mut count = 0usize;
    for value in values {
        total += value;
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn median_f64(sorted: &[f64]) -> f64 {
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

fn median_usize(sorted: &[usize]) -> f64 {
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
            (Some(left), Some(right)) => f64::midpoint(left as f64, right as f64),
            _ => 0.0,
        }
    } else {
        sorted
            .get(middle)
            .copied()
            .map_or(0.0, |value| value as f64)
    }
}

fn quantile_f64(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or(0.0)
}

fn quantile_usize(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

fn cycle_distance(residual: usize, alphabet_size: usize) -> usize {
    let wrapped = residual % alphabet_size;
    wrapped.min(alphabet_size - wrapped)
}

fn cycle_closure(residual_distance: usize, alphabet_size: usize) -> f64 {
    let max_distance = alphabet_size / 2;
    if max_distance == 0 {
        1.0
    } else {
        1.0 - residual_distance as f64 / max_distance as f64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChainingClassification, ChainingConfig, SourceProfile, build_control_fixtures,
        chaining_signature, run_chaining,
    };
    use crate::null::SplitMix64;
    use crate::orders;
    use crate::trigram::TrigramValue;

    #[test]
    fn known_succeed_and_fail_controls_are_distinct_and_separated() {
        let lengths = [99, 103, 118, 102, 137, 124, 119, 120, 114];
        let period = 7;
        let alphabet_size = orders::READING_LAYER_ALPHABET_SIZE;
        let source = SourceProfile::new(alphabet_size);
        let mut rng = SplitMix64::new(0x5eed);
        let controls =
            build_control_fixtures(&lengths, period, alphabet_size, &source, &mut rng).unwrap();

        assert_ne!(controls.succeed, controls.fail);
        assert_ne!(controls.fail, controls.shuffled_fail);

        let succeed = chaining_signature(&controls.succeed, period, alphabet_size).unwrap();
        let fail = chaining_signature(&controls.fail, period, alphabet_size).unwrap();
        let shuffled = chaining_signature(&controls.shuffled_fail, period, alphabet_size).unwrap();

        assert_eq!(succeed.cycle_residual_distance, 0);
        assert!(succeed.chain_score > fail.chain_score);
        assert!(succeed.chain_score > shuffled.chain_score);
        assert_eq!(
            fail.mean_alignment_quality.to_bits(),
            shuffled.mean_alignment_quality.to_bits()
        );
        assert_eq!(fail.chain_score.to_bits(), shuffled.chain_score.to_bits());
    }

    #[test]
    fn multi_seed_calibration_bands_separate_for_candidate_periods() {
        let config = ChainingConfig {
            seed: 0x7171,
            trials: 64,
            min_period: 2,
            max_period: 10,
            alphabet_size: orders::READING_LAYER_ALPHABET_SIZE,
        };
        let report = run_chaining(config).unwrap();

        assert_eq!(report.rows.len(), 9);
        for row in &report.rows {
            assert!(
                row.score_bands_separated,
                "p={} succeed={:?} fail={:?} shuffled={:?}",
                row.period,
                row.succeed.chain_score,
                row.fail.chain_score,
                row.shuffled_fail.chain_score
            );
            assert!(row.fail.chain_score.q975 < row.succeed.chain_score.q025);
            assert!(row.shuffled_fail.chain_score.q975 < row.succeed.chain_score.q025);
        }
    }

    #[test]
    fn real_eye_scores_are_measured_against_the_fail_band() {
        let config = ChainingConfig {
            seed: 0x8888,
            trials: 64,
            min_period: 2,
            max_period: 8,
            alphabet_size: orders::READING_LAYER_ALPHABET_SIZE,
        };
        let report = run_chaining(config).unwrap();

        assert_eq!(report.order.name(), "standard36-u012-d012");
        assert_eq!(report.total_length, 1036);
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.classification == ChainingClassification::MatchesKnownFail),
            "{:?}",
            report
                .rows
                .iter()
                .map(|row| (row.period, row.real.chain_score, row.classification))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn out_of_alphabet_values_are_rejected() {
        let values = vec![vec![TrigramValue::new(83).unwrap(); 12]];
        let error = chaining_signature(&values, 2, 83).unwrap_err();
        assert!(matches!(
            error,
            super::ChainingError::ValueOutsideAlphabet {
                value: 83,
                alphabet_size: 83
            }
        ));
    }
}
