//! Experiment 2 — generation-pipeline artifact test.
//!
//! The community's headline statistics (contiguous `0..=82` range, zero
//! adjacency, the distance-4 spike) all describe the *reading* layer after the
//! honeycomb walk. Experiment 2 asks a prior question: are those features a
//! by-product of the deterministic base-7 *generation* pipeline (a fixed 64-bit
//! integer expanded in base 7, minus one), rather than evidence of an enciphered
//! plaintext?
//!
//! This module answers it two ways, both routed through the real
//! [`crate::generator`] decode:
//!
//! 1. [`run_pipeline_null`] — the **structure-matched null**. It rebuilds the
//!    verified grids but fills their cells with orientations harvested from
//!    decoding random 64-bit integers whose per-pair base-7 lengths match the
//!    real message blocks, then runs the identical standard-36 reading-order
//!    search as [`crate::null`]. Sub-22-symbol blocks have independent uniform
//!    base-7 digits after conditioning on emitted orientations; 22-symbol blocks
//!    preserve the real `u64` ceiling, so this is an actual storage-pipeline null
//!    rather than a mathematically identical copy of the uniform-orientation
//!    null. Running it confirms empirically that the base-7 pipeline
//!    manufactures *no* reading-layer contiguity: the `0..=82` range essentially
//!    never appears, just as it does not for uniform cells.
//!
//! 2. [`input_randomness_report`] — the **negative control**. Genuine random
//!    integers of the same magnitude are wildly inconsistent with the real
//!    engine inputs: they decode to hundreds of `-1` control symbols and
//!    hundreds of delimiters per corpus, whereas the real messages contain zero
//!    `-1` and only 86 delimiters. This quantifies that the inputs are
//!    deliberately authored in the `0..=5` alphabet (engine-generated structured
//!    data), not random — which says nothing about whether the authored content
//!    is a recoverable message.
//!
//! Honest reading: "not a pipeline artifact" only means the specific authored
//! digit values matter; uniform-random data also never produces the contiguity,
//! so this is equally consistent with structured-but-meaningless data. No
//! isomorph null is computed here — that is Experiment 7.

use crate::generator::{self, ENGINE_MESSAGES};
use crate::glyph::Orientation;
use crate::null::{NullConfig, NullReport, SplitMix64, run_standard36_null_with};
use crate::orders::{GlyphGrid, GridError};

const SYMBOL_BUCKETS: usize = 7;
const BASE7_CEILING_DIGITS: u32 = 22;

/// Total decoded storage symbols across the nine verified messages.
#[must_use]
pub fn real_symbol_total() -> usize {
    ENGINE_MESSAGES
        .iter()
        .map(|pairs| generator::decode_message(pairs).len())
        .sum()
}

/// Runs the structure-matched base-7 pipeline null over the standard-36 family.
///
/// Synthetic corpora preserve the verified row-width structure; each cell is an
/// orientation harvested from decoding random 64-bit integers whose per-pair
/// base-7 lengths cycle through the verified engine block lengths. The returned
/// [`NullReport`] uses the same statistics as [`crate::null::run_standard36_null`]
/// so the two are directly comparable.
///
/// # Errors
/// Returns [`GridError`] if the verified corpus grids cannot be reconstructed or
/// if an order is incompatible with a generated grid.
pub fn run_pipeline_null(config: NullConfig) -> Result<NullReport, GridError> {
    let lengths: Vec<usize> = generator::engine_pair_lengths()
        .into_iter()
        .flatten()
        .collect();
    run_standard36_null_with(config, |templates, rng| {
        pipeline_grids_like(templates, rng, &lengths)
    })
}

fn pipeline_grids_like(
    templates: &[GlyphGrid],
    rng: &mut SplitMix64,
    lengths: &[usize],
) -> Vec<GlyphGrid> {
    let mut source = OrientationSource::new(lengths);
    let mut grids = Vec::new();
    for template in templates {
        let mut rows = Vec::new();
        for width in template.row_widths() {
            let mut row = Vec::with_capacity(width);
            for _cell in 0..width {
                row.push(source.next(rng));
            }
            rows.push(row);
        }
        grids.push(GlyphGrid::from_orientation_rows(
            template.message_key(),
            rows,
        ));
    }
    grids
}

/// Streams orientations harvested from base-7 decodes of matched-length random
/// integers, refilling from the next scheduled per-pair length as needed.
struct OrientationSource<'a> {
    lengths: &'a [usize],
    next_pair: usize,
    buffer: Vec<Orientation>,
    cursor: usize,
}

impl<'a> OrientationSource<'a> {
    fn new(lengths: &'a [usize]) -> Self {
        Self {
            lengths,
            next_pair: 0,
            buffer: Vec::new(),
            cursor: 0,
        }
    }

    fn next(&mut self, rng: &mut SplitMix64) -> Orientation {
        loop {
            if let Some(orientation) = self.buffer.get(self.cursor).copied() {
                self.cursor += 1;
                return orientation;
            }
            self.refill(rng);
        }
    }

    fn refill(&mut self, rng: &mut SplitMix64) {
        let modulus = self.lengths.len().max(1);
        let length = self
            .lengths
            .get(self.next_pair % modulus)
            .copied()
            .unwrap_or(BASE7_CEILING_DIGITS as usize);
        self.next_pair = self.next_pair.wrapping_add(1);
        let value = random_value_of_length(length, rng);
        self.buffer.clear();
        self.cursor = 0;
        for symbol in generator::decode_u64(value) {
            if let Some(orientation) = generator::storage_orientation(symbol) {
                self.buffer.push(orientation);
            }
        }
    }
}

/// Returns a random 64-bit integer whose base-7 decode emits exactly `length`
/// storage symbols.
///
/// A value in `[7^length, min(7^(length+1), 2^64))` decodes to `length` symbols:
/// the engine drops the trailing base-7 digit, leaving a value with exactly
/// `length` base-7 digits. The `2^64` cap reproduces the genuine ceiling the
/// real engine integers also live under, so the most-significant digit of a
/// maximal (length-22) block carries the same `u64` ceiling the real data has.
fn random_value_of_length(length: usize, rng: &mut SplitMix64) -> u64 {
    let lower = pow7_u128(length);
    let upper = pow7_u128(length + 1).min(1u128 << 64);
    let lower_u64 = u64::try_from(lower).unwrap_or(u64::MAX);
    let span = u64::try_from(upper.saturating_sub(lower))
        .unwrap_or(u64::MAX)
        .max(1);
    lower_u64.wrapping_add(rng.next_u64() % span)
}

fn pow7_u128(exponent: usize) -> u128 {
    (0..exponent).fold(1u128, |acc, _| acc.saturating_mul(7))
}

/// Summary of how unlike random 64-bit integers the real engine inputs are.
#[derive(Clone, Debug, PartialEq)]
pub struct InputRandomnessReport {
    /// Configuration used for the Monte-Carlo arm.
    pub config: NullConfig,
    /// Number of verified engine blocks (64-bit integers) across all messages.
    pub pair_count: usize,
    /// Total decoded storage symbols across all messages.
    pub total_symbols: usize,
    /// Count of `-1` control symbols in the real decode (always zero).
    pub real_minus_one: usize,
    /// Count of delimiter (`5`) symbols in the real decode.
    pub real_delimiters: usize,
    /// Real decoded-symbol histogram, indexed by `symbol + 1` over `-1..=5`.
    pub real_symbol_histogram: [usize; SYMBOL_BUCKETS],
    /// Chi-square of the real histogram against a uniform base-7 expectation.
    pub real_chi_square_vs_uniform: f64,
    /// Analytic probability a matched-length random corpus decodes with no `-1`.
    pub analytic_probability_no_minus_one: f64,
    /// Mean `-1` symbols produced per random matched-length corpus.
    pub mc_mean_minus_one: f64,
    /// Mean delimiter symbols produced per random matched-length corpus.
    pub mc_mean_delimiters: f64,
    /// Random matched-length corpora (of `config.trials`) that produced no `-1`.
    pub mc_corpora_with_zero_minus_one: usize,
}

/// Quantifies the structural gap between the real engine inputs and random
/// 64-bit integers of identical per-pair magnitude.
///
/// # Errors
/// This function never fails on the verified corpus, but returns [`GridError`]
/// for signature parity with the other nulls so callers can treat them
/// uniformly.
pub fn input_randomness_report(config: NullConfig) -> Result<InputRandomnessReport, GridError> {
    let lengths: Vec<usize> = generator::engine_pair_lengths()
        .into_iter()
        .flatten()
        .collect();
    let pair_count = lengths.len();

    let mut real_histogram = [0usize; SYMBOL_BUCKETS];
    for pairs in ENGINE_MESSAGES {
        for symbol in generator::decode_message(pairs) {
            if let Some(bucket) = usize::try_from(symbol + 1)
                .ok()
                .and_then(|index| real_histogram.get_mut(index))
            {
                *bucket += 1;
            }
        }
    }
    let total_symbols: usize = real_histogram.iter().sum();
    let real_minus_one = real_histogram.first().copied().unwrap_or(0);
    let real_delimiters = real_histogram.get(6).copied().unwrap_or(0);
    let real_chi_square_vs_uniform = chi_square_vs_uniform(&real_histogram, total_symbols);

    // Each block's most-significant digit is non-zero by construction, leaving
    // `length - 1` interior digits that each avoid `-1` with probability 6/7.
    let interior_digits = total_symbols.saturating_sub(pair_count);
    let analytic_probability_no_minus_one =
        (6.0f64 / 7.0).powi(i32::try_from(interior_digits).unwrap_or(i32::MAX));

    let mut rng = SplitMix64::new(config.seed);
    let mut total_minus_one = 0u64;
    let mut total_delimiters = 0u64;
    let mut corpora_with_zero_minus_one = 0usize;
    for _trial in 0..config.trials {
        let mut minus_one = 0usize;
        let mut delimiters = 0usize;
        for &length in &lengths {
            for symbol in generator::decode_u64(random_value_of_length(length, &mut rng)) {
                if symbol == -1 {
                    minus_one += 1;
                } else if symbol == 5 {
                    delimiters += 1;
                }
            }
        }
        total_minus_one += minus_one as u64;
        total_delimiters += delimiters as u64;
        if minus_one == 0 {
            corpora_with_zero_minus_one += 1;
        }
    }
    let trials = config.trials.max(1) as f64;

    Ok(InputRandomnessReport {
        config,
        pair_count,
        total_symbols,
        real_minus_one,
        real_delimiters,
        real_symbol_histogram: real_histogram,
        real_chi_square_vs_uniform,
        analytic_probability_no_minus_one,
        mc_mean_minus_one: total_minus_one as f64 / trials,
        mc_mean_delimiters: total_delimiters as f64 / trials,
        mc_corpora_with_zero_minus_one: corpora_with_zero_minus_one,
    })
}

fn chi_square_vs_uniform(histogram: &[usize; SYMBOL_BUCKETS], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let expected = total as f64 / SYMBOL_BUCKETS as f64;
    histogram
        .iter()
        .map(|&observed| {
            let delta = observed as f64 - expected;
            delta * delta / expected
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{
        BASE7_CEILING_DIGITS, OrientationSource, input_randomness_report, random_value_of_length,
        real_symbol_total, run_pipeline_null,
    };
    use crate::generator;
    use crate::null::{NullConfig, SplitMix64};

    #[test]
    fn random_value_decodes_to_requested_length() {
        let mut rng = SplitMix64::new(99);
        for &length in &[2usize, 9, 11, 16, 21, BASE7_CEILING_DIGITS as usize] {
            for _ in 0..64 {
                let value = random_value_of_length(length, &mut rng);
                assert_eq!(
                    generator::decode_u64(value).len(),
                    length,
                    "length {length} not reproduced for value {value}"
                );
            }
        }
    }

    #[test]
    fn orientation_source_yields_only_orientations() {
        let lengths = vec![22usize, 21, 11];
        let mut source = OrientationSource::new(&lengths);
        let mut rng = SplitMix64::new(7);
        for _ in 0..5_000 {
            let orientation = source.next(&mut rng);
            assert!(orientation.digit() <= 4);
        }
    }

    #[test]
    fn pipeline_null_is_reproducible_and_finds_no_contiguity() {
        let config = NullConfig {
            seed: 0xabc_def,
            trials: 40,
        };
        let first = run_pipeline_null(config).unwrap();
        let second = run_pipeline_null(config).unwrap();
        assert_eq!(first.headline_count, second.headline_count);
        assert_eq!(first.min_distinct_histogram, second.min_distinct_histogram);

        // Like the uniform null, the base-7 pipeline never produces the bounded
        // 0..=82 range, and the minimum distinct count stays far above 83.
        assert_eq!(first.headline_count, 0);
        let reached_83 = first
            .min_distinct_histogram
            .iter()
            .any(|&(distinct, _count)| distinct <= 83);
        assert!(!reached_83, "pipeline null implausibly bounded near 83");
    }

    #[test]
    fn real_inputs_are_not_random_integers() {
        let config = NullConfig {
            seed: 0x1234,
            trials: 20,
        };
        let report = input_randomness_report(config).unwrap();

        assert_eq!(report.pair_count, 150);
        assert_eq!(report.total_symbols, 3194);
        assert_eq!(report.total_symbols, real_symbol_total());
        assert_eq!(report.real_minus_one, 0);
        assert_eq!(report.real_delimiters, 86);
        assert_eq!(report.real_symbol_histogram.iter().sum::<usize>(), 3194);

        // Random matched-length integers flood the decode with control symbols
        // the real corpus never contains.
        assert!(report.mc_mean_minus_one > 300.0);
        assert!(report.mc_mean_delimiters > 300.0);
        assert_eq!(report.mc_corpora_with_zero_minus_one, 0);

        // The real histogram is astronomically far from a uniform base-7 decode,
        // and a random corpus essentially never reproduces the no-`-1` property.
        assert!(report.real_chi_square_vs_uniform > 1_000.0);
        assert!(report.analytic_probability_no_minus_one < 1e-100);
        assert!(report.analytic_probability_no_minus_one > 0.0);
    }
}
