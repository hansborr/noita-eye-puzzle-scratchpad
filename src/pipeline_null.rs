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
//!    decoding uniformly sampled 64-bit integers whose per-pair base-7 output
//!    lengths match the real message blocks, then runs the identical
//!    standard-36 reading-order search as [`crate::null`]. Sub-22-symbol blocks
//!    induce independent decoded storage symbols with a non-`-1` leading symbol
//!    and uniform `-1..=5` interior symbols; 22-symbol blocks preserve the real
//!    `u64` ceiling, so their high digits are mildly truncated. This makes the
//!    experiment an actual storage-pipeline null rather than a mathematically
//!    identical copy of the uniform-orientation null. Running it confirms
//!    empirically that the base-7 pipeline manufactures *no* reading-layer
//!    contiguity: the `0..=82` range essentially never appears, just as it does
//!    not for uniform cells.
//!
//! 2. [`input_randomness_report`] — the **negative control**. Genuine random
//!    integers from the same matched-length, `u64`-capped model are wildly
//!    inconsistent with the real engine inputs: they decode to hundreds of `-1`
//!    control symbols and hundreds of delimiters per corpus, whereas the real
//!    messages contain zero `-1` and only 86 delimiters. The analytic no-`-1`
//!    probability is counted against that same capped model, including the
//!    length-22 ceiling. This quantifies that the inputs are deliberately
//!    authored in the `0..=5` alphabet (engine-generated structured data), not
//!    random — which says nothing about whether the authored content is a
//!    recoverable message.
//!
//! Honest reading: "not a pipeline artifact" only means the specific authored
//! digit values matter; uniform-random data also never produces the contiguity,
//! so this is equally consistent with structured-but-meaningless data. No
//! isomorph null is computed here — that is Experiment 7.

use crate::analysis;
use crate::generator::{self, ENGINE_MESSAGES};
use crate::glyph::Orientation;
use crate::null::{NullConfig, NullReport, SplitMix64, run_standard36_null_with};
use crate::orders::{GlyphGrid, GridError};

const SYMBOL_BUCKETS: usize = 7;
const BASE7_CEILING_DIGITS: u32 = 22;
const U64_DRAW_DOMAIN: u128 = 1u128 << 64;

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
/// orientation harvested from decoding uniformly sampled matched-length 64-bit
/// integers whose per-pair base-7 output lengths cycle through the verified
/// engine block lengths. The returned [`NullReport`] uses the same statistics
/// as [`crate::null::run_standard36_null`] so the two are directly comparable.
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

/// Returns a uniformly sampled 64-bit integer whose base-7 decode emits exactly
/// `length` storage symbols.
///
/// A value in `[7^length, min(7^(length+1), 2^64))` decodes to `length` symbols:
/// the engine drops the trailing base-7 digit, leaving a quotient with exactly
/// `length` base-7 digits. The offset inside that interval is drawn with
/// rejection sampling over the full `u64` domain, so there is no modulo bias.
///
/// For lengths below 22, the decoded storage-symbol distribution has a
/// non-`-1` leading symbol followed by independent uniform `-1..=5` interior
/// symbols. A maximal length-22 block is still uniform over its representable
/// interval, but that interval ends at `2^64` rather than `7^23`, carrying the
/// same ceiling the real engine integers have.
///
/// # Invariant
/// `length` must be at most [`BASE7_CEILING_DIGITS`] (22): every real engine
/// per-pair length lies in `0..=22`, and only those lengths have a representable
/// base-7 span in a `u64` (see [`value_span_for_length`]). A larger length is a
/// programming error — caught by a `debug_assert` here — rather than a data
/// condition; in release builds it falls back to `u64::MAX` so the caller still
/// gets a defined (if meaningless) value instead of panicking.
fn random_value_of_length(length: usize, rng: &mut SplitMix64) -> u64 {
    debug_assert!(
        length <= BASE7_CEILING_DIGITS as usize,
        "length {length} exceeds the base-7 u64 ceiling {BASE7_CEILING_DIGITS}; \
         no representable span exists"
    );
    let Some((lower, span)) = value_span_for_length(length) else {
        return u64::MAX;
    };
    lower.wrapping_add(random_offset_below(span, rng))
}

fn value_bounds_for_length(length: usize) -> Option<(u128, u128)> {
    let lower = pow7_u128(length);
    let upper_exponent = length.checked_add(1)?;
    let upper = pow7_u128(upper_exponent).min(U64_DRAW_DOMAIN);
    (lower < upper).then_some((lower, upper))
}

fn value_span_for_length(length: usize) -> Option<(u64, u64)> {
    let (lower, upper) = value_bounds_for_length(length)?;
    let lower = u64::try_from(lower).ok()?;
    let span = u64::try_from(upper.saturating_sub(u128::from(lower))).ok()?;
    (span > 0).then_some((lower, span))
}

fn random_offset_below(span: u64, rng: &mut SplitMix64) -> u64 {
    if span <= 1 {
        return 0;
    }

    let span = u128::from(span);
    let acceptance_zone = (U64_DRAW_DOMAIN / span) * span;
    loop {
        let draw = u128::from(rng.next_u64());
        if draw < acceptance_zone {
            return (draw % span) as u64;
        }
    }
}

fn pow7_u128(exponent: usize) -> u128 {
    (0..exponent).fold(1u128, |acc, _| acc.saturating_mul(7))
}

fn pow6_u128(exponent: usize) -> u128 {
    (0..exponent).fold(1u128, |acc, _| acc.saturating_mul(6))
}

fn exact_probability_no_minus_one(lengths: &[usize]) -> f64 {
    lengths
        .iter()
        .map(|&length| {
            no_minus_one_count_and_span(length)
                .map_or(0.0, |(count, span)| count as f64 / span as f64)
        })
        .product()
}

fn no_minus_one_count_and_span(length: usize) -> Option<(u128, u128)> {
    let (lower, upper) = value_bounds_for_length(length)?;
    let span = upper.saturating_sub(lower);
    if length == 0 {
        return Some((span, span));
    }

    let full_q_limit = upper / 7;
    let partial_residues = upper % 7;
    let mut count = 7 * count_nonzero_base7_below(full_q_limit, length);
    if partial_residues > 0 && has_fixed_width_nonzero_base7_digits(full_q_limit, length) {
        count += partial_residues;
    }

    Some((count, span))
}

fn count_nonzero_base7_below(limit: u128, length: usize) -> u128 {
    if length == 0 {
        return u128::from(limit > 0);
    }

    let lower = pow7_u128(length.saturating_sub(1));
    let upper = pow7_u128(length);
    if limit <= lower {
        return 0;
    }
    if limit >= upper {
        return pow6_u128(length);
    }

    let mut count = 0u128;
    let mut remainder = limit;
    let mut divisor = lower;
    let mut remaining_positions = length;
    for _position in 0..length {
        let digit = remainder / divisor;
        remainder %= divisor;
        remaining_positions = remaining_positions.saturating_sub(1);
        count += digit.saturating_sub(1).min(6) * pow6_u128(remaining_positions);
        if digit == 0 {
            return count;
        }
        divisor /= 7;
    }
    count
}

fn has_fixed_width_nonzero_base7_digits(value: u128, length: usize) -> bool {
    if length == 0 {
        return value == 0;
    }
    if value < pow7_u128(length.saturating_sub(1)) || value >= pow7_u128(length) {
        return false;
    }

    let mut remainder = value;
    let mut divisor = pow7_u128(length.saturating_sub(1));
    for _position in 0..length {
        let digit = remainder / divisor;
        if digit == 0 {
            return false;
        }
        remainder %= divisor;
        divisor /= 7;
    }
    true
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
    /// Exact probability a matched-length, `u64`-capped random corpus decodes
    /// with no `-1`.
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
    let real_chi_square_vs_uniform = analysis::chi_square_goodness_of_fit_uniform(&real_histogram);

    let analytic_probability_no_minus_one = exact_probability_no_minus_one(&lengths);

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

#[cfg(test)]
mod tests {
    use super::{
        BASE7_CEILING_DIGITS, OrientationSource, U64_DRAW_DOMAIN, input_randomness_report,
        no_minus_one_count_and_span, pow6_u128, pow7_u128, random_value_of_length,
        real_symbol_total, run_pipeline_null, value_span_for_length,
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
    fn value_span_for_length_rejects_unrepresentable_length() {
        // Every real engine per-pair length (0..=22) is representable in a u64,
        // so the sampler's `None`/`u64::MAX` fallback is unreachable for real
        // data. One length past the base-7 u64 ceiling has no representable span.
        for length in 0..=(BASE7_CEILING_DIGITS as usize) {
            assert!(
                value_span_for_length(length).is_some(),
                "length {length} should have a representable base-7 span"
            );
        }
        assert!(value_span_for_length(BASE7_CEILING_DIGITS as usize + 1).is_none());
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
    fn no_minus_one_probability_accounts_for_u64_cap() {
        let (sub_ceiling_count, sub_ceiling_span) =
            no_minus_one_count_and_span(21).expect("length 21 is representable");
        assert_eq!(sub_ceiling_span, 6 * pow7_u128(21));
        assert_eq!(sub_ceiling_count, 7 * pow6_u128(21));

        let (ceiling_count, ceiling_span) =
            no_minus_one_count_and_span(22).expect("length 22 is representable");
        assert_eq!(ceiling_span, U64_DRAW_DOMAIN - pow7_u128(22));
        assert_ne!(
            ceiling_count * 6 * pow7_u128(22),
            ceiling_span * 7 * pow6_u128(22),
            "length-22 no -1 rate must not use the uncapped independence ratio"
        );
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

        // The real histogram is astronomically far from the capped matched-length
        // random decode, and a random corpus essentially never reproduces the
        // no-`-1` property.
        assert!(report.real_chi_square_vs_uniform > 1_000.0);
        assert!(report.analytic_probability_no_minus_one < 1e-100);
        assert!(report.analytic_probability_no_minus_one > 0.0);
    }
}
