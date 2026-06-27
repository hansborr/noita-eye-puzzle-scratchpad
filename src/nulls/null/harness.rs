// ===========================================================================
// Matched-null harness
//
// The within-message shuffle nulls in the structural battery
// (`isomorph_null`, `zero_adjacency_null`, `perseus`, `tree_residual`,
// `orientation_homogeneity`, `conditional_structure`, `modular_diff`,
// `periodicity`) all share the same scaffolding: clone a real observation,
// resample it, recompute a statistic, count tails, and summarize the sample
// set into a band. The types and functions below centralize that scaffolding
// while leaving every numeric convention (p-value combiner, band fields, tail
// direction) with the caller — the harness performs only the mechanical loop.
// ===========================================================================

use super::{
    RandomBoundError, SplitMix64, fisher_yates, median_f64, median_usize, scaled_quantile_index,
};

/// A resampling scheme: produces one synthetic draw from `rng`, of the same
/// shape as the real observation it is calibrating.
///
/// The associated [`NullSampler::Draw`] type lets each scheme preserve its own
/// draw shape (per-message value vectors, segment-shaped messages, repartition
/// tables, …) rather than flattening to a single `Vec` and discarding the
/// boundary structure the null exists to preserve.
pub trait NullSampler {
    /// The unit of data a statistic consumes (for example
    /// `Vec<Vec<TrigramValue>>` for a within-message shuffle).
    type Draw;

    /// Produces one synthetic draw.
    ///
    /// # Errors
    /// Returns [`RandomBoundError`] if a bounded index draw fails; this is
    /// unreachable for in-bounds slices on 64-bit targets.
    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError>;
}

/// Within-message Fisher-Yates shuffle: clones each message's value multiset
/// and shuffles it in place, preserving per-message length and multiset.
///
/// This is the shared form of the per-module `shuffled_messages` helper that the
/// structural battery used to copy verbatim. Messages are iterated in order and
/// each is shuffled with one [`fisher_yates`] pass, so the PRNG draw order is
/// identical to the hand-written loops it replaces.
pub struct WithinMessageShuffle<'a, T: Clone> {
    /// The real per-message value vectors to resample.
    pub messages: &'a [Vec<T>],
}

impl<T: Clone> NullSampler for WithinMessageShuffle<'_, T> {
    type Draw = Vec<Vec<T>>;

    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError> {
        let mut shuffled = self.messages.to_vec();
        for values in &mut shuffled {
            fisher_yates(values, rng)?;
        }
        Ok(shuffled)
    }
}

/// Outcome of comparing a real statistic to a Monte-Carlo shuffle null.
///
/// Carries the raw samples (in draw order) and both tail counts only; it
/// deliberately does **not** compute a p-value or band, because those
/// conventions differ per caller. Finish with
/// [`add_one_p_value`](crate::nulls::null::add_one_p_value) and the shared
/// band constructors ([`usize_band`] / [`f64_band`]).
#[derive(Clone, Debug, PartialEq)]
pub struct NullResult<T> {
    /// The real observed statistic the samples are compared against.
    pub observed: T,
    /// Sampled statistics in draw order; callers that pin sample order rely on
    /// this ordering being stable.
    pub samples: Vec<T>,
    /// Number of samples less than or equal to `observed`.
    pub lower_tail_count: usize,
    /// Number of samples greater than or equal to `observed`.
    pub upper_tail_count: usize,
    /// Total number of trials sampled.
    pub trials: usize,
}

/// Error returned by [`run_null_test`] / [`run_null_test_streams`].
///
/// Folds the harness's own [`RandomBoundError`] and the statistic's error `E`
/// into one type so each caller can map it into its own error variant exactly as
/// it maps [`RandomBoundError`] today. An infallible statistic uses
/// `E = core::convert::Infallible`, leaving the [`NullTestError::Statistic`] arm
/// uninhabited.
///
/// This is the generic per-trial error type; it is distinct from the non-generic
/// [`NullRunError`](crate::nulls::null::NullRunError) used by the grid-content
/// standard-36 null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullTestError<E> {
    /// A bounded PRNG draw failed inside the sampler.
    Random(RandomBoundError),
    /// The statistic returned an error for a synthetic draw.
    Statistic(E),
}

impl<E> From<RandomBoundError> for NullTestError<E> {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

/// Error returned by [`run_null_test_columns`] /
/// [`run_null_test_columns_streams`].
///
/// Like [`NullTestError`] but adds a [`NullColumnError::WidthMismatch`] arm for
/// the case where the row statistic returns a row whose width differs from the
/// observed row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullColumnError<E> {
    /// A row statistic returned a row of unexpected width.
    WidthMismatch {
        /// Expected column count (the observed row width).
        expected: usize,
        /// Observed column count returned by the statistic.
        observed: usize,
    },
    /// A bounded PRNG draw failed inside the sampler.
    Random(RandomBoundError),
    /// The statistic returned an error for a synthetic draw.
    Statistic(E),
}

impl<E> From<RandomBoundError> for NullColumnError<E> {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

/// Runs `trials` shuffle draws, scoring each with `statistic`, counting both
/// tails against `observed`.
///
/// Deterministic in `seed`: a fresh [`SplitMix64`] is seeded and threaded
/// through every sampler call, so the PRNG stream — and therefore every reported
/// number — depends only on `seed`, the sampler, and the statistic. The
/// `statistic` is fallible (`Result<T, E>`); the loop propagates the first `Err`
/// as [`NullTestError::Statistic`], and a sampler draw failure surfaces as
/// [`NullTestError::Random`].
///
/// # Errors
/// Returns [`NullTestError::Random`] if a sampler draw fails, or
/// [`NullTestError::Statistic`] if the statistic returns an error.
pub fn run_null_test<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<NullResult<T>, NullTestError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut outcomes = Vec::with_capacity(trials);
    let mut lower_tail_count = 0usize;
    let mut upper_tail_count = 0usize;
    let mut rng = SplitMix64::new(seed);
    for _trial in 0..trials {
        let draw = sampler.sample(&mut rng)?;
        let value = statistic(&draw).map_err(NullTestError::Statistic)?;
        if value <= observed {
            lower_tail_count += 1;
        }
        if value >= observed {
            upper_tail_count += 1;
        }
        outcomes.push(value);
    }
    Ok(NullResult {
        observed,
        samples: outcomes,
        lower_tail_count,
        upper_tail_count,
        trials,
    })
}

/// Runs [`run_null_test`] once per derived seed stream and concatenates the
/// samples, reproducing the `seed_count × trials_per_stream` loops that several
/// modules write by hand.
///
/// `derive_seed(stream_index)` stays caller-supplied because the derivation
/// differs per module (a chained base RNG, a wrapping stride, an xor-mix). It is
/// [`FnMut`] so a *stateful* derivation — for example one that advances a single
/// captured base [`SplitMix64`] per stream — can mutate its captured state. The
/// returned [`NullResult::trials`] is the total over all streams, and the tail
/// counts are summed (counting is additive over disjoint sample partitions).
///
/// # Errors
/// Returns [`NullTestError::Random`] if a sampler draw fails, or
/// [`NullTestError::Statistic`] if the statistic returns an error.
pub fn run_null_test_streams<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    streams: usize,
    trials_per_stream: usize,
    mut derive_seed: impl FnMut(usize) -> u64,
) -> Result<NullResult<T>, NullTestError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut outcomes = Vec::with_capacity(streams.saturating_mul(trials_per_stream));
    let mut lower_tail_count = 0usize;
    let mut upper_tail_count = 0usize;
    for stream_index in 0..streams {
        let seed = derive_seed(stream_index);
        let stream = run_null_test(&statistic, observed, sampler, trials_per_stream, seed)?;
        lower_tail_count += stream.lower_tail_count;
        upper_tail_count += stream.upper_tail_count;
        outcomes.extend(stream.samples);
    }
    let trials = outcomes.len();
    Ok(NullResult {
        observed,
        samples: outcomes,
        lower_tail_count,
        upper_tail_count,
        trials,
    })
}

/// Like [`run_null_test`] but the statistic emits a fixed-width row of scalars,
/// returning one [`NullResult`] per column.
///
/// Every trial draws once from `sampler`, scores the draw into a row, and
/// distributes the row across the per-column accumulators (so all columns share
/// the same draws, exactly as the hand-written multi-statistic loops do). The
/// width is fixed by `observed.len()`; a row of any other width is a
/// [`NullColumnError::WidthMismatch`].
///
/// # Errors
/// Returns [`NullColumnError::Random`] if a sampler draw fails,
/// [`NullColumnError::Statistic`] if the statistic returns an error, or
/// [`NullColumnError::WidthMismatch`] if a row's width differs from `observed`.
pub fn run_null_test_columns<S, T, E>(
    row_statistic: impl Fn(&S::Draw) -> Result<Vec<T>, E>,
    observed: Vec<T>,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<Vec<NullResult<T>>, NullColumnError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let width = observed.len();
    let mut columns = observed
        .into_iter()
        .map(|observed| NullResult {
            observed,
            samples: Vec::with_capacity(trials),
            lower_tail_count: 0,
            upper_tail_count: 0,
            trials,
        })
        .collect::<Vec<_>>();
    let mut rng = SplitMix64::new(seed);
    for _trial in 0..trials {
        let draw = sampler.sample(&mut rng)?;
        let row = row_statistic(&draw).map_err(NullColumnError::Statistic)?;
        if row.len() != width {
            return Err(NullColumnError::WidthMismatch {
                expected: width,
                observed: row.len(),
            });
        }
        for (column, value) in columns.iter_mut().zip(row) {
            if value <= column.observed {
                column.lower_tail_count += 1;
            }
            if value >= column.observed {
                column.upper_tail_count += 1;
            }
            column.samples.push(value);
        }
    }
    Ok(columns)
}

/// Runs [`run_null_test_columns`] once per derived seed stream and concatenates
/// each column's samples, the columnar analogue of [`run_null_test_streams`].
///
/// `derive_seed` is [`FnMut`] for the same stateful-derivation reason as
/// [`run_null_test_streams`]. Per-column tail counts and trial totals are summed
/// across streams.
///
/// # Errors
/// Returns [`NullColumnError::Random`] if a sampler draw fails,
/// [`NullColumnError::Statistic`] if the statistic returns an error, or
/// [`NullColumnError::WidthMismatch`] if a row's width differs from `observed`.
pub fn run_null_test_columns_streams<S, T, E>(
    row_statistic: impl Fn(&S::Draw) -> Result<Vec<T>, E>,
    observed: &[T],
    sampler: &S,
    streams: usize,
    trials_per_stream: usize,
    mut derive_seed: impl FnMut(usize) -> u64,
) -> Result<Vec<NullResult<T>>, NullColumnError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut merged = observed
        .iter()
        .copied()
        .map(|observed| NullResult {
            observed,
            samples: Vec::new(),
            lower_tail_count: 0,
            upper_tail_count: 0,
            trials: 0,
        })
        .collect::<Vec<_>>();
    for stream_index in 0..streams {
        let seed = derive_seed(stream_index);
        let columns = run_null_test_columns(
            &row_statistic,
            observed.to_vec(),
            sampler,
            trials_per_stream,
            seed,
        )?;
        for (accumulator, column) in merged.iter_mut().zip(columns) {
            accumulator.lower_tail_count += column.lower_tail_count;
            accumulator.upper_tail_count += column.upper_tail_count;
            accumulator.trials += column.trials;
            accumulator.samples.extend(column.samples);
        }
    }
    Ok(merged)
}

/// Monte-Carlo band over a `usize` sample set.
///
/// Holds `{trials, mean, min, q025, median, q975, max}`, computed with the same
/// conventions every per-module `null_band` used: arithmetic `mean`, raw
/// `min`/`max` from the sorted ends, `scaled_quantile_index(_, 25|975, 1000)`
/// for the percentile edges, and [`median_usize`] for the median. Modules bridge
/// their named band struct from this via a `From` conversion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UsizeBand {
    /// Number of samples summarized.
    pub trials: usize,
    /// Arithmetic mean of the samples.
    pub mean: f64,
    /// Smallest sampled value.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled value.
    pub max: usize,
}

/// Summarizes a `usize` sample set into a [`UsizeBand`].
#[must_use]
pub fn usize_band(samples: &[usize]) -> UsizeBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    UsizeBand {
        trials: samples.len(),
        mean: usize_sample_mean(samples),
        min: sorted.first().copied().unwrap_or_default(),
        q025: sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or_default(),
        median: median_usize(&sorted),
        q975: sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or_default(),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn usize_sample_mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<usize>() as f64 / samples.len() as f64
    }
}

/// Monte-Carlo band over an `f64` sample set.
///
/// Holds `{trials, mean, min, q025, median, q975, max}`, computed with the same
/// conventions every per-module `scalar_null_band`/`scalar_band` used: arithmetic
/// `mean` over the samples in slice order, a [`f64::total_cmp`] sort, raw
/// `min`/`max` from the sorted ends, `scaled_quantile_index(_, 25|975, 1000)` for
/// the percentile edges, and [`median_f64`] for the median.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F64Band {
    /// Number of samples summarized.
    pub trials: usize,
    /// Arithmetic mean of the samples.
    pub mean: f64,
    /// Smallest sampled value.
    pub min: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

/// Summarizes an `f64` sample set into a [`F64Band`].
#[must_use]
pub fn f64_band(samples: &[f64]) -> F64Band {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    F64Band {
        trials: samples.len(),
        mean: f64_sample_mean(samples),
        min: sorted.first().copied().unwrap_or(0.0),
        q025: sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or(0.0),
        median: median_f64(&sorted),
        q975: sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or(0.0),
        max: sorted.last().copied().unwrap_or(0.0),
    }
}

fn f64_sample_mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    }
}
