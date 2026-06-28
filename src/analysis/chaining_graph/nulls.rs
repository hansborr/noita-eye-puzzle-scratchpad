//! Matched within-message shuffle null and the synthetic non-commutative GAK
//! positive control for the Thread 5 chaining-graph audit.
//!
//! Holds the shuffle-null sampler, the upper/lower-tail statistics, and the
//! planted non-commuting fixture used as a positive control, split out of the
//! battery body.

use std::collections::BTreeSet;

use crate::analysis::orders;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullSampler, SplitMix64, WithinMessageShuffle, add_one_p_value, median_usize,
    scaled_quantile_index, shuffled_permutation, stateless_splitmix,
};

use super::{
    ChainingGraphConfig, ChainingGraphError, ConflictCatalogue, ConflictCoverageNull,
    CoverageReport, GraphComputation, NullStatistic, NullStatisticBand, POSITIVE_CONTROL_MAX_DRAWS,
    POSITIVE_CONTROL_MIN_MARGIN, POSITIVE_CONTROL_NULL_TRIALS, POSITIVE_CONTROL_STACKS,
    POSITIVE_CONTROL_STREAM_LEN, PositiveControlOutcome, SymbolValue, compute_graph,
};

pub(super) fn run_shuffle_null(
    config: ChainingGraphConfig,
    message_values: &[Vec<SymbolValue>],
    real: &GraphComputation,
) -> Result<ConflictCoverageNull, ChainingGraphError> {
    let within_message_shuffle = WithinMessageShuffle {
        messages: message_values,
    };
    let mut rng = SplitMix64::new(config.seed);
    let mut samples = NullSamples::default();
    for _trial in 0..config.trials {
        let shuffled = within_message_shuffle.sample(&mut rng)?;
        let graph = compute_graph(&shuffled, config.window_len, config.core_len)?;
        samples.push(&graph.catalogue, &graph.coverage);
    }
    Ok(samples.into_null(real, config.trials))
}

#[derive(Default)]
struct NullSamples {
    total_conflicts: Vec<usize>,
    independent_conflicts: Vec<usize>,
    symbols_touched: Vec<usize>,
    largest_component: Vec<usize>,
    component_count: Vec<usize>,
}

impl NullSamples {
    fn push(&mut self, catalogue: &ConflictCatalogue, coverage: &CoverageReport) {
        self.total_conflicts.push(catalogue.total);
        self.independent_conflicts.push(catalogue.independent);
        self.symbols_touched.push(coverage.symbols_touched);
        self.largest_component.push(coverage.largest_component);
        self.component_count.push(coverage.component_count);
    }

    fn into_null(self, real: &GraphComputation, trials: usize) -> ConflictCoverageNull {
        ConflictCoverageNull {
            total_conflicts: upper_tail_stat(real.catalogue.total, &self.total_conflicts, trials),
            independent_conflicts: upper_tail_stat(
                real.catalogue.independent,
                &self.independent_conflicts,
                trials,
            ),
            symbols_touched: upper_tail_stat(
                real.coverage.symbols_touched,
                &self.symbols_touched,
                trials,
            ),
            largest_component: upper_tail_stat(
                real.coverage.largest_component,
                &self.largest_component,
                trials,
            ),
            component_count: lower_tail_stat(
                real.coverage.component_count,
                &self.component_count,
                trials,
            ),
        }
    }
}

fn upper_tail_stat(real: usize, samples: &[usize], trials: usize) -> NullStatistic {
    let empirical_p_count = samples.iter().filter(|sample| **sample >= real).count();
    NullStatistic {
        real,
        band: null_band(samples),
        empirical_p_count,
        empirical_p: add_one_p_value(empirical_p_count, trials),
    }
}

fn lower_tail_stat(real: usize, samples: &[usize], trials: usize) -> NullStatistic {
    let empirical_p_count = samples.iter().filter(|sample| **sample <= real).count();
    NullStatistic {
        real,
        band: null_band(samples),
        empirical_p_count,
        empirical_p: add_one_p_value(empirical_p_count, trials),
    }
}

fn null_band(samples: &[usize]) -> NullStatisticBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    NullStatisticBand {
        trials: samples.len(),
        mean: mean(samples),
        q025: quantile_from_sorted(&sorted, 25, 1_000),
        median: median_usize(&sorted),
        q975: quantile_from_sorted(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

pub(super) fn run_positive_control(
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<PositiveControlOutcome, ChainingGraphError> {
    let fixture = positive_control_fixture(seed, window_len, core_len)?;
    let graph = compute_graph(&fixture.streams, window_len, core_len)?;
    let null_max_conflicts = positive_control_null_max(&fixture, seed, window_len, core_len)?;
    let conflict_margin = graph.catalogue.total.saturating_sub(null_max_conflicts);
    let passed = graph.catalogue.total
        > null_max_conflicts.saturating_add(POSITIVE_CONTROL_MIN_MARGIN)
        && graph.coverage.symbols_touched >= fixture.planted_symbols;
    if !passed {
        return Err(ChainingGraphError::PositiveControlFailed {
            conflicts: graph.catalogue.total,
            null_max_conflicts,
            required_margin: POSITIVE_CONTROL_MIN_MARGIN,
            expected_symbols: fixture.planted_symbols,
            observed_symbols: graph.coverage.symbols_touched,
        });
    }
    Ok(PositiveControlOutcome {
        conflicts: graph.catalogue.total,
        planted_symbols: fixture.planted_symbols,
        observed_symbols: graph.coverage.symbols_touched,
        null_max_conflicts,
        conflict_margin,
        required_margin: POSITIVE_CONTROL_MIN_MARGIN,
        passed,
    })
}

#[derive(Clone, Debug)]
pub(super) struct PositiveControlFixture {
    pub(super) streams: Vec<Vec<SymbolValue>>,
    pub(super) planted_symbols: usize,
}

#[derive(Clone, Debug)]
struct PositiveControlBase {
    stream: Vec<SymbolValue>,
    planted_windows: Vec<Vec<SymbolValue>>,
}

pub(super) fn positive_control_fixture(
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<PositiveControlFixture, ChainingGraphError> {
    if window_len < 4 || core_len > window_len {
        return Err(ChainingGraphError::InvalidWindowConfig {
            window_len,
            core_len,
        });
    }

    let (a, b) = non_commuting_permutations(seed)?;
    let base = positive_control_base_stream(&a, &b, window_len)?;
    let a_stream = apply_permutation_window(&a, &base.stream)?;
    let b_stream = apply_permutation_window(&b, &base.stream)?;
    let planted_symbols = planted_symbol_count_from_windows(&base.planted_windows, &a, &b)?;
    Ok(PositiveControlFixture {
        streams: vec![base.stream, a_stream, b_stream],
        planted_symbols,
    })
}

fn positive_control_base_stream(
    a: &[usize],
    b: &[usize],
    window_len: usize,
) -> Result<PositiveControlBase, ChainingGraphError> {
    let stack_count = POSITIVE_CONTROL_STACKS.min(window_len.saturating_sub(3));
    if stack_count == 0 {
        return Err(positive_control_failure(0, 0, 0, 0));
    }

    let mut used = BTreeSet::new();
    let mut stream = Vec::new();
    let mut planted_windows = Vec::with_capacity(stack_count);
    for stack_index in 0..stack_count {
        if !stream.is_empty() {
            append_control_filler(&mut stream, &mut used, 1)?;
        }
        let Some(start) = next_non_commuting_start(a, b, &used) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let duplicate_gap = 3usize.saturating_add(stack_index);
        let window =
            positive_control_base_window(a, b, start, window_len, duplicate_gap, &mut used)?;
        stream.extend(window.iter().copied());
        planted_windows.push(window);
    }

    while stream.len() < POSITIVE_CONTROL_STREAM_LEN {
        append_control_filler(&mut stream, &mut used, 1)?;
    }

    Ok(PositiveControlBase {
        stream,
        planted_windows,
    })
}

pub(super) fn positive_control_null_max(
    fixture: &PositiveControlFixture,
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<usize, ChainingGraphError> {
    let within_message_shuffle = WithinMessageShuffle {
        messages: &fixture.streams,
    };
    let mut rng = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_6e75_6c6c_0001));
    let mut max_conflicts = 0usize;
    for _trial in 0..POSITIVE_CONTROL_NULL_TRIALS {
        let shuffled = within_message_shuffle.sample(&mut rng)?;
        let graph = compute_graph(&shuffled, window_len, core_len)?;
        max_conflicts = max_conflicts.max(graph.catalogue.total);
    }
    Ok(max_conflicts)
}

fn non_commuting_permutations(seed: u64) -> Result<(Vec<usize>, Vec<usize>), ChainingGraphError> {
    for attempt in 0_u64..POSITIVE_CONTROL_MAX_DRAWS {
        let mut rng_a = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_7472_6c61_0000 ^ attempt));
        let mut rng_b = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_7472_6c62_0000 ^ attempt));
        let a = shuffled_permutation(orders::READING_LAYER_ALPHABET_SIZE, &mut rng_a)?;
        let b = shuffled_permutation(orders::READING_LAYER_ALPHABET_SIZE, &mut rng_b)?;
        if first_non_commuting_start(&a, &b).is_some() {
            return Ok((a, b));
        }
    }
    Err(positive_control_failure(0, 0, 0, 0))
}

fn first_non_commuting_start(a: &[usize], b: &[usize]) -> Option<usize> {
    (0..a.len().min(b.len())).find(|start| non_commutes_at(a, b, *start))
}

fn next_non_commuting_start(a: &[usize], b: &[usize], used: &BTreeSet<usize>) -> Option<usize> {
    for start in 0..a.len().min(b.len()) {
        let Some(a_start) = a.get(start).copied() else {
            continue;
        };
        let Some(b_start) = b.get(start).copied() else {
            continue;
        };
        if start == a_start || start == b_start || a_start == b_start {
            continue;
        }
        if used.contains(&start) || used.contains(&a_start) || used.contains(&b_start) {
            continue;
        }
        if non_commutes_at(a, b, start) {
            return Some(start);
        }
    }
    None
}

fn non_commutes_at(a: &[usize], b: &[usize], start: usize) -> bool {
    let Some(a_start) = a.get(start).copied() else {
        return false;
    };
    let Some(b_start) = b.get(start).copied() else {
        return false;
    };
    let Some(ab) = b.get(a_start).copied() else {
        return false;
    };
    let Some(ba) = a.get(b_start).copied() else {
        return false;
    };
    ab != ba
}

fn positive_control_base_window(
    a: &[usize],
    b: &[usize],
    start: usize,
    window_len: usize,
    duplicate_gap: usize,
    used: &mut BTreeSet<usize>,
) -> Result<Vec<SymbolValue>, ChainingGraphError> {
    let Some(a_start) = a.get(start).copied() else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };
    let Some(b_start) = b.get(start).copied() else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };

    let mut selected = BTreeSet::new();
    for value in [start, a_start, b_start] {
        if used.contains(&value) || !selected.insert(value) {
            return Err(positive_control_failure(0, 0, 0, 0));
        }
    }

    let mut slots = vec![None; window_len];
    set_control_window_slot(&mut slots, 0, start)?;
    set_control_window_slot(&mut slots, 1, a_start)?;
    set_control_window_slot(&mut slots, 2, b_start)?;
    set_control_window_slot(&mut slots, duplicate_gap, start)?;

    for slot in &mut slots {
        if slot.is_some() {
            continue;
        }
        let Some(value) = next_unused_control_symbol(used, &selected) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let _inserted = selected.insert(value);
        *slot = Some(value);
    }

    for value in &selected {
        let _inserted = used.insert(*value);
    }

    slots
        .into_iter()
        .map(|value| {
            value
                .ok_or_else(|| positive_control_failure(0, 0, 0, 0))
                .and_then(symbol_from_usize)
        })
        .collect()
}

fn set_control_window_slot(
    slots: &mut [Option<usize>],
    column: usize,
    value: usize,
) -> Result<(), ChainingGraphError> {
    let Some(slot) = slots.get_mut(column) else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };
    if slot.is_some() {
        return Err(positive_control_failure(0, 0, 0, 0));
    }
    *slot = Some(value);
    Ok(())
}

fn append_control_filler(
    stream: &mut Vec<SymbolValue>,
    used: &mut BTreeSet<usize>,
    count: usize,
) -> Result<(), ChainingGraphError> {
    let selected = BTreeSet::new();
    for _item in 0..count {
        let Some(value) = next_unused_control_symbol(used, &selected) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let _inserted = used.insert(value);
        stream.push(symbol_from_usize(value)?);
    }
    Ok(())
}

fn next_unused_control_symbol(used: &BTreeSet<usize>, selected: &BTreeSet<usize>) -> Option<usize> {
    (0..orders::READING_LAYER_ALPHABET_SIZE)
        .find(|value| !used.contains(value) && !selected.contains(value))
}

fn apply_permutation_window(
    permutation: &[usize],
    window: &[SymbolValue],
) -> Result<Vec<SymbolValue>, ChainingGraphError> {
    let mut output = Vec::with_capacity(window.len());
    for symbol in window {
        let index = usize::from(symbol.get());
        let Some(image) = permutation.get(index).copied() else {
            return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
        };
        output.push(symbol_from_usize(image)?);
    }
    Ok(output)
}

fn symbol_from_usize(value: usize) -> Result<SymbolValue, ChainingGraphError> {
    let raw = u8::try_from(value)
        .map_err(|_error| ChainingGraphError::ControlSymbolOutOfRange { value })?;
    TrigramValue::new(raw).map_err(|bad| ChainingGraphError::ControlSymbolOutOfRange {
        value: usize::from(bad),
    })
}

fn planted_symbol_count_from_windows(
    windows: &[Vec<SymbolValue>],
    a: &[usize],
    b: &[usize],
) -> Result<usize, ChainingGraphError> {
    let mut symbols = BTreeSet::new();
    for window in windows {
        for symbol in window {
            let index = usize::from(symbol.get());
            let Some(a_image) = a.get(index).copied() else {
                return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
            };
            let Some(b_image) = b.get(index).copied() else {
                return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
            };
            let _inserted = symbols.insert(*symbol);
            let _inserted = symbols.insert(symbol_from_usize(a_image)?);
            let _inserted = symbols.insert(symbol_from_usize(b_image)?);
        }
    }
    Ok(symbols.len())
}

fn positive_control_failure(
    conflicts: usize,
    null_max_conflicts: usize,
    expected_symbols: usize,
    observed_symbols: usize,
) -> ChainingGraphError {
    ChainingGraphError::PositiveControlFailed {
        conflicts,
        null_max_conflicts,
        required_margin: POSITIVE_CONTROL_MIN_MARGIN,
        expected_symbols,
        observed_symbols,
    }
}
