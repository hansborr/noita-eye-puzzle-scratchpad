//! Transition-count matrix, entropy/MI estimates, and successor-graph summaries.

use std::collections::BTreeMap;

use crate::core::trigram::TrigramValue;

use super::{
    ADD_CONSTANT_ALPHA, ConditionalStatistic, ConditionalStructureError, DiagonalTransitionSummary,
    EntropyEstimates, FirstOrderStats, OffDiagonalTransitionSummary, SuccessorGraphSummary,
    TransitionChiSquare, TransitionMatrixSummary,
};

pub(super) fn first_order_stats(
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
    alphabet_size: usize,
) -> Result<FirstOrderStats, ConditionalStructureError> {
    let counts = TransitionCounts::from_messages(keys, messages, alphabet_size)?;
    Ok(FirstOrderStats {
        matrix: matrix_summary(&counts),
        entropy: entropy_estimates(&counts),
        chi_square: transition_chi_square(&counts),
        diagonal: diagonal_transition_summary(&counts),
        off_diagonal: off_diagonal_transition_summary(&counts),
        graph: successor_graph_summary(&counts),
    })
}

pub(super) fn statistic_value(stats: &FirstOrderStats, statistic: ConditionalStatistic) -> f64 {
    match statistic {
        ConditionalStatistic::NextEntropyCorrected => stats.entropy.next_entropy_corrected_bits,
        ConditionalStatistic::ConditionalEntropyCorrected => {
            stats.entropy.conditional_entropy_corrected_bits
        }
        ConditionalStatistic::MutualInformationCorrected => {
            stats.entropy.mutual_information_corrected_bits
        }
        ConditionalStatistic::TransitionChiSquare => stats.chi_square.statistic,
        ConditionalStatistic::TransitionChiSquareOffDiagonal => {
            stats.off_diagonal.chi_square_statistic
        }
        ConditionalStatistic::DistinctSuccessorEdges => stats.graph.distinct_successor_edges as f64,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal => {
            stats.off_diagonal.distinct_successor_edges as f64
        }
        ConditionalStatistic::SelfTransitions => stats.diagonal.self_transitions as f64,
        ConditionalStatistic::SuccessorEntropy => stats.graph.successor_entropy_bits,
        ConditionalStatistic::GreedyFsmStateLowerBound => {
            stats.graph.greedy_fsm_state_lower_bound as f64
        }
    }
}

pub(super) const COMPARISON_STATISTICS: [ConditionalStatistic; 10] = [
    ConditionalStatistic::NextEntropyCorrected,
    ConditionalStatistic::ConditionalEntropyCorrected,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquare,
    ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ConditionalStatistic::DistinctSuccessorEdges,
    ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ConditionalStatistic::SelfTransitions,
    ConditionalStatistic::SuccessorEntropy,
    ConditionalStatistic::GreedyFsmStateLowerBound,
];

pub(super) const NO_REPEAT_COMPARISON_STATISTICS: [ConditionalStatistic; 4] = [
    ConditionalStatistic::SelfTransitions,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionCounts {
    alphabet_size: usize,
    matrix: Vec<usize>,
    row_totals: Vec<usize>,
    column_totals: Vec<usize>,
    symbol_totals: Vec<usize>,
    symbols: usize,
    transitions: usize,
}

impl TransitionCounts {
    fn from_messages(
        keys: &[&'static str],
        messages: &[Vec<TrigramValue>],
        alphabet_size: usize,
    ) -> Result<Self, ConditionalStructureError> {
        let cells = matrix_cell_count(alphabet_size)?;
        let mut counts = Self {
            alphabet_size,
            matrix: vec![0; cells],
            row_totals: vec![0; alphabet_size],
            column_totals: vec![0; alphabet_size],
            symbol_totals: vec![0; alphabet_size],
            symbols: 0,
            transitions: 0,
        };

        for (message_index, values) in messages.iter().enumerate() {
            let message_key = keys.get(message_index).copied().unwrap_or("synthetic");
            for &value in values {
                let index = value_index(value, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: value.get(),
                        alphabet_size,
                    },
                )?;
                increment(&mut counts.symbol_totals, index, alphabet_size)?;
                counts.symbols = counts.symbols.saturating_add(1);
            }

            for pair in values.windows(2) {
                let [current, next] = pair else {
                    continue;
                };
                let current = value_index(*current, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: current.get(),
                        alphabet_size,
                    },
                )?;
                let next = value_index(*next, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: next.get(),
                        alphabet_size,
                    },
                )?;
                increment(&mut counts.row_totals, current, alphabet_size)?;
                increment(&mut counts.column_totals, next, alphabet_size)?;
                let cell = flat_index(current, next, alphabet_size)?;
                increment(&mut counts.matrix, cell, alphabet_size)?;
                counts.transitions = counts.transitions.saturating_add(1);
            }
        }

        Ok(counts)
    }

    fn row(&self, row: usize) -> Option<&[usize]> {
        let start = row.checked_mul(self.alphabet_size)?;
        let end = start.checked_add(self.alphabet_size)?;
        self.matrix.get(start..end)
    }

    fn cell(&self, row: usize, column: usize) -> Option<usize> {
        let index = flat_index(row, column, self.alphabet_size).ok()?;
        self.matrix.get(index).copied()
    }
}

fn value_index(value: TrigramValue, alphabet_size: usize) -> Option<usize> {
    let index = usize::from(value.get());
    if index < alphabet_size {
        Some(index)
    } else {
        None
    }
}

pub(super) fn matrix_cell_count(alphabet_size: usize) -> Result<usize, ConditionalStructureError> {
    alphabet_size
        .checked_mul(alphabet_size)
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })
}

fn flat_index(
    row: usize,
    column: usize,
    alphabet_size: usize,
) -> Result<usize, ConditionalStructureError> {
    let offset = row
        .checked_mul(alphabet_size)
        .and_then(|base| base.checked_add(column))
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })?;
    Ok(offset)
}

fn increment(
    values: &mut [usize],
    index: usize,
    alphabet_size: usize,
) -> Result<(), ConditionalStructureError> {
    let slot = values
        .get_mut(index)
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })?;
    *slot = slot.saturating_add(1);
    Ok(())
}

fn matrix_summary(counts: &TransitionCounts) -> TransitionMatrixSummary {
    let matrix_cells = counts.matrix.len();
    let nonzero_cells = counts.matrix.iter().filter(|&&count| count > 0).count();
    TransitionMatrixSummary {
        alphabet_size: counts.alphabet_size,
        symbols: counts.symbols,
        transitions: counts.transitions,
        matrix_cells,
        nonzero_cells,
        density: fraction(nonzero_cells, matrix_cells),
        mean_transitions_per_cell: fraction(counts.transitions, matrix_cells),
        mean_symbols_per_value: fraction(counts.symbols, counts.alphabet_size),
    }
}

fn entropy_estimates(counts: &TransitionCounts) -> EntropyEstimates {
    let transitions = counts.transitions;
    if transitions == 0 {
        return EntropyEstimates {
            transitions,
            max_entropy_bits: (counts.alphabet_size as f64).log2(),
            next_entropy_mle_bits: 0.0,
            next_entropy_corrected_bits: 0.0,
            conditional_entropy_mle_bits: 0.0,
            conditional_entropy_corrected_bits: 0.0,
            mutual_information_mle_bits: 0.0,
            mutual_information_corrected_bits: 0.0,
            add_constant_alpha: ADD_CONSTANT_ALPHA,
        };
    }

    let next_entropy_mle_bits = entropy_from_counts(&counts.column_totals, transitions);
    let next_entropy_corrected_bits = add_constant_entropy(
        &counts.column_totals,
        transitions,
        counts.alphabet_size,
        ADD_CONSTANT_ALPHA,
    );

    let mut conditional_entropy_mle_bits = 0.0;
    let mut conditional_entropy_corrected_bits = 0.0;
    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        let Some(row) = counts.row(row_index) else {
            continue;
        };
        conditional_entropy_mle_bits +=
            row_total as f64 / transitions as f64 * entropy_from_counts(row, row_total);
        conditional_entropy_corrected_bits += row_total as f64 / transitions as f64
            * add_constant_entropy(row, row_total, counts.alphabet_size, ADD_CONSTANT_ALPHA);
    }

    EntropyEstimates {
        transitions,
        max_entropy_bits: (counts.alphabet_size as f64).log2(),
        next_entropy_mle_bits,
        next_entropy_corrected_bits,
        conditional_entropy_mle_bits,
        conditional_entropy_corrected_bits,
        mutual_information_mle_bits: next_entropy_mle_bits - conditional_entropy_mle_bits,
        mutual_information_corrected_bits: next_entropy_corrected_bits
            - conditional_entropy_corrected_bits,
        add_constant_alpha: ADD_CONSTANT_ALPHA,
    }
}

fn transition_chi_square(counts: &TransitionCounts) -> TransitionChiSquare {
    let transitions = counts.transitions;
    let active_rows = nonzero_count(&counts.row_totals);
    let active_columns = nonzero_count(&counts.column_totals);
    if transitions == 0 {
        return TransitionChiSquare {
            statistic: 0.0,
            degrees_of_freedom: 0,
            active_rows,
            active_columns,
            expected_cells: 0,
            expected_lt_1_cells: 0,
            expected_lt_5_cells: 0,
        };
    }

    let mut statistic = 0.0;
    let mut expected_cells = 0usize;
    let mut expected_lt_1_cells = 0usize;
    let mut expected_lt_5_cells = 0usize;
    for (row, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        for (column, &column_total) in counts.column_totals.iter().enumerate() {
            if column_total == 0 {
                continue;
            }
            let expected = row_total as f64 * column_total as f64 / transitions as f64;
            if expected <= 0.0 {
                continue;
            }
            expected_cells = expected_cells.saturating_add(1);
            if expected < 1.0 {
                expected_lt_1_cells = expected_lt_1_cells.saturating_add(1);
            }
            if expected < 5.0 {
                expected_lt_5_cells = expected_lt_5_cells.saturating_add(1);
            }
            let observed = counts.cell(row, column).unwrap_or(0) as f64;
            let delta = observed - expected;
            statistic += delta * delta / expected;
        }
    }

    TransitionChiSquare {
        statistic,
        degrees_of_freedom: active_rows
            .saturating_sub(1)
            .saturating_mul(active_columns.saturating_sub(1)),
        active_rows,
        active_columns,
        expected_cells,
        expected_lt_1_cells,
        expected_lt_5_cells,
    }
}

fn diagonal_transition_summary(counts: &TransitionCounts) -> DiagonalTransitionSummary {
    if counts.transitions == 0 {
        return DiagonalTransitionSummary {
            self_transitions: 0,
            self_transition_edges: 0,
            expected_self_transitions_independence: 0.0,
            chi_square_contribution: 0.0,
        };
    }

    let mut self_transitions = 0usize;
    let mut self_transition_edges = 0usize;
    let mut expected_self_transitions_independence = 0.0;
    let mut chi_square_contribution = 0.0;
    for (index, (&row_total, &column_total)) in counts
        .row_totals
        .iter()
        .zip(counts.column_totals.iter())
        .enumerate()
    {
        let observed = counts.cell(index, index).unwrap_or(0);
        self_transitions = self_transitions.saturating_add(observed);
        if observed > 0 {
            self_transition_edges = self_transition_edges.saturating_add(1);
        }
        let expected = row_total as f64 * column_total as f64 / counts.transitions as f64;
        expected_self_transitions_independence += expected;
        if expected > 0.0 {
            let delta = observed as f64 - expected;
            chi_square_contribution += delta * delta / expected;
        }
    }

    DiagonalTransitionSummary {
        self_transitions,
        self_transition_edges,
        expected_self_transitions_independence,
        chi_square_contribution,
    }
}

fn off_diagonal_transition_summary(counts: &TransitionCounts) -> OffDiagonalTransitionSummary {
    let matrix_cells = counts.matrix.len().saturating_sub(counts.alphabet_size);
    if counts.transitions == 0 {
        return OffDiagonalTransitionSummary {
            matrix_cells,
            distinct_successor_edges: 0,
            edge_density: 0.0,
            chi_square_statistic: 0.0,
            expected_cells: 0,
            expected_lt_1_cells: 0,
            expected_lt_5_cells: 0,
        };
    }

    let mut distinct_successor_edges = 0usize;
    let mut chi_square_statistic = 0.0;
    let mut expected_cells = 0usize;
    let mut expected_lt_1_cells = 0usize;
    let mut expected_lt_5_cells = 0usize;
    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        let Some(row) = counts.row(row_index) else {
            continue;
        };
        for (column_index, (&observed, &column_total)) in
            row.iter().zip(counts.column_totals.iter()).enumerate()
        {
            if row_index == column_index {
                continue;
            }
            if observed > 0 {
                distinct_successor_edges = distinct_successor_edges.saturating_add(1);
            }
            if column_total == 0 {
                continue;
            }
            let expected = row_total as f64 * column_total as f64 / counts.transitions as f64;
            if expected <= 0.0 {
                continue;
            }
            expected_cells = expected_cells.saturating_add(1);
            if expected < 1.0 {
                expected_lt_1_cells = expected_lt_1_cells.saturating_add(1);
            }
            if expected < 5.0 {
                expected_lt_5_cells = expected_lt_5_cells.saturating_add(1);
            }
            let delta = observed as f64 - expected;
            chi_square_statistic += delta * delta / expected;
        }
    }

    OffDiagonalTransitionSummary {
        matrix_cells,
        distinct_successor_edges,
        edge_density: fraction(distinct_successor_edges, matrix_cells),
        chi_square_statistic,
        expected_cells,
        expected_lt_1_cells,
        expected_lt_5_cells,
    }
}

fn successor_graph_summary(counts: &TransitionCounts) -> SuccessorGraphSummary {
    let mut out_degrees = Vec::with_capacity(counts.alphabet_size);
    let mut row_entropy_total = 0.0;
    let mut active_sources = 0usize;
    let mut distinct_successor_edges = 0usize;
    let mut max_out_degree = 0usize;

    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        let out_degree = counts.row(row_index).map_or(0, nonzero_count);
        out_degrees.push(out_degree);
        distinct_successor_edges = distinct_successor_edges.saturating_add(out_degree);
        max_out_degree = max_out_degree.max(out_degree);
        if row_total > 0 {
            active_sources = active_sources.saturating_add(1);
            if let Some(row) = counts.row(row_index) {
                row_entropy_total += entropy_from_counts(row, row_total);
            }
        }
    }

    let observed_symbols = nonzero_count(&counts.symbol_totals);
    let observed_zero_out_degree_symbols = counts
        .symbol_totals
        .iter()
        .zip(out_degrees.iter())
        .filter(|(symbol_total, out_degree)| **symbol_total > 0 && **out_degree == 0)
        .count();
    let greedy_fsm_state_lower_bound = counts
        .symbol_totals
        .iter()
        .zip(out_degrees.iter())
        .filter(|(symbol_total, _out_degree)| **symbol_total > 0)
        .map(|(_symbol_total, &out_degree)| out_degree.max(1))
        .sum();

    SuccessorGraphSummary {
        observed_symbols,
        active_sources,
        active_targets: nonzero_count(&counts.column_totals),
        distinct_successor_edges,
        edge_density: fraction(distinct_successor_edges, counts.matrix.len()),
        mean_out_degree: fraction(distinct_successor_edges, active_sources),
        max_out_degree,
        observed_zero_out_degree_symbols,
        successor_entropy_bits: if active_sources == 0 {
            0.0
        } else {
            row_entropy_total / active_sources as f64
        },
        out_degree_entropy_bits: out_degree_histogram_entropy(&counts.symbol_totals, &out_degrees),
        greedy_fsm_state_lower_bound,
    }
}

fn out_degree_histogram_entropy(symbol_totals: &[usize], out_degrees: &[usize]) -> f64 {
    let mut histogram = BTreeMap::new();
    let mut total = 0usize;
    for (&symbol_total, &out_degree) in symbol_totals.iter().zip(out_degrees) {
        if symbol_total == 0 {
            continue;
        }
        *histogram.entry(out_degree).or_insert(0usize) += 1;
        total = total.saturating_add(1);
    }
    let counts = histogram.values().copied().collect::<Vec<_>>();
    entropy_from_counts(&counts, total)
}

fn entropy_from_counts(counts: &[usize], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn add_constant_entropy(counts: &[usize], total: usize, categories: usize, alpha: f64) -> f64 {
    if categories == 0 || !alpha.is_finite() || alpha <= 0.0 {
        return 0.0;
    }
    let denominator = total as f64 + alpha * categories as f64;
    if denominator <= 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .take(categories)
        .map(|&count| {
            let probability = (count as f64 + alpha) / denominator;
            -probability * probability.log2()
        })
        .sum()
}

fn nonzero_count(counts: &[usize]) -> usize {
    counts.iter().filter(|&&count| count > 0).count()
}
fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
