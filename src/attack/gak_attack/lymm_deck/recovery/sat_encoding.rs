//! SAT channeling clauses for the Lymm swap-recovery residual.

use std::collections::BTreeMap;

use batsat::{BasicSolver, Lit, SolverInterface};

use super::super::{LymmComposeDirection, LymmDeckSpec};
use super::AlignedMessage;
use super::residual::ResidualDomains;

const MAX_TRANSITION_READ_POSITIONS: u32 = 8;

pub(super) type CandidateVars = BTreeMap<(char, usize), Lit>;
pub(super) type TopVars = BTreeMap<(char, usize), Lit>;

pub(super) fn add_top_image_channel_clauses(
    spec: &LymmDeckSpec,
    residual: &ResidualDomains,
    vars: &CandidateVars,
    solver: &mut BasicSolver,
) -> TopVars {
    let mut top_vars = TopVars::new();
    for (&letter, domain) in &residual.by_letter {
        let mut by_top = BTreeMap::<usize, Vec<Lit>>::new();
        for &candidate_index in domain {
            let Some(candidate) = residual.domains.candidates.get(candidate_index) else {
                continue;
            };
            let Some(&literal) = vars.get(&(letter, candidate_index)) else {
                continue;
            };
            by_top.entry(candidate.top_image).or_default().push(literal);
        }
        for (top_image, literals) in by_top {
            let top_literal = Lit::new(solver.new_var_default(), true);
            let _old = top_vars.insert((letter, top_image), top_literal);
            for &candidate_literal in &literals {
                add_sat_clause(solver, &[!candidate_literal, top_literal]);
            }
            let mut clause = Vec::with_capacity(literals.len().saturating_add(1));
            clause.push(!top_literal);
            clause.extend(literals);
            add_sat_clause(solver, &clause);
        }
    }
    add_distinct_target_clauses(spec, residual, &top_vars, solver);
    top_vars
}

pub(super) fn add_adjacent_transition_clauses(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &ResidualDomains,
    vars: &CandidateVars,
    top_vars: &TopVars,
    solver: &mut BasicSolver,
) {
    if spec.compose_dir != LymmComposeDirection::Left {
        return;
    }
    let full = full_mask(spec.n);
    let target_masks = build_target_masks(residual);
    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get(message_index) else {
            continue;
        };
        for (event_index, window) in message.events.windows(2).enumerate() {
            let [first, second] = window else {
                continue;
            };
            let pre_positions = message_states
                .get(event_index)
                .and_then(|state| state.get(second.ct_value))
                .copied()
                .unwrap_or(full);
            if pre_positions == full
                || pre_positions == 0
                || pre_positions.count_ones() > MAX_TRANSITION_READ_POSITIONS
            {
                continue;
            }
            let second_target_mask = target_masks.get(&second.letter).copied().unwrap_or(0);
            if second_target_mask == 0 {
                continue;
            }
            let Some(first_domain) = residual.by_letter.get(&first.letter) else {
                continue;
            };
            for &candidate_index in first_domain {
                if residual.domains.candidates.get(candidate_index).is_none() {
                    continue;
                }
                let allowed_targets =
                    residual.preimage_mask(candidate_index, pre_positions) & second_target_mask;
                if allowed_targets == second_target_mask {
                    continue;
                }
                let Some(&candidate_literal) = vars.get(&(first.letter, candidate_index)) else {
                    continue;
                };
                let mut clause = vec![!candidate_literal];
                for target in bit_positions(allowed_targets) {
                    if let Some(&top_literal) = top_vars.get(&(second.letter, target)) {
                        clause.push(top_literal);
                    }
                }
                add_sat_clause(solver, &clause);
            }
        }
    }
}

fn add_distinct_target_clauses(
    spec: &LymmDeckSpec,
    residual: &ResidualDomains,
    top_vars: &TopVars,
    solver: &mut BasicSolver,
) {
    for &letter in &residual.letters {
        if let Some(&zero_top) = top_vars.get(&(letter, 0)) {
            add_sat_clause(solver, &[!zero_top]);
        }
    }
    for target in 0..spec.n {
        for (left_index, &left) in residual.letters.iter().enumerate() {
            let Some(&left_literal) = top_vars.get(&(left, target)) else {
                continue;
            };
            for &right in residual.letters.iter().skip(left_index.saturating_add(1)) {
                if let Some(&right_literal) = top_vars.get(&(right, target)) {
                    add_sat_clause(solver, &[!left_literal, !right_literal]);
                }
            }
        }
    }
}

fn build_target_masks(residual: &ResidualDomains) -> BTreeMap<char, u128> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| {
            let mask = domain.iter().fold(0u128, |acc, &candidate_index| {
                residual
                    .domains
                    .candidates
                    .get(candidate_index)
                    .map_or(acc, |candidate| acc | bit(candidate.top_image))
            });
            (letter, mask)
        })
        .collect()
}

fn add_sat_clause(solver: &mut BasicSolver, literals: &[Lit]) {
    let mut clause = literals.to_vec();
    let _still_satisfiable = solver.add_clause_reuse(&mut clause);
}

fn full_mask(n: usize) -> u128 {
    if n >= u128::BITS as usize {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

fn bit(position: usize) -> u128 {
    1u128 << position
}

fn bit_positions(mut mask: u128) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let bit = mask & mask.wrapping_neg();
        mask &= !bit;
        Some(bit.trailing_zeros() as usize)
    })
}
