//! Target-image SAT pre-solver for the ns=3 Lymm residual.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::{LymmDeckSpec, TopSwapCandidate};
use super::residual::ResidualDomains;
use super::{AlignedMessage, SwapRecoveryError};

const MAX_TARGET_READ_POSITIONS: u32 = 8;

pub(super) struct TargetAssignmentSolver {
    solver: BasicSolver,
    vars: BTreeMap<(char, usize), Lit>,
    letters: Vec<char>,
}

impl TargetAssignmentSolver {
    pub(super) fn new(
        spec: &LymmDeckSpec,
        messages: &[AlignedMessage],
        state_domains: &[Vec<Vec<u128>>],
        residual: &ResidualDomains,
    ) -> Self {
        let mut solver = BasicSolver::default();
        let target_order = shadow_target_order(spec, messages);
        let vars = build_target_variables(residual, &target_order, &mut solver);
        trace("target-solver: variables built");
        add_exactly_one_target_clauses(residual, &vars, &mut solver);
        trace("target-solver: exactly-one clauses built");
        add_distinct_target_clauses(spec, residual, &vars, &mut solver);
        trace("target-solver: distinct-target clauses built");
        add_transition_target_clauses(spec, messages, state_domains, residual, &vars, &mut solver);
        trace("target-solver: transition clauses built");
        add_two_step_target_clauses(spec, messages, state_domains, residual, &vars, &mut solver);
        trace("target-solver: two-step clauses built");
        Self {
            solver,
            vars,
            letters: residual.letters.clone(),
        }
    }

    pub(super) fn next_assignment(
        &mut self,
    ) -> Result<Option<BTreeMap<char, usize>>, SwapRecoveryError> {
        let sat = self.solver.solve_limited(&[]);
        if sat == lbool::FALSE {
            Ok(None)
        } else if sat == lbool::UNDEF {
            Err(SwapRecoveryError::SatSolver(
                "target solver returned an indeterminate result".to_owned(),
            ))
        } else {
            self.extract_assignment().map(Some)
        }
    }

    pub(super) fn forbid_assignment(&mut self, assignment: &BTreeMap<char, usize>) {
        let clause = assignment
            .iter()
            .filter_map(|(&letter, &target)| self.vars.get(&(letter, target)).copied())
            .map(|literal| !literal)
            .collect::<Vec<_>>();
        add_sat_clause(&mut self.solver, &clause);
    }

    pub(super) fn forbid_core(&mut self, choices: &[(char, usize)]) {
        let clause = choices
            .iter()
            .filter_map(|&(letter, target)| self.vars.get(&(letter, target)).copied())
            .map(|literal| !literal)
            .collect::<Vec<_>>();
        add_sat_clause(&mut self.solver, &clause);
    }

    fn extract_assignment(&self) -> Result<BTreeMap<char, usize>, SwapRecoveryError> {
        let mut assignment = BTreeMap::new();
        for &letter in &self.letters {
            let selected = self
                .vars
                .iter()
                .find_map(|(&(candidate_letter, target), &literal)| {
                    (candidate_letter == letter && self.solver.value_lit(literal) == lbool::TRUE)
                        .then_some(target)
                });
            let Some(target) = selected else {
                return Err(SwapRecoveryError::NoResidualCandidate);
            };
            let _old = assignment.insert(letter, target);
        }
        Ok(assignment)
    }
}

fn trace(message: &str) {
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("{message}");
    }
}

fn build_target_variables(
    residual: &ResidualDomains,
    target_order: &BTreeMap<char, Vec<usize>>,
    solver: &mut BasicSolver,
) -> BTreeMap<(char, usize), Lit> {
    let mut vars = BTreeMap::new();
    for (&letter, domain) in &residual.by_letter {
        let mut values = target_values(residual, domain);
        if let Some(order) = target_order.get(&letter) {
            values.sort_by_key(|target| {
                order
                    .iter()
                    .position(|candidate| candidate == target)
                    .unwrap_or(usize::MAX)
            });
        }
        for target in values {
            let literal = Lit::new(solver.new_var(lbool::TRUE, true), true);
            let _old = vars.insert((letter, target), literal);
        }
    }
    vars
}

fn shadow_target_order(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
) -> BTreeMap<char, Vec<usize>> {
    let mut scores = spec
        .pt_alphabet
        .iter()
        .copied()
        .map(|letter| (letter, vec![0usize; spec.n]))
        .collect::<BTreeMap<_, _>>();
    for message in messages {
        let mut state = spec.initial_state.clone();
        for event in &message.events {
            if let Some(target) = state.iter().position(|&value| value == event.ct_value)
                && let Some(letter_scores) = scores.get_mut(&event.letter)
                && let Some(slot) = letter_scores.get_mut(target)
            {
                *slot = slot.saturating_add(1);
            }
            state = apply_permutation(&spec.base, &state);
        }
    }
    scores
        .into_iter()
        .map(|(letter, letter_scores)| {
            let mut targets = (0..spec.n).collect::<Vec<_>>();
            targets.sort_by_key(|&target| {
                (
                    Reverse(letter_scores.get(target).copied().unwrap_or(0)),
                    target,
                )
            });
            (letter, targets)
        })
        .collect()
}

fn apply_permutation(perm: &[usize], state: &[usize]) -> Vec<usize> {
    perm.iter()
        .filter_map(|&position| state.get(position).copied())
        .collect()
}

fn add_exactly_one_target_clauses(
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    for &letter in &residual.letters {
        let literals = vars
            .iter()
            .filter_map(|(&(candidate_letter, _target), &literal)| {
                (candidate_letter == letter).then_some(literal)
            })
            .collect::<Vec<_>>();
        add_sat_clause(solver, &literals);
        for (left_index, &left) in literals.iter().enumerate() {
            for &right in literals.iter().skip(left_index.saturating_add(1)) {
                add_sat_clause(solver, &[!left, !right]);
            }
        }
    }
}

fn add_distinct_target_clauses(
    spec: &LymmDeckSpec,
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    for &letter in &residual.letters {
        if let Some(&zero_top) = vars.get(&(letter, 0)) {
            add_sat_clause(solver, &[!zero_top]);
        }
    }
    for target in 0..spec.n {
        for (left_index, &left) in residual.letters.iter().enumerate() {
            let Some(&left_literal) = vars.get(&(left, target)) else {
                continue;
            };
            for &right in residual.letters.iter().skip(left_index.saturating_add(1)) {
                if let Some(&right_literal) = vars.get(&(right, target)) {
                    add_sat_clause(solver, &[!left_literal, !right_literal]);
                }
            }
        }
    }
}

fn add_transition_target_clauses(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    let full = full_mask(spec.n);
    let base_inverse = base_inverse(spec);
    let grouped = candidates_by_letter_target(residual);
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
                || pre_positions.count_ones() > MAX_TARGET_READ_POSITIONS
            {
                continue;
            }
            let first_mask = target_masks.get(&first.letter).copied().unwrap_or(0);
            let second_mask = target_masks.get(&second.letter).copied().unwrap_or(0);
            for first_target in bit_positions(first_mask) {
                let allowed_second = grouped
                    .get(&(first.letter, first_target))
                    .into_iter()
                    .flat_map(|candidates| candidates.iter())
                    .fold(0u128, |acc, &candidate_index| {
                        residual
                            .domains
                            .candidates
                            .get(candidate_index)
                            .map_or(acc, |candidate| {
                                acc | candidate_preimage_mask(
                                    candidate,
                                    pre_positions,
                                    &base_inverse,
                                )
                            })
                    })
                    & second_mask;
                for second_target in bit_positions(second_mask & !allowed_second) {
                    let (Some(&left), Some(&right)) = (
                        vars.get(&(first.letter, first_target)),
                        vars.get(&(second.letter, second_target)),
                    ) else {
                        continue;
                    };
                    add_sat_clause(solver, &[!left, !right]);
                }
            }
        }
    }
}

fn add_two_step_target_clauses(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    let full = full_mask(spec.n);
    let base_inverse = base_inverse(spec);
    let grouped = candidates_by_letter_target(residual);
    let target_masks = build_target_masks(residual);
    let mut allowed_cache = BTreeMap::<(char, usize, u128), u128>::new();
    let mut image_cache = BTreeMap::<(char, usize, usize), u128>::new();

    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get(message_index) else {
            continue;
        };
        for (event_index, window) in message.events.windows(3).enumerate() {
            let [first, second, third] = window else {
                continue;
            };
            let pre_positions = message_states
                .get(event_index)
                .and_then(|state| state.get(third.ct_value))
                .copied()
                .unwrap_or(full);
            if pre_positions == full
                || pre_positions == 0
                || pre_positions.count_ones() > MAX_TARGET_READ_POSITIONS
            {
                continue;
            }

            let first_mask = target_masks.get(&first.letter).copied().unwrap_or(0);
            let second_mask = target_masks.get(&second.letter).copied().unwrap_or(0);
            let third_mask = target_masks.get(&third.letter).copied().unwrap_or(0);
            if third_mask == 0 || third_mask.count_ones() > MAX_TARGET_READ_POSITIONS {
                continue;
            }

            for third_target in bit_positions(third_mask) {
                let Some(&third_literal) = vars.get(&(third.letter, third_target)) else {
                    continue;
                };
                for first_target in bit_positions(first_mask) {
                    let allowed_inputs = *allowed_cache
                        .entry((first.letter, first_target, pre_positions))
                        .or_insert_with(|| {
                            union_candidate_preimages(
                                residual,
                                &grouped,
                                first.letter,
                                first_target,
                                pre_positions,
                                &base_inverse,
                            )
                        });
                    if allowed_inputs == 0 {
                        continue;
                    }
                    let Some(&first_literal) = vars.get(&(first.letter, first_target)) else {
                        continue;
                    };
                    for second_target in bit_positions(second_mask) {
                        let second_outputs = *image_cache
                            .entry((second.letter, second_target, third_target))
                            .or_insert_with(|| {
                                union_candidate_images(
                                    residual,
                                    &grouped,
                                    second.letter,
                                    second_target,
                                    third_target,
                                )
                            });
                        if second_outputs & allowed_inputs != 0 {
                            continue;
                        }
                        let Some(&second_literal) = vars.get(&(second.letter, second_target))
                        else {
                            continue;
                        };
                        add_sat_clause(solver, &[!first_literal, !second_literal, !third_literal]);
                    }
                }
            }
        }
    }
}

fn union_candidate_preimages(
    residual: &ResidualDomains,
    grouped: &BTreeMap<(char, usize), Vec<usize>>,
    letter: char,
    target: usize,
    pre_positions: u128,
    base_inverse: &[usize],
) -> u128 {
    grouped
        .get(&(letter, target))
        .into_iter()
        .flat_map(|candidates| candidates.iter())
        .fold(0u128, |acc, &candidate_index| {
            residual
                .domains
                .candidates
                .get(candidate_index)
                .map_or(acc, |candidate| {
                    acc | candidate_preimage_mask(candidate, pre_positions, base_inverse)
                })
        })
}

fn union_candidate_images(
    residual: &ResidualDomains,
    grouped: &BTreeMap<(char, usize), Vec<usize>>,
    letter: char,
    target: usize,
    input_position: usize,
) -> u128 {
    grouped
        .get(&(letter, target))
        .into_iter()
        .flat_map(|candidates| candidates.iter())
        .fold(0u128, |acc, &candidate_index| {
            residual
                .candidates
                .get(candidate_index)
                .and_then(|candidate| candidate.perm.get(input_position).copied())
                .map_or(acc, |output| acc | bit(output))
        })
}

fn candidates_by_letter_target(residual: &ResidualDomains) -> BTreeMap<(char, usize), Vec<usize>> {
    let mut grouped = BTreeMap::<(char, usize), Vec<usize>>::new();
    for (&letter, domain) in &residual.by_letter {
        for &candidate_index in domain {
            if let Some(candidate) = residual.domains.candidates.get(candidate_index) {
                grouped
                    .entry((letter, candidate.top_image))
                    .or_default()
                    .push(candidate_index);
            }
        }
    }
    grouped
}

fn build_target_masks(residual: &ResidualDomains) -> BTreeMap<char, u128> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| {
            let mask = target_values(residual, domain)
                .into_iter()
                .fold(0u128, |acc, target| acc | bit(target));
            (letter, mask)
        })
        .collect()
}

fn target_values(residual: &ResidualDomains, domain: &[usize]) -> Vec<usize> {
    let mut values = domain
        .iter()
        .filter_map(|&candidate_index| {
            residual
                .domains
                .candidates
                .get(candidate_index)
                .map(|candidate| candidate.top_image)
        })
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn base_inverse(spec: &LymmDeckSpec) -> Vec<usize> {
    let mut inverse = vec![0usize; spec.n];
    for (position, &image) in spec.base.iter().enumerate() {
        if let Some(slot) = inverse.get_mut(image) {
            *slot = position;
        }
    }
    inverse
}

fn candidate_preimage_mask(
    candidate: &TopSwapCandidate,
    pre_positions: u128,
    base_inverse: &[usize],
) -> u128 {
    let mut mask = 0u128;
    for pre_position in bit_positions(pre_positions) {
        let Some(&sigma_image) = base_inverse.get(pre_position) else {
            continue;
        };
        let candidate_position = candidate
            .support
            .iter()
            .zip(&candidate.sigma_images)
            .find_map(|(&support_position, &image)| {
                (image == sigma_image).then_some(support_position)
            })
            .unwrap_or(sigma_image);
        mask |= bit(candidate_position);
    }
    mask
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
