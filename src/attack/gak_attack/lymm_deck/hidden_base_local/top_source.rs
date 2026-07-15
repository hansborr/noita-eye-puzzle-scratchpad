//! Bounded top-source constraint stage for hidden-base local recovery.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::corpus::LocalCorpus;
use super::search::SigmaDomain;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TopSourceBeam {
    pub(super) hypotheses: Vec<Vec<Option<usize>>>,
    pub(super) planted_hypothesis_rank: Option<usize>,
    pub(super) planted_hypothesis_retained: Option<bool>,
    pub(super) states_expanded: usize,
    pub(super) states_pruned: usize,
    pub(super) states_dropped: usize,
    pub(super) constraint_evaluations: usize,
    pub(super) third_symbol_evaluations: usize,
    pub(super) elapsed: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnchorGroup {
    target: usize,
    letters: Vec<usize>,
    involvement: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BeamState {
    sources: Vec<Option<usize>>,
    used_sources: Vec<bool>,
    likelihood: u128,
    third_symbol_viable: bool,
}

pub(super) fn build_top_source_beam(
    width: usize,
    rank_with_third_symbol: bool,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    planted_sources: Option<&[Option<usize>]>,
) -> TopSourceBeam {
    let started = Instant::now();
    let n = domain.by_top_source.len();
    let alphabet_len = corpus.anchors.len();
    if corpus.anchor_conflict {
        return TopSourceBeam {
            hypotheses: Vec::new(),
            planted_hypothesis_rank: None,
            planted_hypothesis_retained: planted_sources.map(|_| false),
            states_expanded: 0,
            states_pruned: 1,
            states_dropped: 0,
            constraint_evaluations: 0,
            third_symbol_evaluations: 0,
            elapsed: started.elapsed(),
        };
    }
    let groups = anchor_groups(corpus);
    let mut states = vec![BeamState {
        sources: vec![None; alphabet_len],
        used_sources: vec![false; n],
        likelihood: 0,
        third_symbol_viable: false,
    }];
    let mut states_expanded = 0usize;
    let mut states_pruned = 0usize;
    let mut constraint_evaluations = 0usize;

    for group in groups {
        let mut next = Vec::new();
        for state in states {
            for source in 0..n {
                states_expanded = states_expanded.saturating_add(1);
                if state.used_sources.get(source).copied().unwrap_or(true)
                    || domain.by_top_source.get(source).is_none_or(Vec::is_empty)
                {
                    states_pruned = states_pruned.saturating_add(1);
                    continue;
                }
                let mut child = state.clone();
                if let Some(slot) = child.used_sources.get_mut(source) {
                    *slot = true;
                }
                for &letter in &group.letters {
                    if let Some(slot) = child.sources.get_mut(letter) {
                        *slot = Some(source);
                    }
                }
                let Some(likelihood) = constraint_likelihood(
                    corpus,
                    domain,
                    &child.sources,
                    &mut constraint_evaluations,
                ) else {
                    states_pruned = states_pruned.saturating_add(1);
                    continue;
                };
                child.likelihood = likelihood;
                next.push(child);
            }
        }
        states = next;
        if states.is_empty() {
            break;
        }
    }

    let mut third_symbol_evaluations = 0usize;
    if rank_with_third_symbol {
        for state in &mut states {
            state.third_symbol_viable = third_symbol_viability(
                n,
                corpus,
                domain,
                &state.sources,
                &mut third_symbol_evaluations,
            );
        }
    }
    states.sort_by(compare_states);
    let retained_cap = width.max(1);
    let planted_hypothesis_rank = planted_sources.and_then(|planted| {
        states
            .iter()
            .position(|state| state.sources == planted)
            .map(|index| index.saturating_add(1))
    });
    let planted_hypothesis_retained =
        planted_sources.map(|_| planted_hypothesis_rank.is_some_and(|rank| rank <= retained_cap));
    let states_dropped = states.len().saturating_sub(retained_cap);
    states.truncate(retained_cap);
    TopSourceBeam {
        hypotheses: states.into_iter().map(|state| state.sources).collect(),
        planted_hypothesis_rank,
        planted_hypothesis_retained,
        states_expanded,
        states_pruned,
        states_dropped,
        constraint_evaluations,
        third_symbol_evaluations,
        elapsed: started.elapsed(),
    }
}

fn anchor_groups(corpus: &LocalCorpus) -> Vec<AnchorGroup> {
    let mut letters_by_target = BTreeMap::<usize, Vec<usize>>::new();
    for (letter, target) in corpus.anchors.iter().copied().enumerate() {
        if let Some(target) = target {
            letters_by_target.entry(target).or_default().push(letter);
        }
    }
    let mut groups = letters_by_target
        .into_iter()
        .map(|(target, letters)| {
            let involvement = corpus
                .pair_constraints
                .iter()
                .filter(|constraint| {
                    letters.contains(&constraint.first_letter)
                        || letters.contains(&constraint.emitted_anchor_letter)
                })
                .count();
            AnchorGroup {
                target,
                letters,
                involvement,
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by_key(|group| (std::cmp::Reverse(group.involvement), group.target));
    groups
}

fn constraint_likelihood(
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    sources: &[Option<usize>],
    evaluations: &mut usize,
) -> Option<u128> {
    const SCALE: u128 = 1_000_000_000_000_000_000;
    let mut likelihood = SCALE;
    for (first_letter, top_source) in sources.iter().copied().enumerate() {
        let Some(top_source) = top_source else {
            continue;
        };
        let resolved = corpus
            .pair_constraints
            .iter()
            .filter(|constraint| {
                constraint.first_letter == first_letter
                    && sources
                        .get(constraint.emitted_anchor_letter)
                        .copied()
                        .flatten()
                        .is_some()
            })
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            continue;
        }
        let bucket = domain.by_top_source.get(top_source)?;
        let compatible = bucket
            .iter()
            .filter(|&&candidate_index| {
                *evaluations = evaluations.saturating_add(1);
                let Some(candidate) = domain.candidates.get(candidate_index) else {
                    return false;
                };
                resolved.iter().all(|constraint| {
                    let emitted_source = sources
                        .get(constraint.emitted_anchor_letter)
                        .copied()
                        .flatten();
                    candidate.sigma.get(constraint.second_anchor_value).copied() == emitted_source
                })
            })
            .count();
        if compatible == 0 {
            return None;
        }
        likelihood = likelihood
            .saturating_mul(compatible as u128)
            .checked_div(bucket.len() as u128)
            .unwrap_or(0);
    }
    Some(likelihood)
}

fn compare_states(left: &BeamState, right: &BeamState) -> Ordering {
    right
        .third_symbol_viable
        .cmp(&left.third_symbol_viable)
        .then_with(|| right.likelihood.cmp(&left.likelihood))
        .then_with(|| left.sources.cmp(&right.sources))
}

fn third_symbol_viability(
    n: usize,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    sources: &[Option<usize>],
    evaluations: &mut usize,
) -> bool {
    let Some(base) = representative_base(n, corpus, sources) else {
        return false;
    };
    let mut domains = (0..sources.len())
        .map(|letter| compatible_candidates(letter, corpus, domain, sources))
        .collect::<Vec<_>>();
    let mut constraints = Vec::new();
    for message in &corpus.messages {
        let Some([first, second, third]) = message.events.get(..3) else {
            continue;
        };
        let Some(third_source) = sources.get(third.letter).copied().flatten() else {
            continue;
        };
        if sources.get(first.letter).copied().flatten().is_none()
            || sources.get(second.letter).copied().flatten().is_none()
        {
            continue;
        }
        constraints.push((first.letter, second.letter, third_source, third.ct_value));
    }
    if constraints.is_empty() {
        return false;
    }
    third_constraints_arc_consistent(&base, domain, &mut domains, &constraints, evaluations)
}

fn third_constraints_arc_consistent(
    base: &[usize],
    domain: &SigmaDomain,
    domains: &mut [Vec<usize>],
    constraints: &[(usize, usize, usize, usize)],
    evaluations: &mut usize,
) -> bool {
    let mut changed = true;
    while changed {
        changed = false;
        for &(first, second, third_source, target) in constraints {
            if first == second {
                let current = domains.get(first).cloned().unwrap_or_default();
                let current_len = current.len();
                let retained = current
                    .into_iter()
                    .filter(|&candidate| {
                        third_symbol_matches(
                            base,
                            domain,
                            candidate,
                            candidate,
                            third_source,
                            target,
                            evaluations,
                        )
                    })
                    .collect::<Vec<_>>();
                if retained.is_empty() {
                    return false;
                }
                changed |= retained.len() < current_len;
                let Some(slot) = domains.get_mut(first) else {
                    return false;
                };
                *slot = retained;
                continue;
            }
            let second_domain = domains.get(second).cloned().unwrap_or_default();
            let first_current = domains.get(first).cloned().unwrap_or_default();
            let first_current_len = first_current.len();
            let first_retained = first_current
                .into_iter()
                .filter(|&first_candidate| {
                    second_domain.iter().any(|&second_candidate| {
                        third_symbol_matches(
                            base,
                            domain,
                            first_candidate,
                            second_candidate,
                            third_source,
                            target,
                            evaluations,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if first_retained.is_empty() {
                return false;
            }
            changed |= first_retained.len() < first_current_len;
            let Some(first_slot) = domains.get_mut(first) else {
                return false;
            };
            *first_slot = first_retained;

            let first_domain = domains.get(first).cloned().unwrap_or_default();
            let second_current = domains.get(second).cloned().unwrap_or_default();
            let second_current_len = second_current.len();
            let second_retained = second_current
                .into_iter()
                .filter(|&second_candidate| {
                    first_domain.iter().any(|&first_candidate| {
                        third_symbol_matches(
                            base,
                            domain,
                            first_candidate,
                            second_candidate,
                            third_source,
                            target,
                            evaluations,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if second_retained.is_empty() {
                return false;
            }
            changed |= second_retained.len() < second_current_len;
            let Some(second_slot) = domains.get_mut(second) else {
                return false;
            };
            *second_slot = second_retained;
        }
    }
    true
}

fn third_symbol_matches(
    base: &[usize],
    domain: &SigmaDomain,
    first_index: usize,
    second_index: usize,
    third_source: usize,
    target: usize,
    evaluations: &mut usize,
) -> bool {
    *evaluations = evaluations.saturating_add(1);
    let Some(first_sigma) = domain
        .candidates
        .get(first_index)
        .map(|candidate| candidate.sigma.as_slice())
    else {
        return false;
    };
    let Some(second_sigma) = domain
        .candidates
        .get(second_index)
        .map(|candidate| candidate.sigma.as_slice())
    else {
        return false;
    };
    base.get(third_source)
        .and_then(|&position| second_sigma.get(position))
        .and_then(|&position| base.get(position))
        .and_then(|&position| first_sigma.get(position))
        .and_then(|&position| base.get(position))
        .copied()
        == Some(target)
}

fn compatible_candidates(
    letter: usize,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    sources: &[Option<usize>],
) -> Vec<usize> {
    let Some(source) = sources.get(letter).copied().flatten() else {
        return Vec::new();
    };
    domain
        .by_top_source
        .get(source)
        .into_iter()
        .flatten()
        .copied()
        .filter(|&candidate_index| {
            let Some(candidate) = domain.candidates.get(candidate_index) else {
                return false;
            };
            corpus
                .pair_constraints
                .iter()
                .filter(|constraint| constraint.first_letter == letter)
                .all(|constraint| {
                    let emitted_source = sources
                        .get(constraint.emitted_anchor_letter)
                        .copied()
                        .flatten();
                    emitted_source.is_none()
                        || candidate.sigma.get(constraint.second_anchor_value).copied()
                            == emitted_source
                })
        })
        .collect()
}

fn representative_base(
    n: usize,
    corpus: &LocalCorpus,
    sources: &[Option<usize>],
) -> Option<Vec<usize>> {
    let mut base = vec![None; n];
    let mut value_used = vec![false; n];
    for (letter, target) in corpus.anchors.iter().copied().enumerate() {
        let Some(target) = target else {
            continue;
        };
        let source = sources.get(letter).copied().flatten()?;
        match base.get_mut(source)? {
            Some(previous) if *previous != target => return None,
            Some(_previous) => {}
            slot @ None => {
                *slot = Some(target);
                *value_used.get_mut(target)? = true;
            }
        }
    }
    let mut remaining = (0..n)
        .filter(|&value| !value_used.get(value).copied().unwrap_or(true))
        .rev()
        .collect::<Vec<_>>();
    for slot in &mut base {
        if slot.is_none() {
            *slot = remaining.pop();
        }
    }
    base.into_iter().collect()
}
