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
}

pub(super) fn build_top_source_beam(
    n: usize,
    alphabet_len: usize,
    width: usize,
    restart_cap: usize,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    planted_sources: Option<&[Option<usize>]>,
) -> TopSourceBeam {
    let started = Instant::now();
    if corpus.anchor_conflict {
        return TopSourceBeam {
            hypotheses: Vec::new(),
            planted_hypothesis_rank: None,
            planted_hypothesis_retained: planted_sources.map(|_| false),
            states_expanded: 0,
            states_pruned: 1,
            states_dropped: 0,
            constraint_evaluations: 0,
            elapsed: started.elapsed(),
        };
    }
    let groups = anchor_groups(corpus);
    let mut states = vec![BeamState {
        sources: vec![None; alphabet_len],
        used_sources: vec![false; n],
        likelihood: 0,
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

    states.sort_by(compare_states);
    let retained_cap = width.min(restart_cap).max(1);
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
        .likelihood
        .cmp(&left.likelihood)
        .then_with(|| left.sources.cmp(&right.sources))
}
