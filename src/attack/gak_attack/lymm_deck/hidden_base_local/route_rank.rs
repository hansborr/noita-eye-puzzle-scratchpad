//! Completion-aware route-domain relaxation for top-source ranking.

use super::base_completion::base_completions;
use super::corpus::LocalCorpus;
use super::search::SigmaDomain;
use super::top_source::compatible_candidates;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RouteRankScore {
    pub(super) coverage: usize,
    pub(super) evaluations: usize,
}

pub(super) fn route_relaxation_score(
    n: usize,
    completion_cap: usize,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    sources: &[Option<usize>],
) -> RouteRankScore {
    let Some((bases, _cap_exhausted)) = base_completions(n, corpus, sources, completion_cap) else {
        return RouteRankScore::default();
    };
    let candidates = (0..sources.len())
        .map(|letter| compatible_candidates(letter, corpus, domain, sources))
        .collect::<Vec<_>>();
    let mut score = RouteRankScore::default();
    for base in bases {
        let routes = build_routes(n, &base, domain, &candidates);
        let completion_coverage = completion_coverage(n, corpus, &routes, &mut score.evaluations);
        score.coverage = score.coverage.max(completion_coverage);
    }
    score
}

fn build_routes(
    n: usize,
    base: &[usize],
    domain: &SigmaDomain,
    candidates: &[Vec<usize>],
) -> Vec<Vec<Vec<usize>>> {
    candidates
        .iter()
        .map(|letter_candidates| {
            (0..n)
                .map(|position| {
                    let mut seen = vec![false; n];
                    for &candidate_index in letter_candidates {
                        let Some(source) = domain
                            .candidates
                            .get(candidate_index)
                            .and_then(|candidate| candidate.sigma.get(position))
                            .and_then(|&sigma_source| base.get(sigma_source))
                            .copied()
                        else {
                            continue;
                        };
                        if let Some(slot) = seen.get_mut(source) {
                            *slot = true;
                        }
                    }
                    seen.into_iter()
                        .enumerate()
                        .filter_map(|(source, present)| present.then_some(source))
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn completion_coverage(
    n: usize,
    corpus: &LocalCorpus,
    routes: &[Vec<Vec<usize>>],
    evaluations: &mut usize,
) -> usize {
    let mut total = 0usize;
    for message in &corpus.messages {
        let mut current = identity_domains(n);
        let mut next = vec![vec![false; n]; n];
        for event in &message.events {
            let Some(letter_routes) = routes.get(event.letter) else {
                break;
            };
            for position in 0..n {
                let Some(target_domain) = next.get_mut(position) else {
                    break;
                };
                target_domain.fill(false);
                let Some(position_routes) = letter_routes.get(position) else {
                    continue;
                };
                for &source in position_routes {
                    *evaluations = evaluations.saturating_add(1);
                    let Some(source_domain) = current.get(source) else {
                        continue;
                    };
                    for (value, possible) in source_domain.iter().copied().enumerate() {
                        if possible && let Some(slot) = target_domain.get_mut(value) {
                            *slot = true;
                        }
                    }
                }
            }
            let observed_possible = next
                .first()
                .and_then(|top| top.get(event.ct_value))
                .copied()
                .unwrap_or(false);
            if !observed_possible {
                break;
            }
            if let Some(top) = next.first_mut() {
                top.fill(false);
                if let Some(observed) = top.get_mut(event.ct_value) {
                    *observed = true;
                }
            }
            total = total.saturating_add(1);
            std::mem::swap(&mut current, &mut next);
        }
    }
    total
}

fn identity_domains(n: usize) -> Vec<Vec<bool>> {
    (0..n)
        .map(|position| {
            let mut domain = vec![false; n];
            if let Some(slot) = domain.get_mut(position) {
                *slot = true;
            }
            domain
        })
        .collect()
}
