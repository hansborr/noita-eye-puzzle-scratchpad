//! Substitution-first local search for ns=3 top-swap recovery.

use std::collections::BTreeMap;
use std::thread;
use std::time::Instant;

use crate::attack::gak_attack::lymm_deck::{
    LymmComposeDirection, LymmDeckSpec, TopSwapConstraints, TopSwapDomains,
    enumerate_top_swap_domains,
};
use crate::nulls::null::{RandomBoundError, SplitMix64, random_index_below};

use super::domain_oracle::LetterDomainOracle;
use super::local_search_data::{CandidateCache, LocalCorpus, Scorer, reset_identity};
use super::report::build_report_from_assignment;
use super::residual::ResidualDomains;
use super::{
    AlignedMessage, LetterRecoveryVerdict, RecoveryGeneratorSet, RecoveryReport,
    SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats,
};

const DEFAULT_PREFIX_LEN: usize = 90;
const DEFAULT_MAX_ATTEMPTS: usize = 60;
const LOCAL_SEARCH_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

pub(super) fn can_use_local_search(spec: &LymmDeckSpec, config: &SwapRecoveryConfig) -> bool {
    config.generator_set == RecoveryGeneratorSet::TopSwaps
        && (1..=3).contains(&config.max_swaps)
        && spec.compose_dir == LymmComposeDirection::Left
        && spec.emit_index == 0
        && u16::try_from(spec.n).is_ok()
        && spec
            .initial_state
            .iter()
            .copied()
            .eq(0..spec.initial_state.len())
}

pub(super) fn recover_with_local_search(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    if !can_use_local_search(spec, &config) {
        return Err(SwapRecoveryError::UnsupportedBudget {
            max_swaps: config.max_swaps,
        });
    }
    let domains = enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(config.max_swaps))?;
    let cache = CandidateCache::new(spec, &domains)?;
    let corpus = LocalCorpus::new(spec, messages)?;
    let started = Instant::now();
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: domains.candidates.len(),
        deductions: corpus
            .forced
            .iter()
            .filter(|forced| forced.is_some())
            .count(),
        ..SwapRecoveryStats::default()
    };
    let assignment = solve_key(&corpus, &cache, &config, started, &mut stats)?;
    build_local_report(spec, messages, config, domains, &corpus, &assignment, stats)
}

fn solve_key(
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    config: &SwapRecoveryConfig,
    started: Instant,
    stats: &mut SwapRecoveryStats,
) -> Result<Vec<usize>, SwapRecoveryError> {
    let max_attempts = config.max_nodes.map_or(DEFAULT_MAX_ATTEMPTS, |nodes| {
        nodes.min(DEFAULT_MAX_ATTEMPTS)
    });
    if max_attempts == 0 {
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: 0 });
    }

    let mut rng = SplitMix64::new(LOCAL_SEARCH_SEED);
    let mut seed = vec![cache.base_index; corpus.letter_count];
    let mut best = seed.clone();
    let mut best_residual = u32::MAX;
    for attempt in 0..max_attempts {
        check_time(config, started, attempt)?;
        let (phase1, _) = coordinate_descent_full(
            seed.clone(),
            corpus,
            cache,
            DEFAULT_PREFIX_LEN,
            10,
            config,
            started,
            attempt,
        )?;
        let (phase2, _) = coordinate_descent(
            phase1,
            corpus,
            cache,
            DEFAULT_PREFIX_LEN,
            25,
            config,
            started,
            attempt,
        )?;
        let (assignment, residual) =
            coordinate_descent(phase2, corpus, cache, 0, 12, config, started, attempt)?;
        stats.nodes = attempt.saturating_add(1);
        if residual < best_residual {
            best_residual = residual;
            best = assignment;
        }
        if residual == 0 {
            return Ok(best);
        }
        seed.clone_from(&best);
        perturb_seed(&mut seed, corpus, cache, &best, &mut rng)?;
    }
    Ok(best)
}

#[allow(
    clippy::too_many_arguments,
    reason = "keeps the three descent phases explicit without allocating a context object"
)]
fn coordinate_descent_full(
    mut assignment: Vec<usize>,
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    prefix: usize,
    max_rounds: usize,
    config: &SwapRecoveryConfig,
    started: Instant,
    nodes: usize,
) -> Result<(Vec<usize>, u32), SwapRecoveryError> {
    let mut scorer = Scorer::new(cache.n);
    for _round in 0..max_rounds {
        check_time(config, started, nodes)?;
        let mut improved = false;
        for &letter in &corpus.observed_letters {
            let top = if let Some(forced) = forced_top(corpus, letter) {
                usize::from(forced)
            } else {
                let representative = best_candidate(
                    &mut scorer,
                    &assignment,
                    corpus,
                    cache,
                    letter,
                    &cache.reps,
                    prefix,
                );
                cache.candidate_top(representative).unwrap_or(0)
            };
            let bucket = cache.bucket_for_top(top);
            let best = best_candidate(
                &mut scorer,
                &assignment,
                corpus,
                cache,
                letter,
                bucket,
                prefix,
            );
            if set_assignment(&mut assignment, letter, best) {
                improved = true;
            }
        }
        if !improved || scorer.mismatch(&assignment, corpus, cache, None, 0, 0, u32::MAX) == 0 {
            break;
        }
    }
    let residual = scorer.mismatch(&assignment, corpus, cache, None, 0, 0, u32::MAX);
    Ok((assignment, residual))
}

#[allow(
    clippy::too_many_arguments,
    reason = "keeps the three descent phases explicit without allocating a context object"
)]
fn coordinate_descent(
    mut assignment: Vec<usize>,
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    prefix: usize,
    max_rounds: usize,
    config: &SwapRecoveryConfig,
    started: Instant,
    nodes: usize,
) -> Result<(Vec<usize>, u32), SwapRecoveryError> {
    let mut scorer = Scorer::new(cache.n);
    for _round in 0..max_rounds {
        check_time(config, started, nodes)?;
        let residual = scorer.mismatch(&assignment, corpus, cache, None, 0, 0, u32::MAX);
        if residual == 0 {
            return Ok((assignment, 0));
        }
        let votes = vote_perm0(&assignment, corpus, cache);
        let mut improved = false;
        for &letter in &corpus.observed_letters {
            let Some(top) = forced_top(corpus, letter)
                .or_else(|| votes.get(letter).copied().flatten())
                .map(usize::from)
            else {
                continue;
            };
            let bucket = cache.bucket_for_top(top);
            let best = best_candidate(
                &mut scorer,
                &assignment,
                corpus,
                cache,
                letter,
                bucket,
                prefix,
            );
            if set_assignment(&mut assignment, letter, best) {
                improved = true;
            }
        }
        if !improved {
            break;
        }
    }
    let residual = scorer.mismatch(&assignment, corpus, cache, None, 0, 0, u32::MAX);
    Ok((assignment, residual))
}

fn best_candidate(
    scorer: &mut Scorer,
    assignment: &[usize],
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    letter: usize,
    candidates: &[usize],
    prefix: usize,
) -> usize {
    if candidates.len() > 512 {
        return best_candidate_parallel(assignment, corpus, cache, letter, candidates, prefix);
    }
    let mut best_index = current_assignment(assignment, letter, cache.base_index);
    let mut best_score = u32::MAX;
    for &candidate in candidates {
        let score = scorer.mismatch(
            assignment,
            corpus,
            cache,
            Some(letter),
            candidate,
            prefix,
            best_score,
        );
        if score < best_score || (score == best_score && candidate < best_index) {
            best_score = score;
            best_index = candidate;
        }
    }
    best_index
}

fn best_candidate_parallel(
    assignment: &[usize],
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    letter: usize,
    candidates: &[usize],
    prefix: usize,
) -> usize {
    let workers = thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(candidates.len())
        .max(1);
    let chunk_len = candidates.len().div_ceil(workers);
    let best = thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in candidates.chunks(chunk_len) {
            handles.push(scope.spawn(move || {
                let mut scorer = Scorer::new(cache.n);
                let mut best_index = usize::MAX;
                let mut best_score = u32::MAX;
                for &candidate in chunk {
                    let score = scorer.mismatch(
                        assignment,
                        corpus,
                        cache,
                        Some(letter),
                        candidate,
                        prefix,
                        best_score,
                    );
                    if score < best_score || (score == best_score && candidate < best_index) {
                        best_score = score;
                        best_index = candidate;
                    }
                }
                (best_score, best_index)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or((u32::MAX, usize::MAX)))
            .min_by_key(|&(score, candidate)| (score, candidate))
            .unwrap_or((u32::MAX, usize::MAX))
    });
    if best.1 == usize::MAX {
        current_assignment(assignment, letter, cache.base_index)
    } else {
        best.1
    }
}

fn vote_perm0(
    assignment: &[usize],
    corpus: &LocalCorpus,
    cache: &CandidateCache,
) -> Vec<Option<u16>> {
    let mut counts = vec![vec![0u32; cache.n]; corpus.letter_count];
    let mut cur = vec![0u16; cache.n];
    let mut nxt = vec![0u16; cache.n];
    let mut inverse = vec![0usize; cache.n];
    for message in &corpus.messages {
        reset_identity(&mut cur);
        for event in &message.events {
            for (position, &value) in cur.iter().enumerate() {
                if let Some(slot) = inverse.get_mut(usize::from(value)) {
                    *slot = position;
                }
            }
            let target = inverse
                .get(usize::from(event.ct_value))
                .copied()
                .unwrap_or(0);
            if let Some(count) = counts
                .get_mut(event.letter)
                .and_then(|row| row.get_mut(target))
            {
                *count = count.saturating_add(1);
            }
            cache.apply(
                current_assignment(assignment, event.letter, cache.base_index),
                &cur,
                &mut nxt,
            );
            std::mem::swap(&mut cur, &mut nxt);
        }
    }
    counts
        .into_iter()
        .map(|row| {
            row.iter()
                .copied()
                .enumerate()
                .max_by_key(|&(target, count)| (count, std::cmp::Reverse(target)))
                .and_then(|(target, count)| (count > 0).then(|| u16::try_from(target).ok()))
                .flatten()
        })
        .collect()
}

fn perturb_seed(
    seed: &mut [usize],
    corpus: &LocalCorpus,
    cache: &CandidateCache,
    best: &[usize],
    rng: &mut SplitMix64,
) -> Result<(), SwapRecoveryError> {
    let blame = blame_by_letter(best, corpus, cache);
    let mut order = corpus.observed_letters.clone();
    order.sort_by_key(|&letter| {
        (
            std::cmp::Reverse(blame.get(letter).copied().unwrap_or(0)),
            letter,
        )
    });
    let perturb_count = 2usize.saturating_add(draw_below(4, rng)?);
    let mut changed = 0usize;
    for letter in order {
        if forced_top(corpus, letter).is_some() {
            continue;
        }
        let top = cache
            .reps
            .get(draw_below(cache.reps.len(), rng)?)
            .copied()
            .ok_or_else(|| {
                SwapRecoveryError::SatSolver("empty local-search representative set".to_owned())
            })?;
        let top_image = cache.candidate_top(top).unwrap_or(0);
        let bucket = cache.by_top.get(top_image).ok_or_else(|| {
            SwapRecoveryError::SatSolver("empty local-search top bucket".to_owned())
        })?;
        let candidate = bucket
            .get(draw_below(bucket.len(), rng)?)
            .copied()
            .ok_or_else(|| {
                SwapRecoveryError::SatSolver("empty local-search top bucket".to_owned())
            })?;
        if let Some(slot) = seed.get_mut(letter) {
            *slot = candidate;
            changed = changed.saturating_add(1);
        }
        if changed >= perturb_count {
            break;
        }
    }
    Ok(())
}

fn blame_by_letter(assignment: &[usize], corpus: &LocalCorpus, cache: &CandidateCache) -> Vec<u32> {
    let mut blame = vec![0u32; corpus.letter_count];
    let mut cur = vec![0u16; cache.n];
    let mut nxt = vec![0u16; cache.n];
    for message in &corpus.messages {
        reset_identity(&mut cur);
        for event in &message.events {
            cache.apply(
                current_assignment(assignment, event.letter, cache.base_index),
                &cur,
                &mut nxt,
            );
            std::mem::swap(&mut cur, &mut nxt);
            if cur.first().copied().unwrap_or(u16::MAX) != event.ct_value
                && let Some(slot) = blame.get_mut(event.letter)
            {
                *slot = slot.saturating_add(1);
            }
        }
    }
    blame
}

fn build_local_report(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
    domains: TopSwapDomains,
    corpus: &LocalCorpus,
    assignment: &[usize],
    stats: SwapRecoveryStats,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut by_letter = BTreeMap::new();
    let mut assignment_by_letter = BTreeMap::new();
    for (letter_index, &letter) in spec.pt_alphabet.iter().enumerate() {
        let candidate = assignment.get(letter_index).copied().unwrap_or(0);
        let _old = by_letter.insert(letter, vec![candidate]);
        let _old = assignment_by_letter.insert(letter, candidate);
    }
    let residual = ResidualDomains {
        oracle: LetterDomainOracle::for_domains(spec, &domains),
        domains,
        by_letter,
        letters: corpus
            .observed_letters
            .iter()
            .filter_map(|&index| spec.pt_alphabet.get(index).copied())
            .collect(),
    };
    let mut report = build_report_from_assignment(
        spec,
        messages,
        config,
        &residual,
        &assignment_by_letter,
        stats,
    )?;
    if report.round_trip.exact() {
        report.verdict = LetterRecoveryVerdict::Candidate;
        for letter in &mut report.letters {
            if letter.occurrences > 0 {
                letter.verdict = LetterRecoveryVerdict::Candidate;
            }
        }
    }
    Ok(report)
}

fn check_time(
    config: &SwapRecoveryConfig,
    started: Instant,
    nodes: usize,
) -> Result<(), SwapRecoveryError> {
    if let Some(time_budget) = config.time_budget
        && started.elapsed() >= time_budget
    {
        return Err(SwapRecoveryError::SearchTimeExceeded { nodes });
    }
    Ok(())
}

fn draw_below(bound: usize, rng: &mut SplitMix64) -> Result<usize, SwapRecoveryError> {
    random_index_below(bound, rng).map_err(random_bound_error)
}

fn random_bound_error(error: RandomBoundError) -> SwapRecoveryError {
    SwapRecoveryError::SatSolver(format!(
        "deterministic random bound failed: {}",
        error.bound
    ))
}

fn forced_top(corpus: &LocalCorpus, letter: usize) -> Option<u16> {
    corpus.forced.get(letter).copied().flatten()
}

fn current_assignment(assignment: &[usize], letter: usize, fallback: usize) -> usize {
    assignment.get(letter).copied().unwrap_or(fallback)
}

fn set_assignment(assignment: &mut [usize], letter: usize, value: usize) -> bool {
    let Some(slot) = assignment.get_mut(letter) else {
        return false;
    };
    if *slot == value {
        false
    } else {
        *slot = value;
        true
    }
}
