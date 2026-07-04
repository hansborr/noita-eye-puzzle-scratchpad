//! In-process controls for the closure-shadow key-search instrument.

use crate::analysis::isomorph_map::IsoMapError;
use crate::analysis::translate_isomorph::markov_resample;
use crate::nulls::null::{SplitMix64, mix_seed};

use super::{
    DEFAULT_CLASS_REPORT_LIMIT, DEFAULT_HARD_MIN_LEN, DEFAULT_SOFT_MAX_LEN, DEFAULT_SOFT_MIN_LEN,
    DEFAULT_SOFT_TRIM, NoBasisReason, ShadowSearchConfig, ShadowSearchError, ShadowSearchOutcome,
    run_shadow_search,
};

const S3_SIZE: usize = 3;
const CONTROL_NULL_TRIALS: usize = 24;
const CONTROL_TOP_K: usize = 24;
const CONTROL_MIN_SPAN: usize = 10;
const HARD_BLOCK_LEN: usize = 72;
const DIRTY_CORE_LEN: usize = 28;

/// Outcome of `shadowsearch --self-test`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test report DTO: each bool is an independent control verdict surfaced by the CLI"
)]
pub struct ShadowSearchSelfTest {
    /// The planted hidden-state positive survived all hard filters.
    pub positive_truth_survived: bool,
    /// The positive truth sequence reached the maximum soft score.
    pub positive_truth_at_max_soft: bool,
    /// Closure order recovered in the positive control.
    pub positive_closure_order: usize,
    /// Maximum soft score in the positive control.
    pub positive_max_soft_score: usize,
    /// Truth soft score in the positive control.
    pub positive_truth_soft_score: usize,
    /// The untrimmed dirty-boundary run killed the planted truth.
    pub untrimmed_anchor_killed_truth: bool,
    /// The trimmed dirty-boundary run retained the planted truth.
    pub trimmed_anchor_retained_truth: bool,
    /// The order-1 Markov matched null refused to search with a no-basis verdict.
    pub markov_null_no_basis: bool,
    /// No-basis reason returned by the Markov null.
    pub markov_null_reason: Option<NoBasisReason>,
    /// Overall self-test verdict.
    pub passed: bool,
}

/// Runs the planted positive, dirty-boundary failure, and matched-null controls.
///
/// # Errors
/// Returns [`ShadowSearchError`] when a control cannot be constructed or the
/// production scan/search path itself errors.
pub fn shadow_search_self_test(seed: u64) -> Result<ShadowSearchSelfTest, ShadowSearchError> {
    let positive = positive_fixture();
    let positive_report = run_shadow_search(
        &positive.ciphertext,
        positive.alphabet_size,
        control_config(seed),
    )?;
    let positive_truth_soft_score = truth_soft_score(&positive_report, &positive.truth_q_indices);
    let positive_max_soft_score = max_soft_score(&positive_report);
    let positive_truth_survived = positive_truth_soft_score.is_some();
    let positive_truth_at_max_soft =
        positive_truth_soft_score == Some(positive_max_soft_score) && positive_max_soft_score > 0;
    let positive_closure_order = positive_report
        .closure
        .as_ref()
        .map_or(0, |closure| closure.order);

    let dirty = dirty_fixture();
    let mut untrimmed_config = control_config(mix_seed(seed, 0x101));
    untrimmed_config.hard_anchor_trim = 0;
    let untrimmed = run_shadow_search(&dirty.ciphertext, dirty.alphabet_size, untrimmed_config)?;
    let untrimmed_anchor_killed_truth =
        matches!(untrimmed.outcome, ShadowSearchOutcome::Searched { .. })
            && truth_soft_score(&untrimmed, &dirty.truth_q_indices).is_none();

    let trimmed = run_shadow_search(
        &dirty.ciphertext,
        dirty.alphabet_size,
        control_config(mix_seed(seed, 0x202)),
    )?;
    let trimmed_anchor_retained_truth =
        truth_soft_score(&trimmed, &dirty.truth_q_indices).is_some();

    let null_values = markov_null(&positive.ciphertext, positive.alphabet_size, seed)?;
    let null_report = run_shadow_search(
        &null_values,
        positive.alphabet_size,
        control_config(mix_seed(seed, 0x303)),
    )?;
    let markov_null_reason = match null_report.outcome {
        ShadowSearchOutcome::NoBasis { reason } => Some(reason),
        ShadowSearchOutcome::Searched { .. } => None,
    };
    let markov_null_no_basis =
        markov_null_reason == Some(NoBasisReason::NoSignificantIsomorphStructure);

    let passed = positive_truth_survived
        && positive_truth_at_max_soft
        && positive_closure_order == 6
        && untrimmed_anchor_killed_truth
        && trimmed_anchor_retained_truth
        && markov_null_no_basis;
    Ok(ShadowSearchSelfTest {
        positive_truth_survived,
        positive_truth_at_max_soft,
        positive_closure_order,
        positive_max_soft_score,
        positive_truth_soft_score: positive_truth_soft_score.unwrap_or(0),
        untrimmed_anchor_killed_truth,
        trimmed_anchor_retained_truth,
        markov_null_no_basis,
        markov_null_reason,
        passed,
    })
}

fn control_config(seed: u64) -> ShadowSearchConfig {
    ShadowSearchConfig {
        min_span_len: CONTROL_MIN_SPAN,
        map_trim: 2,
        hard_anchor_trim: 2,
        hard_min_len: DEFAULT_HARD_MIN_LEN,
        top_k: CONTROL_TOP_K,
        null_trials: CONTROL_NULL_TRIALS,
        closure_cap: 256,
        seed,
        soft_min_len: DEFAULT_SOFT_MIN_LEN,
        soft_max_len: DEFAULT_SOFT_MAX_LEN,
        soft_trim: DEFAULT_SOFT_TRIM,
        class_report_limit: DEFAULT_CLASS_REPORT_LIMIT,
    }
}

#[derive(Clone, Debug)]
struct Fixture {
    ciphertext: Vec<u16>,
    truth_q_indices: Vec<u16>,
    alphabet_size: usize,
}

fn positive_fixture() -> Fixture {
    let mut builder = QBuilder::new();
    let block = patterned_block(HARD_BLOCK_LEN, 0);
    builder.append(&[1, 2, 1, 1, 2, 1, 2, 2]);
    builder.append(&block);
    builder.bridge_to(&[1, 0, 2]);
    builder.append(&block);
    builder.bridge_to(&[2, 1, 0]);
    builder.append(&block);
    builder.bridge_to(&[0, 1, 2]);
    for soft in [
        [1, 1, 2, 2, 1, 1],
        [2, 2, 1, 1, 2, 2],
        [1, 1, 1, 1, 2, 2],
        [2, 2, 2, 2, 1, 1],
    ] {
        builder.append(&soft);
        builder.append(&soft);
        builder.append(&[1, 2]);
        builder.bridge_to(&[0, 1, 2]);
    }
    builder.append(&[2, 1, 1, 2, 1]);
    fixture_from_q_values(&builder.q_values)
}

fn dirty_fixture() -> Fixture {
    let core = vec![1usize; DIRTY_CORE_LEN];
    let clean = guarded_full_block(44);
    let mut builder = QBuilder::new();
    builder.append(&[1, 2, 2, 1, 1, 2, 1, 2, 1]);
    builder.append(&clean);
    builder.bridge_to(&[1, 0, 2]);
    builder.append(&clean);
    builder.bridge_to(&[2, 1, 0]);
    builder.append(&clean);
    builder.bridge_to(&[0, 1, 2]);
    builder.append(&[2, 2]);
    builder.append(&core);
    builder.append(&[2, 1]);
    builder.append(&[1, 2, 1, 1, 2, 2, 1, 2]);
    builder.bridge_to(&[1, 0, 2]);
    builder.append(&[1, 2]);
    builder.append(&core);
    builder.append(&[1, 2]);
    builder.append(&[2, 1, 1, 2, 1, 2, 2]);
    fixture_from_q_values(&builder.q_values)
}

fn patterned_block(len: usize, phase: usize) -> Vec<usize> {
    (0..len)
        .map(|index| {
            if (index * 5 + phase * 3 + index / 3).is_multiple_of(2) {
                1
            } else {
                2
            }
        })
        .collect()
}

fn guarded_full_block(core_len: usize) -> Vec<usize> {
    let mut block = vec![1, 2, 1, 2];
    block.extend(patterned_block(core_len, 0));
    block.extend([2, 1, 2, 1]);
    block
}

fn fixture_from_q_values(q_values: &[usize]) -> Fixture {
    let initial = identity();
    let mut state = initial;
    let mut ciphertext = Vec::with_capacity(q_values.len());
    let mut truth_q_indices = Vec::with_capacity(q_values.len());
    for &q in q_values {
        let symbol = state.get(q).copied().unwrap_or(0);
        ciphertext.push(u16::try_from(symbol).unwrap_or(0));
        truth_q_indices.push(u16::try_from(q.saturating_sub(1)).unwrap_or(0));
        let gamma = gamma_for(q);
        state = compose_stage(gamma, &state);
    }
    Fixture {
        ciphertext,
        truth_q_indices,
        alphabet_size: S3_SIZE,
    }
}

#[derive(Clone, Debug)]
struct QBuilder {
    q_values: Vec<usize>,
    state: Vec<usize>,
}

impl QBuilder {
    fn new() -> Self {
        Self {
            q_values: Vec::new(),
            state: identity(),
        }
    }

    fn append(&mut self, values: &[usize]) {
        for &q in values {
            self.q_values.push(q);
            self.state = compose_stage(gamma_for(q), &self.state);
        }
    }

    fn bridge_to(&mut self, target: &[usize]) {
        if self.state == target {
            return;
        }
        if let Some(word) = bridge_word(&self.state, target) {
            self.append(&word);
        }
    }
}

fn bridge_word(start: &[usize], target: &[usize]) -> Option<Vec<usize>> {
    let mut frontier = vec![(start.to_vec(), Vec::new())];
    for _depth in 0..8 {
        let mut next = Vec::new();
        for (state, word) in frontier {
            for q in [1usize, 2] {
                let candidate = compose_stage(gamma_for(q), &state);
                let mut candidate_word = word.clone();
                candidate_word.push(q);
                if candidate == target {
                    return Some(candidate_word);
                }
                next.push((candidate, candidate_word));
            }
        }
        frontier = next;
    }
    None
}

fn identity() -> Vec<usize> {
    vec![0, 1, 2]
}

fn gamma_for(q: usize) -> &'static [usize; 3] {
    if q == 1 { &[1, 0, 2] } else { &[2, 1, 0] }
}

fn compose_stage(first: &[usize], second: &[usize]) -> Vec<usize> {
    first
        .iter()
        .filter_map(|&image| second.get(image).copied())
        .collect()
}

fn truth_soft_score(report: &super::ShadowSearchReport, truth: &[u16]) -> Option<usize> {
    match &report.outcome {
        ShadowSearchOutcome::NoBasis { .. } => None,
        ShadowSearchOutcome::Searched { survivors, .. } => survivors
            .iter()
            .find(|survivor| survivor.q_sequence == truth)
            .map(|survivor| survivor.soft_score),
    }
}

fn max_soft_score(report: &super::ShadowSearchReport) -> usize {
    match &report.outcome {
        ShadowSearchOutcome::NoBasis { .. } => 0,
        ShadowSearchOutcome::Searched { summary, .. } => summary.max_soft_score,
    }
}

fn markov_null(
    values: &[u16],
    alphabet_size: usize,
    seed: u64,
) -> Result<Vec<u16>, ShadowSearchError> {
    let stream: Vec<u32> = values.iter().map(|&value| u32::from(value)).collect();
    let mut rng = SplitMix64::new(mix_seed(seed, 0x404));
    let resampled = markov_resample(&stream, alphabet_size, &mut rng).map_err(IsoMapError::from)?;
    Ok(resampled
        .iter()
        .map(|&value| u16::try_from(value).unwrap_or(0))
        .collect())
}
