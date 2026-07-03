//! Structured-coloring oracle-decode pipeline and controls.

use crate::attack::pairclass::campaign::{PowerCfg, StreamPrep};
use crate::attack::pairclass::plant::{
    CopySpan, Plant, PlantSpec, copy_ties, plant_from_text_with_coloring,
};
mod types;

pub use types::{
    StructuredControlCfg, StructuredDecodedCandidate, StructuredNegativeReport, StructuredNullCfg,
    StructuredNullGate, StructuredPlantOutcome, StructuredPowerReport, StructuredRunReport,
    StructuredVerdict, StructuredVerdictCfg, StructuredVerdictProfile, structured_verdict,
};

use crate::attack::pairclass::solve::{SolveCfg, SolveInput, solve};
use crate::attack::pairclass::structured::enumerate::{
    StructuredRunCfg, StructuredStream, expanded_family_colorings, generate_structured_candidates,
};
use crate::attack::pairclass::structured::nulls::{markov_resample_with_ties, prep_tie_to};
use crate::attack::pairclass::structured::random::draw_out_of_family_random_plant;
use crate::attack::pairclass::ties::tie_targets;
use crate::attack::pairclass::{Lexicon, PairclassError};
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

const STRUCTURED_CONTROL_TAG: u64 = 0x7374_7275_6374_0001;
const STRUCTURED_POSITIVE_NULL_TAG: u64 = 0x7374_7275_706f_736e;
const STRUCTURED_NEGATIVE_NULL_TAG: u64 = 0x7374_7275_6e65_676e;

#[derive(Clone, Copy)]
struct PlantNullCfg {
    null_trials: usize,
    seed: u64,
}

/// Runs the structured oracle-decode pipeline for the supplied streams.
/// # Errors
/// Propagates candidate-generation and solver errors.
pub fn run_structured_oracle_decode(
    streams: &[StructuredStream<'_>],
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
) -> Result<StructuredRunReport, PairclassError> {
    let generation = generate_structured_candidates(streams, word_entries, run_cfg)?;
    let rank_cfg = SolveCfg {
        beam: run_cfg.rank_beam,
        ..*solve_cfg
    };
    let mut attempts = Vec::with_capacity(generation.candidates.len());
    let mut total_expanded = 0u64;
    for candidate in &generation.candidates {
        let Some(stream) = streams
            .iter()
            .find(|stream| stream.label == candidate.stream_label)
        else {
            continue;
        };
        let report = solve(
            &SolveInput {
                tokens: stream.tokens,
                n_classes: stream.n_classes,
                tie_to: stream.tie_to,
                lexicon,
                truth: None,
                seed_coloring: Some(&candidate.coloring),
                accept_partial_final: false,
            },
            &rank_cfg,
        )?;
        total_expanded = total_expanded.saturating_add(report.expanded);
        attempts.push(StructuredDecodedCandidate {
            meta: candidate.clone(),
            solution: report.solutions.first().cloned(),
            confirm: None,
            expanded: report.expanded,
            feasible_final: report.feasible_final,
        });
    }
    let solutions = rank_structured_solutions(attempts.clone(), solve_cfg.top);
    Ok(StructuredRunReport {
        generation,
        attempts,
        solutions,
        total_expanded,
    })
}

/// Runs structured-coloring planted positives.
///
/// # Errors
/// Propagates plant construction, candidate generation, and solver errors.
pub fn measure_structured_power(
    text: &str,
    power: &PowerCfg,
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
    null_trials: usize,
) -> Result<StructuredPowerReport, PairclassError> {
    let letters = text_letters(text);
    let copy = tie_to_copy(power.longest_tie, power.plant_len);
    let control_coloring = choose_control_coloring(word_entries, run_cfg, power.seed)?;
    let mut plants = Vec::with_capacity(power.n_plants);
    for index in 0..power.n_plants {
        let source = plant_source(&letters, power.plant_len, index, power.n_plants);
        let plant = plant_from_text_with_coloring(
            &source,
            &PlantSpec {
                len: power.plant_len,
                n_classes: power.n_classes,
                copy,
            },
            control_coloring,
        )?;
        let prep = plant_prep(&plant, copy)?;
        let outcome = run_structured_plant(
            &plant,
            &prep,
            word_entries,
            lexicon,
            solve_cfg,
            run_cfg,
            PlantNullCfg {
                null_trials,
                seed: mix_seed(
                    power.seed.wrapping_add(index as u64),
                    STRUCTURED_POSITIVE_NULL_TAG,
                ),
            },
        )?;
        plants.push(outcome);
    }
    let mean_recovery = mean(plants.iter().map(|plant| plant.recovery));
    let all_truth_scored =
        !plants.is_empty() && plants.iter().all(|plant| plant.truth_score.is_some());
    Ok(StructuredPowerReport {
        plants,
        mean_recovery,
        cleared_bar: all_truth_scored && mean_recovery >= power.bar,
    })
}

/// Runs random-coloring negatives through the structured pipeline.
///
/// # Errors
/// Propagates plant construction, candidate generation, and solver errors.
pub fn measure_structured_random_negative(
    text: &str,
    power: &PowerCfg,
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
    control_cfg: &StructuredControlCfg,
) -> Result<StructuredNegativeReport, PairclassError> {
    let letters = text_letters(text);
    let copy = tie_to_copy(power.longest_tie, power.plant_len);
    let family_colorings = expanded_family_colorings(run_cfg.profile);
    let mut plants = Vec::with_capacity(power.n_plants);
    for index in 0..power.n_plants {
        let source = plant_source(&letters, power.plant_len, index, power.n_plants);
        let spec = PlantSpec {
            len: power.plant_len,
            n_classes: power.n_classes,
            copy,
        };
        let (plant, _redraws) =
            draw_out_of_family_random_plant(&source, &spec, power.seed, index, &family_colorings)?;
        let prep = plant_prep(&plant, copy)?;
        plants.push(run_structured_plant(
            &plant,
            &prep,
            word_entries,
            lexicon,
            solve_cfg,
            run_cfg,
            PlantNullCfg {
                null_trials: control_cfg.null_trials,
                seed: mix_seed(
                    power.seed.wrapping_add(index as u64),
                    STRUCTURED_NEGATIVE_NULL_TAG,
                ),
            },
        )?);
    }
    let false_positive_like = plants
        .iter()
        .filter(|plant| plant.null_significant(control_cfg.candidate_alpha))
        .count();
    Ok(StructuredNegativeReport {
        plants,
        false_positive_like,
        quiet: false_positive_like == 0,
    })
}

/// Runs the structured pipeline on matched Markov null resamples.
///
/// # Errors
/// Propagates resampling, candidate generation, and solver errors.
pub fn structured_null_gate(
    prep: &StreamPrep,
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
    null_cfg: &StructuredNullCfg,
) -> Result<StructuredNullGate, PairclassError> {
    let mut null_bests = Vec::with_capacity(null_cfg.null_trials);
    let mut null_candidate_counts = Vec::with_capacity(null_cfg.null_trials);
    let mut null_ge = 0usize;
    for trial in 0..null_cfg.null_trials {
        let tokens = markov_resample_with_ties(prep, null_cfg.seed.wrapping_add(trial as u64))?;
        let stream = StructuredStream {
            label: "null",
            tokens: &tokens,
            n_classes: prep.n_classes,
            tie_to: prep_tie_to(prep),
        };
        let report =
            run_structured_oracle_decode(&[stream], word_entries, lexicon, solve_cfg, run_cfg)?;
        null_candidate_counts.push(report.generation.candidates.len());
        let best = report.best_score();
        if let (Some(null), Some(observed)) = (best, null_cfg.observed_best)
            && null >= observed
        {
            null_ge += 1;
        }
        null_bests.push(best);
    }
    Ok(StructuredNullGate {
        observed_best: null_cfg.observed_best,
        null_bests,
        null_candidate_counts,
        null_ge,
    })
}

/// Runs the structured matched null across the same stream variants as real scoring.
///
/// Each trial resamples every stream variant and records the best structured
/// score seen across variants, matching the multiple-testing surface of the
/// real structured run.
///
/// # Errors
/// Propagates resampling, candidate generation, and solver errors.
pub fn structured_null_gate_streams(
    preps: &[StreamPrep],
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
    null_cfg: &StructuredNullCfg,
) -> Result<StructuredNullGate, PairclassError> {
    let mut null_bests = Vec::with_capacity(null_cfg.null_trials);
    let mut null_candidate_counts = Vec::with_capacity(null_cfg.null_trials);
    let mut null_ge = 0usize;
    for trial in 0..null_cfg.null_trials {
        let mut token_variants = Vec::with_capacity(preps.len());
        let mut labels = Vec::with_capacity(preps.len());
        for (variant, prep) in preps.iter().enumerate() {
            let trial_seed = null_cfg
                .seed
                .wrapping_add(trial as u64)
                .wrapping_add((variant as u64) << 32);
            token_variants.push(markov_resample_with_ties(prep, trial_seed)?);
            labels.push(format!("null-{variant}"));
        }
        let streams = token_variants
            .iter()
            .zip(labels.iter())
            .zip(preps)
            .map(|((tokens, label), prep)| StructuredStream {
                label: label.as_str(),
                tokens,
                n_classes: prep.n_classes,
                tie_to: prep_tie_to(prep),
            })
            .collect::<Vec<_>>();
        let report =
            run_structured_oracle_decode(&streams, word_entries, lexicon, solve_cfg, run_cfg)?;
        null_candidate_counts.push(report.generation.candidates.len());
        let best = report.best_score();
        if let (Some(null), Some(observed)) = (best, null_cfg.observed_best)
            && null >= observed
        {
            null_ge += 1;
        }
        null_bests.push(best);
    }
    Ok(StructuredNullGate {
        observed_best: null_cfg.observed_best,
        null_bests,
        null_candidate_counts,
        null_ge,
    })
}

fn run_structured_plant(
    plant: &Plant,
    prep: &StreamPrep,
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
    run_cfg: &StructuredRunCfg,
    null_cfg: PlantNullCfg,
) -> Result<StructuredPlantOutcome, PairclassError> {
    let tie_to = (!prep.tie_table.is_empty()).then_some(prep.tie_table.as_slice());
    let stream = StructuredStream {
        label: "plant",
        tokens: &prep.tokens,
        n_classes: prep.n_classes,
        tie_to,
    };
    let report =
        run_structured_oracle_decode(&[stream], word_entries, lexicon, solve_cfg, run_cfg)?;
    let truth = plant.coloring.map(Some);
    let truth_attempt = report
        .attempts
        .iter()
        .find(|attempt| attempt.meta.coloring == truth);
    let truth_candidate_rank = truth_attempt.map(|attempt| attempt.meta.rank);
    let truth_score = truth_attempt.and_then(StructuredDecodedCandidate::best_score);
    let truth_score_rank = truth_score_rank(&report, &truth);
    let recovery = truth_attempt
        .and_then(|attempt| attempt.solution.as_ref())
        .map_or(0.0, |solution| {
            letter_recovery(&solution.letters, &plant.letters)
        });
    let best_score = report.best_score();
    let truth_is_family_best = truth_score
        .zip(best_score)
        .is_some_and(|(truth_score, best_score)| truth_score >= best_score);
    let null = if null_cfg.null_trials == 0 {
        None
    } else {
        Some(structured_null_gate(
            prep,
            word_entries,
            lexicon,
            solve_cfg,
            run_cfg,
            &StructuredNullCfg {
                null_trials: null_cfg.null_trials,
                observed_best: best_score,
                seed: null_cfg.seed,
            },
        )?)
    };
    Ok(StructuredPlantOutcome {
        recovery,
        truth_candidate_rank,
        truth_score_rank,
        truth_score,
        best_score,
        truth_is_family_best,
        null,
    })
}

fn truth_score_rank(report: &StructuredRunReport, truth: &[Option<u8>; 26]) -> Option<usize> {
    let mut scored = report
        .attempts
        .iter()
        .filter(|attempt| attempt.best_score().is_some())
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        let a_score = a.best_score().unwrap_or(f32::NEG_INFINITY);
        let b_score = b.best_score().unwrap_or(f32::NEG_INFINITY);
        b_score
            .total_cmp(&a_score)
            .then_with(|| a.meta.rank.cmp(&b.meta.rank))
    });
    scored
        .iter()
        .position(|attempt| attempt.meta.coloring == *truth)
        .map(|index| index + 1)
}

fn choose_control_coloring(
    word_entries: &[(String, u64)],
    run_cfg: &StructuredRunCfg,
    seed: u64,
) -> Result<[u8; 26], PairclassError> {
    let stream_tokens = [0u8, 1, 2, 3];
    let stream = StructuredStream {
        label: "control",
        tokens: &stream_tokens,
        n_classes: 4,
        tie_to: None,
    };
    let mut cfg = *run_cfg;
    cfg.max_decodes = cfg.max_decodes.max(1);
    cfg.marginal_l1 = 2.0;
    let generated = generate_structured_candidates(&[stream], word_entries, &cfg)?;
    if generated.candidates.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    let mut rng = SplitMix64::new(mix_seed(seed, STRUCTURED_CONTROL_TAG));
    let index = random_index_below(generated.candidates.len(), &mut rng)
        .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?;
    let candidate = generated
        .candidates
        .get(index)
        .or_else(|| generated.candidates.first())
        .ok_or(PairclassError::EmptyInput)?;
    Ok(candidate.coloring.map(|slot| slot.unwrap_or(0)))
}

fn rank_structured_solutions(
    mut attempts: Vec<StructuredDecodedCandidate>,
    limit: usize,
) -> Vec<StructuredDecodedCandidate> {
    attempts.retain(|attempt| attempt.solution.is_some());
    attempts.sort_by(|a, b| {
        let a_score = a.best_score().unwrap_or(f32::NEG_INFINITY);
        let b_score = b.best_score().unwrap_or(f32::NEG_INFINITY);
        b_score
            .total_cmp(&a_score)
            .then_with(|| a.meta.rank.cmp(&b.meta.rank))
    });
    let mut seen = Vec::<Vec<u8>>::new();
    let mut out = Vec::new();
    for attempt in attempts {
        let Some(solution) = attempt.solution.as_ref() else {
            continue;
        };
        if seen.iter().any(|letters| letters == &solution.letters) {
            continue;
        }
        seen.push(solution.letters.clone());
        out.push(attempt);
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn plant_prep(plant: &Plant, copy: Option<CopySpan>) -> Result<StreamPrep, PairclassError> {
    let (tie_table, n_tied, longest_tie) = if let Some(span) = copy {
        let table = tie_targets(&copy_ties(span, plant.tokens.len())?, plant.tokens.len());
        let n_tied = table.iter().filter(|slot| slot.is_some()).count();
        (table, n_tied, Some((span.src, span.dst, span.len)))
    } else {
        (Vec::new(), 0, None)
    };
    Ok(StreamPrep {
        tokens: plant.tokens.clone(),
        n_classes: max_class(&plant.tokens),
        tie_table,
        n_tied,
        longest_tie,
    })
}

fn tie_to_copy(longest_tie: Option<(usize, usize, usize)>, plant_len: usize) -> Option<CopySpan> {
    let (_src, _dst, span_len) = longest_tie?;
    let span_len = span_len.min(plant_len / 3).max(1);
    if plant_len < 3 * span_len {
        return None;
    }
    Some(CopySpan {
        src: 0,
        dst: plant_len / 3,
        len: span_len,
    })
}

fn plant_source(letters: &[u8], plant_len: usize, index: usize, n_plants: usize) -> String {
    let start = plant_slice_start(letters.len(), plant_len, index, n_plants);
    letters
        .get(start..)
        .unwrap_or(&[])
        .iter()
        .map(|&letter| char::from(b'a' + letter.min(25)))
        .collect()
}

fn text_letters(text: &str) -> Vec<u8> {
    text.chars()
        .filter_map(|ch| {
            let lower = ch.to_ascii_lowercase();
            lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
        })
        .collect()
}

fn plant_slice_start(available: usize, plant_len: usize, index: usize, n_plants: usize) -> usize {
    if available <= plant_len || n_plants == 0 {
        return 0;
    }
    let span = available - plant_len;
    (span / n_plants.max(1)) * index
}

fn max_class(tokens: &[u8]) -> u8 {
    tokens.iter().copied().max().map_or(1, |max| max + 1)
}

fn letter_recovery(found: &[u8], truth: &[u8]) -> f64 {
    if truth.is_empty() {
        return 0.0;
    }
    let matched = found.iter().zip(truth).filter(|(a, b)| a == b).count();
    matched as f64 / truth.len() as f64
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let (sum, count) = values.fold((0.0, 0usize), |(sum, count), value| {
        (sum + value, count + 1)
    });
    if count == 0 { 0.0 } else { sum / count as f64 }
}
