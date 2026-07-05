//! Streaming enumeration engine for the shadow-finish ladder.

use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::{SplitMix64, fisher_yates, mix_seed};

use super::artifact::{PreparedClass, canonical_from_plaintext, encode_with_key};
use super::scoring::{WordSegModel, combined_score, score_anchor_words, score_quadgrams as quad};
use super::tables::{loose_printable, strict_language_byte};
use super::{
    CalibrationReport, DigitOrder, FinishCandidate, PairPhase, ShadowFinishArtifact,
    ShadowFinishConfig, ShadowFinishError, ShadowFinishReport, ShadowFinishTable,
    ShadowFinishVerdict, SurfaceReport, TierAReport, calibration_report,
};

const PERMUTATIONS_PER_CLASS: usize = 40_320;
const MAX_TOP_CANDIDATES: usize = 16;

#[derive(Clone, Debug)]
pub(super) struct TruthProbe<'a> {
    pub(super) plaintext: &'a [u8],
}

#[derive(Clone, Debug)]
pub(super) struct LadderOutcome {
    pub(super) report: ShadowFinishReport,
    pub(super) truth_tier_a_rank: Option<usize>,
}

#[derive(Clone, Debug)]
struct TierACandidate {
    class_index: usize,
    table_index: usize,
    phase: PairPhase,
    order: DigitOrder,
    permutation: [u8; 8],
    plaintext: Vec<u8>,
    quadgram_score: f64,
    strict_valid: bool,
}

#[derive(Clone, Debug)]
struct TierBScored {
    candidate: TierACandidate,
    word_score: f32,
    anchor_score: f32,
    combined_score: f64,
    roundtrip: bool,
}

#[derive(Clone, Debug)]
struct EnumerationSummary {
    tier_a: TierAReport,
    observed_best_tier_b: Vec<TierBScored>,
    truth_rank: Option<usize>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal engine entry keeps the artifact, prepared classes, models, and config explicit"
)]
pub(super) fn run_ladder(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    word_model: &WordSegModel,
    quadgram: &QuadgramModel,
    config: &ShadowFinishConfig,
    truth: Option<&TruthProbe<'_>>,
) -> Result<ShadowFinishReport, ShadowFinishError> {
    Ok(run_ladder_with_probe(
        artifact, prepared, ciphertext, tables, word_model, quadgram, config, truth,
    )?
    .report)
}

#[allow(
    clippy::too_many_arguments,
    reason = "control path needs the same explicit engine context plus a truth probe"
)]
pub(super) fn run_ladder_with_probe(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    word_model: &WordSegModel,
    quadgram: &QuadgramModel,
    config: &ShadowFinishConfig,
    truth: Option<&TruthProbe<'_>>,
) -> Result<LadderOutcome, ShadowFinishError> {
    if tables.is_empty() {
        return Err(ShadowFinishError::Table(
            "at least one charset table is required".to_owned(),
        ));
    }
    let surface = surface_report(prepared.len(), artifact.input_len, tables.len(), config);
    let estimated_mib = estimate_mib(prepared.len(), config.top_k_per_class);
    if estimated_mib > config.max_mem_mib {
        return Err(ShadowFinishError::MemoryCap {
            estimated_mib,
            cap_mib: config.max_mem_mib,
        });
    }

    let observed = enumerate_and_score(
        artifact, prepared, ciphertext, tables, word_model, quadgram, config, truth,
    )?;
    let observed_best = observed
        .observed_best_tier_b
        .first()
        .map_or(f64::NEG_INFINITY, |candidate| candidate.combined_score);
    let samples = matched_null_samples(
        artifact, prepared, ciphertext, tables, word_model, quadgram, config,
    )?;
    let calibration = calibration_report(observed_best, samples);
    let top_candidates = observed
        .observed_best_tier_b
        .iter()
        .take(MAX_TOP_CANDIDATES)
        .map(|scored| finish_candidate(scored, tables))
        .collect::<Vec<_>>();
    let best_roundtrip = top_candidates
        .first()
        .is_some_and(|candidate| candidate.roundtrip);
    let verdict = finish_verdict_with_alpha(best_roundtrip, &calibration, config.alpha);
    Ok(LadderOutcome {
        report: ShadowFinishReport {
            verdict,
            artifact_classes: prepared.len(),
            input_len: ciphertext.len(),
            table_names: tables.iter().map(|table| table.name.clone()).collect(),
            surface,
            tier_a: observed.tier_a,
            calibration,
            top_candidates,
            estimated_mib,
        },
        truth_tier_a_rank: observed.truth_rank,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "hot-loop worker receives borrowed context to avoid rebuilding per class/null"
)]
fn enumerate_and_score(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    word_model: &WordSegModel,
    quadgram: &QuadgramModel,
    config: &ShadowFinishConfig,
    truth: Option<&TruthProbe<'_>>,
) -> Result<EnumerationSummary, ShadowFinishError> {
    let permutations = all_permutations();
    let phases = phases(config);
    let orders = [DigitOrder::HighLow, DigitOrder::LowHigh];
    let mut tier_a = TierAReport {
        visited: 0,
        table_rejects: 0,
        loose_rejects: 0,
        strict_passes: 0,
        retained_for_tier_b: 0,
        top_k_dropped: 0,
    };
    let mut retained = Vec::new();
    let truth_reference_score = truth.map(|probe| quadgram_score(quadgram, probe.plaintext));
    let mut truth_better_tier_a = 0usize;
    let mut truth_seen_tier_a = false;

    for (class_index, class) in prepared.iter().enumerate() {
        validate_pattern_labels(&class.class.canonical_pattern)?;
        let mut top = Vec::<TierACandidate>::new();
        for &permutation in &permutations {
            for &phase in &phases {
                for &order in &orders {
                    for (table_index, table) in tables.iter().enumerate() {
                        tier_a.visited += 1;
                        let decoded = decode_pattern(
                            &class.class.canonical_pattern,
                            phase,
                            order,
                            permutation,
                            table,
                        );
                        let Some((plaintext, strict_valid)) = decoded else {
                            tier_a.table_rejects += 1;
                            continue;
                        };
                        if !plaintext.iter().copied().all(loose_printable) {
                            tier_a.loose_rejects += 1;
                            continue;
                        }
                        if strict_valid {
                            tier_a.strict_passes += 1;
                        }
                        let quadgram_score = quadgram_score(quadgram, &plaintext);
                        if truth.is_some_and(|probe| probe.plaintext == plaintext.as_slice()) {
                            truth_seen_tier_a = true;
                        } else if truth_reference_score
                            .is_some_and(|truth_score| quadgram_score > truth_score)
                        {
                            truth_better_tier_a += 1;
                        }
                        offer_top_a(
                            &mut top,
                            TierACandidate {
                                class_index,
                                table_index,
                                phase,
                                order,
                                permutation,
                                plaintext,
                                quadgram_score,
                                strict_valid,
                            },
                            config.top_k_per_class,
                            &mut tier_a.top_k_dropped,
                        );
                    }
                }
            }
        }
        retained.extend(top);
    }

    tier_a.retained_for_tier_b = retained.len();
    let mut scored = retained
        .iter()
        .map(|candidate| {
            score_tier_b(
                artifact, prepared, ciphertext, tables, word_model, candidate,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    scored.sort_by(|left, right| {
        right
            .combined_score
            .total_cmp(&left.combined_score)
            .then_with(|| {
                right
                    .candidate
                    .quadgram_score
                    .total_cmp(&left.candidate.quadgram_score)
            })
    });
    let truth_rank = if truth.is_some() && truth_seen_tier_a {
        Some(truth_better_tier_a + 1)
    } else {
        None
    };
    Ok(EnumerationSummary {
        tier_a,
        observed_best_tier_b: scored,
        truth_rank,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "matched null reruns the same borrowed scoring context over decoy classes"
)]
fn matched_null_samples(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    word_model: &WordSegModel,
    quadgram: &QuadgramModel,
    config: &ShadowFinishConfig,
) -> Result<Vec<f64>, ShadowFinishError> {
    let mut samples = Vec::with_capacity(config.null_trials);
    for trial in 0..config.null_trials {
        let decoys = decoy_classes(prepared, mix_seed(config.seed, trial as u64 + 0x6600))?;
        let summary = enumerate_and_score(
            artifact, &decoys, ciphertext, tables, word_model, quadgram, config, None,
        )?;
        let best = summary
            .observed_best_tier_b
            .first()
            .map_or(f64::NEG_INFINITY, |candidate| candidate.combined_score);
        samples.push(best);
    }
    Ok(samples)
}

fn decoy_classes(
    prepared: &[PreparedClass],
    seed: u64,
) -> Result<Vec<PreparedClass>, ShadowFinishError> {
    let mut rng = SplitMix64::new(seed);
    prepared
        .iter()
        .map(|class| {
            let mut decoy = class.clone();
            let mut shuffled = decoy.class.canonical_pattern.clone();
            fisher_yates(&mut shuffled, &mut rng).map_err(|error| {
                ShadowFinishError::Config(format!(
                    "decoy label shuffle rejected bound {}",
                    error.bound
                ))
            })?;
            decoy.class.canonical_pattern = shuffled;
            Ok(decoy)
        })
        .collect()
}

fn score_tier_b(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    word_model: &WordSegModel,
    candidate: &TierACandidate,
) -> Result<TierBScored, ShadowFinishError> {
    let word = word_model.score_text(&candidate.plaintext);
    let anchor = score_anchor_words(word_model, &candidate.plaintext, &artifact.hard_anchors);
    let combined = combined_score(candidate.quadgram_score, word, anchor);
    let roundtrip = exact_roundtrip(artifact, prepared, ciphertext, tables, candidate)?;
    Ok(TierBScored {
        candidate: candidate.clone(),
        word_score: word.mean_logp,
        anchor_score: anchor.mean_logp,
        combined_score: combined,
        roundtrip,
    })
}

fn exact_roundtrip(
    artifact: &ShadowFinishArtifact,
    prepared: &[PreparedClass],
    ciphertext: &[u16],
    tables: &[ShadowFinishTable],
    candidate: &TierACandidate,
) -> Result<bool, ShadowFinishError> {
    if candidate.phase != PairPhase::Phase0 {
        return Ok(false);
    }
    let table = tables.get(candidate.table_index).ok_or_else(|| {
        ShadowFinishError::RoundTrip(format!(
            "table index {} outside table set",
            candidate.table_index
        ))
    })?;
    let canonical = canonical_from_plaintext(
        &candidate.plaintext,
        table,
        candidate.order,
        candidate.permutation,
    )?;
    let Some(prepared_class) = prepared.get(candidate.class_index) else {
        return Err(ShadowFinishError::RoundTrip(format!(
            "class index {} outside prepared classes",
            candidate.class_index
        )));
    };
    if canonical != prepared_class.class.canonical_pattern {
        return Ok(false);
    }
    let actual = prepared_class.actual_from_canonical(&canonical)?;
    let rendered = encode_with_key(
        &actual,
        artifact.alphabet_size,
        &artifact.legal_readouts,
        &prepared_class.class.representative_key,
    )?;
    Ok(rendered == ciphertext)
}

fn decode_pattern(
    pattern: &[u16],
    phase: PairPhase,
    order: DigitOrder,
    permutation: [u8; 8],
    table: &ShadowFinishTable,
) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::with_capacity(pattern.len() / 2);
    let mut strict = true;
    for (left, right) in pair_iter(pattern, phase) {
        let left = *permutation.get(usize::from(left))?;
        let right = *permutation.get(usize::from(right))?;
        let value = match order {
            DigitOrder::HighLow => left * 8 + right,
            DigitOrder::LowHigh => right * 8 + left,
        };
        let byte = table.decode(value)?;
        strict &= strict_language_byte(byte);
        out.push(byte);
    }
    Some((out, strict))
}

fn pair_iter(pattern: &[u16], phase: PairPhase) -> impl Iterator<Item = (u16, u16)> + '_ {
    let start = match phase {
        PairPhase::Phase0 => 0,
        PairPhase::Phase1 => 1,
    };
    pattern
        .get(start..)
        .unwrap_or(&[])
        .chunks_exact(2)
        .filter_map(|chunk| match *chunk {
            [left, right] => Some((left, right)),
            _ => None,
        })
}

fn offer_top_a(
    top: &mut Vec<TierACandidate>,
    candidate: TierACandidate,
    cap: usize,
    dropped: &mut u128,
) {
    if top.len() < cap {
        top.push(candidate);
        return;
    }
    let Some((worst_index, worst)) = top
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| left.quadgram_score.total_cmp(&right.quadgram_score))
    else {
        return;
    };
    if candidate.quadgram_score > worst.quadgram_score
        && let Some(slot) = top.get_mut(worst_index)
    {
        *slot = candidate;
    }
    *dropped += 1;
}

fn surface_report(
    classes: usize,
    input_len: usize,
    tables: usize,
    config: &ShadowFinishConfig,
) -> SurfaceReport {
    let phases = if config.include_phase1 { 2 } else { 1 };
    let total_interpretations =
        classes as u128 * PERMUTATIONS_PER_CLASS as u128 * 2 * tables as u128 * phases as u128;
    SurfaceReport {
        classes,
        permutations_per_class: PERMUTATIONS_PER_CLASS,
        digit_orders: 2,
        tables,
        phases,
        total_interpretations,
        phase0_dropped_q_symbols: input_len % 2,
        phase1_dropped_q_symbols: config
            .include_phase1
            .then_some(1 + input_len.saturating_sub(1) % 2),
    }
}

fn finish_candidate(scored: &TierBScored, tables: &[ShadowFinishTable]) -> FinishCandidate {
    FinishCandidate {
        class_index: scored.candidate.class_index,
        table: tables.get(scored.candidate.table_index).map_or_else(
            || scored.candidate.table_index.to_string(),
            |table| table.name.clone(),
        ),
        phase: scored.candidate.phase,
        order: scored.candidate.order,
        permutation: scored.candidate.permutation,
        plaintext: scored.candidate.plaintext.clone(),
        quadgram_score: scored.candidate.quadgram_score,
        word_score: scored.word_score,
        anchor_score: scored.anchor_score,
        combined_score: scored.combined_score,
        strict_valid: scored.candidate.strict_valid,
        roundtrip: scored.roundtrip,
    }
}

fn all_permutations() -> Vec<[u8; 8]> {
    fn rec(position: usize, values: &mut [u8; 8], out: &mut Vec<[u8; 8]>) {
        if position == values.len() {
            out.push(*values);
            return;
        }
        for index in position..values.len() {
            values.swap(position, index);
            rec(position + 1, values, out);
            values.swap(position, index);
        }
    }
    let mut values = [0, 1, 2, 3, 4, 5, 6, 7];
    let mut out = Vec::with_capacity(PERMUTATIONS_PER_CLASS);
    rec(0, &mut values, &mut out);
    out
}

fn phases(config: &ShadowFinishConfig) -> Vec<PairPhase> {
    if config.include_phase1 {
        vec![PairPhase::Phase0, PairPhase::Phase1]
    } else {
        vec![PairPhase::Phase0]
    }
}

fn validate_pattern_labels(pattern: &[u16]) -> Result<(), ShadowFinishError> {
    if let Some(label) = pattern.iter().copied().find(|&label| label >= 8) {
        return Err(ShadowFinishError::Artifact(format!(
            "canonical label {label} exceeds the 8-digit finish surface"
        )));
    }
    Ok(())
}

fn quadgram_score(model: &QuadgramModel, plaintext: &[u8]) -> f64 {
    let score = quad(model, plaintext);
    if score.is_finite() {
        score
    } else {
        f64::NEG_INFINITY
    }
}

fn finish_verdict_with_alpha(
    best_roundtrip: bool,
    calibration: &CalibrationReport,
    alpha: f64,
) -> ShadowFinishVerdict {
    let min_p = 1.0 / (calibration.trials.saturating_add(1) as f64);
    if min_p > alpha {
        return ShadowFinishVerdict::LowPowerNoExclusion;
    }
    if calibration.p_emp > alpha {
        ShadowFinishVerdict::NoCandidate
    } else if best_roundtrip {
        ShadowFinishVerdict::RoundTripDecode
    } else {
        ShadowFinishVerdict::Candidate
    }
}

fn estimate_mib(classes: usize, top_k: usize) -> usize {
    let bytes = classes
        .saturating_mul(top_k)
        .saturating_mul(1024)
        .saturating_add(8 * 1024 * 1024);
    bytes.div_ceil(1024 * 1024)
}
