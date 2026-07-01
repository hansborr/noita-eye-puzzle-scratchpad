//! MDL-like scoring and post-selection null evaluation.

use std::collections::BTreeSet;

use crate::attack::cribfit::{AnchorPair, crib_geometry};
use crate::attack::quadgram::QuadgramModel;
use crate::attack::rankcodec::{markov_resample_pinned, pinned_positions};
use crate::attack::rlcodec::substitution_search;
use crate::nulls::null::{SplitMix64, mix_seed};

use super::grid::{
    AffineCell, affine_stream, crib_consistent, english_feasible, enumerate_canonical_cells,
};
use super::{
    CellCoverage, MdlCarrierSummary, MdlCellReport, MdlCfg, MdlError, MdlNullSummary, MdlReport,
    MdlVerdict, derive_geometry,
};

const REAL_SEARCH_TAG: u64 = 0x6d64_6c63_5ea1_0001;
const NULL_MAG_TAG: u64 = 0x6d64_6c63_0011_0001;
const NULL_SEARCH_TAG: u64 = 0x6d64_6c63_5ea1_0011;
const SIGMA_FLOOR: f64 = 1e-9;

#[derive(Clone, Debug, PartialEq)]
struct EvaluatedCell {
    cell: AffineCell,
    effective_alphabet: usize,
    l_codec_bits: f64,
    l_text_bits: f64,
    mdl_bits: f64,
    candidate: String,
}

pub(super) fn analyze_magnitudes(
    carrier: MdlCarrierSummary,
    magnitudes: &[usize],
    cfg: &MdlCfg,
    model: &QuadgramModel,
) -> Result<MdlReport, MdlError> {
    let (geometry, census) = derive_geometry(magnitudes, cfg)?;
    let cells = enumerate_canonical_cells(&cfg.ring_sizes, cfg.coeff_max);
    if cells.is_empty() {
        return Err(MdlError::EmptyRingGrid);
    }

    let (coverage, mut evaluated) = evaluate_cells(
        magnitudes,
        &geometry.anchors,
        &cells,
        cfg,
        model,
        REAL_SEARCH_TAG,
    )?;
    if evaluated.is_empty() {
        return Err(MdlError::NoEvaluatedCells);
    }
    evaluated.sort_by(|left, right| left.mdl_bits.total_cmp(&right.mdl_bits));

    let null = post_selection_null(magnitudes, &geometry.anchors, &cells, cfg, model)?;
    let best_mdl = evaluated
        .first()
        .map(|cell| cell.mdl_bits)
        .ok_or(MdlError::NoEvaluatedCells)?;
    let underdetermined = evaluated
        .iter()
        .filter(|cell| cell.mdl_bits <= best_mdl + cfg.epsilon_bits)
        .collect::<Vec<_>>();
    let underdetermination_count = underdetermined.len();
    let underdetermination_spread_bits = underdetermined
        .iter()
        .map(|cell| cell.mdl_bits)
        .fold(best_mdl, f64::max)
        - best_mdl;

    let winner = report_cell(evaluated.first().ok_or(MdlError::NoEvaluatedCells)?, &null);
    let top_cells = evaluated
        .iter()
        .take(cfg.top)
        .map(|cell| report_cell(cell, &null))
        .collect::<Vec<_>>();
    let verdict = if winner.survivor && underdetermination_count == 1 {
        MdlVerdict::SelectedCandidate
    } else {
        MdlVerdict::UnderDetermined
    };

    Ok(MdlReport {
        carrier,
        geometry,
        census,
        coverage,
        null,
        top_cells,
        winner,
        underdetermination_count,
        underdetermination_spread_bits,
        verdict,
    })
}

fn evaluate_cells(
    magnitudes: &[usize],
    anchors: &[AnchorPair],
    cells: &[AffineCell],
    cfg: &MdlCfg,
    model: &QuadgramModel,
    seed_tag: u64,
) -> Result<(CellCoverage, Vec<EvaluatedCell>), MdlError> {
    let searched = cells.len();
    let mut eligible = 0usize;
    let mut feasible = 0usize;
    let mut deduped = 0usize;
    let mut seen_streams = BTreeSet::new();
    let mut evaluated = Vec::new();

    for (ordinal, &cell) in cells.iter().enumerate() {
        if !crib_consistent(anchors, cell) {
            continue;
        }
        eligible += 1;
        let stream = affine_stream(magnitudes, cell);
        if !english_feasible(&stream, cfg.min_effective_alphabet) {
            continue;
        }
        feasible += 1;
        if !seen_streams.insert(stream.dense.clone()) {
            continue;
        }
        deduped += 1;
        let seed = cell_seed(cfg.seed, seed_tag, ordinal, cell);
        let result = substitution_search(
            &stream.dense,
            stream.alphabet,
            model,
            cfg.restarts,
            cfg.iters,
            seed,
        )?;
        if result.skipped {
            continue;
        }
        let l_text_bits = text_cost_bits(result.best_sum);
        let l_codec_bits = codec_cost_bits(stream.alphabet, searched);
        evaluated.push(EvaluatedCell {
            cell,
            effective_alphabet: stream.alphabet,
            l_codec_bits,
            l_text_bits,
            mdl_bits: l_codec_bits + l_text_bits,
            candidate: result.text,
        });
    }

    Ok((
        CellCoverage {
            searched,
            eligible,
            feasible,
            deduped,
        },
        evaluated,
    ))
}

fn post_selection_null(
    magnitudes: &[usize],
    anchors: &[AnchorPair],
    cells: &[AffineCell],
    cfg: &MdlCfg,
    model: &QuadgramModel,
) -> Result<MdlNullSummary, MdlError> {
    let pairs = anchors
        .iter()
        .map(|anchor| (anchor.length, anchor.first, anchor.second))
        .collect::<Vec<_>>();
    let pinned = pinned_positions(magnitudes.len(), anchors);
    let alphabet = magnitudes.iter().copied().max().unwrap_or(1).max(1);
    let mut rng = SplitMix64::new(mix_seed(cfg.seed, NULL_MAG_TAG));
    let mut best_values = Vec::with_capacity(cfg.null_trials);

    for trial in 0..cfg.null_trials {
        let sampled = markov_resample_pinned(magnitudes, alphabet, &pinned, &mut rng)?;
        let geometry = crib_geometry(&sampled, &pairs);
        let tag = NULL_SEARCH_TAG ^ (trial as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let (_coverage, mut evaluated) =
            evaluate_cells(&sampled, &geometry.anchors, cells, cfg, model, tag)?;
        evaluated.sort_by(|left, right| left.mdl_bits.total_cmp(&right.mdl_bits));
        if let Some(best) = evaluated.first() {
            best_values.push(best.mdl_bits);
        }
    }

    if best_values.is_empty() {
        return Err(MdlError::NoEvaluatedNulls);
    }
    Ok(null_summary(&best_values, cfg.null_trials))
}

fn null_summary(values: &[f64], requested: usize) -> MdlNullSummary {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = sorted.len();
    let mean = sorted.iter().sum::<f64>() / count as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / count as f64;
    let p05_index = count.saturating_sub(1) / 20;
    MdlNullSummary {
        trials_requested: requested,
        trials_evaluated: count,
        mean_mdl_bits: mean,
        std_mdl_bits: variance.sqrt(),
        p05_mdl_bits: sorted.get(p05_index).copied().unwrap_or(mean),
        min_mdl_bits: sorted.first().copied().unwrap_or(mean),
        max_mdl_bits: sorted.last().copied().unwrap_or(mean),
    }
}

fn report_cell(cell: &EvaluatedCell, null: &MdlNullSummary) -> MdlCellReport {
    let delta = cell.mdl_bits - null.mean_mdl_bits;
    let z = if null.std_mdl_bits > SIGMA_FLOOR {
        delta / null.std_mdl_bits
    } else if delta < 0.0 {
        f64::NEG_INFINITY
    } else {
        0.0
    };
    MdlCellReport {
        cell: cell.cell,
        effective_alphabet: cell.effective_alphabet,
        l_codec_bits: cell.l_codec_bits,
        l_text_bits: cell.l_text_bits,
        mdl_bits: cell.mdl_bits,
        delta_mdl_bits: delta,
        z,
        survivor: cell.mdl_bits <= null.p05_mdl_bits,
        candidate: cell.candidate.clone(),
    }
}

pub(super) fn text_cost_bits(best_sum: f64) -> f64 {
    -best_sum / std::f64::consts::LN_2
}

pub(super) fn codec_cost_bits(effective_alphabet: usize, searched_grid_size: usize) -> f64 {
    permutation_charge_bits(effective_alphabet) + (searched_grid_size.max(1) as f64).log2()
}

fn permutation_charge_bits(effective_alphabet: usize) -> f64 {
    (0..effective_alphabet)
        .map(|offset| (26usize.saturating_sub(offset).max(1) as f64).log2())
        .sum()
}

fn cell_seed(seed: u64, seed_tag: u64, ordinal: usize, cell: AffineCell) -> u64 {
    let cell_tag = ((cell.ring as u64) << 40)
        ^ ((cell.a as u64) << 24)
        ^ ((cell.b as u64) << 8)
        ^ ordinal as u64;
    mix_seed(seed, seed_tag ^ cell_tag)
}
