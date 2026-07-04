//! Key enumeration, survivor dedupe, soft scoring, and canonicalization.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::isomorph_map::GroupClosure;
use crate::ciphers::{CipherError, validate_permutation};

use super::ranking::summarize;
use super::{Anchor, ShadowSearchConfig, ShadowSearchError};

/// Closure fiber for one legal readout symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiberReport {
    /// Readout symbol `q`.
    pub readout: usize,
    /// Number of closure elements with `g[0] == q`.
    pub size: usize,
    /// Indices of those elements in the closure element list.
    pub element_indices: Vec<usize>,
}

/// One selected fiber element in a representative key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChoice {
    /// Readout symbol this choice applies to.
    pub readout: usize,
    /// Choice index within the readout's fiber.
    pub fiber_choice: usize,
    /// Closure element index selected for this readout.
    pub element_index: usize,
    /// Selected closure element as a permutation.
    pub element: Vec<usize>,
}

/// One representative key for a deduplicated q-index sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepresentativeKey {
    /// Closure element index of `u_-1`.
    pub initial_state_index: usize,
    /// Initial state `u_-1` as a permutation.
    pub initial_state: Vec<usize>,
    /// One selected fiber element per legal readout.
    pub choices: Vec<KeyChoice>,
}

/// One deduplicated q-index sequence that survived all hard filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoredSurvivor {
    /// Length-`n` q-index sequence over `0..legal_readouts.len()`.
    pub q_sequence: Vec<u16>,
    /// Number of keys inducing this same q sequence on this ciphertext.
    pub key_multiplicity: u64,
    /// One representative key inducing this q sequence.
    pub representative_key: RepresentativeKey,
    /// Soft-anchor score, one point per satisfied soft anchor.
    pub soft_score: usize,
}

/// One canonical class under first-occurrence relabeling of q-index symbols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalClass {
    /// Canonical q pattern after first-occurrence relabeling.
    pub canonical_pattern: Vec<u16>,
    /// Soft score shared by this top class.
    pub soft_score: usize,
    /// Number of deduplicated survivor sequences in this class.
    pub sequence_count: usize,
    /// Sum of key multiplicities over sequences in this class.
    pub key_multiplicity: u64,
    /// Representative key from one sequence in this class.
    pub representative_key: RepresentativeKey,
}

/// Counts and rankings from the two-pass key search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSummary {
    /// Total keys enumerated.
    pub total_keys: u128,
    /// Keys that passed the first hard anchor and full-stream legality.
    pub pass1_survivor_keys: u64,
    /// Keys that passed every hard anchor before dedupe.
    pub pass2_survivor_keys: u64,
    /// Deduplicated q-index survivor sequences.
    pub deduped_sequences: usize,
    /// Number of soft anchors scored.
    pub soft_anchor_count: usize,
    /// Maximum soft score reached by any deduplicated survivor sequence.
    pub max_soft_score: usize,
    /// Number of deduplicated sequences reaching the maximum soft score.
    pub max_soft_sequence_count: usize,
    /// Number of canonical classes among maximum-soft-score sequences.
    pub max_soft_canonical_class_count: usize,
    /// Histogram `soft_score -> deduplicated sequence count`.
    pub score_histogram: BTreeMap<usize, usize>,
    /// Retained top canonical classes.
    pub top_canonical_classes: Vec<CanonicalClass>,
}

pub(super) struct PreparedBasis {
    pub(super) elements: Vec<Vec<usize>>,
    pub(super) legal_readouts: Vec<usize>,
    pub(super) fiber_reports: Vec<FiberReport>,
    pub(super) fibers: Vec<Vec<usize>>,
    pub(super) key_space: u128,
    inverses: Vec<Vec<usize>>,
    legal_lookup: Vec<Option<usize>>,
    composition: Vec<Vec<usize>>,
}

pub(super) struct KeySearchResult {
    pub(super) summary: SearchSummary,
    pub(super) survivors: Vec<ScoredSurvivor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct KeySpec {
    pub(super) initial_state_index: usize,
    pub(super) fiber_choices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CandidateEntry {
    pub(super) key_multiplicity: u64,
    pub(super) representative: KeySpec,
}

pub(super) fn prepare_basis(
    values: &[u16],
    alphabet_size: usize,
    closure: &GroupClosure,
) -> Result<PreparedBasis, ShadowSearchError> {
    let inverses = inverses(&closure.elements, alphabet_size)?;
    let legal_readouts = derive_legal_readouts(values, &closure.elements, &inverses);
    if legal_readouts.len() > usize::from(u16::MAX) + 1 {
        return Err(ShadowSearchError::TooManyLegalReadouts {
            count: legal_readouts.len(),
        });
    }
    let (fiber_reports, fibers) = build_fibers(&closure.elements, &legal_readouts)?;
    let key_space = key_space(closure.order, &fibers)?;
    let legal_lookup = legal_lookup(alphabet_size, &legal_readouts);
    let composition = stage_composition_table(&closure.elements)?;
    Ok(PreparedBasis {
        elements: closure.elements.clone(),
        legal_readouts,
        fiber_reports,
        fibers,
        key_space,
        inverses,
        legal_lookup,
        composition,
    })
}

pub(super) fn search(
    values: &[u16],
    basis: &PreparedBasis,
    hard_anchors: &[Anchor],
    soft_anchors: &[Anchor],
    config: ShadowSearchConfig,
) -> Result<KeySearchResult, ShadowSearchError> {
    let symbols: Vec<usize> = values.iter().map(|&value| usize::from(value)).collect();
    let Some(first_anchor) = hard_anchors.first() else {
        return Ok(empty_search_result(basis.key_space, soft_anchors.len()));
    };

    let mut table: BTreeMap<Vec<u16>, CandidateEntry> = BTreeMap::new();
    let mut choices = vec![0usize; basis.legal_readouts.len()];
    let mut total_keys = 0u128;
    let mut pass1_survivor_keys = 0u64;
    let mut pass2_survivor_keys = 0u64;
    let mut q_prefix = Vec::new();
    let mut q_history = Vec::new();

    loop {
        for initial_state_index in 0..basis.elements.len() {
            total_keys += 1;
            let key = KeySpec {
                initial_state_index,
                fiber_choices: choices.clone(),
            };
            if !survives_first_anchor(&symbols, basis, &key, first_anchor, &mut q_prefix) {
                continue;
            }
            pass1_survivor_keys += 1;
            let remaining_anchors = hard_anchors.get(1..).unwrap_or(&[]);
            let Some(sequence) =
                full_q_history(&symbols, basis, &key, &mut q_history, remaining_anchors)
            else {
                continue;
            };
            pass2_survivor_keys += 1;
            let _entry = table
                .entry(sequence)
                .and_modify(|entry| entry.key_multiplicity += 1)
                .or_insert(CandidateEntry {
                    key_multiplicity: 1,
                    representative: key,
                });
        }
        if !increment_choices(&mut choices, &basis.fibers) {
            break;
        }
    }

    debug_assert_eq!(total_keys, basis.key_space);
    let (summary, survivors) = summarize(table, basis, soft_anchors, config.class_report_limit)?;
    Ok(KeySearchResult {
        summary: SearchSummary {
            total_keys,
            pass1_survivor_keys,
            pass2_survivor_keys,
            ..summary
        },
        survivors,
    })
}

fn empty_search_result(total_keys: u128, soft_anchor_count: usize) -> KeySearchResult {
    KeySearchResult {
        summary: SearchSummary {
            total_keys,
            pass1_survivor_keys: 0,
            pass2_survivor_keys: 0,
            deduped_sequences: 0,
            soft_anchor_count,
            max_soft_score: 0,
            max_soft_sequence_count: 0,
            max_soft_canonical_class_count: 0,
            score_histogram: BTreeMap::new(),
            top_canonical_classes: Vec::new(),
        },
        survivors: Vec::new(),
    }
}

fn inverses(
    elements: &[Vec<usize>],
    alphabet_size: usize,
) -> Result<Vec<Vec<usize>>, ShadowSearchError> {
    elements
        .iter()
        .map(|element| invert_permutation(element, alphabet_size))
        .collect()
}

fn invert_permutation(
    permutation: &[usize],
    alphabet_size: usize,
) -> Result<Vec<usize>, ShadowSearchError> {
    validate_permutation("shadow-search group element", permutation, alphabet_size)?;
    let mut inverse = vec![0usize; alphabet_size];
    for (source, &target) in permutation.iter().enumerate() {
        let Some(slot) = inverse.get_mut(target) else {
            return Err(CipherError::InternalInvariant {
                context: "shadow-search inverse target",
            }
            .into());
        };
        *slot = source;
    }
    Ok(inverse)
}

fn derive_legal_readouts(
    values: &[u16],
    elements: &[Vec<usize>],
    inverses: &[Vec<usize>],
) -> Vec<usize> {
    let mut readouts = BTreeSet::new();
    for window in values.windows(2) {
        let [prev_raw, current_raw] = window else {
            continue;
        };
        let prev = usize::from(*prev_raw);
        let current = usize::from(*current_raw);
        for (state_index, state) in elements.iter().enumerate() {
            if state.first().copied() != Some(prev) {
                continue;
            }
            if let Some(readout) = inverses
                .get(state_index)
                .and_then(|inverse| inverse.get(current))
                .copied()
            {
                let _inserted = readouts.insert(readout);
            }
        }
    }
    readouts.into_iter().collect()
}

fn build_fibers(
    elements: &[Vec<usize>],
    legal_readouts: &[usize],
) -> Result<(Vec<FiberReport>, Vec<Vec<usize>>), ShadowSearchError> {
    let mut reports = Vec::with_capacity(legal_readouts.len());
    let mut fibers = Vec::with_capacity(legal_readouts.len());
    for &readout in legal_readouts {
        let element_indices: Vec<usize> = elements
            .iter()
            .enumerate()
            .filter_map(|(index, element)| {
                (element.first().copied() == Some(readout)).then_some(index)
            })
            .collect();
        if element_indices.is_empty() {
            return Err(ShadowSearchError::MissingFiber { readout });
        }
        reports.push(FiberReport {
            readout,
            size: element_indices.len(),
            element_indices: element_indices.clone(),
        });
        fibers.push(element_indices);
    }
    Ok((reports, fibers))
}

fn key_space(group_order: usize, fibers: &[Vec<usize>]) -> Result<u128, ShadowSearchError> {
    let mut total = group_order as u128;
    for fiber in fibers {
        total = total
            .checked_mul(fiber.len() as u128)
            .ok_or(ShadowSearchError::KeySpaceOverflow)?;
    }
    Ok(total)
}

fn legal_lookup(alphabet_size: usize, legal_readouts: &[usize]) -> Vec<Option<usize>> {
    let mut lookup = vec![None; alphabet_size];
    for (index, &readout) in legal_readouts.iter().enumerate() {
        if let Some(slot) = lookup.get_mut(readout) {
            *slot = Some(index);
        }
    }
    lookup
}

fn stage_composition_table(elements: &[Vec<usize>]) -> Result<Vec<Vec<usize>>, ShadowSearchError> {
    let mut index_by_element = BTreeMap::new();
    for (index, element) in elements.iter().enumerate() {
        let _previous = index_by_element.insert(element.clone(), index);
    }
    let mut table = Vec::with_capacity(elements.len());
    for gamma in elements {
        let mut row = Vec::with_capacity(elements.len());
        for state in elements {
            let product = compose_stage(gamma, state)?;
            let index =
                index_by_element
                    .get(&product)
                    .copied()
                    .ok_or(CipherError::InternalInvariant {
                        context: "shadow-search stage composition closure",
                    })?;
            row.push(index);
        }
        table.push(row);
    }
    Ok(table)
}

fn compose_stage(first: &[usize], second: &[usize]) -> Result<Vec<usize>, CipherError> {
    let mut composed = Vec::with_capacity(first.len());
    for &image in first {
        composed.push(
            second
                .get(image)
                .copied()
                .ok_or(CipherError::InternalInvariant {
                    context: "shadow-search stage composition index",
                })?,
        );
    }
    Ok(composed)
}

#[allow(
    clippy::indexing_slicing,
    reason = "hot loop over prevalidated dense tables; checked construction owns bounds"
)]
fn survives_first_anchor(
    symbols: &[usize],
    basis: &PreparedBasis,
    key: &KeySpec,
    anchor: &Anchor,
    q_prefix: &mut Vec<u16>,
) -> bool {
    let stop = anchor.second + anchor.length;
    q_prefix.clear();
    q_prefix.resize(stop, 0);
    let mut state = key.initial_state_index;
    for (position, &symbol) in symbols.iter().enumerate() {
        let readout = basis.inverses[state][symbol];
        let Some(q_index) = basis.legal_lookup[readout] else {
            return false;
        };
        if position < stop {
            let q_value = q_index as u16;
            q_prefix[position] = q_value;
            if position >= anchor.second {
                let left = anchor.first + (position - anchor.second);
                if q_prefix[left] != q_value {
                    return false;
                }
            }
        }
        let choice = key.fiber_choices[q_index];
        let gamma = basis.fibers[q_index][choice];
        state = basis.composition[gamma][state];
    }
    true
}

#[allow(
    clippy::indexing_slicing,
    reason = "hot loop over prevalidated dense tables; checked construction owns bounds"
)]
fn full_q_history(
    symbols: &[usize],
    basis: &PreparedBasis,
    key: &KeySpec,
    q_history: &mut Vec<u16>,
    anchors: &[Anchor],
) -> Option<Vec<u16>> {
    q_history.clear();
    q_history.resize(symbols.len(), 0);
    let mut state = key.initial_state_index;
    for (position, &symbol) in symbols.iter().enumerate() {
        let readout = basis.inverses[state][symbol];
        let q_index = basis.legal_lookup[readout]?;
        q_history[position] = q_index as u16;
        let choice = key.fiber_choices[q_index];
        let gamma = basis.fibers[q_index][choice];
        state = basis.composition[gamma][state];
    }
    anchors
        .iter()
        .all(|anchor| spans_equal(q_history, anchor))
        .then(|| q_history.clone())
}

fn spans_equal(sequence: &[u16], anchor: &Anchor) -> bool {
    let left = sequence.get(anchor.first..anchor.first + anchor.length);
    let right = sequence.get(anchor.second..anchor.second + anchor.length);
    left.zip(right).is_some_and(|(left, right)| left == right)
}

fn increment_choices(choices: &mut [usize], fibers: &[Vec<usize>]) -> bool {
    for (choice, fiber) in choices.iter_mut().zip(fibers) {
        *choice += 1;
        if *choice < fiber.len() {
            return true;
        }
        *choice = 0;
    }
    false
}
