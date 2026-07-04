//! Soft-anchor scoring and canonical-class ranking.

use std::collections::BTreeMap;

use crate::ciphers::CipherError;

use super::engine::{
    CandidateEntry, CanonicalClass, KeyChoice, KeySpec, PreparedBasis, RepresentativeKey,
    ScoredSurvivor, SearchSummary,
};
use super::{Anchor, ShadowSearchError};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClassAccumulator {
    sequence_count: usize,
    key_multiplicity: u64,
    representative_key: RepresentativeKey,
}

pub(super) fn summarize(
    table: BTreeMap<Vec<u16>, CandidateEntry>,
    basis: &PreparedBasis,
    soft_anchors: &[Anchor],
    class_limit: usize,
) -> Result<(SearchSummary, Vec<ScoredSurvivor>), ShadowSearchError> {
    let mut survivors = Vec::with_capacity(table.len());
    let mut score_histogram = BTreeMap::new();
    let mut max_soft_score = 0usize;
    for (sequence, entry) in table {
        let soft_score = score_sequence(&sequence, soft_anchors);
        max_soft_score = max_soft_score.max(soft_score);
        *score_histogram.entry(soft_score).or_insert(0) += 1;
        survivors.push(ScoredSurvivor {
            q_sequence: sequence,
            key_multiplicity: entry.key_multiplicity,
            representative_key: representative_key(basis, &entry.representative)?,
            soft_score,
        });
    }

    let max_soft_sequence_count = survivors
        .iter()
        .filter(|survivor| survivor.soft_score == max_soft_score)
        .count();
    let mut classes = BTreeMap::<Vec<u16>, ClassAccumulator>::new();
    for survivor in survivors
        .iter()
        .filter(|survivor| survivor.soft_score == max_soft_score)
    {
        let canonical = canonicalize(&survivor.q_sequence, basis.legal_readouts.len());
        let _entry = classes
            .entry(canonical)
            .and_modify(|class| {
                class.sequence_count += 1;
                class.key_multiplicity += survivor.key_multiplicity;
            })
            .or_insert_with(|| ClassAccumulator {
                sequence_count: 1,
                key_multiplicity: survivor.key_multiplicity,
                representative_key: survivor.representative_key.clone(),
            });
    }

    let max_soft_canonical_class_count = classes.len();
    let mut top_canonical_classes = classes
        .into_iter()
        .map(|(canonical_pattern, class)| CanonicalClass {
            canonical_pattern,
            soft_score: max_soft_score,
            sequence_count: class.sequence_count,
            key_multiplicity: class.key_multiplicity,
            representative_key: class.representative_key,
        })
        .collect::<Vec<_>>();
    top_canonical_classes.sort_by(|left, right| {
        right
            .sequence_count
            .cmp(&left.sequence_count)
            .then_with(|| right.key_multiplicity.cmp(&left.key_multiplicity))
            .then_with(|| left.canonical_pattern.cmp(&right.canonical_pattern))
    });
    top_canonical_classes.truncate(class_limit);

    Ok((
        SearchSummary {
            total_keys: 0,
            pass1_survivor_keys: 0,
            pass2_survivor_keys: 0,
            deduped_sequences: survivors.len(),
            soft_anchor_count: soft_anchors.len(),
            max_soft_score,
            max_soft_sequence_count,
            max_soft_canonical_class_count,
            score_histogram,
            top_canonical_classes,
        },
        survivors,
    ))
}

fn score_sequence(sequence: &[u16], soft_anchors: &[Anchor]) -> usize {
    soft_anchors
        .iter()
        .filter(|anchor| spans_equal(sequence, anchor))
        .count()
}

fn spans_equal(sequence: &[u16], anchor: &Anchor) -> bool {
    let left = sequence.get(anchor.first..anchor.first + anchor.length);
    let right = sequence.get(anchor.second..anchor.second + anchor.length);
    left.zip(right).is_some_and(|(left, right)| left == right)
}

fn canonicalize(sequence: &[u16], symbol_count: usize) -> Vec<u16> {
    let mut labels = vec![None; symbol_count];
    let mut next = 0u16;
    let mut canonical = Vec::with_capacity(sequence.len());
    for &symbol in sequence {
        let index = usize::from(symbol);
        let label = if let Some(slot) = labels.get_mut(index) {
            if let Some(label) = *slot {
                label
            } else {
                let label = next;
                next = next.saturating_add(1);
                *slot = Some(label);
                label
            }
        } else {
            symbol
        };
        canonical.push(label);
    }
    canonical
}

fn representative_key(
    basis: &PreparedBasis,
    key: &KeySpec,
) -> Result<RepresentativeKey, ShadowSearchError> {
    let initial_state = basis.elements.get(key.initial_state_index).cloned().ok_or(
        CipherError::InternalInvariant {
            context: "shadow-search representative initial state",
        },
    )?;
    let mut choices = Vec::with_capacity(key.fiber_choices.len());
    for (legal_index, &fiber_choice) in key.fiber_choices.iter().enumerate() {
        let fiber = basis
            .fibers
            .get(legal_index)
            .ok_or(CipherError::InternalInvariant {
                context: "shadow-search representative fiber",
            })?;
        let element_index =
            fiber
                .get(fiber_choice)
                .copied()
                .ok_or(CipherError::InternalInvariant {
                    context: "shadow-search representative fiber choice",
                })?;
        let element =
            basis
                .elements
                .get(element_index)
                .cloned()
                .ok_or(CipherError::InternalInvariant {
                    context: "shadow-search representative fiber element",
                })?;
        choices.push(KeyChoice {
            readout: basis.legal_readouts.get(legal_index).copied().ok_or(
                CipherError::InternalInvariant {
                    context: "shadow-search representative readout",
                },
            )?,
            fiber_choice,
            element_index,
            element,
        });
    }
    Ok(RepresentativeKey {
        initial_state_index: key.initial_state_index,
        initial_state,
        choices,
    })
}
