//! Source-layer perturbation certificate for the AGL prefix obstruction.

use std::collections::BTreeSet;

use super::{
    AglGakError, AglGakGlobalPrefix, checked_streams, first_obstruction, first_symbols,
    global_prefix, global_prefix_obstruction, selected_shared_runs,
};
use crate::analysis::orders::{self, GlyphGrid};
use crate::analysis::perturbation::{DigitChange, DigitWindow, PerturbedMessage};
use crate::core::trigram::TrigramValue;
use crate::data::corpus::{Message, messages};
use crate::nulls::perseus;

const PREFIX_COORDS: [(usize, usize); 9] = [
    (0, 0),
    (0, 1),
    (1, 0),
    (1, 2),
    (1, 1),
    (0, 2),
    (0, 3),
    (0, 4),
    (1, 3),
];
const VERIFIED_PREFIX_START: usize = 1;
const VERIFIED_PREFIX_VALUES: [usize; 2] = [66, 5];

/// Source digits covered by the AGL transcription certificate for one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakTranscriptionFootprint {
    /// Message key, such as `east1`.
    pub message_key: &'static str,
    /// Non-delimiter source digit indices covered by the footprint.
    pub digit_indices: Vec<usize>,
}

/// A counterfactual perturbation that dissolved the AGL exclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakRobustnessBreak {
    /// One or two source-layer digit changes.
    pub changes: Vec<DigitChange>,
    /// Why the perturbation no longer supports the exclusion verdict.
    pub reason: AglGakRobustnessBreakReason,
}

/// Reason a perturbation no longer supports the AGL exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglGakRobustnessBreakReason {
    /// No varying shared run after differing predecessors survived.
    NoVaryingRunObstruction,
}

/// Summary for one exact perturbation depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakRobustnessSummary {
    /// Exact number of source digits changed per variant.
    pub changed_digits: usize,
    /// Total generated counterfactual variants.
    pub total_variants: usize,
    /// Variants for which the AGL exclusion still held.
    pub excluded_variants: usize,
    /// Variants where the all-message prefix still supplied an obstruction.
    pub global_prefix_obstruction_variants: usize,
    /// Variants that leave the accepted 83-symbol reading-layer alphabet.
    pub outside_alphabet_variants: usize,
    /// Variants preserving the exact verified prefix data from section 4.4.
    pub exact_verified_prefix_variants: usize,
    /// Perturbations that dissolved the AGL exclusion, if any.
    pub breaks: Vec<AglGakRobustnessBreak>,
}

/// Source-layer transcription certificate for the AGL load-bearing region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakTranscriptionRobustness {
    /// Per-message source digit footprints.
    pub footprints: Vec<AglGakTranscriptionFootprint>,
    /// Exact-one-source-digit certification.
    pub singles: AglGakRobustnessSummary,
    /// Exact-two-source-digit certification, bounded within one message footprint.
    pub doubles: AglGakRobustnessSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceDigit {
    digit_index: usize,
    raw_index: usize,
    old: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrefixFootprint {
    message: usize,
    message_key: &'static str,
    digit_indices: Vec<usize>,
    source_digits: Vec<SourceDigit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PerturbedVerdict {
    status: PerturbedExclusionStatus,
    global_prefix_obstruction: bool,
    exact_verified_prefix: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PerturbedExclusionStatus {
    Excluded,
    OutsideAlphabet,
    NotExcluded,
}

pub(super) fn certify_transcription_robustness()
-> Result<AglGakTranscriptionRobustness, AglGakError> {
    let footprints = prefix_footprints()?;
    let singles = certify_depth(&footprints, 1)?;
    let doubles = certify_depth(&footprints, 2)?;
    Ok(AglGakTranscriptionRobustness {
        footprints: footprints
            .iter()
            .map(|footprint| AglGakTranscriptionFootprint {
                message_key: footprint.message_key,
                digit_indices: footprint.digit_indices.clone(),
            })
            .collect(),
        singles,
        doubles,
    })
}

fn certify_depth(
    footprints: &[PrefixFootprint],
    changed_digits: usize,
) -> Result<AglGakRobustnessSummary, AglGakError> {
    let mut total_variants = 0usize;
    let mut excluded_variants = 0usize;
    let mut global_prefix_obstruction_variants = 0usize;
    let mut outside_alphabet_variants = 0usize;
    let mut exact_verified_prefix_variants = 0usize;
    let mut breaks = Vec::new();

    for footprint in footprints {
        for changes in change_sets(footprint, changed_digits)? {
            let variant = variant_for_changes(footprint, changes)?;
            let values = match crate::analysis::perturbation::message_values_for_variant(&variant) {
                Ok(values) => values,
                Err(_error) => {
                    return Err(AglGakError::InternalInvariant {
                        context: "AGL robustness perturbed grid rebuild",
                    });
                }
            };
            let verdict = classify_perturbed_values(&values)?;
            total_variants += 1;
            if verdict.status == PerturbedExclusionStatus::NotExcluded {
                breaks.push(AglGakRobustnessBreak {
                    changes: variant.changes,
                    reason: AglGakRobustnessBreakReason::NoVaryingRunObstruction,
                });
            } else {
                excluded_variants += 1;
            }
            if verdict.global_prefix_obstruction {
                global_prefix_obstruction_variants += 1;
            }
            if verdict.status == PerturbedExclusionStatus::OutsideAlphabet {
                outside_alphabet_variants += 1;
            }
            if verdict.exact_verified_prefix {
                exact_verified_prefix_variants += 1;
            }
        }
    }

    Ok(AglGakRobustnessSummary {
        changed_digits,
        total_variants,
        excluded_variants,
        global_prefix_obstruction_variants,
        outside_alphabet_variants,
        exact_verified_prefix_variants,
        breaks,
    })
}

fn classify_perturbed_values(
    message_values: &[Vec<TrigramValue>],
) -> Result<PerturbedVerdict, AglGakError> {
    let keys = messages()
        .iter()
        .map(|message| message.key)
        .collect::<Vec<_>>();
    let streams = match checked_streams(&keys, message_values) {
        Ok(streams) => streams,
        Err(AglGakError::ValueOutsideAlphabet { .. }) => {
            return Ok(PerturbedVerdict {
                status: PerturbedExclusionStatus::OutsideAlphabet,
                global_prefix_obstruction: false,
                exact_verified_prefix: false,
            });
        }
        Err(error) => return Err(error),
    };
    let first_symbols = first_symbols(&keys, &streams)?;
    let partition = perseus::build_shared_partition(&keys, message_values)?;
    let shared_runs = selected_shared_runs(&keys, &streams, &partition)?;
    let prefix = global_prefix(&partition);
    let obstruction = first_obstruction(&keys, &streams, &shared_runs, prefix.as_ref())?;
    let global_prefix_obstruction =
        global_prefix_obstruction(&keys, &streams, prefix.as_ref())?.is_some();

    Ok(PerturbedVerdict {
        status: if obstruction.is_some() {
            PerturbedExclusionStatus::Excluded
        } else {
            PerturbedExclusionStatus::NotExcluded
        },
        global_prefix_obstruction,
        exact_verified_prefix: exact_verified_prefix(&first_symbols, prefix.as_ref()),
    })
}

fn exact_verified_prefix(
    first_symbols: &[(&'static str, usize)],
    prefix: Option<&AglGakGlobalPrefix>,
) -> bool {
    let Some(prefix) = prefix else {
        return false;
    };
    let expected = VERIFIED_PREFIX_VALUES.to_vec();
    let distinct_starts = first_symbols
        .iter()
        .map(|(_key, value)| *value)
        .collect::<BTreeSet<_>>();
    prefix.start == VERIFIED_PREFIX_START
        && prefix.values == expected
        && prefix.distinct_symbols == VERIFIED_PREFIX_VALUES.len()
        && distinct_starts.len() == first_symbols.len()
}

fn prefix_footprints() -> Result<Vec<PrefixFootprint>, AglGakError> {
    let grids = orders::corpus_grids()?;
    let mut footprints = Vec::new();
    for (message, grid) in grids.iter().enumerate() {
        let corpus_message = messages()
            .get(message)
            .ok_or(AglGakError::InternalInvariant {
                context: "AGL robustness message lookup",
            })?;
        let digit_indices = prefix_digit_indices(grid)?;
        let source_digits = digit_indices
            .iter()
            .map(|&digit_index| source_digit(corpus_message, digit_index))
            .collect::<Result<Vec<_>, _>>()?;
        footprints.push(PrefixFootprint {
            message,
            message_key: corpus_message.key,
            digit_indices,
            source_digits,
        });
    }
    Ok(footprints)
}

fn prefix_digit_indices(grid: &GlyphGrid) -> Result<Vec<usize>, AglGakError> {
    let rows = grid.orientation_rows();
    let mut indices = PREFIX_COORDS
        .iter()
        .map(|&(row, column)| digit_index_for_coord(rows, row, column))
        .collect::<Result<Vec<_>, _>>()?;
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

fn digit_index_for_coord(
    rows: &[Vec<crate::core::glyph::Orientation>],
    row: usize,
    column: usize,
) -> Result<usize, AglGakError> {
    let Some(cells) = rows.get(row) else {
        return Err(AglGakError::InternalInvariant {
            context: "AGL robustness footprint row",
        });
    };
    if column >= cells.len() {
        return Err(AglGakError::InternalInvariant {
            context: "AGL robustness footprint column",
        });
    }
    Ok(rows.iter().take(row).map(Vec::len).sum::<usize>() + column)
}

fn source_digit(message: &Message, digit_index: usize) -> Result<SourceDigit, AglGakError> {
    let mut current = 0usize;
    for (raw_index, byte) in message.digits.bytes().enumerate() {
        match byte {
            b'0'..=b'4' => {
                if current == digit_index {
                    return Ok(SourceDigit {
                        digit_index,
                        raw_index,
                        old: byte - b'0',
                    });
                }
                current += 1;
            }
            b'5' => {}
            _ => {
                return Err(AglGakError::InternalInvariant {
                    context: "AGL robustness malformed source digit",
                });
            }
        }
    }
    Err(AglGakError::InternalInvariant {
        context: "AGL robustness source digit lookup",
    })
}

fn change_sets(
    footprint: &PrefixFootprint,
    changed_digits: usize,
) -> Result<Vec<Vec<DigitChange>>, AglGakError> {
    match changed_digits {
        1 => Ok(single_change_sets(footprint)),
        2 => Ok(double_change_sets(footprint)),
        _ => Err(AglGakError::InternalInvariant {
            context: "AGL robustness changed digit depth",
        }),
    }
}

fn single_change_sets(footprint: &PrefixFootprint) -> Vec<Vec<DigitChange>> {
    let mut sets = Vec::new();
    for source in &footprint.source_digits {
        for new in alternative_digits(source.old) {
            sets.push(vec![digit_change(footprint, source, new)]);
        }
    }
    sets
}

fn double_change_sets(footprint: &PrefixFootprint) -> Vec<Vec<DigitChange>> {
    let mut sets = Vec::new();
    for (left_index, left) in footprint.source_digits.iter().enumerate() {
        for right in footprint.source_digits.iter().skip(left_index + 1) {
            for left_new in alternative_digits(left.old) {
                for right_new in alternative_digits(right.old) {
                    sets.push(vec![
                        digit_change(footprint, left, left_new),
                        digit_change(footprint, right, right_new),
                    ]);
                }
            }
        }
    }
    sets
}

fn alternative_digits(old: u8) -> impl Iterator<Item = u8> {
    (0..=4).filter(move |&candidate| candidate != old)
}

fn digit_change(footprint: &PrefixFootprint, source: &SourceDigit, new: u8) -> DigitChange {
    DigitChange {
        message: footprint.message,
        message_key: footprint.message_key,
        digit_index: source.digit_index,
        raw_index: source.raw_index,
        old: source.old,
        new,
    }
}

fn variant_for_changes(
    footprint: &PrefixFootprint,
    changes: Vec<DigitChange>,
) -> Result<PerturbedMessage, AglGakError> {
    let message = messages()
        .get(footprint.message)
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL robustness variant message lookup",
        })?;
    let mut digits = message.digits.as_bytes().to_vec();
    for change in &changes {
        let Some(byte) = digits.get_mut(change.raw_index) else {
            return Err(AglGakError::InternalInvariant {
                context: "AGL robustness variant raw index",
            });
        };
        *byte = b'0' + change.new;
    }
    let start = footprint.digit_indices.first().copied().unwrap_or_default();
    let len = footprint
        .digit_indices
        .last()
        .copied()
        .and_then(|last| last.checked_sub(start))
        .map_or(0, |delta| delta + 1);
    Ok(PerturbedMessage {
        window: DigitWindow {
            message: footprint.message,
            start,
            len,
        },
        changes,
        digits: digits.into_iter().map(char::from).collect(),
    })
}
