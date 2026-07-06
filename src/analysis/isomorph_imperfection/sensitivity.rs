//! Source-layer Stutter-region sensitivity certificate for G2.

use std::collections::BTreeSet;

use super::{
    EXTENDED_WINDOWS, IsomorphImperfectionError, LooseCandidate, collect_loose_candidates,
    counts_from_breaks, scan_breaks, to_symbol_messages,
};
use crate::analysis::orders::{self, GlyphGrid};
use crate::analysis::perturbation::{DigitChange, DigitWindow, PerturbedMessage};
use crate::core::glyph::Orientation;
use crate::core::trigram::TrigramValue;
use crate::data::corpus::{Message, messages};

const STUTTER_KEYS: [&str; 3] = ["east4", "west4", "east5"];
const STUTTER_START: usize = 65;
const STUTTER_END: usize = 69;

/// Source digits covered by the Stutter sensitivity certificate for one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StutterSensitivityFootprint {
    /// Message key, such as `east4`.
    pub message_key: &'static str,
    /// Non-delimiter source digit indices covered by the footprint.
    pub digit_indices: Vec<usize>,
}

/// A counterfactual perturbation that promoted a robust internal violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StutterSensitivityFlip {
    /// One or two source-layer digit changes.
    pub changes: Vec<DigitChange>,
    /// Promoted non-benign loose candidates under this counterfactual.
    pub promoted_candidates: Vec<LooseCandidate>,
}

/// Summary for one exact perturbation depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StutterSensitivitySummary {
    /// Exact number of source digits changed per variant.
    pub changed_digits: usize,
    /// Total generated counterfactual variants.
    pub total_variants: usize,
    /// Variants that still have zero promoted robust internal violations.
    pub surviving_negative_variants: usize,
    /// Variants that promote at least one robust internal violation.
    pub promoted_variants: usize,
    /// Exact perturbations that promote candidates, if any.
    pub flips: Vec<StutterSensitivityFlip>,
}

/// Source-layer sensitivity certificate for the G2 Stutter loose candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StutterSensitivity {
    /// Reading-layer offsets covered in each selected message.
    pub reading_offsets: Vec<usize>,
    /// Per-message source digit footprints.
    pub footprints: Vec<StutterSensitivityFootprint>,
    /// Exact-one-source-digit certification.
    pub singles: StutterSensitivitySummary,
    /// Exact-two-source-digit certification, bounded within one message footprint.
    pub doubles: StutterSensitivitySummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceDigit {
    digit_index: usize,
    raw_index: usize,
    old: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StutterFootprint {
    message: usize,
    message_key: &'static str,
    digit_indices: Vec<usize>,
    source_digits: Vec<SourceDigit>,
}

pub(super) fn certify_stutter_sensitivity(
    base_values: &[Vec<TrigramValue>],
) -> Result<StutterSensitivity, IsomorphImperfectionError> {
    let footprints = stutter_footprints()?;
    let stutter_values = stutter_values(base_values)?;
    let singles = certify_depth(&footprints, &stutter_values, 1)?;
    let doubles = certify_depth(&footprints, &stutter_values, 2)?;
    Ok(StutterSensitivity {
        reading_offsets: (STUTTER_START..=STUTTER_END).collect(),
        footprints: footprints
            .iter()
            .map(|footprint| StutterSensitivityFootprint {
                message_key: footprint.message_key,
                digit_indices: footprint.digit_indices.clone(),
            })
            .collect(),
        singles,
        doubles,
    })
}

fn certify_depth(
    footprints: &[StutterFootprint],
    base_stutter_values: &[Vec<TrigramValue>],
    changed_digits: usize,
) -> Result<StutterSensitivitySummary, IsomorphImperfectionError> {
    let keys = STUTTER_KEYS.to_vec();
    let mut total_variants = 0usize;
    let mut surviving_negative_variants = 0usize;
    let mut flips = Vec::new();

    for footprint in footprints {
        for changes in change_sets(footprint, changed_digits)? {
            let variant = variant_for_changes(footprint, changes)?;
            let values = stutter_values_for_variant(base_stutter_values, footprint, &variant)?;
            let promoted_candidates = promoted_candidates(&keys, &values);
            total_variants += 1;
            if promoted_candidates.is_empty() {
                surviving_negative_variants += 1;
            } else {
                flips.push(StutterSensitivityFlip {
                    changes: variant.changes,
                    promoted_candidates,
                });
            }
        }
    }

    Ok(StutterSensitivitySummary {
        changed_digits,
        total_variants,
        surviving_negative_variants,
        promoted_variants: flips.len(),
        flips,
    })
}

fn promoted_candidates(
    keys: &[&'static str],
    values: &[Vec<crate::core::trigram::TrigramValue>],
) -> Vec<LooseCandidate> {
    let messages = to_symbol_messages(values);
    let breaks = scan_breaks(keys, &messages, &EXTENDED_WINDOWS);
    let counts = counts_from_breaks(&breaks);
    if counts.robust_internal_violations == 0 {
        return Vec::new();
    }
    collect_loose_candidates(keys, &breaks)
        .into_iter()
        .filter(|candidate| candidate.promoted_to_violation)
        .collect()
}

fn stutter_values(
    values: &[Vec<TrigramValue>],
) -> Result<Vec<Vec<TrigramValue>>, IsomorphImperfectionError> {
    let mut selected = Vec::new();
    for key in STUTTER_KEYS {
        let index = message_index_for_key(key)?;
        let message = values
            .get(index)
            .ok_or(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity perturbed message lookup",
            })?;
        selected.push(message.clone());
    }
    Ok(selected)
}

fn stutter_values_for_variant(
    base_stutter_values: &[Vec<TrigramValue>],
    footprint: &StutterFootprint,
    variant: &PerturbedMessage,
) -> Result<Vec<Vec<TrigramValue>>, IsomorphImperfectionError> {
    let mut values = base_stutter_values.to_vec();
    let stutter_index = STUTTER_KEYS
        .iter()
        .position(|key| *key == footprint.message_key)
        .ok_or(IsomorphImperfectionError::InternalInvariant {
            context: "Stutter sensitivity family index",
        })?;
    let slot =
        values
            .get_mut(stutter_index)
            .ok_or(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity family value slot",
            })?;
    *slot = read_variant_message_values(footprint.message_key, &variant.digits)?;
    Ok(values)
}

fn read_variant_message_values(
    message_key: &'static str,
    digits: &str,
) -> Result<Vec<TrigramValue>, IsomorphImperfectionError> {
    let grid = grid_from_digits(message_key, digits)?;
    Ok(orders::read_grid_values(
        &grid,
        orders::accepted_honeycomb_order(),
    )?)
}

fn grid_from_digits(
    message_key: &'static str,
    digits: &str,
) -> Result<GlyphGrid, IsomorphImperfectionError> {
    let mut rows = Vec::new();
    let mut current = Vec::new();
    for byte in digits.bytes() {
        match byte {
            b'0'..=b'4' => current.push(Orientation::from_base5_digit(byte - b'0')),
            b'5' => {
                if current.is_empty() {
                    return Err(orders::GridError::EmptyInteriorRow { message_key }.into());
                }
                rows.push(current);
                current = Vec::new();
            }
            _ => {
                return Err(IsomorphImperfectionError::InternalInvariant {
                    context: "Stutter sensitivity malformed variant digit",
                });
            }
        }
    }
    if !current.is_empty() {
        rows.push(current);
    }
    Ok(GlyphGrid::from_orientation_rows(message_key, rows))
}

fn stutter_footprints() -> Result<Vec<StutterFootprint>, IsomorphImperfectionError> {
    let grids = orders::corpus_grids()?;
    let mut footprints = Vec::new();
    for key in STUTTER_KEYS {
        let message = message_index_for_key(key)?;
        let grid = grids
            .get(message)
            .ok_or(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity grid lookup",
            })?;
        let corpus_message =
            messages()
                .get(message)
                .ok_or(IsomorphImperfectionError::InternalInvariant {
                    context: "Stutter sensitivity message lookup",
                })?;
        let digit_indices = stutter_digit_indices(grid)?;
        let source_digits = digit_indices
            .iter()
            .map(|&digit_index| source_digit(corpus_message, digit_index))
            .collect::<Result<Vec<_>, _>>()?;
        footprints.push(StutterFootprint {
            message,
            message_key: corpus_message.key,
            digit_indices,
            source_digits,
        });
    }
    Ok(footprints)
}

fn message_index_for_key(key: &str) -> Result<usize, IsomorphImperfectionError> {
    messages()
        .iter()
        .position(|message| message.key == key)
        .ok_or(IsomorphImperfectionError::InternalInvariant {
            context: "Stutter sensitivity message key lookup",
        })
}

fn stutter_digit_indices(grid: &GlyphGrid) -> Result<Vec<usize>, IsomorphImperfectionError> {
    let targets = (STUTTER_START..=STUTTER_END).collect::<BTreeSet<_>>();
    let mut indices = Vec::new();
    let rows = grid.orientation_rows();
    let mut offset = 0usize;
    let mut upper_row = 0usize;
    while upper_row < rows.len() {
        let lower_row =
            upper_row
                .checked_add(1)
                .ok_or(IsomorphImperfectionError::InternalInvariant {
                    context: "Stutter sensitivity row-pair overflow",
                })?;
        if lower_row >= rows.len() {
            return Err(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity odd row count",
            });
        }
        let width = rows.get(upper_row).map_or(0, Vec::len);
        let mut column = 0usize;
        while column + 1 < width {
            push_target_tri(
                rows,
                offset,
                &targets,
                [
                    (upper_row, column),
                    (upper_row, column + 1),
                    (lower_row, column),
                ],
                &mut indices,
            )?;
            offset += 1;
            column += 2;
            if column >= width {
                break;
            }
            push_target_tri(
                rows,
                offset,
                &targets,
                [
                    (lower_row, column),
                    (lower_row, column - 1),
                    (upper_row, column),
                ],
                &mut indices,
            )?;
            offset += 1;
            column += 1;
        }
        upper_row += 2;
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

fn push_target_tri(
    rows: &[Vec<crate::core::glyph::Orientation>],
    offset: usize,
    targets: &BTreeSet<usize>,
    coords: [(usize, usize); 3],
    indices: &mut Vec<usize>,
) -> Result<(), IsomorphImperfectionError> {
    if !targets.contains(&offset) {
        return Ok(());
    }
    for (row, column) in coords {
        indices.push(digit_index_for_coord(rows, row, column)?);
    }
    Ok(())
}

fn digit_index_for_coord(
    rows: &[Vec<crate::core::glyph::Orientation>],
    row: usize,
    column: usize,
) -> Result<usize, IsomorphImperfectionError> {
    let Some(cells) = rows.get(row) else {
        return Err(IsomorphImperfectionError::InternalInvariant {
            context: "Stutter sensitivity footprint row",
        });
    };
    if column >= cells.len() {
        return Err(IsomorphImperfectionError::InternalInvariant {
            context: "Stutter sensitivity footprint column",
        });
    }
    Ok(rows.iter().take(row).map(Vec::len).sum::<usize>() + column)
}

fn source_digit(
    message: &Message,
    digit_index: usize,
) -> Result<SourceDigit, IsomorphImperfectionError> {
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
                return Err(IsomorphImperfectionError::InternalInvariant {
                    context: "Stutter sensitivity malformed source digit",
                });
            }
        }
    }
    Err(IsomorphImperfectionError::InternalInvariant {
        context: "Stutter sensitivity source digit lookup",
    })
}

fn change_sets(
    footprint: &StutterFootprint,
    changed_digits: usize,
) -> Result<Vec<Vec<DigitChange>>, IsomorphImperfectionError> {
    match changed_digits {
        1 => Ok(single_change_sets(footprint)),
        2 => Ok(double_change_sets(footprint)),
        _ => Err(IsomorphImperfectionError::InternalInvariant {
            context: "Stutter sensitivity changed digit depth",
        }),
    }
}

fn single_change_sets(footprint: &StutterFootprint) -> Vec<Vec<DigitChange>> {
    let mut sets = Vec::new();
    for source in &footprint.source_digits {
        for new in alternative_digits(source.old) {
            sets.push(vec![digit_change(footprint, source, new)]);
        }
    }
    sets
}

fn double_change_sets(footprint: &StutterFootprint) -> Vec<Vec<DigitChange>> {
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

fn digit_change(footprint: &StutterFootprint, source: &SourceDigit, new: u8) -> DigitChange {
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
    footprint: &StutterFootprint,
    changes: Vec<DigitChange>,
) -> Result<PerturbedMessage, IsomorphImperfectionError> {
    let message =
        messages()
            .get(footprint.message)
            .ok_or(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity variant message lookup",
            })?;
    let mut digits = message.digits.as_bytes().to_vec();
    for change in &changes {
        let Some(byte) = digits.get_mut(change.raw_index) else {
            return Err(IsomorphImperfectionError::InternalInvariant {
                context: "Stutter sensitivity variant raw index",
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
