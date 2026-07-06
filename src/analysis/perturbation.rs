//! Source-layer transcription perturbations for sensitivity certificates.
//!
//! This module deliberately perturbs rendered orientation digits (`0..=4`) in
//! the verified corpus, never reading-layer trigram values. Each variant is
//! rebuilt as a [`crate::analysis::orders::GlyphGrid`] and read through
//! [`crate::analysis::orders::accepted_honeycomb_order`], so downstream verdicts
//! see the same reading-layer representation as the structural analyses.

use crate::analysis::orders::{self, GlyphGrid, GridError};
use crate::core::glyph::Orientation;
use crate::core::trigram::TrigramValue;
use crate::data::corpus::messages;

/// Maximum exact-two-change variants accepted by the generic harness.
///
/// For a window with `k` rendered orientation digits, the double-change count
/// is `C(k, 2) * 16`. Keeping this in the low hundreds avoids accidentally
/// turning a local sensitivity check into a broad transcription search.
pub const MAX_DOUBLE_PERTURBATIONS: usize = 512;

/// A bounded source-layer window in one verified message.
///
/// `start` and `len` are zero-based indices over rendered orientation digits
/// after skipping row delimiters. They are not raw string byte offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigitWindow {
    /// Corpus message index in `data::corpus::messages()` order.
    pub message: usize,
    /// First non-delimiter orientation digit included in the window.
    pub start: usize,
    /// Number of non-delimiter orientation digits included in the window.
    pub len: usize,
}

/// One rendered orientation-digit counterfactual.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigitChange {
    /// Corpus message index in `data::corpus::messages()` order.
    pub message: usize,
    /// Message key, such as `east1`.
    pub message_key: &'static str,
    /// Zero-based non-delimiter orientation digit index.
    pub digit_index: usize,
    /// Raw byte index in `Message::digits`, including row delimiters.
    pub raw_index: usize,
    /// Verified rendered orientation digit before perturbation.
    pub old: u8,
    /// Counterfactual rendered orientation digit.
    pub new: u8,
}

/// A perturbed copy of one verified message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerturbedMessage {
    /// Window that generated this variant.
    pub window: DigitWindow,
    /// One or two source-layer digit changes.
    pub changes: Vec<DigitChange>,
    /// Full rendered message string after applying `changes`.
    pub digits: String,
}

/// First variant for which a caller-supplied verdict failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstBreak {
    /// Zero-based ordinal among generated variants.
    pub variant_index: usize,
    /// Source-layer digit changes that caused the break.
    pub changes: Vec<DigitChange>,
}

/// Summary returned by [`certify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateReport {
    /// Window certified by this run.
    pub window: DigitWindow,
    /// Maximum number of changed orientation digits per variant.
    pub max_changes: usize,
    /// Total generated counterfactual variants.
    pub total_variants: usize,
    /// Number of variants for which the verdict still held.
    pub holding_variants: usize,
    /// First failing variant, if any.
    pub first_break: Option<FirstBreak>,
}

/// Error returned by the perturbation harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerturbationError {
    /// The requested message index is outside the verified corpus.
    MessageOutOfRange {
        /// Requested message index.
        message: usize,
        /// Number of verified messages.
        message_count: usize,
    },
    /// The non-delimiter digit window extends past the message's eye count.
    WindowOutOfRange {
        /// Requested message index.
        message: usize,
        /// Requested start index.
        start: usize,
        /// Requested window length.
        len: usize,
        /// Number of non-delimiter orientation digits in the message.
        eye_count: usize,
    },
    /// Only one- and two-digit variants are supported.
    UnsupportedMaxChanges {
        /// Requested maximum number of changed digits.
        max_changes: usize,
    },
    /// The requested two-change window would generate too many variants.
    DoublePerturbationExplosion {
        /// Number of exact-two-change variants that would be generated.
        variants: usize,
        /// Maximum allowed exact-two-change variants.
        limit: usize,
        /// Number of orientation positions in the window.
        positions: usize,
    },
    /// A generated change pointed outside its rendered message string.
    ChangeOutOfRange {
        /// Raw byte index in `Message::digits`.
        raw_index: usize,
        /// Rendered message string length.
        len: usize,
    },
    /// A byte in a rendered message was not one of `0..=5`.
    MalformedDigit {
        /// Message key, such as `east1`.
        message_key: &'static str,
        /// Raw byte index in `Message::digits`.
        raw_index: usize,
        /// Malformed byte.
        byte: u8,
    },
    /// Rebuilding a perturbed grid or reading order failed.
    Grid(GridError),
}

impl From<GridError> for PerturbationError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowPosition {
    digit_index: usize,
    raw_index: usize,
    old: u8,
}

/// Enumerates all exact-one-digit perturbations for `window`.
///
/// The iteration order is deterministic: source positions ascend, and
/// replacement orientation digits ascend within each position.
///
/// # Errors
/// Returns [`PerturbationError`] when the window is outside the verified corpus
/// or outside the requested message.
pub fn single_digit_perturbations(
    window: DigitWindow,
) -> Result<impl Iterator<Item = PerturbedMessage>, PerturbationError> {
    Ok(exact_change_perturbations(window, 1)?.into_iter())
}

/// Enumerates all exact-two-digit perturbations for `window`.
///
/// The double-change explosion guard applies here and in [`certify`] when
/// `max_changes` is `2`.
///
/// # Errors
/// Returns [`PerturbationError`] when the window is invalid or would generate
/// more than [`MAX_DOUBLE_PERTURBATIONS`] exact-two-change variants.
pub fn double_digit_perturbations(
    window: DigitWindow,
) -> Result<impl Iterator<Item = PerturbedMessage>, PerturbationError> {
    ensure_double_count_is_bounded(window)?;
    Ok(exact_change_perturbations(window, 2)?.into_iter())
}

/// Runs a sensitivity certificate over one small source-layer window.
///
/// `max_changes = 1` checks every exact-one-digit counterfactual. `max_changes =
/// 2` checks those singles plus every bounded exact-two-digit counterfactual.
/// The supplied verdict consumes reading-layer trigram values rebuilt through
/// the accepted honeycomb order for each perturbed corpus.
///
/// # Errors
/// Returns [`PerturbationError`] when the window is invalid, the requested
/// change depth is unsupported, the double-change guard would be exceeded, or a
/// perturbed grid cannot be read.
pub fn certify<V>(
    window: DigitWindow,
    max_changes: usize,
    verdict: V,
) -> Result<CertificateReport, PerturbationError>
where
    V: Fn(&[Vec<TrigramValue>]) -> bool,
{
    let variants = perturbations(window, max_changes)?;
    let mut total_variants = 0;
    let mut holding_variants = 0;
    let mut first_break = None;

    for variant in variants {
        let values = message_values_for_variant(&variant)?;
        if verdict(&values) {
            holding_variants += 1;
        } else if first_break.is_none() {
            first_break = Some(FirstBreak {
                variant_index: total_variants,
                changes: variant.changes.clone(),
            });
        }
        total_variants += 1;
    }

    Ok(CertificateReport {
        window,
        max_changes,
        total_variants,
        holding_variants,
        first_break,
    })
}

/// Rebuilds reading-layer values after applying one perturbation variant.
///
/// # Errors
/// Returns [`PerturbationError`] if the perturbed rendered digits cannot be
/// reconstructed as a grid or read under the accepted honeycomb order.
pub fn message_values_for_variant(
    variant: &PerturbedMessage,
) -> Result<Vec<Vec<TrigramValue>>, PerturbationError> {
    let corpus = messages();
    let mut grids = orders::corpus_grids()?;
    let message =
        corpus
            .get(variant.window.message)
            .ok_or(PerturbationError::MessageOutOfRange {
                message: variant.window.message,
                message_count: corpus.len(),
            })?;
    let message_count = grids.len();
    let grid =
        grids
            .get_mut(variant.window.message)
            .ok_or(PerturbationError::MessageOutOfRange {
                message: variant.window.message,
                message_count,
            })?;
    *grid = grid_from_digits(message.key, &variant.digits)?;
    Ok(orders::read_corpus_message_values(
        &grids,
        orders::accepted_honeycomb_order(),
    )?)
}

/// Enumerates every one- and optionally two-digit perturbation for `window`.
///
/// # Errors
/// Returns [`PerturbationError`] for invalid windows, unsupported change depths,
/// or over-large two-change windows.
pub fn perturbations(
    window: DigitWindow,
    max_changes: usize,
) -> Result<Vec<PerturbedMessage>, PerturbationError> {
    match max_changes {
        1 => exact_change_perturbations(window, 1),
        2 => {
            ensure_double_count_is_bounded(window)?;
            let mut variants = exact_change_perturbations(window, 1)?;
            variants.extend(exact_change_perturbations(window, 2)?);
            Ok(variants)
        }
        _ => Err(PerturbationError::UnsupportedMaxChanges { max_changes }),
    }
}

fn exact_change_perturbations(
    window: DigitWindow,
    changes: usize,
) -> Result<Vec<PerturbedMessage>, PerturbationError> {
    let (digits, positions) = window_positions(window)?;
    match changes {
        1 => single_variants(window, digits, &positions),
        2 => double_variants(window, digits, &positions),
        _ => Err(PerturbationError::UnsupportedMaxChanges {
            max_changes: changes,
        }),
    }
}

fn single_variants(
    window: DigitWindow,
    digits: &str,
    positions: &[WindowPosition],
) -> Result<Vec<PerturbedMessage>, PerturbationError> {
    let mut variants = Vec::new();
    let message_key = messages()
        .get(window.message)
        .ok_or(PerturbationError::MessageOutOfRange {
            message: window.message,
            message_count: messages().len(),
        })?
        .key;
    for position in positions {
        for new in alternative_digits(position.old) {
            let change = change_for(window.message, message_key, position, new);
            variants.push(apply_changes(window, digits, &[change])?);
        }
    }
    Ok(variants)
}

fn double_variants(
    window: DigitWindow,
    digits: &str,
    positions: &[WindowPosition],
) -> Result<Vec<PerturbedMessage>, PerturbationError> {
    let mut variants = Vec::new();
    let message_key = messages()
        .get(window.message)
        .ok_or(PerturbationError::MessageOutOfRange {
            message: window.message,
            message_count: messages().len(),
        })?
        .key;
    for (left, left_position) in positions.iter().copied().enumerate() {
        for right_position in positions.iter().copied().skip(left + 1) {
            for left_new in alternative_digits(left_position.old) {
                for right_new in alternative_digits(right_position.old) {
                    let changes = [
                        change_for(window.message, message_key, &left_position, left_new),
                        change_for(window.message, message_key, &right_position, right_new),
                    ];
                    variants.push(apply_changes(window, digits, &changes)?);
                }
            }
        }
    }
    Ok(variants)
}

fn change_for(
    message: usize,
    message_key: &'static str,
    position: &WindowPosition,
    new: u8,
) -> DigitChange {
    DigitChange {
        message,
        message_key,
        digit_index: position.digit_index,
        raw_index: position.raw_index,
        old: position.old,
        new,
    }
}

fn apply_changes(
    window: DigitWindow,
    digits: &str,
    changes: &[DigitChange],
) -> Result<PerturbedMessage, PerturbationError> {
    let mut bytes = digits.as_bytes().to_vec();
    for change in changes {
        let len = bytes.len();
        let byte = bytes
            .get_mut(change.raw_index)
            .ok_or(PerturbationError::ChangeOutOfRange {
                raw_index: change.raw_index,
                len,
            })?;
        *byte = b'0' + change.new;
    }
    let digits = bytes.into_iter().map(char::from).collect();
    Ok(PerturbedMessage {
        window,
        changes: changes.to_vec(),
        digits,
    })
}

fn alternative_digits(old: u8) -> impl Iterator<Item = u8> {
    (0..=4).filter(move |&candidate| candidate != old)
}

fn ensure_double_count_is_bounded(window: DigitWindow) -> Result<(), PerturbationError> {
    let positions = window_positions(window)?.1.len();
    let variants = double_variant_count(positions);
    if variants > MAX_DOUBLE_PERTURBATIONS {
        return Err(PerturbationError::DoublePerturbationExplosion {
            variants,
            limit: MAX_DOUBLE_PERTURBATIONS,
            positions,
        });
    }
    Ok(())
}

fn double_variant_count(positions: usize) -> usize {
    positions.saturating_mul(positions.saturating_sub(1)) / 2 * 16
}

fn window_positions(
    window: DigitWindow,
) -> Result<(&'static str, Vec<WindowPosition>), PerturbationError> {
    let corpus = messages();
    let message = corpus
        .get(window.message)
        .ok_or(PerturbationError::MessageOutOfRange {
            message: window.message,
            message_count: corpus.len(),
        })?;
    let end = window
        .start
        .checked_add(window.len)
        .ok_or(PerturbationError::WindowOutOfRange {
            message: window.message,
            start: window.start,
            len: window.len,
            eye_count: message.eye_count,
        })?;
    if end > message.eye_count {
        return Err(PerturbationError::WindowOutOfRange {
            message: window.message,
            start: window.start,
            len: window.len,
            eye_count: message.eye_count,
        });
    }

    let mut positions = Vec::new();
    let mut digit_index = 0;
    for (raw_index, byte) in message.digits.bytes().enumerate() {
        match byte {
            b'0'..=b'4' => {
                if (window.start..end).contains(&digit_index) {
                    positions.push(WindowPosition {
                        digit_index,
                        raw_index,
                        old: byte - b'0',
                    });
                }
                digit_index += 1;
            }
            b'5' => {}
            _ => {
                return Err(PerturbationError::MalformedDigit {
                    message_key: message.key,
                    raw_index,
                    byte,
                });
            }
        }
    }
    Ok((message.digits, positions))
}

fn grid_from_digits(
    message_key: &'static str,
    digits: &str,
) -> Result<GlyphGrid, PerturbationError> {
    let mut rows = Vec::new();
    let mut current = Vec::new();
    for (raw_index, byte) in digits.bytes().enumerate() {
        match byte {
            b'0'..=b'4' => {
                current.push(Orientation::from_base5_digit(byte - b'0'));
            }
            b'5' => {
                if current.is_empty() {
                    return Err(GridError::EmptyInteriorRow { message_key }.into());
                }
                rows.push(current);
                current = Vec::new();
            }
            _ => {
                return Err(PerturbationError::MalformedDigit {
                    message_key,
                    raw_index,
                    byte,
                });
            }
        }
    }
    if !current.is_empty() {
        rows.push(current);
    }
    Ok(GlyphGrid::from_orientation_rows(message_key, rows))
}

#[cfg(test)]
mod tests;
