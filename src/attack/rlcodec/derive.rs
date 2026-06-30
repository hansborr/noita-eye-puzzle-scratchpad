//! Magnitude derivation: the `±1`-walk validity gate and the direction-blind
//! run-length encode that produces the carrier the battery analyses.

use crate::core::glyph::Glyph;

use super::RlError;

/// The verified-on-import real practice puzzle `one` (266 base-5 digits).
///
/// Embedded so the self-test's documented *honest-negative* anchor and the
/// library tests can run on the real target without a runtime file read. The
/// instrument itself is fully file-driven through the CLI; this fixture is only
/// the self-test's negative control (mirroring how
/// [`crate::analysis::translate_isomorph::iso_scan_self_test`] plants its own
/// positive control).
pub const ONE_PRACTICE_PUZZLE: &str = include_str!("../../../research/data/practice-puzzles/one");

/// The outcome of deriving the run-length magnitude carrier from a `±1` walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunLengthDerivation {
    /// Run-length magnitudes (each `>= 1`): the direction-blind carrier `M`.
    pub magnitudes: Vec<usize>,
    /// Per-run direction (`true` = the `+1` / up direction).
    pub run_directions: Vec<bool>,
    /// Number of `±1` move bits (one fewer than the digit count).
    pub n_bits: usize,
    /// Number of up (`+1`) moves.
    pub n_up: usize,
    /// Number of down (`-1`) moves.
    pub n_down: usize,
}

/// Parses a base-`base` digit string into [`Glyph`]s.
///
/// ASCII digits `0..base` map to `Glyph(digit)`; whitespace is skipped. This is
/// the library-side parser the self-test and tests use to read
/// [`ONE_PRACTICE_PUZZLE`]; the CLI uses `cli::shared::parse_cli_sequence`, which
/// yields the identical glyphs for the `--alphabet 01234` spec.
///
/// # Errors
/// Returns [`RlError::InvalidBase`] if `base` exceeds 10, or
/// [`RlError::InvalidDigit`] for any non-whitespace character that is not a digit
/// below `base`.
pub fn parse_base_digits(text: &str, base: usize) -> Result<Vec<Glyph>, RlError> {
    if !(2..=10).contains(&base) {
        return Err(RlError::InvalidBase { base });
    }
    let mut glyphs = Vec::new();
    for character in text.chars() {
        if character.is_whitespace() {
            continue;
        }
        let Some(digit) = character.to_digit(10) else {
            return Err(RlError::InvalidDigit { character });
        };
        if digit as usize >= base {
            return Err(RlError::InvalidDigit { character });
        }
        glyphs.push(Glyph(u16::try_from(digit).unwrap_or(0)));
    }
    Ok(glyphs)
}

/// Returns the real practice puzzle `one` digits (the self-test negative target).
///
/// # Errors
/// Returns [`RlError`] if the embedded fixture fails to parse as base-5 digits
/// (it should not in a correct build).
pub fn one_practice_digits() -> Result<Vec<Glyph>, RlError> {
    parse_base_digits(ONE_PRACTICE_PUZZLE, 5)
}

/// Derives the run-length magnitude carrier from a `±1` walk on `C_base`.
///
/// The first difference `d[i] = (digits[i+1] - digits[i]) mod base` must be `1`
/// (up) or `base - 1` (down) for **every** step — this is the honest gate that
/// refuses to read a sequence that is not a clean walk. The up/down bits are then
/// run-length encoded into the direction-blind magnitude sequence `M`.
///
/// # Errors
/// Returns [`RlError::InvalidBase`] if `base < 2`, [`RlError::TooFewDigits`] if
/// fewer than two digits are supplied, [`RlError::SymbolOutOfRange`] if a digit is
/// not below `base`, or [`RlError::NonUnitStep`] if any move is not `±1 mod base`.
pub fn derive_magnitudes(digits: &[Glyph], base: usize) -> Result<RunLengthDerivation, RlError> {
    if base < 2 {
        return Err(RlError::InvalidBase { base });
    }
    if digits.len() < 2 {
        return Err(RlError::TooFewDigits {
            count: digits.len(),
        });
    }

    let mut bits: Vec<bool> = Vec::with_capacity(digits.len() - 1);
    for pair in digits.windows(2) {
        let [a, b] = pair else { continue };
        let from = usize::from(a.0);
        let to = usize::from(b.0);
        if from >= base {
            return Err(RlError::SymbolOutOfRange { value: from, base });
        }
        if to >= base {
            return Err(RlError::SymbolOutOfRange { value: to, base });
        }
        let diff = (to + base - from) % base;
        if diff == 1 {
            bits.push(true);
        } else if diff == base - 1 {
            bits.push(false);
        } else {
            return Err(RlError::NonUnitStep {
                from,
                to,
                diff,
                base,
            });
        }
    }

    let n_up = bits.iter().filter(|&&bit| bit).count();
    let n_down = bits.len() - n_up;

    let mut magnitudes = Vec::new();
    let mut run_directions = Vec::new();
    let mut index = 0usize;
    while let Some(&direction) = bits.get(index) {
        let mut length = 0usize;
        while bits.get(index + length) == Some(&direction) {
            length += 1;
        }
        magnitudes.push(length);
        run_directions.push(direction);
        index += length;
    }

    Ok(RunLengthDerivation {
        magnitudes,
        run_directions,
        n_bits: bits.len(),
        n_up,
        n_down,
    })
}

/// Synthesises a `±1` walk on `C_base` whose run-length magnitudes equal
/// `magnitudes` exactly (alternating up/down runs from digit 0).
///
/// This is the inverse of [`derive_magnitudes`] up to direction parity: feeding
/// the result back through `derive_magnitudes` recovers `magnitudes`. It is used
/// to realise a planted or resampled magnitude carrier as a digit stream the
/// file-driven battery can re-derive.
pub(crate) fn synthesize_walk(magnitudes: &[usize], base: usize) -> Vec<Glyph> {
    let modulus = i64::try_from(base).unwrap_or(5);
    let mut current: i64 = 0;
    let mut digits: Vec<Glyph> = vec![Glyph(0)];
    let mut up = true;
    for &magnitude in magnitudes {
        for _ in 0..magnitude {
            current = if up {
                (current + 1).rem_euclid(modulus)
            } else {
                (current - 1).rem_euclid(modulus)
            };
            digits.push(Glyph(u16::try_from(current).unwrap_or(0)));
        }
        up = !up;
    }
    digits
}
