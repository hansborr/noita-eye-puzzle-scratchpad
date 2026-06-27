//! Cipher mechanics: additive combination, the affine/AGL and modular math,
//! the Chaocipher dynamic-alphabet step, and the deck-keystream operations.

use std::collections::BTreeMap;

use crate::ciphers::MAX_ALPHABET_SIZE;
use crate::ciphers::error::CipherError;
use crate::ciphers::keys_gak::AglGakKey;
use crate::ciphers::keys_simple::{ChaocipherKey, DeckCipherKey, IncrementingWheelKey};
use crate::core::glyph::Glyph;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

pub(crate) fn symbol_from_glyph(glyph: Glyph, alphabet_size: usize) -> Result<usize, CipherError> {
    let symbol = usize::from(glyph.0);
    if symbol >= alphabet_size {
        return Err(CipherError::SymbolOutsideAlphabet {
            symbol: glyph,
            alphabet_size,
        });
    }
    Ok(symbol)
}

pub(crate) fn glyph_from_symbol(symbol: usize, alphabet_size: usize) -> Result<Glyph, CipherError> {
    let glyph = u16::try_from(symbol).map_err(|_error| CipherError::InvalidAlphabetSize {
        alphabet_size,
        min: 1,
        max: MAX_ALPHABET_SIZE,
    })?;
    Ok(Glyph(glyph))
}

pub(crate) fn translate_additive(
    values: &[Glyph],
    alphabet_size: usize,
    mut shift_at: impl FnMut(usize) -> Result<usize, CipherError>,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut output = Vec::with_capacity(values.len());
    for (position, glyph) in values.iter().copied().enumerate() {
        let symbol = symbol_from_glyph(glyph, alphabet_size)?;
        let shift = shift_at(position)? % alphabet_size;
        output.push(glyph_from_symbol(
            combine_additive(symbol, shift, alphabet_size, direction),
            alphabet_size,
        )?);
    }
    Ok(output)
}

pub(crate) fn periodic_shift_at(shifts: &[usize], position: usize) -> Result<usize, CipherError> {
    if shifts.is_empty() {
        return Err(CipherError::InternalInvariant {
            context: "empty periodic shift lookup",
        });
    }
    let offset = position % shifts.len();
    shifts
        .get(offset)
        .copied()
        .ok_or(CipherError::InternalInvariant {
            context: "periodic shift lookup",
        })
}

pub(crate) fn progressive_shift_at(key: &IncrementingWheelKey, position: usize) -> usize {
    let position_mod = position % key.alphabet_size;
    let stepped = (position_mod * key.step) % key.alphabet_size;
    (key.start + stepped) % key.alphabet_size
}

fn combine_additive(
    symbol: usize,
    shift: usize,
    alphabet_size: usize,
    direction: Direction,
) -> usize {
    match direction {
        Direction::Encrypt => (symbol + shift) % alphabet_size,
        Direction::Decrypt => (symbol + alphabet_size - shift) % alphabet_size,
    }
}

pub(crate) fn agl_compose(g: (usize, usize), h: (usize, usize), n: usize) -> (usize, usize) {
    let g_a = g.0 % n;
    let g_b = g.1 % n;
    let h_a = h.0 % n;
    let h_b = h.1 % n;
    ((g_a * h_a) % n, (((g_a * h_b) % n) + g_b) % n)
}

pub(crate) fn agl_inverse(g: (usize, usize), n: usize) -> Option<(usize, usize)> {
    let a_inv = mul_inverse_mod(g.0, n)?;
    Some((a_inv, neg_mod((a_inv * (g.1 % n)) % n, n)))
}

pub(crate) fn agl_apply(g: (usize, usize), x: usize, n: usize) -> usize {
    (((g.0 % n) * (x % n)) % n + (g.1 % n)) % n
}

pub(crate) fn agl_coset_symbol(g: (usize, usize), x0: usize, n: usize) -> usize {
    agl_apply(g, x0, n)
}

pub(crate) fn mul_inverse_mod(a: usize, n: usize) -> Option<usize> {
    if n < 2 || a.is_multiple_of(n) {
        return None;
    }
    Some(pow_mod(a % n, n - 2, n))
}

pub(crate) fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    ((a % n) + n - (b % n)) % n
}

pub(crate) fn neg_mod(t: usize, n: usize) -> usize {
    (n - (t % n)) % n
}

pub(crate) fn quadratic_residues_mod(n: usize) -> Vec<usize> {
    let mut residues = Vec::new();
    let mut seen = vec![false; n];
    for value in 1..n {
        let residue = (value * value) % n;
        if let Some(seen_residue) = seen.get_mut(residue)
            && !*seen_residue
        {
            *seen_residue = true;
            residues.push(residue);
        }
    }
    residues.sort_unstable();
    residues
}

pub(crate) fn agl_step_lookup(
    state: (usize, usize),
    key: &AglGakKey,
) -> Result<BTreeMap<usize, usize>, CipherError> {
    let mut lookup = BTreeMap::new();
    for (letter, &element) in key.letter_elements.iter().enumerate() {
        let next_state = agl_compose(state, element, key.alphabet_size);
        let symbol = agl_coset_symbol(next_state, key.reference_point, key.alphabet_size);
        if lookup.insert(symbol, letter).is_some() {
            return Err(CipherError::InternalInvariant {
                context: "AGL step lookup duplicate coset",
            });
        }
    }
    Ok(lookup)
}

fn pow_mod(mut base: usize, mut exponent: usize, n: usize) -> usize {
    let mut acc = 1 % n;
    base %= n;
    while exponent > 0 {
        if exponent % 2 == 1 {
            acc = (acc * base) % n;
        }
        base = (base * base) % n;
        exponent /= 2;
    }
    acc
}

pub(crate) fn is_quadratic_residue_mod(multiplier: usize, n: usize) -> bool {
    quadratic_residues_mod(n).contains(&multiplier)
}

pub(crate) fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }
    let mut divisor = 3usize;
    while divisor <= n / divisor {
        if n.is_multiple_of(divisor) {
            return false;
        }
        divisor += 2;
    }
    true
}

pub(crate) fn translate_chaocipher(
    values: &[Glyph],
    key: &ChaocipherKey,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut left = key.left.clone();
    let mut right = key.right.clone();
    let mut output = Vec::with_capacity(values.len());

    for glyph in values.iter().copied() {
        let input = symbol_from_glyph(glyph, key.alphabet_size)?;
        let (cipher_symbol, plain_symbol, output_symbol) = match direction {
            Direction::Encrypt => {
                let position = symbol_position(&right, input, "Chaocipher right")?;
                let cipher = symbol_at(&left, position, "Chaocipher left")?;
                (cipher, input, cipher)
            }
            Direction::Decrypt => {
                let position = symbol_position(&left, input, "Chaocipher left")?;
                let plain = symbol_at(&right, position, "Chaocipher right")?;
                (input, plain, plain)
            }
        };
        output.push(glyph_from_symbol(output_symbol, key.alphabet_size)?);
        permute_chaocipher_alphabets(
            &mut left,
            &mut right,
            cipher_symbol,
            plain_symbol,
            key.alphabet_size,
        )?;
    }

    Ok(output)
}

fn symbol_position(
    values: &[usize],
    symbol: usize,
    label: &'static str,
) -> Result<usize, CipherError> {
    values
        .iter()
        .position(|&candidate| candidate == symbol)
        .ok_or(CipherError::InternalInvariant { context: label })
}

fn symbol_at(values: &[usize], position: usize, label: &'static str) -> Result<usize, CipherError> {
    values
        .get(position)
        .copied()
        .ok_or(CipherError::InternalInvariant { context: label })
}

fn permute_chaocipher_alphabets(
    left: &mut Vec<usize>,
    right: &mut Vec<usize>,
    cipher_symbol: usize,
    plain_symbol: usize,
    alphabet_size: usize,
) -> Result<(), CipherError> {
    let nadir = alphabet_size / 2;

    rotate_symbol_to_front(left, cipher_symbol, "Chaocipher left rotate")?;
    move_position(left, 1, nadir, "Chaocipher left tab")?;

    rotate_symbol_to_front(right, plain_symbol, "Chaocipher right rotate")?;
    rotate_left_one(right, "Chaocipher right extra rotate")?;
    move_position(right, 2, nadir, "Chaocipher right tab")?;

    Ok(())
}

fn rotate_symbol_to_front(
    values: &mut [usize],
    symbol: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    let position = symbol_position(values, symbol, label)?;
    values.rotate_left(position);
    Ok(())
}

fn rotate_left_one(values: &mut [usize], label: &'static str) -> Result<(), CipherError> {
    if values.is_empty() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    values.rotate_left(1);
    Ok(())
}

fn move_position(
    values: &mut Vec<usize>,
    from: usize,
    to: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    if from >= values.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    let value = values.remove(from);
    if to > values.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    values.insert(to, value);
    Ok(())
}

pub(crate) fn translate_deck_cipher(
    values: &[Glyph],
    key: &DeckCipherKey,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut deck = key.deck.clone();
    let mut output = Vec::with_capacity(values.len());

    for glyph in values.iter().copied() {
        let symbol = symbol_from_glyph(glyph, key.alphabet_size)?;
        let shift = next_deck_keystream(&mut deck, key)?;
        output.push(glyph_from_symbol(
            combine_additive(symbol, shift, key.alphabet_size, direction),
            key.alphabet_size,
        )?);
    }

    Ok(output)
}

fn next_deck_keystream(deck: &mut Vec<usize>, key: &DeckCipherKey) -> Result<usize, CipherError> {
    move_card_down(deck, key.control_a, 1, "deck control A move")?;
    move_card_down(deck, key.control_b, 2, "deck control B move")?;
    triple_cut(deck, key.control_a, key.control_b)?;
    count_cut(deck, key)?;

    let top = top_card(deck)?;
    let count = deck_count_value(top, key);
    let selected = symbol_at(deck, count, "deck output lookup")?;
    Ok(selected % key.alphabet_size)
}

fn move_card_down(
    deck: &mut Vec<usize>,
    card: usize,
    steps: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    if deck.len() < 2 {
        return Err(CipherError::InternalInvariant { context: label });
    }
    let Some(position) = deck.iter().position(|&candidate| candidate == card) else {
        return Err(CipherError::InternalInvariant { context: label });
    };
    let value = deck.remove(position);
    let len_after_remove = deck.len();
    let target = wrapped_down_position(position, steps, len_after_remove)?;
    if target > deck.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    deck.insert(target, value);
    Ok(())
}

fn wrapped_down_position(
    position: usize,
    steps: usize,
    len_after_remove: usize,
) -> Result<usize, CipherError> {
    if len_after_remove == 0 {
        return Err(CipherError::InternalInvariant {
            context: "deck move in empty deck",
        });
    }
    if steps == 0 {
        return Ok(position);
    }
    let shifted = position
        .checked_add(steps)
        .and_then(|value| value.checked_sub(1))
        .ok_or(CipherError::InternalInvariant {
            context: "deck move offset",
        })?;
    Ok(1 + shifted % len_after_remove)
}

fn triple_cut(
    deck: &mut Vec<usize>,
    control_a: usize,
    control_b: usize,
) -> Result<(), CipherError> {
    let first_control = symbol_position(deck, control_a, "deck triple cut A")?;
    let second_control = symbol_position(deck, control_b, "deck triple cut B")?;
    let first = first_control.min(second_control);
    let second = first_control.max(second_control);

    let mut before = Vec::new();
    let mut middle = Vec::new();
    let mut after = Vec::new();
    for (index, card) in deck.iter().copied().enumerate() {
        if index < first {
            before.push(card);
        } else if index <= second {
            middle.push(card);
        } else {
            after.push(card);
        }
    }

    let mut permuted = Vec::with_capacity(deck.len());
    permuted.extend(after);
    permuted.extend(middle);
    permuted.extend(before);
    *deck = permuted;
    Ok(())
}

fn count_cut(deck: &mut Vec<usize>, key: &DeckCipherKey) -> Result<(), CipherError> {
    let bottom = bottom_card(deck)?;
    let count = deck_count_value(bottom, key);
    if count == 0 || count >= deck.len().saturating_sub(1) {
        return Ok(());
    }

    let bottom_index = deck.len().saturating_sub(1);
    let mut top = Vec::new();
    let mut middle = Vec::new();
    let mut bottom_card = None;
    for (index, card) in deck.iter().copied().enumerate() {
        if index < count {
            top.push(card);
        } else if index < bottom_index {
            middle.push(card);
        } else {
            bottom_card = Some(card);
        }
    }

    let Some(bottom) = bottom_card else {
        return Err(CipherError::InternalInvariant {
            context: "deck count-cut bottom",
        });
    };
    let mut cut = Vec::with_capacity(deck.len());
    cut.extend(middle);
    cut.extend(top);
    cut.push(bottom);
    *deck = cut;
    Ok(())
}

fn top_card(deck: &[usize]) -> Result<usize, CipherError> {
    deck.first().copied().ok_or(CipherError::InternalInvariant {
        context: "deck top card",
    })
}

fn bottom_card(deck: &[usize]) -> Result<usize, CipherError> {
    deck.last().copied().ok_or(CipherError::InternalInvariant {
        context: "deck bottom card",
    })
}

fn deck_count_value(card: usize, key: &DeckCipherKey) -> usize {
    if card == key.control_a || card == key.control_b {
        key.alphabet_size - 1
    } else {
        (card % (key.alphabet_size - 1)) + 1
    }
}
