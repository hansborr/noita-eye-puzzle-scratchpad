//! Construction-time validation and the group/permutation bookkeeping shared
//! by the key constructors and the GAK transforms.

use std::collections::{BTreeMap, BTreeSet};

use crate::ciphers::error::CipherError;
use crate::ciphers::keys_gak::{
    AglMultiplierSubgroup, CosetReadout, GakKey, GakSubgroupConstraint,
};
use crate::ciphers::keys_simple::TranspositionKey;
use crate::ciphers::mechanics::{
    agl_coset_symbol, is_prime, is_quadratic_residue_mod, quadratic_residues_mod,
};
use crate::ciphers::{MAX_ALPHABET_SIZE, MAX_GAK_COSET_TABLE_GROUP};

pub(crate) fn validate_alphabet_size(alphabet_size: usize, min: usize) -> Result<(), CipherError> {
    if alphabet_size < min || alphabet_size > MAX_ALPHABET_SIZE {
        return Err(CipherError::InvalidAlphabetSize {
            alphabet_size,
            min,
            max: MAX_ALPHABET_SIZE,
        });
    }
    Ok(())
}

pub(crate) fn validate_agl_alphabet(alphabet_size: usize) -> Result<(), CipherError> {
    validate_alphabet_size(alphabet_size, 3)?;
    if !is_prime(alphabet_size) {
        return Err(CipherError::AlphabetNotPrime { alphabet_size });
    }
    let subgroup_order = quadratic_residues_mod(alphabet_size).len();
    if subgroup_order == 0 {
        return Err(CipherError::UnsupportedMultiplierSubgroup {
            order: subgroup_order,
        });
    }
    Ok(())
}

pub(crate) fn normalize_shifts(shifts: Vec<usize>, alphabet_size: usize) -> Vec<usize> {
    shifts
        .into_iter()
        .map(|shift| shift % alphabet_size)
        .collect()
}

pub(crate) fn identity_permutation(
    alphabet_size: usize,
    min: usize,
) -> Result<Vec<usize>, CipherError> {
    validate_alphabet_size(alphabet_size, min)?;
    Ok((0..alphabet_size).collect())
}

pub(crate) fn validate_gak_state_size(state_size: usize) -> Result<(), CipherError> {
    if !(2..=MAX_ALPHABET_SIZE).contains(&state_size) {
        return Err(CipherError::InvalidGakStateSize {
            state_size,
            min: 2,
            max: MAX_ALPHABET_SIZE,
        });
    }
    Ok(())
}

pub(crate) fn identity_gak_permutation(state_size: usize) -> Result<Vec<usize>, CipherError> {
    validate_gak_state_size(state_size)?;
    Ok((0..state_size).collect())
}

/// Composes two permutations of `0..n` in the `(f ∘ g)[i] = f[g[i]]` convention.
///
/// `outer` and `inner` are assumed validated; an out-of-range image is reported
/// as an internal invariant rather than panicking.
pub(crate) fn compose_permutations(
    outer: &[usize],
    inner: &[usize],
) -> Result<Vec<usize>, CipherError> {
    let mut composed = Vec::with_capacity(inner.len());
    for &image in inner {
        let mapped = outer
            .get(image)
            .copied()
            .ok_or(CipherError::InternalInvariant {
                context: "GAK permutation composition index",
            })?;
        composed.push(mapped);
    }
    Ok(composed)
}

pub(crate) fn validate_gak_letter_parity(
    permutation: &[usize],
    subgroup: GakSubgroupConstraint,
    letter_index: usize,
) -> Result<(), CipherError> {
    match subgroup {
        GakSubgroupConstraint::SymmetricGroup => Ok(()),
        GakSubgroupConstraint::AlternatingGroup => {
            if permutation_parity_is_even(permutation)? {
                Ok(())
            } else {
                Err(CipherError::GakLetterWrongParity { letter_index })
            }
        }
    }
}

/// Returns `true` when a validated permutation of `0..n` is even.
///
/// Parity is the parity of `n` minus the number of disjoint cycles.
fn permutation_parity_is_even(permutation: &[usize]) -> Result<bool, CipherError> {
    let len = permutation.len();
    let mut visited = vec![false; len];
    let mut transpositions = 0usize;
    for start in 0..len {
        let Some(seen) = visited.get(start).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "GAK parity visited lookup",
            });
        };
        if seen {
            continue;
        }
        let mut cursor = start;
        let mut cycle_len = 0usize;
        loop {
            let Some(slot) = visited.get_mut(cursor) else {
                return Err(CipherError::InternalInvariant {
                    context: "GAK parity cursor lookup",
                });
            };
            if *slot {
                break;
            }
            *slot = true;
            cycle_len += 1;
            cursor = permutation
                .get(cursor)
                .copied()
                .ok_or(CipherError::InternalInvariant {
                    context: "GAK parity image lookup",
                })?;
        }
        transpositions += cycle_len.saturating_sub(1);
    }
    Ok(transpositions.is_multiple_of(2))
}

pub(crate) fn gak_step_lookup(
    state: &[usize],
    key: &GakKey,
) -> Result<BTreeMap<usize, usize>, CipherError> {
    let mut lookup = BTreeMap::new();
    for (letter, permutation) in key.plaintext_letters.iter().enumerate() {
        let next_state = compose_permutations(permutation, state)?;
        let coset = key.coset_readout.coset_of(&next_state)?;
        if lookup.insert(coset, letter).is_some() {
            return Err(CipherError::InternalInvariant {
                context: "GAK step lookup duplicate coset",
            });
        }
    }
    Ok(lookup)
}

/// Verifies a [`CosetReadout::CosetTable`] GAK key is decrypt-invertible by
/// bounded enumeration of its reachable state set.
///
/// The identity-state injectivity check that suffices for
/// [`CosetReadout::TopCard`] is *not* sufficient for an arbitrary supplied coset
/// table: a coarser partition can merge points so two letters that separate from
/// the identity state collide from another reachable state. The reachable states
/// are `{ w ∘ initial_state : w ∈ ⟨p(a)⟩ }` where `⟨p(a)⟩` is the subgroup of
/// `S_n` generated by the per-letter permutations. This enumerates that group by
/// closure under composition (worklist from the identity plus the generators),
/// then for each reachable state checks the per-letter readout `a ↦ c(p(a) ∘ g)`
/// is injective.
///
/// Enumeration is capped at [`MAX_GAK_COSET_TABLE_GROUP`]; exceeding the cap
/// yields [`CipherError::GakCosetTableGroupTooLarge`] rather than an unbounded
/// loop or an unvalidated key.
///
/// # Errors
/// [`CipherError::GakCosetTableNotInvertible`] when some reachable state admits a
/// two-letter coset collision; [`CipherError::GakCosetTableGroupTooLarge`] when
/// the generated state group exceeds the cap.
pub(crate) fn validate_coset_table_invertible(
    plaintext_letters: &[Vec<usize>],
    initial_state: &[usize],
    coset_readout: &CosetReadout,
) -> Result<(), CipherError> {
    let state_size = initial_state.len();
    let identity: Vec<usize> = (0..state_size).collect();
    let mut group: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut worklist: Vec<Vec<usize>> = Vec::new();
    if group.insert(identity.clone()) {
        worklist.push(identity);
    }
    // BFS closure of ⟨p(a)⟩: pop an element, left-multiply by every generator,
    // enqueue any newly discovered element until the group is closed.
    while let Some(element) = worklist.pop() {
        for generator in plaintext_letters {
            let product = compose_permutations(generator, &element)?;
            if group.insert(product.clone()) {
                if group.len() > MAX_GAK_COSET_TABLE_GROUP {
                    return Err(CipherError::GakCosetTableGroupTooLarge {
                        cap: MAX_GAK_COSET_TABLE_GROUP,
                    });
                }
                worklist.push(product);
            }
        }
    }
    // Every reachable state is w ∘ initial_state for w in the generated group;
    // require per-letter readout injectivity from each.
    for element in &group {
        let state = compose_permutations(element, initial_state)?;
        let mut seen: BTreeMap<usize, usize> = BTreeMap::new();
        for (letter_index, permutation) in plaintext_letters.iter().enumerate() {
            let updated = compose_permutations(permutation, &state)?;
            let coset = coset_readout.coset_of(&updated)?;
            if seen.insert(coset, letter_index).is_some() {
                return Err(CipherError::GakCosetTableNotInvertible {
                    state: state.clone(),
                    coset,
                    duplicate_index: letter_index,
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_permutation(
    label: &'static str,
    symbols: &[usize],
    alphabet_size: usize,
) -> Result<(), CipherError> {
    if symbols.len() != alphabet_size {
        return Err(CipherError::PermutationLengthMismatch {
            label,
            len: symbols.len(),
            alphabet_size,
        });
    }

    let mut seen = vec![false; alphabet_size];
    for (index, &symbol) in symbols.iter().enumerate() {
        if symbol >= alphabet_size {
            return Err(CipherError::PermutationSymbolOutsideAlphabet {
                label,
                symbol,
                alphabet_size,
            });
        }
        let Some(slot) = seen.get_mut(symbol) else {
            return Err(CipherError::InternalInvariant {
                context: "permutation slot lookup",
            });
        };
        if *slot {
            return Err(CipherError::DuplicatePermutationSymbol {
                label,
                symbol,
                duplicate_index: index,
            });
        }
        *slot = true;
    }

    for (symbol, present) in seen.iter().copied().enumerate() {
        if !present {
            return Err(CipherError::MissingPermutationSymbol { label, symbol });
        }
    }
    Ok(())
}

pub(crate) fn transposition_order(
    key: &TranspositionKey,
    block_len: usize,
) -> Result<Vec<usize>, CipherError> {
    if block_len > key.period {
        return Err(CipherError::InternalInvariant {
            context: "transposition block longer than period",
        });
    }
    let mut columns = key
        .permutation
        .iter()
        .copied()
        .enumerate()
        .filter(|(column, _rank)| *column < block_len)
        .collect::<Vec<_>>();
    columns.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    Ok(columns.into_iter().map(|(column, _rank)| column).collect())
}

pub(crate) fn validate_control_cards(
    alphabet_size: usize,
    control_a: usize,
    control_b: usize,
) -> Result<(), CipherError> {
    if control_a >= alphabet_size {
        return Err(CipherError::ControlSymbolOutsideAlphabet {
            symbol: control_a,
            alphabet_size,
        });
    }
    if control_b >= alphabet_size {
        return Err(CipherError::ControlSymbolOutsideAlphabet {
            symbol: control_b,
            alphabet_size,
        });
    }
    if control_a == control_b {
        return Err(CipherError::DuplicateControlSymbols {
            control_a,
            control_b,
        });
    }
    Ok(())
}

pub(crate) fn validate_agl_letter_elements(
    elements: &[(usize, usize)],
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    reference_point: usize,
) -> Result<(), CipherError> {
    let mut seen_cosets = vec![false; alphabet_size];
    for (index, &element) in elements.iter().enumerate() {
        validate_agl_element(element, alphabet_size, subgroup, "AGL letter element")?;
        let symbol = agl_coset_symbol(element, reference_point, alphabet_size);
        let Some(seen) = seen_cosets.get_mut(symbol) else {
            return Err(CipherError::InternalInvariant {
                context: "AGL coset seen lookup",
            });
        };
        if *seen {
            return Err(CipherError::DuplicatePermutationSymbol {
                label: "AGL letter coset",
                symbol,
                duplicate_index: index,
            });
        }
        *seen = true;
    }
    Ok(())
}

pub(crate) fn validate_agl_element(
    element: (usize, usize),
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    label: &'static str,
) -> Result<(), CipherError> {
    let (multiplier, translation) = element;
    if translation >= alphabet_size {
        return Err(CipherError::PermutationSymbolOutsideAlphabet {
            label,
            symbol: translation,
            alphabet_size,
        });
    }
    if !agl_multiplier_allowed(multiplier, alphabet_size, subgroup) {
        return Err(CipherError::NonUnitMultiplier {
            multiplier,
            modulus: alphabet_size,
        });
    }
    Ok(())
}

fn agl_multiplier_allowed(
    multiplier: usize,
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
) -> bool {
    if multiplier == 0 || multiplier >= alphabet_size {
        return false;
    }
    match subgroup {
        AglMultiplierSubgroup::Full => true,
        AglMultiplierSubgroup::QuadraticResidues => {
            is_quadratic_residue_mod(multiplier, alphabet_size)
        }
    }
}
