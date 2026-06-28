//! Key types for the AGL(1,n)-GAK and general permutation-group GAK ciphers.
//!
//! These carry the group-theoretic state (affine maps / permutations and the
//! hidden-subgroup coset readout); the stream transforms live in the
//! `transforms` sibling and the group math in `mechanics`/`validation`.

use crate::ciphers::MAX_ALPHABET_SIZE;
use crate::ciphers::error::CipherError;
use crate::ciphers::validation::{
    compose_permutations, identity_gak_permutation, validate_agl_alphabet, validate_agl_element,
    validate_agl_letter_elements, validate_coset_table_invertible, validate_gak_letter_parity,
    validate_gak_state_size, validate_permutation,
};

/// Which multiplicative subgroup the AGL multiplier `a` ranges over.
///
/// [`AglMultiplierSubgroup::Full`] is `C83:C82` for the eye alphabet, and
/// [`AglMultiplierSubgroup::QuadraticResidues`] is the index-2 subgroup
/// `C83:C41`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglMultiplierSubgroup {
    /// All nonzero units modulo the prime alphabet size.
    Full,
    /// The quadratic-residue subgroup of the units modulo the prime alphabet.
    QuadraticResidues,
}

/// Key for an AGL(1,n)-GAK stream cipher in the verified convention.
///
/// State is an affine map `(a,b): x -> a*x + b (mod n)`. Each plaintext letter
/// right-multiplies the state by its configured group element, and the emitted
/// ciphertext is the updated state's image of the fixed reference point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakKey {
    pub(crate) alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    pub(crate) reference_point: usize,
    pub(crate) initial_state: (usize, usize),
    pub(crate) letter_elements: Vec<(usize, usize)>,
}

impl AglGakKey {
    /// Builds an AGL(1,n)-GAK key from explicit state and letter elements.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is not a supported prime, if a
    /// state element is outside the selected AGL subgroup, or if two plaintext
    /// letters occupy the same point-stabilizer coset.
    pub fn new(
        alphabet_size: usize,
        subgroup: AglMultiplierSubgroup,
        reference_point: usize,
        initial_state: (usize, usize),
        letter_elements: Vec<(usize, usize)>,
    ) -> Result<Self, CipherError> {
        validate_agl_alphabet(alphabet_size)?;
        if reference_point >= alphabet_size {
            return Err(CipherError::PermutationSymbolOutsideAlphabet {
                label: "AGL reference point",
                symbol: reference_point,
                alphabet_size,
            });
        }
        validate_agl_element(initial_state, alphabet_size, subgroup, "AGL initial state")?;
        validate_agl_letter_elements(&letter_elements, alphabet_size, subgroup, reference_point)?;
        Ok(Self {
            alphabet_size,
            subgroup,
            reference_point,
            initial_state,
            letter_elements,
        })
    }

    /// Builds an identity-state key with one translation representative per coset.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is not a supported prime.
    pub fn identity(
        alphabet_size: usize,
        subgroup: AglMultiplierSubgroup,
    ) -> Result<Self, CipherError> {
        validate_agl_alphabet(alphabet_size)?;
        let letter_elements = (0..alphabet_size).map(|symbol| (1, symbol)).collect();
        Self::new(alphabet_size, subgroup, 0, (1, 0), letter_elements)
    }

    /// Returns the configured ciphertext alphabet size.
    #[must_use]
    pub const fn alphabet_size(&self) -> usize {
        self.alphabet_size
    }

    /// Returns the configured multiplier subgroup.
    #[must_use]
    pub const fn subgroup(&self) -> AglMultiplierSubgroup {
        self.subgroup
    }

    /// Returns the fixed reference point `x0`.
    #[must_use]
    pub const fn reference_point(&self) -> usize {
        self.reference_point
    }

    /// Returns the initial affine state `(a,b)`.
    #[must_use]
    pub const fn initial_state(&self) -> (usize, usize) {
        self.initial_state
    }

    /// Returns plaintext-letter group elements in letter-index order.
    #[must_use]
    pub fn letter_elements(&self) -> &[(usize, usize)] {
        &self.letter_elements
    }
}

/// Hidden-subgroup coset readout `c: G -> C` for a [`GakKey`].
///
/// The readout must be constant on the right cosets `Hg` of the hidden subgroup
/// `H` — the `Group-Autokey-(GAK).md` requirement — paired with the spec's
/// left-multiplication state update `g_{i+1} = p(a_i) ∘ g_i` in the
/// `(f ∘ g)[i] = f[g[i]]` convention. Concretely the visible symbol is read off
/// `g^{-1}` (the *position* a marked card occupies): `c(g) = g^{-1}[reference]`.
/// This is the **intentional dual** of the literal deck/GAK spec's
/// `g[top_index]` readout, *not* that literal expression. The dual is forced by
/// the convention: under the left update `g ← p(a) ∘ g`, the function constant
/// on right cosets `Hg` (and hence invertible from any reachable state for
/// arbitrary `p(a)`) is `g^{-1}[reference]`, whereas `g[index]` is constant on
/// *left* cosets and would not be reversible here. Both variants realize the
/// abstract group `G` as a permutation group on `0..n` (`Deck-Cipher.md`: every
/// finite group is a permutation group, so one representation covers the deck
/// case and explicitly enumerated small groups alike).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosetReadout {
    /// Deck realization (`S_n` over the stabilizer `H = S_{n-1}` of one card):
    /// the visible ciphertext symbol is the *position* currently holding the
    /// marked card `reference_value`, i.e. `c(g) = g^{-1}[reference_value]`,
    /// with `|C| = n`. This is the deck cipher's "where is the top card"
    /// reading, the right-coset-constant dual of `g[index]` under left-update.
    TopCard {
        /// The marked card whose position is the visible ciphertext symbol.
        reference_value: usize,
    },
    /// Explicit coset projection for an enumerated small group: read the
    /// position of `reference_value` under `g` (i.e. `g^{-1}[reference_value]`,
    /// a value in `0..n`) and project it through `coset_of` to a coset label in
    /// `0..ciphertext_alphabet_size`.
    ///
    /// The caller is responsible for supplying a `(G, H)` pair whose right
    /// cosets `Hg` are exactly the fibers of
    /// `g -> coset_of[g^{-1}[reference_value]]` (document the pair and its
    /// source rather than re-deriving irreducibility of `H` in code).
    CosetTable {
        /// The marked card whose position indexes the projection table.
        reference_value: usize,
        /// Projection from card-position (`0..n`) to coset label
        /// (`0..ciphertext_alphabet_size`); length must equal the state size.
        coset_of: Vec<usize>,
    },
}

impl CosetReadout {
    /// Projects a state permutation to its visible ciphertext coset.
    ///
    /// The permutation is taken in the `(f ∘ g)[i] = f[g[i]]` convention used by
    /// [`gak_encrypt`](crate::ciphers::gak_encrypt); the readout reads `g^{-1}[reference_value]` so that it
    /// is constant on right cosets under the left-multiplication update.
    pub(crate) fn coset_of(&self, state: &[usize]) -> Result<usize, CipherError> {
        match self {
            Self::TopCard { reference_value } => inverse_image(state, *reference_value),
            Self::CosetTable {
                reference_value,
                coset_of,
            } => {
                let position = inverse_image(state, *reference_value)?;
                coset_of
                    .get(position)
                    .copied()
                    .ok_or(CipherError::InternalInvariant {
                        context: "GAK coset-table projection",
                    })
            }
        }
    }

    /// Number of distinct cosets `|C|` this readout can emit over `0..state_size`.
    fn ciphertext_alphabet_size(&self, state_size: usize) -> usize {
        match self {
            Self::TopCard { .. } => state_size,
            Self::CosetTable { coset_of, .. } => coset_of
                .iter()
                .copied()
                .max()
                .map_or(0, |max| max.saturating_add(1)),
        }
    }

    /// Validates the readout against the state size, returning `|C|`.
    fn validate(&self, state_size: usize) -> Result<usize, CipherError> {
        match self {
            Self::TopCard { reference_value } => {
                if *reference_value >= state_size {
                    return Err(CipherError::GakReferenceOutsideState {
                        reference_point: *reference_value,
                        state_size,
                    });
                }
                Ok(state_size)
            }
            Self::CosetTable {
                reference_value,
                coset_of,
            } => {
                if *reference_value >= state_size {
                    return Err(CipherError::GakReferenceOutsideState {
                        reference_point: *reference_value,
                        state_size,
                    });
                }
                if coset_of.len() != state_size {
                    return Err(CipherError::GakReadoutSizeMismatch {
                        label: "GAK coset table",
                        len: coset_of.len(),
                        state_size,
                    });
                }
                // Cap the ciphertext alphabet at the largest size a `Glyph` can
                // encode. Without this an unbounded coset label (e.g.
                // `usize::MAX - 1`) would pass the trivially-true `coset <
                // max(coset_of) + 1` check, then either trigger an impossible
                // `vec![false; alphabet_size]` allocation in `GakKey::new` or
                // emit a coset too large to represent as a `Glyph`.
                let alphabet_size = self.ciphertext_alphabet_size(state_size);
                if alphabet_size > MAX_ALPHABET_SIZE {
                    let coset = coset_of.iter().copied().max().unwrap_or(0);
                    return Err(CipherError::GakReadoutCosetOutsideAlphabet {
                        coset,
                        ciphertext_alphabet_size: MAX_ALPHABET_SIZE,
                    });
                }
                for &coset in coset_of {
                    if coset >= alphabet_size {
                        return Err(CipherError::GakReadoutCosetOutsideAlphabet {
                            coset,
                            ciphertext_alphabet_size: alphabet_size,
                        });
                    }
                }
                Ok(alphabet_size)
            }
        }
    }
}

/// Returns the position `j` with `state[j] == value`, i.e. `state^{-1}[value]`.
fn inverse_image(state: &[usize], value: usize) -> Result<usize, CipherError> {
    state
        .iter()
        .position(|&entry| entry == value)
        .ok_or(CipherError::InternalInvariant {
            context: "GAK inverse-image readout",
        })
}

/// Optional subgroup-parity constraint on a [`GakKey`]'s plaintext-letter
/// permutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GakSubgroupConstraint {
    /// No constraint: each `p(a)` may be any permutation of `0..n` (`S_n`).
    SymmetricGroup,
    /// Alternating group `A_n`: every `p(a)` must be an even permutation.
    AlternatingGroup,
}

/// Options applied while constructing a [`GakKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakKeyOptions {
    /// Reject any plaintext letter whose permutation leaves the readout coset
    /// unchanged from the initial state.
    ///
    /// This realizes `Deck-Cipher.md`'s "don't pick from the identity coset"
    /// rule. For the `TopCard` readout (and any readout where `c(p∘g) == c(g)` is
    /// state-independent, i.e. equivalent to `p` fixing the reference value)
    /// this guarantees no adjacent-equal ciphertext symbols. For an arbitrary
    /// `CosetTable` readout the check is performed only against the initial
    /// state, so it forbids initial-state doubles but does NOT guarantee the
    /// absence of adjacent-equal symbols from later reachable states.
    pub avoid_doubles: bool,
    /// Subgroup-parity constraint the plaintext-letter permutations must obey.
    pub subgroup: GakSubgroupConstraint,
}

impl Default for GakKeyOptions {
    fn default() -> Self {
        Self {
            avoid_doubles: false,
            subgroup: GakSubgroupConstraint::SymmetricGroup,
        }
    }
}

/// Key for a general Group-Autokey (GAK) cipher realized as a permutation group.
///
/// This is the abstract GAK of `Group-Autokey-(GAK).md`: a state group `G`
/// (here a permutation group on `0..n`) with a hidden subgroup `H`, a plaintext
/// map `p: P -> G`, and a ciphertext map `c: G -> C` constant on right cosets
/// `Hg`. The state updates by cumulative left-multiplication
/// `g_{i+1} = p(a_i) ∘ g_i` and the emitted symbol is `c(g_{i+1})`, with
/// `|C| = |G| / |H|`. With a trivial hidden subgroup (`c` bijective) it reduces
/// to GCTAK.
///
/// `S_n` / `A_n` / `D_{2n}` / `AGL(1,p)` and the candidate 83-symbol groups all
/// fit this one type by choosing the per-letter permutations and the
/// [`CosetReadout`]. The small-support / `≤k`-swaps (`≤k`-transpositions) prior
/// used by the generator drivers is a **TENTATIVE** search heuristic, not a
/// property of this key, and is not encoded here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakKey {
    pub(crate) ciphertext_alphabet_size: usize,
    pub(crate) state_size: usize,
    pub(crate) plaintext_letters: Vec<Vec<usize>>,
    pub(crate) initial_state: Vec<usize>,
    pub(crate) coset_readout: CosetReadout,
}

impl GakKey {
    /// Builds a GAK key from explicit per-letter permutations and a readout.
    ///
    /// Each entry of `plaintext_letters` is the permutation `p(a)` for one
    /// plaintext letter, in the `(f ∘ g)[i] = f[g[i]]` convention. The
    /// well-formedness rules of `Group-Autokey-(GAK).md` are enforced.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the state size is out of range; if
    /// `initial_state` or any `p(a)` is not a permutation of `0..n`; if the
    /// readout is malformed for the state size; if no plaintext letters are
    /// supplied; if two plaintext letters land in the same readout coset from
    /// the initial state (not injective on cosets, hence not reversible); if
    /// `avoid_doubles` is set and some `p(a)` fixes the readout coset; or if a
    /// requested subgroup-parity constraint is violated.
    pub fn new(
        state_size: usize,
        plaintext_letters: Vec<Vec<usize>>,
        initial_state: Vec<usize>,
        coset_readout: CosetReadout,
        options: GakKeyOptions,
    ) -> Result<Self, CipherError> {
        validate_gak_state_size(state_size)?;
        validate_permutation("GAK initial state", &initial_state, state_size)?;
        let ciphertext_alphabet_size = coset_readout.validate(state_size)?;
        if plaintext_letters.is_empty() {
            return Err(CipherError::EmptyGakLetters);
        }

        let base_coset = coset_readout.coset_of(&initial_state)?;
        let mut seen_cosets = vec![false; ciphertext_alphabet_size];
        for (letter_index, permutation) in plaintext_letters.iter().enumerate() {
            validate_permutation("GAK plaintext letter", permutation, state_size)?;
            validate_gak_letter_parity(permutation, options.subgroup, letter_index)?;

            let updated = compose_permutations(permutation, &initial_state)?;
            let coset = coset_readout.coset_of(&updated)?;
            if options.avoid_doubles && coset == base_coset {
                return Err(CipherError::GakLetterFixesCoset {
                    letter_index,
                    coset,
                });
            }
            let Some(slot) = seen_cosets.get_mut(coset) else {
                return Err(CipherError::InternalInvariant {
                    context: "GAK coset seen lookup",
                });
            };
            if *slot {
                return Err(CipherError::GakLettersShareCoset {
                    coset,
                    duplicate_index: letter_index,
                });
            }
            *slot = true;
        }

        // The identity-state injectivity check above is PROVEN sufficient for
        // the TopCard deck readout (its readout is itself the right-coset
        // projection, so per-state injectivity follows from the identity case).
        // It is NOT sufficient for an arbitrary supplied coset table, so those
        // require full reachable-state enumeration; see
        // `validate_coset_table_invertible`.
        if matches!(coset_readout, CosetReadout::CosetTable { .. }) {
            validate_coset_table_invertible(&plaintext_letters, &initial_state, &coset_readout)?;
        }

        Ok(Self {
            ciphertext_alphabet_size,
            state_size,
            plaintext_letters,
            initial_state,
            coset_readout,
        })
    }

    /// Builds a deck-realization GAK key (`S_n`, hidden subgroup `S_{n-1}`).
    ///
    /// Uses the identity initial state and [`CosetReadout::TopCard`] tracking
    /// the marked card `0`. The plaintext letters must already be permutations
    /// of `0..n`; see [`GakKey::new`] for the validation rules.
    ///
    /// # Errors
    /// Returns [`CipherError`] under the same conditions as [`GakKey::new`].
    pub fn deck(
        state_size: usize,
        plaintext_letters: Vec<Vec<usize>>,
        options: GakKeyOptions,
    ) -> Result<Self, CipherError> {
        let initial_state = identity_gak_permutation(state_size)?;
        Self::new(
            state_size,
            plaintext_letters,
            initial_state,
            CosetReadout::TopCard { reference_value: 0 },
            options,
        )
    }

    /// Returns the ciphertext alphabet size `|C| = |G| / |H|`.
    #[must_use]
    pub const fn ciphertext_alphabet_size(&self) -> usize {
        self.ciphertext_alphabet_size
    }

    /// Returns the permutation state size `n` (permutations act on `0..n`).
    #[must_use]
    pub const fn state_size(&self) -> usize {
        self.state_size
    }

    /// Returns the per-letter permutations `p(a)` in plaintext-letter order.
    #[must_use]
    pub fn plaintext_letters(&self) -> &[Vec<usize>] {
        &self.plaintext_letters
    }

    /// Returns the initial state permutation `g_0`.
    #[must_use]
    pub fn initial_state(&self) -> &[usize] {
        &self.initial_state
    }

    /// Returns the hidden-subgroup coset readout `c: G -> C`.
    #[must_use]
    pub const fn coset_readout(&self) -> &CosetReadout {
        &self.coset_readout
    }
}
