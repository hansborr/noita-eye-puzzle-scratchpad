//! Synthetic GAK fixture generator: finite-group fixtures with held-back ground
//! truth, plus the shared edge-map and symbol-conversion utilities reused by the
//! solver, deck, and marginalization siblings.

use super::*;

mod groups;

use groups::{choose_generators, group_table, left_regular_permutation};

/// Which finite state group a synthetic GAK fixture realizes.
///
/// Both kinds are realized as permutation groups via the left regular
/// representation, so the solver code path is identical; the dihedral kind is the
/// **non-commutative** witness that the gate does not accidentally exploit
/// commutativity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// Commutative cyclic group `C_m` of the configured order.
    Cyclic {
        /// Group order `m`.
        order: usize,
    },
    /// Non-commutative dihedral group `D_{2k}` (order `2k`) for `k ≥ 3`.
    Dihedral {
        /// Half-order `k`; the group order is `2k`.
        half_order: usize,
    },
}

impl GroupKind {
    /// Returns the abstract group order `|G|`.
    #[must_use]
    pub const fn order(self) -> usize {
        match self {
            Self::Cyclic { order } => order,
            Self::Dihedral { half_order } => half_order.saturating_mul(2),
        }
    }

    /// Returns a short report label for this group kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cyclic { .. } => "cyclic",
            Self::Dihedral { .. } => "dihedral",
        }
    }

    /// Whether this group is non-commutative (dihedral with `k ≥ 3`).
    #[must_use]
    pub const fn is_non_commutative(self) -> bool {
        matches!(self, Self::Dihedral { half_order } if half_order >= 3)
    }
}

/// Which hidden subgroup `H` a fixture uses.
///
/// The GCTAK gate realizes the **trivial** hidden subgroup (`|H| = 1`, bijective
/// readout `c`). Unit 2a adds the **deck stabilizer** [`Self::DeckStabilizer`]:
/// the real, non-trivial GAK the community's open problem is about
/// (`H = Stab(top) = S_{n-1}`, `|H| = (n-1)! > 1`, `|C| = n`, hidden state = the
/// rest of the deck).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenSubgroupKind {
    /// Trivial hidden subgroup `H = {e}`: the readout `c` is bijective and
    /// `|C| = |G|`. This is the GCTAK regime.
    Trivial,
    /// Deck-stabilizer hidden subgroup `H = Stab(top) = S_{n-1}` over the full
    /// symmetric state group `S_n` ([`CosetReadout::TopCard`]): the visible
    /// symbol is the position holding the marked card, `|C| = n`, `|H| = (n-1)!`,
    /// and the rest of the deck is the hidden state. This is **real GAK**
    /// (`|H| > 1`) — the regime the deck-cipher attack of this unit targets.
    DeckStabilizer,
}

impl HiddenSubgroupKind {
    /// Returns a short report label for this hidden-subgroup kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trivial => "trivial-H (GCTAK)",
            Self::DeckStabilizer => "deck-stabilizer S_{n-1} (real GAK, |H|>1)",
        }
    }

    /// Whether this hidden subgroup is non-trivial (`|H| > 1`), i.e. real GAK.
    #[must_use]
    pub const fn is_non_trivial(self) -> bool {
        matches!(self, Self::DeckStabilizer)
    }
}

/// The structure a fixture's **constructed key actually realizes**, derived by
/// enumerating reachable states — never merely declared.
///
/// The declared `group_kind.order()` is the *base* group order. When the
/// TENTATIVE small-support knob (`small_support_radius > 0`) perturbs a letter
/// permutation it can leave the base group's regular representation, so the
/// subgroup the chosen letters actually generate (and hence the realized
/// ciphertext-coset alphabet `|C|`) may be **smaller** than the declared order.
/// Reporting this realized structure keeps a perturbed fixture from claiming a
/// structure its key lacks (review finding F3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealizedStructure {
    /// Declared base group order `|G|` (before any small-support perturbation).
    pub declared_group_order: usize,
    /// Size of the subgroup the chosen letter permutations actually generate
    /// from the initial state — i.e. the number of reachable states.
    pub realized_subgroup_order: usize,
    /// Number of distinct ciphertext cosets `|C|` the realized states emit. With
    /// the bijective trivial-`H` readout this equals `realized_subgroup_order`.
    pub realized_coset_alphabet_size: usize,
    /// Whether the readout is **bijective on the reachable states** (i.e. the
    /// trivial hidden subgroup holds), *verified from the constructed key*, not
    /// assumed. The gate requires this to stay `true`.
    pub readout_bijective: bool,
    /// Whether the realized subgroup is faithful to the declared base group
    /// (`realized_subgroup_order == declared_group_order`). Always `true` for the
    /// `small_support_radius == 0` gate regime; can be `false` only under the
    /// TENTATIVE perturbation knob.
    pub faithful_to_declared: bool,
}

/// Held-back ground truth for one synthetic GAK fixture.
///
/// The attack always has this so every claim is checkable against truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticFixture {
    /// Plaintext letter stream (each [`Glyph`] is a letter index).
    pub plaintext: Vec<Glyph>,
    /// Ciphertext coset stream emitted by [`gak_encrypt`].
    pub ciphertext: Vec<Glyph>,
    /// The full key, held back for ground-truth checks.
    pub key: GakKey,
    /// The group kind this fixture realizes.
    pub group_kind: GroupKind,
    /// The hidden-subgroup kind this fixture realizes.
    pub hidden_subgroup_kind: HiddenSubgroupKind,
    /// The structure the constructed key **actually** realizes (derived from the
    /// key, not declared). See [`RealizedStructure`]; under the TENTATIVE
    /// small-support knob this can differ from `group_kind.order()`.
    pub realized: RealizedStructure,
}

// =====================================================================
// A. Synthetic generator driver (ground-truth fixtures).
// =====================================================================

/// Builds a synthetic GCTAK fixture with held-back ground truth.
///
/// `group_kind` selects the abstract state group (commutative cyclic or
/// non-commutative dihedral). Both are realized as permutation groups by the
/// **left regular representation**, so the solver code path is identical. The
/// hidden subgroup is trivial ([`HiddenSubgroupKind::Trivial`]) so the readout is
/// bijective (`|C| = |G|`), i.e. GCTAK.
///
/// `config.num_pt_letters` distinct non-identity group elements become the
/// plaintext letters' permutations. `config.small_support_radius` (TENTATIVE)
/// composes each letter permutation with `≤k` random transpositions; `0` is the
/// unconstrained regime the gate uses. The plaintext is a repeated-phrase
/// template so the ciphertext is isomorph-rich.
///
/// # Errors
/// Returns [`GakAttackError`] when the group is too small for the requested
/// letter count, when a generated permutation or key is rejected, or when a
/// generated symbol cannot be represented.
pub fn generate_fixture(
    group_kind: GroupKind,
    config: GakAttackConfig,
    seed: u64,
) -> Result<SyntheticFixture, GakAttackError> {
    let order = group_kind.order();
    if order < 2 {
        return Err(GakAttackError::CyclicOrderTooSmall { order });
    }

    // Group multiplication table over indices 0..order, with index 0 = identity.
    let table = group_table(group_kind)?;

    // Choose `num_pt_letters` distinct non-identity generators.
    let available = order.saturating_sub(1);
    if config.num_pt_letters == 0 || config.num_pt_letters > available {
        return Err(GakAttackError::TooManyLetters {
            requested: config.num_pt_letters,
            available,
        });
    }
    let mut rng = SplitMix64::new(seed);
    let generators = choose_generators(
        &table,
        config.num_pt_letters,
        group_kind.is_non_commutative(),
        &mut rng,
    )?;

    // Realize each generator as its left-regular permutation, then optionally
    // perturb by ≤k transpositions (TENTATIVE small-support knob). The perturbed
    // permutation is still a valid S_n element; GCTAK only needs a bijective
    // readout, which the CosetTable identity projection provides regardless.
    let mut plaintext_letters = Vec::with_capacity(config.num_pt_letters);
    for &generator in &generators {
        let mut permutation = left_regular_permutation(&table, generator)?;
        apply_small_support(&mut permutation, config.small_support_radius, &mut rng)?;
        plaintext_letters.push(permutation);
    }

    // Trivial H: bijective readout via an identity coset table over 0..order.
    let coset_of: Vec<usize> = (0..order).collect();
    let readout = CosetReadout::CosetTable {
        reference_value: 0,
        coset_of,
    };
    let initial_state: Vec<usize> = (0..order).collect();
    let key = GakKey::new(
        order,
        plaintext_letters,
        initial_state,
        readout,
        GakKeyOptions::default(),
    )?;

    let plaintext = repeated_phrase_template(config, config.num_pt_letters, &mut rng)?;
    if plaintext.is_empty() {
        return Err(GakAttackError::EmptyTemplate);
    }
    let ciphertext = gak_encrypt(&plaintext, &key)?;

    // F3: derive the structure the constructed key ACTUALLY realizes (do not
    // declare it). Under the TENTATIVE small-support knob the perturbed letters
    // may generate a smaller subgroup than the declared base order; report the
    // realized size honestly and verify (rather than assume) that the readout
    // stays bijective on reachable states (trivial hidden subgroup).
    let realized = realized_structure(&key, group_kind.order())?;

    Ok(SyntheticFixture {
        plaintext,
        ciphertext,
        key,
        group_kind,
        hidden_subgroup_kind: HiddenSubgroupKind::Trivial,
        realized,
    })
}

/// Derives the structure a constructed [`GakKey`] **actually realizes** by
/// enumerating the reachable states.
///
/// Starting from the key's initial state, this closes the set of states under
/// left-multiplication by every plaintext-letter permutation (the only states the
/// cipher can ever occupy), then reads off:
/// - the realized subgroup order (number of reachable states),
/// - the realized ciphertext-coset alphabet `|C|` (distinct readouts), and
/// - whether the readout is **bijective on those states** (trivial `H`,
///   *verified* not assumed).
///
/// For `small_support_radius == 0` the regular representation is faithful, so the
/// realized order equals `declared_group_order` and nothing changes for the gate.
///
/// # Errors
/// Returns [`GakAttackError`] if a reachable state's readout cannot be computed
/// or a generated symbol cannot be represented (both internal invariants here).
fn realized_structure(
    key: &GakKey,
    declared_group_order: usize,
) -> Result<RealizedStructure, GakAttackError> {
    let initial = key.initial_state().to_vec();
    let mut seen: BTreeSet<Vec<usize>> = BTreeSet::new();
    let _inserted = seen.insert(initial.clone());
    let mut frontier = vec![initial];
    while let Some(state) = frontier.pop() {
        for permutation in key.plaintext_letters() {
            let next = compose_state(permutation, &state)?;
            if seen.insert(next.clone()) {
                frontier.push(next);
            }
        }
    }

    // Readout of every reachable state; |C| and bijectivity follow.
    let mut readouts: Vec<usize> = Vec::with_capacity(seen.len());
    for state in &seen {
        readouts.push(readout_of_state(key, state)?);
    }
    let distinct_cosets: BTreeSet<usize> = readouts.iter().copied().collect();
    let realized_subgroup_order = seen.len();
    let realized_coset_alphabet_size = distinct_cosets.len();
    // Bijective on reachable states iff distinct states map to distinct cosets.
    let readout_bijective = realized_coset_alphabet_size == realized_subgroup_order;

    Ok(RealizedStructure {
        declared_group_order,
        realized_subgroup_order,
        realized_coset_alphabet_size,
        readout_bijective,
        faithful_to_declared: realized_subgroup_order == declared_group_order,
    })
}

/// The held ground-truth per-letter ciphertext-alphabet permutations `tau_a`.
///
/// For GCTAK the readout is bijective on reachable states, so each plaintext
/// letter `a` induces a fixed permutation `tau_a` of the ciphertext alphabet with
/// `c(p(a) ∘ g) = tau_a(c(g))` for every reachable state `g`. This enumerates the
/// reachable states and reads `tau_a` off directly from the key, giving the
/// ground truth the recovered permutations are scored against (review finding F5).
/// Each `tau_a` is returned as a `prev -> next` [`EdgeMap`] so it compares against
/// a recovered permutation by structural equality.
///
/// # Errors
/// Returns [`GakAttackError`] if a reachable state's readout cannot be computed or
/// a coset value exceeds the `u8` symbol range (internal invariants here).
pub(crate) fn truth_letter_permutations(key: &GakKey) -> Result<Vec<EdgeMap>, GakAttackError> {
    // Enumerate reachable states (the same closure used by `realized_structure`).
    let initial = key.initial_state().to_vec();
    let mut seen: BTreeSet<Vec<usize>> = BTreeSet::new();
    let _inserted = seen.insert(initial.clone());
    let mut frontier = vec![initial];
    while let Some(state) = frontier.pop() {
        for permutation in key.plaintext_letters() {
            let next = compose_state(permutation, &state)?;
            if seen.insert(next.clone()) {
                frontier.push(next);
            }
        }
    }

    let mut truths = Vec::with_capacity(key.plaintext_letters().len());
    for permutation in key.plaintext_letters() {
        let mut tau = EdgeMap::new();
        for state in &seen {
            let from = readout_of_state(key, state)?;
            let updated = compose_state(permutation, state)?;
            let to = readout_of_state(key, &updated)?;
            let from_value = u8::try_from(from)
                .map_err(|_error| GakAttackError::SymbolOutOfRange { value: from })?;
            let to_value = u8::try_from(to)
                .map_err(|_error| GakAttackError::SymbolOutOfRange { value: to })?;
            let _old = tau.insert(from_value, to_value);
        }
        truths.push(tau);
    }
    Ok(truths)
}

/// Scores recovered per-letter permutations against the held truth `tau_a`.
///
/// Returns `(matched, total)`: how many of the `total` truth permutations equal
/// some recovered permutation (one-to-one, up to the canonical relabelling of
/// letters that the edge-map representation already absorbs — a `tau_a` is the
/// same fixed bijection however the generator numbered letter `a`). This is the
/// spec's preferred success metric (per-letter permutation recovery), surfaced in
/// the report and asserted in tests (review finding F5).
pub(crate) fn permutation_recovery_fraction(
    truth: &[EdgeMap],
    recovered: &[EdgeMap],
) -> (usize, usize) {
    let mut used = vec![false; recovered.len()];
    let mut matched = 0usize;
    for tau in truth {
        for (index, perm) in recovered.iter().enumerate() {
            let Some(slot) = used.get_mut(index) else {
                continue;
            };
            if !*slot && perm == tau {
                *slot = true;
                matched = matched.saturating_add(1);
                break;
            }
        }
    }
    (matched, truth.len())
}

/// Composes two `0..n` permutations in the `(f ∘ g)[i] = f[g[i]]` convention used
/// by [`gak_encrypt`] (the cipher's state-update convention).
///
/// Thin wrapper over [`compose_permutations`] that maps the shared helper's
/// contextless internal-invariant error into this module's error type. Inputs are
/// assumed validated, so an out-of-range image is an internal invariant rather
/// than expected input; the failing image is not surfaced by the shared helper.
pub(crate) fn compose_state(
    outer: &[usize],
    inner: &[usize],
) -> Result<Vec<usize>, GakAttackError> {
    compose_permutations(outer, inner)
        .map_err(|_error| GakAttackError::SymbolOutOfRange { value: usize::MAX })
}

/// Computes the readout `c(state)` as a plain `usize`, mirroring the cipher's
/// [`CosetReadout`] projection (used by [`realized_structure`]).
pub(crate) fn readout_of_state(key: &GakKey, state: &[usize]) -> Result<usize, GakAttackError> {
    match key.coset_readout() {
        CosetReadout::TopCard { reference_value } => {
            inverse_image_position(state, *reference_value)
        }
        CosetReadout::CosetTable {
            reference_value,
            coset_of,
        } => {
            let position = inverse_image_position(state, *reference_value)?;
            coset_of
                .get(position)
                .copied()
                .ok_or(GakAttackError::SymbolOutOfRange { value: position })
        }
    }
}

/// Composes `permutation` with `radius` random transpositions in place.
///
/// **TENTATIVE small-support heuristic** (`Deck-Cipher.md`): the result is still a
/// valid `S_n` permutation. The GCTAK gate runs with `radius == 0`.
pub(crate) fn apply_small_support(
    permutation: &mut [usize],
    radius: usize,
    rng: &mut SplitMix64,
) -> Result<(), GakAttackError> {
    let len = permutation.len();
    if len < 2 {
        return Ok(());
    }
    for _swap in 0..radius {
        let i = random_index_below(len, rng)?;
        let j = random_index_below(len, rng)?;
        permutation.swap(i, j);
    }
    Ok(())
}

/// Builds a repeated-phrase plaintext template over `num_letters` letter indices.
///
/// A single random phrase of `config.phrase_len` letters is repeated
/// `config.phrase_repeats` times, each repeat preceded by a fixed-length run of
/// **random** mixing letters. The mixing runs let the absolute group state drift
/// over the whole state group between repeats, so the same phrase occurrence is
/// seen from many different entry states; this is what lets the solver observe
/// each per-letter permutation across the full group (and thus merge same-letter
/// phrase columns exactly), and it works for non-commutative groups where a bare
/// repeat would only ever enter from a small orbit.
///
/// The GCTAK ciphertext is **not** periodic (the state accumulates); only the
/// equality/gap pattern of each phrase occurrence recurs, which is the
/// isomorph-rich signal the solver aligns on. The first two phrase positions are
/// forced to two different letters (when `num_letters ≥ 2`) so the partition is
/// non-degenerate.
pub(crate) fn repeated_phrase_template(
    config: GakAttackConfig,
    num_letters: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Glyph>, GakAttackError> {
    if num_letters == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }
    let mut phrase = Vec::with_capacity(config.phrase_len);
    for index in 0..config.phrase_len {
        // The first `num_letters` positions are the distinct letters in order so
        // every fixture uses all letters and the phrase signature starts with a
        // distinctive all-distinct run; later positions are random.
        let letter = if index < num_letters {
            index
        } else {
            random_index_below(num_letters, rng)?
        };
        phrase.push(letter);
    }

    // A short random mixing run between repeats drifts the entry state.
    let mixing_len = MIXING_RUN_LEN;
    let mut letters = Vec::new();
    for repeat in 0..config.phrase_repeats {
        if repeat > 0 {
            for _index in 0..mixing_len {
                letters.push(random_index_below(num_letters, rng)?);
            }
        }
        letters.extend(phrase.iter().copied());
    }

    let mut plaintext = Vec::with_capacity(letters.len());
    for letter in letters {
        let glyph = u16::try_from(letter)
            .map_err(|_error| GakAttackError::SymbolOutOfRange { value: letter })?;
        plaintext.push(Glyph(glyph));
    }
    Ok(plaintext)
}

/// Computes the readout `c(g_0)` of a key's initial state.
///
/// This is the ciphertext symbol the stream conceptually starts from (the state
/// entering the first plaintext letter). For the [`CosetReadout::CosetTable`]
/// readout used by the gate it is `coset_of[g_0^{-1}[reference]]`; for
/// [`CosetReadout::TopCard`] it is `g_0^{-1}[reference]`.
pub(crate) fn initial_state_readout(key: &GakKey) -> Result<SymbolValue, GakAttackError> {
    let state = key.initial_state();
    let readout_value = match key.coset_readout() {
        CosetReadout::TopCard { reference_value } => {
            inverse_image_position(state, *reference_value)?
        }
        CosetReadout::CosetTable {
            reference_value,
            coset_of,
        } => {
            let position = inverse_image_position(state, *reference_value)?;
            coset_of
                .get(position)
                .copied()
                .ok_or(GakAttackError::SymbolOutOfRange { value: position })?
        }
    };
    symbol_from_usize(readout_value)
}

/// Returns the position `j` with `state[j] == value` (`state^{-1}[value]`).
fn inverse_image_position(state: &[usize], value: usize) -> Result<usize, GakAttackError> {
    state
        .iter()
        .position(|&entry| entry == value)
        .ok_or(GakAttackError::SymbolOutOfRange { value })
}

fn symbol_from_usize(value: usize) -> Result<SymbolValue, GakAttackError> {
    let raw = u8::try_from(value).map_err(|_error| GakAttackError::SymbolOutOfRange { value })?;
    TrigramValue::new(raw).map_err(|bad| GakAttackError::SymbolOutOfRange {
        value: usize::from(bad),
    })
}

/// One recovered per-letter permutation as a `prev -> next` edge map.
///
/// Stored as a sorted edge list so two permutations compare by structural
/// equality regardless of insertion order.
pub(crate) type EdgeMap = BTreeMap<u8, u8>;
