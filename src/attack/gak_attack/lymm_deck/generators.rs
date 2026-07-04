//! Explicit generator-set parsing and enumeration for Lymm deck recovery.

use std::collections::BTreeMap;

use crate::ciphers::validate_permutation;

use super::{
    GeneratorBranchStrategy, LymmDeckError, LymmDeckSpec, TopSwapCandidate, TopSwapConstraints,
    TopSwapDomains, compose_lymm,
};

type SparsePermutation = Vec<(usize, usize)>;
type CanonicalWords = BTreeMap<SparsePermutation, Vec<usize>>;

/// Explicit generator set for generalized Lymm swap recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LymmGeneratorSet {
    n: usize,
    generators: Vec<LymmGenerator>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LymmGenerator {
    label: String,
    permutation: Vec<usize>,
    support: Vec<usize>,
    is_transposition: bool,
}

impl LymmGeneratorSet {
    /// Builds a generator set from full deck permutations.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] when `n` is too small, the set is empty, or any
    /// supplied permutation is not a permutation of `0..n`.
    pub fn from_permutations(
        n: usize,
        permutations: Vec<Vec<usize>>,
    ) -> Result<Self, LymmDeckError> {
        let rows = permutations
            .into_iter()
            .enumerate()
            .map(|(index, permutation)| (format!("g{index}"), permutation))
            .collect::<Vec<_>>();
        Self::from_labeled_permutations(n, rows)
    }

    /// Parses a generator file: one full permutation per non-empty line.
    ///
    /// Lines may contain comma, semicolon, or whitespace separated integers.
    /// `#` starts a comment, and an optional `label:` prefix names the generator
    /// without changing its word index.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] when a line is malformed, the set is empty, or
    /// any parsed row is not a permutation of `0..n`.
    pub fn parse_permutation_file(n: usize, raw: &str) -> Result<Self, LymmDeckError> {
        let mut rows = Vec::new();
        for (line_index, raw_line) in raw.lines().enumerate() {
            let line = raw_line
                .split_once('#')
                .map_or(raw_line, |(prefix, _comment)| prefix)
                .trim();
            if line.is_empty() {
                continue;
            }
            let line_number = line_index.saturating_add(1);
            let (label, payload) = if let Some((left, right)) = line.split_once(':') {
                let label = left.trim();
                if label.is_empty() {
                    return Err(LymmDeckError::GeneratorLine {
                        line: line_number,
                        reason: "empty generator label",
                    });
                }
                (label.to_owned(), right.trim())
            } else {
                (format!("g{}", rows.len()), line)
            };
            if payload.is_empty() {
                return Err(LymmDeckError::GeneratorLine {
                    line: line_number,
                    reason: "missing permutation entries",
                });
            }
            rows.push((label, parse_generator_permutation(line_number, payload)?));
        }
        Self::from_labeled_permutations(n, rows)
    }

    /// Deck size of this generator set.
    #[must_use]
    pub const fn n(&self) -> usize {
        self.n
    }

    /// Number of generators in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.generators.len()
    }

    /// Returns true when the set has no generators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.generators.is_empty()
    }

    /// Returns a generator label by word index.
    #[must_use]
    pub fn label(&self, index: usize) -> Option<&str> {
        self.generators
            .get(index)
            .map(|generator| generator.label.as_str())
    }

    /// Returns a generator permutation by word index.
    #[must_use]
    pub fn permutation(&self, index: usize) -> Option<&[usize]> {
        self.generators
            .get(index)
            .map(|generator| generator.permutation.as_slice())
    }

    fn from_labeled_permutations(
        n: usize,
        rows: Vec<(String, Vec<usize>)>,
    ) -> Result<Self, LymmDeckError> {
        if n < 2 {
            return Err(LymmDeckError::DeckTooSmall { n });
        }
        if rows.is_empty() {
            return Err(LymmDeckError::GeneratorSetEmpty);
        }
        let mut generators = Vec::with_capacity(rows.len());
        for (label, permutation) in rows {
            validate_permutation("Lymm generator", &permutation, n)?;
            let support = sparse_support(&permutation);
            let is_transposition = is_transposition_permutation(&permutation, &support);
            generators.push(LymmGenerator {
                label,
                permutation,
                support,
                is_transposition,
            });
        }
        Ok(Self { n, generators })
    }

    fn branch_strategy(&self, max_word_len: usize) -> GeneratorBranchStrategy {
        if self
            .generators
            .iter()
            .all(|generator| generator.is_transposition)
        {
            GeneratorBranchStrategy::SmallTranspositionSupport
        } else {
            GeneratorBranchStrategy::WordMitm {
                split: max_word_len / 2,
            }
        }
    }
}

/// Enumerates the reachable final `sigma` set generated by an explicit generator
/// set.
///
/// Small-support transposition sets use an in-place support path. Other
/// generator sets use a word-based meet-in-the-middle split and then de-duplicate
/// equivalent final permutations.
///
/// # Errors
/// Returns [`LymmDeckError`] if the generator deck size does not match `spec` or
/// a composed generator word becomes invalid.
pub fn enumerate_generator_domains(
    spec: &LymmDeckSpec,
    generator_set: &LymmGeneratorSet,
    constraints: &TopSwapConstraints,
) -> Result<TopSwapDomains, LymmDeckError> {
    if generator_set.n() != spec.n {
        return Err(LymmDeckError::GeneratorDeckSize {
            generator_n: generator_set.n(),
            spec_n: spec.n,
        });
    }
    let strategy = generator_set.branch_strategy(constraints.max_swaps);
    let canonical_words = match strategy {
        GeneratorBranchStrategy::TopSwapSupport => BTreeMap::new(),
        GeneratorBranchStrategy::SmallTranspositionSupport => {
            enumerate_generator_words_by_support(generator_set, constraints.max_swaps)?
        }
        GeneratorBranchStrategy::WordMitm { split } => {
            enumerate_generator_words_mitm(generator_set, constraints.max_swaps, split)?
        }
    };
    domains_from_canonical_words(spec, constraints, canonical_words, strategy)
}

/// Enumerates candidates whose final `base o sigma` maps `entry` to `target`.
pub(crate) fn enumerate_generator_domains_for_entry_target(
    spec: &LymmDeckSpec,
    generator_set: &LymmGeneratorSet,
    constraints: &TopSwapConstraints,
    entry: usize,
    target: usize,
) -> Result<TopSwapDomains, LymmDeckError> {
    if entry >= spec.n {
        return Err(LymmDeckError::EmitIndexOutOfRange {
            emit_index: entry,
            n: spec.n,
        });
    }
    let target_source = spec.base.iter().position(|&image| image == target).ok_or(
        LymmDeckError::EmitIndexOutOfRange {
            emit_index: target,
            n: spec.n,
        },
    )?;
    if generator_set.n() != spec.n {
        return Err(LymmDeckError::GeneratorDeckSize {
            generator_n: generator_set.n(),
            spec_n: spec.n,
        });
    }
    let strategy = generator_set.branch_strategy(constraints.max_swaps);
    let canonical_words = match strategy {
        GeneratorBranchStrategy::TopSwapSupport => BTreeMap::new(),
        GeneratorBranchStrategy::SmallTranspositionSupport => {
            enumerate_generator_words_by_support(generator_set, constraints.max_swaps)?
        }
        GeneratorBranchStrategy::WordMitm { split } => enumerate_generator_words_mitm_entry_target(
            generator_set,
            constraints.max_swaps,
            split,
            entry,
            target_source,
        )?,
    };
    let constraints = TopSwapConstraints::up_to(constraints.max_swaps);
    let domains = domains_from_canonical_words(spec, &constraints, canonical_words, strategy)?;
    Ok(filter_entry_target_domains(spec, domains, entry, target))
}

fn domains_from_canonical_words(
    spec: &LymmDeckSpec,
    constraints: &TopSwapConstraints,
    canonical_words: CanonicalWords,
    branch_strategy: GeneratorBranchStrategy,
) -> Result<TopSwapDomains, LymmDeckError> {
    let mut candidates = Vec::new();
    for (sparse, canonical_swaps) in canonical_words {
        let support = sparse
            .iter()
            .map(|(position, _image)| *position)
            .collect::<Vec<_>>();
        let sigma_images = sparse.iter().map(|(_position, image)| *image).collect();
        let top_source = sparse
            .iter()
            .find_map(|(position, image)| (*position == spec.emit_index).then_some(*image))
            .unwrap_or(spec.emit_index);
        let top_image =
            spec.base
                .get(top_source)
                .copied()
                .ok_or(LymmDeckError::EmitIndexOutOfRange {
                    emit_index: top_source,
                    n: spec.n,
                })?;
        if !top_image_allowed(constraints, top_image) {
            continue;
        }
        if constraints
            .required_support
            .as_ref()
            .is_some_and(|required| required != &support)
        {
            continue;
        }
        let perm_images = sparse
            .iter()
            .filter_map(|(_position, image)| spec.base.get(*image).copied())
            .collect::<Vec<_>>();
        candidates.push(TopSwapCandidate {
            canonical_swaps,
            top_image,
            support,
            sigma_images,
            perm_images,
        });
    }

    let mut by_top_image: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut by_support: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_top_image
            .entry(candidate.top_image)
            .or_default()
            .push(index);
        by_support
            .entry(candidate.support.clone())
            .or_default()
            .push(index);
    }
    Ok(TopSwapDomains {
        candidates,
        by_top_image,
        by_support,
        branch_strategy,
    })
}

fn enumerate_generator_words_by_support(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
) -> Result<CanonicalWords, LymmDeckError> {
    let mut canonical_words = BTreeMap::new();
    let mut sigma = (0..generator_set.n()).collect::<Vec<_>>();
    let mut word = Vec::with_capacity(max_word_len);
    enumerate_generator_words_dfs(
        generator_set,
        max_word_len,
        &mut sigma,
        &mut word,
        &mut canonical_words,
    )?;
    Ok(canonical_words)
}

fn enumerate_generator_words_dfs(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
    sigma: &mut [usize],
    word: &mut Vec<usize>,
    canonical_words: &mut CanonicalWords,
) -> Result<(), LymmDeckError> {
    record_canonical(sigma, word, canonical_words);
    if word.len() == max_word_len {
        return Ok(());
    }
    for (generator_index, generator) in generator_set.generators.iter().enumerate() {
        apply_generator_in_place(generator, sigma)?;
        word.push(generator_index);
        enumerate_generator_words_dfs(generator_set, max_word_len, sigma, word, canonical_words)?;
        let _popped = word.pop();
        apply_generator_in_place(generator, sigma)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WordState {
    sigma: Vec<usize>,
    word: Vec<usize>,
}

fn enumerate_generator_words_mitm(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
    split: usize,
) -> Result<CanonicalWords, LymmDeckError> {
    let prefixes = enumerate_word_states(generator_set, split)?;
    let suffixes = enumerate_word_states(generator_set, max_word_len.saturating_sub(split))?;
    let mut canonical_words = BTreeMap::new();
    for prefix in &prefixes {
        for suffix in &suffixes {
            if prefix.word.len().saturating_add(suffix.word.len()) > max_word_len {
                continue;
            }
            let sigma = compose_lymm(&suffix.sigma, &prefix.sigma)?;
            let mut word = prefix.word.clone();
            word.extend_from_slice(&suffix.word);
            record_canonical(&sigma, &word, &mut canonical_words);
        }
    }
    Ok(canonical_words)
}

fn enumerate_generator_words_mitm_entry_target(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
    split: usize,
    entry: usize,
    target_source: usize,
) -> Result<CanonicalWords, LymmDeckError> {
    let prefixes = enumerate_word_states(generator_set, split)?;
    let suffixes = enumerate_word_states(generator_set, max_word_len.saturating_sub(split))?;
    let mut prefixes_by_input: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, prefix) in prefixes.iter().enumerate() {
        if let Some(input) = prefix
            .sigma
            .iter()
            .position(|&image| image == target_source)
        {
            prefixes_by_input.entry(input).or_default().push(index);
        }
    }

    let mut canonical_words = BTreeMap::new();
    for suffix in &suffixes {
        let Some(&input) = suffix.sigma.get(entry) else {
            continue;
        };
        let Some(prefix_indexes) = prefixes_by_input.get(&input) else {
            continue;
        };
        for &prefix_index in prefix_indexes {
            let Some(prefix) = prefixes.get(prefix_index) else {
                continue;
            };
            if prefix.word.len().saturating_add(suffix.word.len()) > max_word_len {
                continue;
            }
            let sigma = compose_lymm(&suffix.sigma, &prefix.sigma)?;
            let mut word = prefix.word.clone();
            word.extend_from_slice(&suffix.word);
            record_canonical(&sigma, &word, &mut canonical_words);
        }
    }
    Ok(canonical_words)
}

fn enumerate_word_states(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
) -> Result<Vec<WordState>, LymmDeckError> {
    let mut states = Vec::new();
    let mut sigma = (0..generator_set.n()).collect::<Vec<_>>();
    let mut word = Vec::with_capacity(max_word_len);
    enumerate_word_states_dfs(
        generator_set,
        max_word_len,
        &mut sigma,
        &mut word,
        &mut states,
    )?;
    Ok(states)
}

fn enumerate_word_states_dfs(
    generator_set: &LymmGeneratorSet,
    max_word_len: usize,
    sigma: &mut Vec<usize>,
    word: &mut Vec<usize>,
    states: &mut Vec<WordState>,
) -> Result<(), LymmDeckError> {
    states.push(WordState {
        sigma: sigma.clone(),
        word: word.clone(),
    });
    if word.len() == max_word_len {
        return Ok(());
    }
    for (generator_index, generator) in generator_set.generators.iter().enumerate() {
        let previous = sigma.clone();
        *sigma = compose_lymm(&generator.permutation, sigma)?;
        word.push(generator_index);
        enumerate_word_states_dfs(generator_set, max_word_len, sigma, word, states)?;
        let _popped = word.pop();
        *sigma = previous;
    }
    Ok(())
}

fn apply_generator_in_place(
    generator: &LymmGenerator,
    sigma: &mut [usize],
) -> Result<(), LymmDeckError> {
    match generator.support.as_slice() {
        [] => {}
        [left, right] if generator.is_transposition => {
            sigma.swap(*left, *right);
        }
        _ => {
            let updated = compose_lymm(&generator.permutation, sigma)?;
            for (slot, value) in sigma.iter_mut().zip(updated) {
                *slot = value;
            }
        }
    }
    Ok(())
}

fn top_image_allowed(constraints: &TopSwapConstraints, top_image: usize) -> bool {
    if constraints
        .required_top_image
        .is_some_and(|value| value != top_image)
    {
        return false;
    }
    constraints
        .required_top_images
        .as_ref()
        .is_none_or(|values| values.contains(&top_image))
}
fn filter_entry_target_domains(
    spec: &LymmDeckSpec,
    domains: TopSwapDomains,
    entry: usize,
    target: usize,
) -> TopSwapDomains {
    let candidates = domains
        .candidates
        .into_iter()
        .filter(|candidate| {
            candidate
                .permutation(spec)
                .get(entry)
                .is_some_and(|&image| image == target)
        })
        .collect::<Vec<_>>();
    domains_from_candidates(candidates, domains.branch_strategy)
}

fn domains_from_candidates(
    candidates: Vec<TopSwapCandidate>,
    branch_strategy: GeneratorBranchStrategy,
) -> TopSwapDomains {
    let mut by_top_image: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut by_support: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_top_image
            .entry(candidate.top_image)
            .or_default()
            .push(index);
        by_support
            .entry(candidate.support.clone())
            .or_default()
            .push(index);
    }
    TopSwapDomains {
        candidates,
        by_top_image,
        by_support,
        branch_strategy,
    }
}

fn record_canonical(sigma: &[usize], word: &[usize], canonical_words: &mut CanonicalWords) {
    let sparse = sparse_key(sigma);
    let replace = canonical_words
        .get(&sparse)
        .is_none_or(|existing| word.len() < existing.len() || word < existing.as_slice());
    if replace {
        let _old = canonical_words.insert(sparse, word.to_vec());
    }
}

fn parse_generator_permutation(
    line_number: usize,
    payload: &str,
) -> Result<Vec<usize>, LymmDeckError> {
    let mut values = Vec::new();
    for part in payload.split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace()) {
        if part.is_empty() {
            continue;
        }
        let value = part
            .parse::<usize>()
            .map_err(|_error| LymmDeckError::GeneratorLine {
                line: line_number,
                reason: "expected unsigned integer permutation entries",
            })?;
        values.push(value);
    }
    if values.is_empty() {
        return Err(LymmDeckError::GeneratorLine {
            line: line_number,
            reason: "missing permutation entries",
        });
    }
    Ok(values)
}

fn is_transposition_permutation(permutation: &[usize], support: &[usize]) -> bool {
    match support {
        [] => true,
        [left, right] => {
            permutation.get(*left) == Some(right) && permutation.get(*right) == Some(left)
        }
        _ => false,
    }
}

fn sparse_support(permutation: &[usize]) -> Vec<usize> {
    permutation
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, image)| (position != image).then_some(position))
        .collect()
}

fn sparse_key(sigma: &[usize]) -> Vec<(usize, usize)> {
    sigma
        .iter()
        .copied()
        .enumerate()
        .filter(|(position, image)| position != image)
        .collect()
}
