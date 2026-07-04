//! Top-swap domain enumeration and shared generator-domain structs.

use std::collections::{BTreeMap, BTreeSet};

use super::{LymmDeckError, LymmDeckSpec};

/// Representation selected for a generator-domain enumeration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneratorBranchStrategy {
    /// Specialized top-swap support enumeration used for Lymm's vendored S83
    /// generator family.
    TopSwapSupport,
    /// Support-based branch over sparse transposition effects.
    SmallTranspositionSupport,
    /// Word-based branch over generator words, split for meet-in-the-middle
    /// composition.
    WordMitm {
        /// Prefix word length used for the MITM split.
        split: usize,
    },
}

/// Constraints for enumerating generator candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopSwapConstraints {
    /// Maximum number of generators in the word.
    pub max_swaps: usize,
    /// Optional required final `perm[0]` value after composing with the spec base.
    pub required_top_image: Option<usize>,
    /// Optional allowed set of final `perm[0]` values.
    pub required_top_images: Option<BTreeSet<usize>>,
    /// Optional exact support of the final generator-word permutation.
    pub required_support: Option<Vec<usize>>,
}

impl TopSwapConstraints {
    /// Enumerates every candidate reachable by at most `max_swaps` generators.
    #[must_use]
    pub const fn up_to(max_swaps: usize) -> Self {
        Self {
            max_swaps,
            required_top_image: None,
            required_top_images: None,
            required_support: None,
        }
    }

    /// Restricts candidates to a specific final `perm[0]` image.
    #[must_use]
    pub const fn with_top_image(mut self, top_image: usize) -> Self {
        self.required_top_image = Some(top_image);
        self
    }

    /// Restricts candidates to one of the supplied final `perm[0]` images.
    #[must_use]
    pub fn with_top_images(mut self, top_images: BTreeSet<usize>) -> Self {
        self.required_top_images = Some(top_images);
        self
    }

    /// Restricts candidates to an exact final support.
    #[must_use]
    pub fn with_support(mut self, mut support: Vec<usize>) -> Self {
        support.sort_unstable();
        support.dedup();
        self.required_support = Some(support);
        self
    }
}

/// One reachable final generator-word candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopSwapCandidate {
    /// Canonical shortest, lexicographically first word. For top-swaps this is
    /// the sequence of top-swap indices; for explicit generator files it is the
    /// sequence of generator-file row indexes.
    pub canonical_swaps: Vec<usize>,
    /// Final `perm[0]` after composing the candidate `sigma` with `spec.base`.
    pub top_image: usize,
    /// Positions moved by the final `sigma`.
    pub support: Vec<usize>,
    /// Images of the moved support positions under `sigma`, in support order.
    pub sigma_images: Vec<usize>,
    /// Images of the moved support positions under `base o sigma`, in support
    /// order.
    pub perm_images: Vec<usize>,
}

impl TopSwapCandidate {
    /// Expands this sparse candidate into the full final `sigma` permutation.
    #[must_use]
    pub fn sigma_permutation(&self, n: usize) -> Vec<usize> {
        let mut sigma = (0..n).collect::<Vec<_>>();
        for (&position, &image) in self.support.iter().zip(&self.sigma_images) {
            if let Some(slot) = sigma.get_mut(position) {
                *slot = image;
            }
        }
        sigma
    }

    /// Expands this candidate into the full `base o sigma` permutation.
    #[must_use]
    pub fn permutation(&self, spec: &LymmDeckSpec) -> Vec<usize> {
        let sigma = self.sigma_permutation(spec.n);
        sigma
            .into_iter()
            .filter_map(|image| spec.base.get(image).copied())
            .collect()
    }
}

/// A de-duplicated generator domain plus indexes for solver lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopSwapDomains {
    /// Final candidates after repeat and identity words are collapsed.
    pub candidates: Vec<TopSwapCandidate>,
    /// Candidate indexes grouped by final `perm[0]`.
    pub by_top_image: BTreeMap<usize, Vec<usize>>,
    /// Candidate indexes grouped by exact final support.
    pub by_support: BTreeMap<Vec<usize>, Vec<usize>>,
    /// Branch representation selected for this enumeration.
    pub branch_strategy: GeneratorBranchStrategy,
}

impl TopSwapDomains {
    /// Returns candidates whose final `perm[0]` equals `top_image`.
    #[must_use]
    pub fn candidates_with_top_image(&self, top_image: usize) -> Vec<&TopSwapCandidate> {
        self.by_top_image
            .get(&top_image)
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .filter_map(|&index| self.candidates.get(index))
            .collect()
    }

    /// Returns candidates with exactly `support`.
    #[must_use]
    pub fn candidates_with_support(&self, mut support: Vec<usize>) -> Vec<&TopSwapCandidate> {
        support.sort_unstable();
        support.dedup();
        self.by_support
            .get(&support)
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .filter_map(|&index| self.candidates.get(index))
            .collect()
    }
}

/// Enumerates the reachable final `sigma` set generated by top swaps `(0 k)`.
///
/// Repeated swaps and the identity top swap `k=0` are handled by de-duplicating on
/// the final permutation; each candidate records the shortest lexicographically
/// first word that reaches it.
///
/// # Errors
/// Returns [`LymmDeckError`] if the spec's base permutation is internally
/// inconsistent with its deck size.
pub fn enumerate_top_swap_domains(
    spec: &LymmDeckSpec,
    constraints: &TopSwapConstraints,
) -> Result<TopSwapDomains, LymmDeckError> {
    let mut canonical_words: BTreeMap<Vec<(usize, usize)>, Vec<usize>> = BTreeMap::new();
    let mut sigma = (0..spec.n).collect::<Vec<_>>();
    let mut word = Vec::with_capacity(constraints.max_swaps);
    enumerate_words(
        spec.n,
        constraints.max_swaps,
        &mut sigma,
        &mut word,
        &mut canonical_words,
    );
    domains_from_canonical_words(
        spec,
        constraints,
        canonical_words,
        GeneratorBranchStrategy::TopSwapSupport,
    )
}

fn domains_from_canonical_words(
    spec: &LymmDeckSpec,
    constraints: &TopSwapConstraints,
    canonical_words: BTreeMap<Vec<(usize, usize)>, Vec<usize>>,
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
            .find_map(|(position, image)| (*position == 0).then_some(*image))
            .unwrap_or(0);
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

fn enumerate_words(
    n: usize,
    max_swaps: usize,
    sigma: &mut [usize],
    word: &mut Vec<usize>,
    canonical_words: &mut BTreeMap<Vec<(usize, usize)>, Vec<usize>>,
) {
    record_canonical(sigma, word, canonical_words);
    if word.len() == max_swaps {
        return;
    }
    for swap_index in 0..n {
        sigma.swap(0, swap_index);
        word.push(swap_index);
        enumerate_words(n, max_swaps, sigma, word, canonical_words);
        let _popped = word.pop();
        sigma.swap(0, swap_index);
    }
}

fn record_canonical(
    sigma: &[usize],
    word: &[usize],
    canonical_words: &mut BTreeMap<Vec<(usize, usize)>, Vec<usize>>,
) {
    let sparse = sparse_key(sigma);
    let replace = canonical_words
        .get(&sparse)
        .is_none_or(|existing| word.len() < existing.len() || word < existing.as_slice());
    if replace {
        let _old = canonical_words.insert(sparse, word.to_vec());
    }
}

fn sparse_key(sigma: &[usize]) -> Vec<(usize, usize)> {
    sigma
        .iter()
        .copied()
        .enumerate()
        .filter(|(position, image)| position != image)
        .collect()
}
