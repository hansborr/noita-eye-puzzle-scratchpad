//! Chaining validation and group statistics for extracted isomorph column maps.

use std::collections::{BTreeMap, BTreeSet};

use crate::ciphers::{compose_permutations, validate_permutation};
use crate::core::math::gcd;

use super::{ColumnMap, IsoMapError};

const MAX_BLOCK_ENUM_POINTS: usize = 16;

/// One chaining violation: `A~B` composed with `B~C` disagrees with direct
/// `A~C` on a symbol where both maps are defined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainViolation {
    /// Start position of span A.
    pub first: usize,
    /// Start position of span B.
    pub middle: usize,
    /// Start position of span C.
    pub third: usize,
    /// Source symbol where the conflict appears.
    pub symbol: usize,
    /// Image from the composed `A -> B -> C` route.
    pub composed: usize,
    /// Image from the direct `A -> C` map.
    pub direct: usize,
}

/// Result of validating all directly-observed chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainValidation {
    /// Number of triples `(A,B,C)` with all three direct pair maps present.
    pub checked: usize,
    /// Conflicts found after boundary-trimmed map extraction.
    pub violations: Vec<ChainViolation>,
}

/// Composes two partial maps in the same `(outer ∘ inner)[i] = outer[inner[i]]`
/// convention used by the repo's full-permutation helper.
#[must_use]
pub fn compose_partial_maps(
    outer: &[Option<usize>],
    inner: &[Option<usize>],
) -> Vec<Option<usize>> {
    inner
        .iter()
        .map(|entry| entry.and_then(|mid| outer.get(mid).copied().flatten()))
        .collect()
}

/// Validates chaining among extracted maps.
///
/// For every ordered triple `A < B < C` where direct maps exist for `A->B`,
/// `B->C`, and `A->C`, the composed partial map `B->C ∘ A->B` must agree with
/// the direct map on every symbol where both are defined. Missing entries in
/// partial maps are not treated as violations.
#[must_use]
pub fn validate_chains(maps: &[ColumnMap]) -> ChainValidation {
    let mut by_pair = BTreeMap::new();
    let mut starts = BTreeSet::new();
    for map in maps {
        let first = map.span.first;
        let second = map.span.second;
        let _inserted = starts.insert(first);
        let _inserted = starts.insert(second);
        let _entry = by_pair.entry((first, second)).or_insert(map);
    }

    let starts: Vec<usize> = starts.into_iter().collect();
    let mut checked = 0usize;
    let mut violations = Vec::new();
    for (a_index, &first) in starts.iter().enumerate() {
        for (b_index, &middle) in starts.iter().enumerate().skip(a_index + 1) {
            for &third in starts.iter().skip(b_index + 1) {
                let Some(ab) = by_pair.get(&(first, middle)).copied() else {
                    continue;
                };
                let Some(bc) = by_pair.get(&(middle, third)).copied() else {
                    continue;
                };
                let Some(ac) = by_pair.get(&(first, third)).copied() else {
                    continue;
                };
                checked += 1;
                let composed = compose_partial_maps(&bc.mapping, &ab.mapping);
                for (symbol, (via, direct)) in composed.iter().zip(ac.mapping.iter()).enumerate() {
                    if let (Some(composed), Some(direct)) = (*via, *direct)
                        && composed != direct
                    {
                        violations.push(ChainViolation {
                            first,
                            middle,
                            third,
                            symbol,
                            composed,
                            direct,
                        });
                    }
                }
            }
        }
    }
    ChainValidation {
        checked,
        violations,
    }
}

/// Closure and group-statistics over the full column maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupClosure {
    /// Generated permutation group elements, including identity.
    pub elements: Vec<Vec<usize>>,
    /// Group order, equal to `elements.len()`.
    pub order: usize,
    /// Element-order histogram.
    pub element_order_histogram: BTreeMap<usize, usize>,
    /// Orbits of the generated action on the alphabet.
    pub orbits: Vec<Vec<usize>>,
    /// Whether the action is transitive.
    pub transitive: bool,
    /// Preserved block systems discovered by exhaustive subset search.
    pub block_systems: Vec<BlockSystem>,
    /// Whether exhaustive block-system search was skipped due to alphabet size.
    pub block_search_skipped: bool,
    /// Order of the point stabilizer at symbol 0.
    pub point_stabilizer_order: usize,
}

/// One preserved block system for the generated action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSystem {
    /// Blocks as sorted point sets.
    pub blocks: Vec<Vec<usize>>,
}

/// Closes full maps under composition and computes stage-1 group statistics.
///
/// The generated group is a lower bound on the state group: it contains only
/// transforms witnessed by surviving full column maps and their products.
///
/// # Errors
/// Returns [`IsoMapError`] if a generator is not a permutation or closure exceeds
/// `cap`.
pub fn close_full_maps(
    full_maps: &[Vec<usize>],
    alphabet_size: usize,
    cap: usize,
) -> Result<GroupClosure, IsoMapError> {
    if alphabet_size == 0 {
        return Err(IsoMapError::EmptyAlphabet);
    }
    let identity: Vec<usize> = (0..alphabet_size).collect();
    let mut generators = Vec::new();
    for map in full_maps {
        validate_permutation("isomorph full map", map, alphabet_size)?;
        if map != &identity && !generators.contains(map) {
            generators.push(map.clone());
        }
    }

    let mut elements: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut worklist = Vec::new();
    let _inserted = elements.insert(identity.clone());
    worklist.push(identity);
    while let Some(element) = worklist.pop() {
        for generator in &generators {
            let product = compose_permutations(generator, &element)?;
            if elements.insert(product.clone()) {
                if elements.len() > cap {
                    return Err(IsoMapError::ClosureCapExceeded { cap });
                }
                worklist.push(product);
            }
        }
    }
    let elements: Vec<Vec<usize>> = elements.into_iter().collect();
    let order = elements.len();
    let element_order_histogram = element_order_histogram(&elements);
    let orbits = action_orbits(&elements, alphabet_size);
    let transitive = orbits.len() == 1 && orbits.first().is_some_and(|o| o.len() == alphabet_size);
    let point_stabilizer_order = elements
        .iter()
        .filter(|element| element.first().copied() == Some(0))
        .count();
    let (block_systems, block_search_skipped) = if alphabet_size <= MAX_BLOCK_ENUM_POINTS {
        (block_systems(&elements, alphabet_size), false)
    } else {
        (Vec::new(), true)
    };
    Ok(GroupClosure {
        elements,
        order,
        element_order_histogram,
        orbits,
        transitive,
        block_systems,
        block_search_skipped,
        point_stabilizer_order,
    })
}

fn element_order_histogram(elements: &[Vec<usize>]) -> BTreeMap<usize, usize> {
    let mut histogram = BTreeMap::new();
    for element in elements {
        *histogram.entry(permutation_order(element)).or_insert(0) += 1;
    }
    histogram
}

fn permutation_order(permutation: &[usize]) -> usize {
    let mut visited = vec![false; permutation.len()];
    let mut order = 1usize;
    for start in 0..permutation.len() {
        if visited.get(start).copied().unwrap_or(true) {
            continue;
        }
        let mut cursor = start;
        let mut cycle_len = 0usize;
        while !visited.get(cursor).copied().unwrap_or(true) {
            let Some(slot) = visited.get_mut(cursor) else {
                break;
            };
            *slot = true;
            cycle_len += 1;
            let Some(next) = permutation.get(cursor).copied() else {
                break;
            };
            cursor = next;
        }
        order = lcm(order, cycle_len);
    }
    order
}

fn lcm(a: usize, b: usize) -> usize {
    if a == 0 || b == 0 {
        return 0;
    }
    a / gcd(a, b) * b
}

fn action_orbits(elements: &[Vec<usize>], alphabet_size: usize) -> Vec<Vec<usize>> {
    let mut assigned = vec![false; alphabet_size];
    let mut orbits = Vec::new();
    for point in 0..alphabet_size {
        if assigned.get(point).copied().unwrap_or(true) {
            continue;
        }
        let mut orbit: Vec<usize> = elements
            .iter()
            .filter_map(|element| element.get(point).copied())
            .collect();
        orbit.sort_unstable();
        orbit.dedup();
        for &member in &orbit {
            if let Some(slot) = assigned.get_mut(member) {
                *slot = true;
            }
        }
        orbits.push(orbit);
    }
    orbits.sort_by_key(|orbit| orbit.first().copied().unwrap_or(usize::MAX));
    orbits
}

fn block_systems(elements: &[Vec<usize>], alphabet_size: usize) -> Vec<BlockSystem> {
    let mut systems = BTreeSet::new();
    for mask in 0u128..(1u128 << (alphabet_size - 1)) {
        let block = (mask << 1) | 1;
        let size = block.count_ones() as usize;
        if size <= 1 || size >= alphabet_size || !alphabet_size.is_multiple_of(size) {
            continue;
        }
        if let Some(system) = block_system_from_block(elements, alphabet_size, block) {
            let _inserted = systems.insert(system);
        }
    }
    systems
        .into_iter()
        .map(|system| BlockSystem {
            blocks: system
                .into_iter()
                .map(|block| mask_points(block, alphabet_size))
                .collect(),
        })
        .collect()
}

fn block_system_from_block(
    elements: &[Vec<usize>],
    alphabet_size: usize,
    block: u128,
) -> Option<Vec<u128>> {
    let mut images = BTreeSet::new();
    for element in elements {
        let image = image_mask(element, block, alphabet_size);
        let overlap = image & block;
        if overlap != 0 && image != block {
            return None;
        }
        let _inserted = images.insert(image);
    }
    let mut covered = 0u128;
    for image in &images {
        if covered & image != 0 {
            return None;
        }
        covered |= image;
    }
    let all = (1u128 << alphabet_size) - 1;
    if covered != all {
        return None;
    }
    Some(images.into_iter().collect())
}

fn image_mask(permutation: &[usize], block: u128, alphabet_size: usize) -> u128 {
    let mut image = 0u128;
    for (point, &target) in permutation.iter().enumerate().take(alphabet_size) {
        if block & (1u128 << point) != 0 {
            image |= 1u128 << target;
        }
    }
    image
}

fn mask_points(mask: u128, alphabet_size: usize) -> Vec<usize> {
    (0..alphabet_size)
        .filter(|&point| mask & (1u128 << point) != 0)
        .collect()
}
