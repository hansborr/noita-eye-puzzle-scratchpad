//! Permutation algebra and the per-anchor induced-map reading that turns one
//! aligned isomorph occurrence pair into an observed deck-channel permutation
//! and its cycle type (the element order of one hidden-group element).
//!
//! See the module-level documentation in [`super`] for the cryptanalytic
//! derivation. This file holds only the mechanism: compose/invert/cycle-type of
//! permutations, and [`read_context`], which reads `q[first+s] -> q[second+s]`
//! across an aligned span and recovers the inducing permutation when the map is
//! a consistent (TopCard-compatible) bijection.

/// Compose two permutations with the repo convention `(p ∘ q)[i] = p[q[i]]`.
///
/// Out-of-range entries map to themselves so the helper is total; callers only
/// pass equal-length permutations of `0..n`.
#[must_use]
pub(crate) fn compose(p: &[usize], q: &[usize]) -> Vec<usize> {
    q.iter()
        .map(|&qi| p.get(qi).copied().unwrap_or(qi))
        .collect()
}

/// Inverse permutation of `p` (a permutation of `0..p.len()`).
#[must_use]
pub(crate) fn invert(p: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; p.len()];
    for (i, &pi) in p.iter().enumerate() {
        if let Some(slot) = inv.get_mut(pi) {
            *slot = i;
        }
    }
    inv
}

/// Sorted cycle lengths of `p` (fixed points count as length-1 cycles).
///
/// The element order is the least common multiple of the returned lengths; the
/// discriminator only inspects which lengths are present.
#[must_use]
pub(crate) fn cycle_lengths(p: &[usize]) -> Vec<usize> {
    let n = p.len();
    let mut seen = vec![false; n];
    let mut lengths = Vec::new();
    for start in 0..n {
        if seen.get(start).copied().unwrap_or(true) {
            continue;
        }
        let mut len = 0usize;
        let mut cur = start;
        loop {
            if let Some(slot) = seen.get_mut(cur) {
                *slot = true;
            }
            len += 1;
            cur = p.get(cur).copied().unwrap_or(cur);
            if cur == start {
                break;
            }
        }
        lengths.push(len);
    }
    lengths.sort_unstable();
    lengths
}

/// Whether `p` is an even permutation (lies in the alternating group).
///
/// `sign = (-1)^(n - cycles)`; even iff `n - cycles` is even.
#[must_use]
pub(crate) fn is_even(p: &[usize]) -> bool {
    (p.len() - cycle_lengths(p).len()).is_multiple_of(2)
}

/// Outcome of reading one aligned anchor's induced deck-channel map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContextOutcome {
    /// Distinct deck-channel source values observed in the consistent prefix.
    pub(crate) coverage: usize,
    /// Length of the consistent prefix: aligned positions read before the first
    /// collision (a source value mapping to two different images) or the end of
    /// the anchor. The `TopCard` gate — a genuine full-plaintext repeat under a
    /// top-card readout stays consistent for the whole repeat, while an eps-only
    /// (rotor-only) repeat or a non-`TopCard` readout collides quickly, so a short
    /// prefix is the signature of "no deck signal here".
    pub(crate) prefix_len: usize,
    /// The inducing permutation recovered from the consistent prefix, present
    /// only when that prefix is an injection covering at least `deck_size - 1`
    /// values (a permutation of `deck_size` points is fixed by `deck_size - 1` of
    /// its images). The caller additionally requires `prefix_len` to clear a
    /// length floor before trusting it.
    pub(crate) permutation: Option<Vec<usize>>,
}

/// Maximum number of leading positions trimmed when aligning an anchor.
///
/// The binary difference channel lets the maximal eps-repeat extend a position or
/// two past the constant-context region at *either* end. A trailing overrun is
/// handled by stopping at the first collision; a leading overrun (a spurious
/// position before the constant region begins, e.g. a filler/connector symbol
/// whose eps happens to match) would otherwise corrupt the map, so the reader
/// tries the first few start offsets and keeps the longest clean run.
const MAX_LEADING_TRIM: usize = 4;

/// Reads the deck-channel map induced by one aligned isomorph occurrence pair.
///
/// `q` is the full deck-channel stream (`value / rotor_mod`); `first`/`second`
/// are the anchor start positions in the rotor *difference* stream (the aligned
/// visible positions are `first + s` and `second + s`). The constant-context
/// region is a contiguous sub-window of the anchor; the reader finds it by trying
/// the first few leading offsets and, for each, reading forward until the first
/// collision. The returned [`ContextOutcome`] is the offset whose consistent run
/// is longest — the true context yields the longest run by construction, while an
/// eps-only (rotor-only) repeat or a non-TopCard readout collides quickly at every
/// offset and fixes no permutation.
#[must_use]
pub(crate) fn read_context(
    q: &[usize],
    deck_size: usize,
    first: usize,
    second: usize,
    length: usize,
) -> ContextOutcome {
    let max_trim = MAX_LEADING_TRIM.min(length);
    let mut best = ContextOutcome {
        coverage: 0,
        prefix_len: 0,
        permutation: None,
    };
    for start in 0..=max_trim {
        let outcome = read_run(q, deck_size, first + start, second + start, length - start);
        let better = match (&outcome.permutation, &best.permutation) {
            (Some(_), None) => true,
            (None, Some(_)) => false,
            _ => outcome.prefix_len > best.prefix_len,
        };
        if better {
            best = outcome;
        }
    }
    best
}

/// Reads one aligned run forward from `(first, second)`, stopping at the first
/// collision (a source value mapping to two different images) or the end.
fn read_run(
    q: &[usize],
    deck_size: usize,
    first: usize,
    second: usize,
    length: usize,
) -> ContextOutcome {
    let mut image: Vec<Option<usize>> = vec![None; deck_size];
    let mut coverage = 0usize;
    let mut prefix_len = 0usize;
    for s in 0..=length {
        let (Some(&qa), Some(&qb)) = (q.get(first + s), q.get(second + s)) else {
            break;
        };
        if qa >= deck_size || qb >= deck_size {
            break;
        }
        match image.get(qa).copied().flatten() {
            Some(prev) if prev != qb => break, // collision: stop, keep the prefix
            Some(_) => {}                      // consistent repeat of a known source
            None => {
                if let Some(slot) = image.get_mut(qa) {
                    *slot = Some(qb);
                }
                coverage += 1;
            }
        }
        prefix_len += 1;
    }

    let permutation = complete_permutation(&image, deck_size);
    ContextOutcome {
        coverage,
        prefix_len,
        permutation,
    }
}

/// Completes a partially observed injective map into a full permutation when it
/// is uniquely determined (coverage `deck_size` or `deck_size - 1`).
///
/// Returns `None` if the observed images collide (not injective) or coverage is
/// too low to fix the permutation.
fn complete_permutation(image: &[Option<usize>], deck_size: usize) -> Option<Vec<usize>> {
    let mut used = vec![false; deck_size];
    for slot in image.iter().flatten() {
        let flag = used.get_mut(*slot)?;
        if *flag {
            return None; // image collision: not injective
        }
        *flag = true;
    }

    let missing_domain: Vec<usize> = (0..deck_size)
        .filter(|&i| image.get(i).copied().flatten().is_none())
        .collect();
    let missing_range: Vec<usize> = (0..deck_size)
        .filter(|&v| !used.get(v).copied().unwrap_or(true))
        .collect();

    match missing_domain.as_slice() {
        [] => Some(
            image
                .iter()
                .map(|slot| slot.unwrap_or(0))
                .collect::<Vec<usize>>(),
        ),
        [only] => {
            let &fill = missing_range.first()?;
            let mut perm: Vec<usize> = image.iter().map(|slot| slot.unwrap_or(0)).collect();
            *perm.get_mut(*only)? = fill;
            Some(perm)
        }
        _ => None,
    }
}
