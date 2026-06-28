//! Finite-group construction machinery for the synthetic GAK fixture generator:
//! multiplication tables (cyclic and dihedral), the left-regular permutation
//! representation, and non-identity generator selection with a guaranteed
//! non-commuting pair for the dihedral (non-commutative) witness.

use crate::nulls::null::{SplitMix64, fisher_yates};

use super::{GakAttackError, GroupKind};

/// The multiplication table `table[x][y] = index(x · y)` over `0..order`.
pub(super) fn group_table(group_kind: GroupKind) -> Result<Vec<Vec<usize>>, GakAttackError> {
    match group_kind {
        GroupKind::Cyclic { order } => {
            if order < 2 {
                return Err(GakAttackError::CyclicOrderTooSmall { order });
            }
            let mut table = vec![vec![0usize; order]; order];
            for (x, row) in table.iter_mut().enumerate() {
                for (y, slot) in row.iter_mut().enumerate() {
                    *slot = (x + y) % order;
                }
            }
            Ok(table)
        }
        GroupKind::Dihedral { half_order } => dihedral_table(half_order),
    }
}

/// Multiplication table for `D_{2k}` (order `2k`).
///
/// Elements are indexed `0..k` for rotations `r^j` and `k..2k` for reflections
/// `s·r^j`. Products use the dihedral relations `r^a · r^b = r^{a+b}`,
/// `r^a · (s r^b) = s r^{b-a}`, `(s r^a) · r^b = s r^{a+b}`,
/// `(s r^a) · (s r^b) = r^{b-a}` (all exponents mod `k`). Index `0` is the
/// identity `r^0`.
fn dihedral_table(half_order: usize) -> Result<Vec<Vec<usize>>, GakAttackError> {
    if half_order < 3 {
        return Err(GakAttackError::DihedralHalfOrderTooSmall { half_order });
    }
    let order = half_order.saturating_mul(2);
    let mut table = vec![vec![0usize; order]; order];
    for (left, row) in table.iter_mut().enumerate() {
        for (right, slot) in row.iter_mut().enumerate() {
            *slot = dihedral_product(half_order, left, right);
        }
    }
    Ok(table)
}

fn dihedral_product(half_order: usize, left: usize, right: usize) -> usize {
    let k = half_order;
    let left_reflect = left >= k;
    let right_reflect = right >= k;
    let left_exp = left % k;
    let right_exp = right % k;
    match (left_reflect, right_reflect) {
        // r^a · r^b = r^{a+b}
        (false, false) => (left_exp + right_exp) % k,
        // r^a · (s r^b) = s r^{b-a}
        (false, true) => k + (right_exp + k - left_exp % k) % k,
        // (s r^a) · r^b = s r^{a+b}
        (true, false) => k + (left_exp + right_exp) % k,
        // (s r^a) · (s r^b) = r^{b-a}
        (true, true) => (right_exp + k - left_exp % k) % k,
    }
}

/// The left-regular permutation of a group element: `L(x)[i] = index(x · h_i)`.
pub(super) fn left_regular_permutation(
    table: &[Vec<usize>],
    element: usize,
) -> Result<Vec<usize>, GakAttackError> {
    let Some(row) = table.get(element) else {
        return Err(GakAttackError::SymbolOutOfRange { value: element });
    };
    Ok(row.clone())
}

/// Chooses `count` distinct non-identity group elements as the plaintext letters.
///
/// For a **non-commutative** group with `count >= 2` the draw is rejected and
/// re-rolled (deterministically, bounded) until the chosen elements include at
/// least one non-commuting pair, so the generated dihedral fixture genuinely
/// realizes a non-commutative subgroup rather than accidentally an abelian subset.
/// For commutative groups (or `count < 2`) the first draw is
/// kept. If no non-commuting draw is found within the bound, the last draw is
/// returned (the caller's higher-level checks still hold); in practice a
/// non-commuting pair is found almost immediately for `D_{2k}`.
pub(super) fn choose_generators(
    table: &[Vec<usize>],
    count: usize,
    require_non_commuting: bool,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, GakAttackError> {
    const MAX_DRAWS: usize = 64;
    let order = table.len();
    let mut last = Vec::new();
    for _draw in 0..MAX_DRAWS {
        // Non-identity elements are 1..order. Draw `count` distinct ones.
        let mut pool: Vec<usize> = (1..order).collect();
        fisher_yates(&mut pool, rng)?;
        pool.truncate(count);
        pool.sort_unstable();
        if !require_non_commuting || count < 2 || has_non_commuting_pair(table, &pool) {
            return Ok(pool);
        }
        last = pool;
    }
    Ok(last)
}

/// Returns `true` when some pair of elements in `elements` does not commute under
/// the group multiplication `table`.
fn has_non_commuting_pair(table: &[Vec<usize>], elements: &[usize]) -> bool {
    for (i, &x) in elements.iter().enumerate() {
        for &y in elements.iter().skip(i.saturating_add(1)) {
            let xy = table.get(x).and_then(|row| row.get(y)).copied();
            let yx = table.get(y).and_then(|row| row.get(x)).copied();
            if xy != yx {
                return true;
            }
        }
    }
    false
}
