//! Small shared integer-math primitives reused across analysis modules.
//!
//! These are the kind of one-line numeric helpers (greatest common divisor and
//! friends) that several modules would otherwise each define privately. Keeping a
//! single vetted copy here avoids divergence and lets new instruments — such as
//! the [`crate::analysis::predicates`] battery's coprimality predicate — reuse the
//! exact same definition the older modules rely on.

/// Euclidean greatest common divisor.
///
/// Follows the usual conventions: `gcd(0, n) == gcd(n, 0) == n` and
/// `gcd(0, 0) == 0`. The result is always non-negative because the inputs are
/// `usize`.
///
/// ```
/// use noita_eye_puzzle::core::math::gcd;
///
/// assert_eq!(gcd(12, 18), 6);
/// assert_eq!(gcd(0, 7), 7);
/// assert_eq!(gcd(7, 0), 7);
/// assert_eq!(gcd(0, 0), 0);
/// assert_eq!(gcd(17, 5), 1); // coprime
/// ```
#[must_use]
pub fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
