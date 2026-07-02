//! Exact repeated-span (tie anchor) detection on the direction-bit stream and
//! the mapping from bit-span repeats to tied token positions.
//!
//! A tie is a *plaintext-repeat hypothesis*: an exact repeated span of pair
//! tokens long enough that, under the pair-letter model, the parsimonious
//! explanation is that the plaintext itself repeats there. The solver then
//! treats tied positions as hard letter equalities. The hypothesis is
//! model-conditional and is labeled as such in the reports.

/// One maximal repeated span: `bits[a..a+len] == bits[b..b+len]`, `a < b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TieSpan {
    /// Start of the earlier occurrence (bit index).
    pub a: usize,
    /// Start of the later occurrence (bit index).
    pub b: usize,
    /// Span length in bits.
    pub len: usize,
}

/// Finds all maximal repeated spans of length `>= min_len`.
///
/// For each gap `d = b - a` the matching positions `bits[i] == bits[i + d]`
/// form runs; each maximal run of length `>= min_len` is one span. Runs are
/// maximal per gap by construction (they end at a mismatch or the stream
/// boundary). Results are sorted by descending length, then ascending start.
#[must_use]
pub fn maximal_repeats(bits: &[bool], min_len: usize) -> Vec<TieSpan> {
    let n = bits.len();
    let mut spans = Vec::new();
    let floor = min_len.max(1);
    for gap in 1..n {
        let mut run = 0usize;
        let shifted = bits.get(gap..).unwrap_or(&[]);
        for (offset, (early, late)) in bits.iter().zip(shifted.iter()).enumerate() {
            if early == late {
                run += 1;
            } else {
                if run >= floor {
                    spans.push(TieSpan {
                        a: offset - run,
                        b: offset - run + gap,
                        len: run,
                    });
                }
                run = 0;
            }
        }
        if run >= floor {
            let end = n - gap;
            spans.push(TieSpan {
                a: end - run,
                b: end - run + gap,
                len: run,
            });
        }
    }
    spans.sort_by(|x, y| y.len.cmp(&x.len).then(x.a.cmp(&y.a)).then(x.b.cmp(&y.b)));
    spans
}

/// Maps bit-span repeats to tied token-position pairs at the given phase.
///
/// Token `t` covers bits `(phase + 2t, phase + 2t + 1)`; a token is tied only
/// when *both* its bits lie inside the earlier occurrence. Spans with an odd
/// start distance cannot tie same-phase tokens and are skipped.
#[must_use]
pub fn token_ties(spans: &[TieSpan], phase: usize, n_tokens: usize) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    for span in spans {
        let distance = span.b - span.a;
        if distance % 2 != 0 || span.len < 2 {
            continue;
        }
        let token_shift = distance / 2;
        // First token whose low bit (phase + 2t) is >= span.a.
        let t_lo = (span.a.saturating_sub(phase)).div_ceil(2);
        // Last token whose high bit (phase + 2t + 1) is <= span.a + span.len - 1.
        let Some(high_budget) = (span.a + span.len).checked_sub(2 + phase) else {
            continue;
        };
        let t_hi = high_budget / 2;
        for t in t_lo..=t_hi {
            let t2 = t + token_shift;
            if t < n_tokens && t2 < n_tokens {
                pairs.push((t, t2));
            }
        }
    }
    pairs
}

/// Collapses tie pairs into a per-position target table: `tie_to[p]` is the
/// smallest position whose letter position `p` must equal (union-find over the
/// pairs, representative = minimum member), or `None` when `p` is unconstrained
/// or is itself the representative.
#[must_use]
pub fn tie_targets(pairs: &[(usize, usize)], n_positions: usize) -> Vec<Option<usize>> {
    let mut parent: Vec<usize> = (0..n_positions).collect();
    for &(x, y) in pairs {
        if x >= n_positions || y >= n_positions {
            continue;
        }
        let rx = find_root(&mut parent, x);
        let ry = find_root(&mut parent, y);
        if rx != ry {
            let (lo, hi) = if rx < ry { (rx, ry) } else { (ry, rx) };
            if let Some(slot) = parent.get_mut(hi) {
                *slot = lo;
            }
        }
    }
    (0..n_positions)
        .map(|p| {
            let root = find_root(&mut parent, p);
            (root < p).then_some(root)
        })
        .collect()
}

/// Path-compressing union-find root lookup.
fn find_root(parent: &mut [usize], start: usize) -> usize {
    let mut node = start;
    while let Some(&up) = parent.get(node) {
        if up == node {
            break;
        }
        node = up;
    }
    // Path compression: point the chain at the root.
    let root = node;
    let mut walk = start;
    while let Some(slot) = parent.get_mut(walk) {
        if *slot == walk {
            break;
        }
        let next = *slot;
        *slot = root;
        walk = next;
    }
    root
}
