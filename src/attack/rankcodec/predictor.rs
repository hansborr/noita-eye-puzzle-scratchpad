//! Deterministic bounded-order English next-letter predictor for `rankcodec`.

use std::collections::BTreeMap;

/// Number of letters in the predictor alphabet (`A..Z`).
pub const LETTERS: usize = 26;

type Counts = [usize; LETTERS];

/// A deterministic order-`k` next-character predictor over `A..Z`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankPredictor {
    order: usize,
    counts_by_len: Vec<BTreeMap<Vec<usize>, Counts>>,
}

impl RankPredictor {
    /// Trains a predictor from `A=0..Z=25` letters.
    #[must_use]
    pub fn train(letters: &[usize], order: usize) -> Self {
        let mut counts_by_len = (0..=order)
            .map(|_len| BTreeMap::<Vec<usize>, Counts>::new())
            .collect::<Vec<_>>();
        for (position, &letter) in letters.iter().enumerate() {
            if letter >= LETTERS {
                continue;
            }
            let max_len = order.min(position);
            for len in 0..=max_len {
                let start = position - len;
                let context = letters
                    .get(start..position)
                    .map(<[usize]>::to_vec)
                    .unwrap_or_default();
                let Some(bucket) = counts_by_len
                    .get_mut(len)
                    .and_then(|by_context| by_context.entry(context).or_default().get_mut(letter))
                else {
                    continue;
                };
                *bucket = bucket.saturating_add(1);
            }
        }
        Self {
            order,
            counts_by_len,
        }
    }

    /// Returns the predictor order.
    #[must_use]
    pub const fn order(&self) -> usize {
        self.order
    }

    /// Ranked next-letter candidates for the supplied context, most likely first.
    ///
    /// Unseen contexts back off by shortening the context; the final fallback is
    /// the global unigram order, and an empty training source falls back to
    /// alphabetic order. Ties are broken by ascending letter index, so the return
    /// value is deterministic and is always a permutation of `0..26`.
    #[must_use]
    pub fn ranked(&self, context: &[usize]) -> [usize; LETTERS] {
        let counts = self.backoff_counts(context);
        let mut ranked = std::array::from_fn::<usize, LETTERS, _>(|index| index);
        ranked.sort_by(|&a, &b| {
            let count_a = counts.get(a).copied().unwrap_or(0);
            let count_b = counts.get(b).copied().unwrap_or(0);
            count_b.cmp(&count_a).then_with(|| a.cmp(&b))
        });
        ranked
    }

    /// Returns `letter`'s 1-based rank under the predictor for `context`.
    #[must_use]
    pub fn rank_of(&self, context: &[usize], letter: usize) -> usize {
        self.ranked(context)
            .iter()
            .position(|&candidate| candidate == letter)
            .map_or(LETTERS, |position| position + 1)
    }

    fn backoff_counts(&self, context: &[usize]) -> Counts {
        let max_len = self.order.min(context.len());
        for len in (0..=max_len).rev() {
            let start = context.len() - len;
            let Some(key) = context.get(start..) else {
                continue;
            };
            let Some(counts) = self
                .counts_by_len
                .get(len)
                .and_then(|by_context| by_context.get(key))
            else {
                continue;
            };
            if counts.iter().any(|&count| count > 0) {
                return *counts;
            }
        }
        [0usize; LETTERS]
    }
}
