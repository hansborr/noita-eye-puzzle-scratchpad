//! Language discriminators for the shadow-finish ladder.

use std::collections::HashMap;

use crate::analysis::shadow_search::Anchor;
use crate::attack::pairclass::parse_wordlist;
use crate::attack::quadgram::QuadgramModel;

use super::ShadowFinishError;

const UNKNOWN_LETTER_LOGP: f32 = -11.0;
const EMPTY_SCORE: f32 = -20.0;

/// Word-level segmentation model over lowercase ASCII words.
#[derive(Clone, Debug)]
pub struct WordSegModel {
    words: HashMap<Vec<u8>, f32>,
    max_len: usize,
}

impl WordSegModel {
    /// Builds a segmentation model from a `word count` list.
    ///
    /// # Errors
    /// Returns [`ShadowFinishError`] if the wordlist has no usable words.
    pub fn from_wordlist(text: &str, cap: usize) -> Result<Self, ShadowFinishError> {
        let entries = parse_wordlist(text, cap);
        if entries.is_empty() {
            return Err(ShadowFinishError::Scoring(
                "wordlist contains no usable a..z words".to_owned(),
            ));
        }
        let total = entries
            .iter()
            .map(|(_, count)| count.max(&1))
            .copied()
            .sum::<u64>()
            .max(1);
        let mut words = HashMap::with_capacity(entries.len());
        let mut max_len = 0usize;
        for (word, count) in entries {
            max_len = max_len.max(word.len());
            let logp = ((count.max(1) as f64) / (total as f64)).ln() as f32;
            let _previous = words.insert(word.into_bytes(), logp);
        }
        Ok(Self { words, max_len })
    }

    /// Scores a candidate byte string by best word segmentation.
    #[must_use]
    pub fn score_text(&self, text: &[u8]) -> WordSegScore {
        let letters = normalize_letters(text);
        self.score_letters(&letters)
    }

    /// Scores already-normalized lowercase letters by best word segmentation.
    #[must_use]
    pub fn score_letters(&self, letters: &[u8]) -> WordSegScore {
        if letters.is_empty() {
            return WordSegScore {
                letters: 0,
                total_logp: EMPTY_SCORE,
                mean_logp: EMPTY_SCORE,
            };
        }
        let mut dp = vec![f32::NEG_INFINITY; letters.len() + 1];
        if let Some(slot) = dp.get_mut(0) {
            *slot = 0.0;
        }
        for index in 0..letters.len() {
            let Some(&base) = dp.get(index) else {
                continue;
            };
            if !base.is_finite() {
                continue;
            }
            if let Some(slot) = dp.get_mut(index + 1) {
                *slot = (*slot).max(base + UNKNOWN_LETTER_LOGP);
            }
            let max_end = letters.len().min(index + self.max_len);
            for end in index + 1..=max_end {
                let Some(slice) = letters.get(index..end) else {
                    continue;
                };
                let Some(word_logp) = self.words.get(slice) else {
                    continue;
                };
                let len_bonus = ((end - index) as f32).ln();
                if let Some(slot) = dp.get_mut(end) {
                    *slot = (*slot).max(base + *word_logp + len_bonus);
                }
            }
        }
        let total = *dp.last().unwrap_or(&EMPTY_SCORE);
        WordSegScore {
            letters: letters.len(),
            total_logp: total,
            mean_logp: total / letters.len() as f32,
        }
    }
}

/// Word segmentation score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WordSegScore {
    /// Number of letters scored after normalization.
    pub letters: usize,
    /// Total best-path log score.
    pub total_logp: f32,
    /// Mean best-path log score per normalized letter.
    pub mean_logp: f32,
}

/// Repeated-anchor segmentation score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnchorWordScore {
    /// Anchor spans with at least one complete decoded character.
    pub spans_scored: usize,
    /// Total repeated-span segmentation score.
    pub total_logp: f32,
    /// Mean score per anchor-span letter.
    pub mean_logp: f32,
}

/// Scores repeated q-equality anchors as repeated plaintext spans.
#[must_use]
pub fn score_anchor_words(
    word_model: &WordSegModel,
    text: &[u8],
    anchors: &[Anchor],
) -> AnchorWordScore {
    let mut spans_scored = 0usize;
    let mut total = 0.0f32;
    let mut letters = 0usize;
    for anchor in anchors {
        let Some((start, len)) = complete_pair_span(anchor.first, anchor.length) else {
            continue;
        };
        let Some(span) = text.get(start..start + len) else {
            continue;
        };
        let score = word_model.score_text(span);
        if score.letters == 0 {
            continue;
        }
        spans_scored += 1;
        total += score.total_logp * 2.0;
        letters += score.letters * 2;
    }
    AnchorWordScore {
        spans_scored,
        total_logp: total,
        mean_logp: if letters == 0 {
            EMPTY_SCORE
        } else {
            total / letters as f32
        },
    }
}

/// Scores ASCII letters by the committed English quadgram model.
#[must_use]
pub fn score_quadgrams(model: &QuadgramModel, text: &[u8]) -> f64 {
    let indices = text
        .iter()
        .copied()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| usize::from(byte.to_ascii_uppercase() - b'A'))
        .collect::<Vec<_>>();
    model.score_indices(&indices)
}

/// Normalizes ASCII letters to lowercase and drops all other bytes.
#[must_use]
pub fn normalize_letters(text: &[u8]) -> Vec<u8> {
    text.iter()
        .copied()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| byte.to_ascii_lowercase())
        .collect()
}

/// Combines Tier-B language scores into one within-stream ranking statistic.
#[must_use]
pub fn combined_score(quadgram: f64, word: WordSegScore, anchor: AnchorWordScore) -> f64 {
    let anchor_mean = if anchor.spans_scored == 0 {
        word.mean_logp
    } else {
        anchor.mean_logp
    };
    0.05 * quadgram + 0.65 * f64::from(word.mean_logp) + 0.30 * f64::from(anchor_mean)
}

fn complete_pair_span(q_start: usize, q_len: usize) -> Option<(usize, usize)> {
    let first_q = if q_start.is_multiple_of(2) {
        q_start
    } else {
        q_start + 1
    };
    let end_q = q_start.checked_add(q_len)?;
    if first_q + 1 >= end_q {
        return None;
    }
    let last_pair_start = end_q.saturating_sub(2);
    let char_start = first_q / 2;
    let char_end = last_pair_start / 2 + 1;
    (char_end > char_start).then_some((char_start, char_end - char_start))
}
