//! Language discriminators for the shadow-finish ladder.

use std::collections::HashMap;

use crate::analysis::shadow_search::Anchor;
use crate::attack::pairclass::parse_wordlist;
use crate::attack::quadgram::QuadgramModel;

use super::ShadowFinishError;
use super::tables::strict_language_byte;

const UNKNOWN_LETTER_LOGP: f32 = -11.0;
const EMPTY_SCORE: f32 = -20.0;
const STRICT_COVERAGE_WEIGHT: f32 = 4.0;
const ALPHA_SPACE_WEIGHT: f32 = 3.0;
const DIGIT_SPAM_WEIGHT: f32 = 6.0;
const SYMBOL_SPAM_WEIGHT: f32 = 4.0;

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
        let mut score = self.score_letters(&letters);
        score.bytes = text.len();
        score
    }

    /// Scores already-normalized lowercase letters by best word segmentation.
    #[must_use]
    pub fn score_letters(&self, letters: &[u8]) -> WordSegScore {
        if letters.is_empty() {
            return WordSegScore {
                bytes: letters.len(),
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
            bytes: letters.len(),
            letters: letters.len(),
            total_logp: total,
            mean_logp: total / letters.len() as f32,
        }
    }
}

/// Word segmentation score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WordSegScore {
    /// Original byte length covered by this score.
    pub bytes: usize,
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
    /// Trimmed anchor bytes covered by the score.
    pub bytes: usize,
    /// Letters in the scored anchor spans.
    pub letters: usize,
    /// Total repeated-span segmentation score.
    pub total_logp: f32,
    /// Mean score per anchor-span letter.
    pub mean_logp: f32,
    /// Mean byte-coverage score over scored anchor spans.
    pub coverage_score: f32,
}

/// Byte-level natural-language coverage features.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ByteCoverageScore {
    /// Candidate byte length.
    pub bytes: usize,
    /// Fraction of bytes in the strict natural-language set.
    pub strict_coverage: f32,
    /// Fraction of bytes that are ASCII letters or spaces.
    pub alpha_space_ratio: f32,
    /// Fraction of bytes that are ASCII digits.
    pub digit_ratio: f32,
    /// Fraction of bytes that are non-strict non-alphanumeric symbols.
    pub symbol_ratio: f32,
    /// Combined coverage statistic; higher means more natural-language bytes.
    pub score: f32,
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
    let mut bytes = 0usize;
    let mut coverage_total = 0.0f32;
    for anchor in anchors {
        let Some((start, len)) = complete_pair_span(anchor.first, anchor.length) else {
            continue;
        };
        let Some(raw_span) = text.get(start..start + len) else {
            continue;
        };
        let span = trim_dirty_word_boundaries(text, start, raw_span);
        let score = word_model.score_text(span);
        if score.letters == 0 {
            continue;
        }
        let coverage = score_byte_coverage(span);
        spans_scored += 1;
        total += score.total_logp;
        letters += score.letters;
        bytes += span.len();
        coverage_total += coverage.score * span.len() as f32;
    }
    AnchorWordScore {
        spans_scored,
        bytes,
        letters,
        total_logp: total,
        mean_logp: if letters == 0 {
            EMPTY_SCORE
        } else {
            total / letters as f32
        },
        coverage_score: if bytes == 0 {
            EMPTY_SCORE
        } else {
            coverage_total / bytes as f32
        },
    }
}

/// Scores byte-level natural-language coverage for a candidate.
#[must_use]
pub fn score_byte_coverage(text: &[u8]) -> ByteCoverageScore {
    if text.is_empty() {
        return ByteCoverageScore {
            bytes: 0,
            strict_coverage: 0.0,
            alpha_space_ratio: 0.0,
            digit_ratio: 0.0,
            symbol_ratio: 0.0,
            score: EMPTY_SCORE,
        };
    }
    let mut strict = 0usize;
    let mut alpha_space = 0usize;
    let mut digits = 0usize;
    let mut symbols = 0usize;
    for byte in text.iter().copied() {
        let strict_byte = strict_language_byte(byte);
        strict += usize::from(strict_byte);
        alpha_space += usize::from(byte.is_ascii_alphabetic() || byte == b' ');
        digits += usize::from(byte.is_ascii_digit());
        symbols += usize::from(!(byte.is_ascii_alphanumeric() || byte == b' ' || strict_byte));
    }
    let bytes = text.len();
    let scale = bytes as f32;
    let strict_coverage = strict as f32 / scale;
    let alpha_space_ratio = alpha_space as f32 / scale;
    let digit_ratio = digits as f32 / scale;
    let symbol_ratio = symbols as f32 / scale;
    ByteCoverageScore {
        bytes,
        strict_coverage,
        alpha_space_ratio,
        digit_ratio,
        symbol_ratio,
        score: STRICT_COVERAGE_WEIGHT * strict_coverage + ALPHA_SPACE_WEIGHT * alpha_space_ratio
            - DIGIT_SPAM_WEIGHT * digit_ratio
            - SYMBOL_SPAM_WEIGHT * symbol_ratio,
    }
}

/// Cheap repeated-anchor byte-coverage proxy for Tier-A retention.
#[must_use]
pub fn score_anchor_byte_coverage(text: &[u8], anchors: &[Anchor]) -> f32 {
    let mut total = 0.0f32;
    let mut bytes = 0usize;
    for anchor in anchors {
        let Some((start, len)) = complete_pair_span(anchor.first, anchor.length) else {
            continue;
        };
        let Some(raw_span) = text.get(start..start + len) else {
            continue;
        };
        let span = trim_dirty_word_boundaries(text, start, raw_span);
        if span.is_empty() {
            continue;
        }
        let coverage = score_byte_coverage(span);
        total += coverage.score * span.len() as f32;
        bytes += span.len();
    }
    if bytes == 0 {
        EMPTY_SCORE
    } else {
        total / bytes as f32
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

/// Cheap approximation of the final statistic for Tier-A retention.
#[must_use]
pub fn tier_a_score(quadgram: f64, coverage: ByteCoverageScore, anchor_coverage: f32) -> f64 {
    0.10 * quadgram + 0.75 * f64::from(coverage.score) + 0.15 * f64::from(anchor_coverage)
}

/// Combines Tier-B language scores into one within-stream ranking statistic.
#[must_use]
pub fn combined_score(
    quadgram: f64,
    word: WordSegScore,
    anchor: AnchorWordScore,
    coverage: ByteCoverageScore,
) -> f64 {
    let anchor_mean = if anchor.spans_scored == 0 {
        word.mean_logp
    } else {
        anchor.mean_logp
    };
    let anchor_coverage = if anchor.spans_scored == 0 {
        coverage.score
    } else {
        anchor.coverage_score
    };
    0.05 * quadgram
        + 0.40 * f64::from(word.mean_logp)
        + 0.20 * f64::from(anchor_mean)
        + 0.30 * f64::from(coverage.score)
        + 0.05 * f64::from(anchor_coverage)
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

fn trim_dirty_word_boundaries<'a>(text: &[u8], start: usize, span: &'a [u8]) -> &'a [u8] {
    let mut left = 0usize;
    let mut right = span.len();
    if start > 0
        && text
            .get(start.wrapping_sub(1))
            .is_some_and(u8::is_ascii_alphabetic)
        && span.first().is_some_and(u8::is_ascii_alphabetic)
    {
        while left < right && span.get(left).is_some_and(u8::is_ascii_alphabetic) {
            left += 1;
        }
        while left < right && span.get(left) == Some(&b' ') {
            left += 1;
        }
    }
    let end = start.saturating_add(span.len());
    if end < text.len()
        && text.get(end).is_some_and(u8::is_ascii_alphabetic)
        && span
            .get(right.saturating_sub(1))
            .is_some_and(u8::is_ascii_alphabetic)
    {
        while right > left
            && span
                .get(right.saturating_sub(1))
                .is_some_and(u8::is_ascii_alphabetic)
        {
            right -= 1;
        }
        while right > left && span.get(right.saturating_sub(1)) == Some(&b' ') {
            right -= 1;
        }
    }
    span.get(left..right).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::attack::quadgram::{ENGLISH_CORPUS_LARGE, QuadgramModel};

    use super::*;

    const SYMBOL_SOUP: &[u8] = br#"W+2.& %) +'6%. )2*$"4 7]76"* (%1" '+*" $"!+4" 6(" &"'-*%. )2*$"4 7]76"*[ E6 (%7 $"") 72##"76"& 6(%6 6(" 4"'+)7642'6"& H4+6+*E)&+*R24+0"%) 3+4& !+4 $)-)"$ *-#(6 $" 4".%6"& 6+ 6(" H4+6+*E)&+*R24+0"%) 3+4& !+4 $)"3$) T%7"& +) 6(-7. 7+*" (%1" 70"'2.%6"& 6(%6 H4+6+*E)&+*R24+0"%)7 27"& %) +'6%. )2*$"4 7]76"*. 6(+2#( 6(" "1-&")'" 7200+46-)# 6(-7 -7 7.-*)"#;

    #[test]
    fn fixed_statistic_demotes_logged_symbol_soup() {
        let wordlist = derive_wordlist(ENGLISH_CORPUS_LARGE);
        let word_model = WordSegModel::from_wordlist(&wordlist, 50_000).expect("wordlist builds");
        let quadgram = QuadgramModel::english().expect("quadgram builds");
        let planted = planted_english();
        let (soup_old, soup_fixed) = score_pair(&word_model, &quadgram, SYMBOL_SOUP);
        let (plant_old, plant_fixed) = score_pair(&word_model, &quadgram, &planted);
        println!(
            "shadow_finish_regression_scores soup_old={soup_old:.6} plant_old={plant_old:.6} soup_fixed={soup_fixed:.6} plant_fixed={plant_fixed:.6}"
        );
        let soup_coverage = score_byte_coverage(SYMBOL_SOUP);
        assert!(soup_coverage.strict_coverage < 0.50);
        assert!(soup_coverage.alpha_space_ratio < 0.25);
        assert!(soup_coverage.digit_ratio > 0.20);
        assert_close(f64::from(soup_coverage.symbol_ratio), 128.0 / 349.0);
        assert_close(soup_fixed, -1.858_362);
        assert_close(plant_fixed, 0.664_933);
        assert!(
            soup_old > plant_old,
            "old sparse-letter score should expose the regression fixture: soup={soup_old}, plant={plant_old}"
        );
        assert!(
            plant_fixed > soup_fixed,
            "fixed score should prefer planted English: soup={soup_fixed}, plant={plant_fixed}"
        );
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= 1.0e-5,
            "actual {actual} differed from expected {expected}"
        );
    }

    #[test]
    fn dirty_anchor_boundaries_keep_interior_phrase() {
        let model = WordSegModel::from_wordlist(
            "state 100\nsearch 90\ncan 80\nfinish 70\nwithout 60\na 50\nhidden 40\ncrib 30\n",
            usize::MAX,
        )
        .expect("wordlist builds");
        let text = b"the hidden state search can finish without a crib today";
        let anchor = Anchor {
            first: 12,
            second: 80,
            length: 76,
            raw_first: 4,
            raw_second: 76,
            raw_length: 84,
            trim: 4,
        };
        let raw_chars = anchor.length / 2;
        let score = score_anchor_words(&model, text, &[anchor]);
        assert_eq!(score.spans_scored, 1);
        assert!(score.bytes < raw_chars);
        assert!(score.mean_logp > -4.0, "{score:?}");
    }

    fn score_pair(word_model: &WordSegModel, quadgram: &QuadgramModel, text: &[u8]) -> (f64, f64) {
        let quad = score_quadgrams(quadgram, text);
        let word = word_model.score_text(text);
        let anchor = score_anchor_words(word_model, text, &[]);
        let fixed = combined_score(quad, word, anchor, score_byte_coverage(text));
        (old_combined_score(quad, word, anchor), fixed)
    }

    fn old_combined_score(quadgram: f64, word: WordSegScore, anchor: AnchorWordScore) -> f64 {
        let anchor_mean = if anchor.spans_scored == 0 {
            word.mean_logp
        } else {
            anchor.mean_logp
        };
        0.05 * quadgram + 0.65 * f64::from(word.mean_logp) + 0.30 * f64::from(anchor_mean)
    }

    fn planted_english() -> Vec<u8> {
        let phrase = b"the coverage aware discriminator rejects punctuation spam while retaining the truthful interpretation through tier a ";
        let mut out = Vec::with_capacity(SYMBOL_SOUP.len());
        while out.len() < SYMBOL_SOUP.len() {
            out.extend_from_slice(phrase);
        }
        out.truncate(SYMBOL_SOUP.len());
        out
    }

    fn derive_wordlist(text: &str) -> String {
        let mut counts = BTreeMap::<String, u64>::new();
        let mut word = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                word.push(ch.to_ascii_lowercase());
            } else if !word.is_empty() {
                *counts.entry(std::mem::take(&mut word)).or_insert(0) += 1;
            }
        }
        if !word.is_empty() {
            *counts.entry(word).or_insert(0) += 1;
        }
        let mut rows = counts.into_iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        rows.into_iter()
            .map(|(word, count)| format!("{word} {count}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
