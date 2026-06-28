//! Ciphertext structural profile for the practice **letter** puzzles.
//!
//! This module hardens (makes reproducible in-engine) a set of *structural,
//! negative* findings about the practice puzzles `three`/`four`/`five`/`seven`:
//! statistics that constrain the cipher *family* without claiming anything about
//! the plaintext. It computes, over a raw puzzle string:
//!
//! - the whole-stream index of coincidence (`IoC`) of the letters-only stream,
//!   compared against the English-letter reference ([`ENGLISH_IOC`]) and the
//!   flat uniform-26 reference ([`UNIFORM_IOC_26`]);
//! - which of `A..=Z` are absent, and how many one-letter words occur;
//! - the maximum per-period `IoC` over candidate periods `P in 2..=40`, under two
//!   column conventions (by letter index and by full-character index) — a flat
//!   profile is evidence *against* periodic polyalphabetic structure in the
//!   tested period range;
//! - the per-word column `IoC` (the `i`-th letter of every long-enough word);
//! - the maximal repeated substrings (length `>= 4`) of the letters-only stream,
//!   each tagged with whether its occurrences cross a word boundary.
//!
//! # `IoC` reuse and the per-period convention
//!
//! The whole-stream and per-word `IoC` reuse [`crate::analysis::analysis::index_of_coincidence`]
//! by mapping each letter `A..=Z` to a [`Glyph`] index `0..=25`. The per-period
//! statistic reuses [`crate::analysis::analysis::message_weighted_index_of_coincidence`],
//! treating each of the `P` columns as a "message": the columns' coincidence
//! counts are pooled by pair count (equivalently, each column's `IoC` is averaged
//! weighted by its number of letter pairs). This pair-count-weighted pooling is
//! the standard Friedman per-period `IoC`; it is preferred over an unweighted mean
//! of per-column `IoC`s because the unweighted mean is dominated by small-sample
//! noise from the tiny columns at large `P`.
//!
//! Nothing here is a decode. The single positive phrasings the report emits
//! ("not monoalphabetic", "no periodic peak") are claims about the *families*
//! tested, supported only by the constructed statistics.

use std::collections::HashMap;

use crate::analysis::analysis::{index_of_coincidence, message_weighted_index_of_coincidence};
use crate::attack::keystream::{PracticePuzzle, practice_puzzle_text};
use crate::core::glyph::Glyph;

/// Index of coincidence of English letter frequencies (the monoalphabetic
/// reference): two random letters of English prose collide with probability
/// `~0.0667`.
pub const ENGLISH_IOC: f64 = 0.0667;

/// Index of coincidence of a flat distribution over the 26-letter alphabet
/// (`1/26 ~= 0.0385`): the value a perfectly even letter stream tends toward.
pub const UNIFORM_IOC_26: f64 = 0.0385;

/// Half-width of the band around [`ENGLISH_IOC`] within which an `IoC` is treated
/// as monoalphabetic by [`looks_monoalphabetic`].
const MONO_IOC_TOLERANCE: f64 = 0.012;

/// Smallest candidate period scanned by the per-period `IoC` sweep.
const MIN_PERIOD: usize = 2;

/// Largest candidate period scanned by the per-period `IoC` sweep.
const MAX_PERIOD: usize = 40;

/// Minimum length of a repeated substring reported by [`Profile::repeats`].
const MIN_REPEAT_LEN: usize = 4;

/// Minimum column occupancy for a per-word column to be reported.
const PER_WORD_MIN_N: usize = 8;

/// Whether `ioc` is close enough to [`ENGLISH_IOC`] to look monoalphabetic.
///
/// Returns `true` when `ioc` is within a fixed `0.012` tolerance of
/// [`ENGLISH_IOC`]. A flattened polyalphabetic stream (e.g. `five`'s `~0.039`)
/// returns `false`, as does the uniform-26 reference [`UNIFORM_IOC_26`].
#[must_use]
pub fn looks_monoalphabetic(ioc: f64) -> bool {
    (ioc - ENGLISH_IOC).abs() <= MONO_IOC_TOLERANCE
}

/// One maximal repeated substring of the letters-only stream.
#[derive(Clone, Debug)]
pub struct Repeat {
    /// The repeated substring, rendered as `A..=Z` letters.
    pub text: String,
    /// The substring length (in letters).
    pub length: usize,
    /// Start offsets of every occurrence, in the letters-only stream, ascending.
    pub offsets: Vec<usize>,
    /// For each occurrence (parallel to [`Repeat::offsets`]), whether the
    /// occurrence's letters do **not** all belong to the same source word — i.e.
    /// whether the repeat crosses a word boundary.
    pub crosses_word_boundary: Vec<bool>,
}

/// A computed structural profile of one ciphertext.
///
/// Every field is a structural statistic; see the module documentation for the
/// definitions and the discipline that governs how they may be reported.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Length of the letters-only stream.
    pub n_letters: usize,
    /// Index of coincidence over the letters-only stream.
    pub ioc: f64,
    /// Count of distinct `A..=Z` letters present.
    pub distinct_present: usize,
    /// Sorted `A..=Z` letters that do not occur at all.
    pub absent: Vec<char>,
    /// Number of one-letter words.
    pub single_letter_word_count: usize,
    /// Maximum per-period `IoC` over `P in 2..=40`, columns split by letter index.
    pub max_period_ioc_letters: f64,
    /// The period `P` achieving [`Profile::max_period_ioc_letters`].
    pub max_period_ioc_letters_at: usize,
    /// Maximum per-period `IoC` over `P in 2..=40`, columns split by full-char
    /// position (every raw character advances the position counter; only letters
    /// are scored).
    pub max_period_ioc_fullchar: f64,
    /// The period `P` achieving [`Profile::max_period_ioc_fullchar`].
    pub max_period_ioc_fullchar_at: usize,
    /// Per-word column `IoC`s for columns with at least 8 letters, as
    /// `(column, n, ioc)`.
    pub per_word_col_ioc: Vec<(usize, usize, f64)>,
    /// Maximal repeated substrings of length `>= 4`, sorted by descending length.
    pub repeats: Vec<Repeat>,
}

/// The letters-only stream of a raw text, with per-letter word identity and the
/// per-word letter grouping.
struct Normalized {
    /// Each kept letter as a [`Glyph`] index `0..=25`, in reading order.
    letters: Vec<Glyph>,
    /// Parallel to `letters`: the 0-based source-word id each letter came from.
    word_id: Vec<usize>,
    /// The words (maximal runs of ASCII letters), uppercased to glyph indices.
    words: Vec<Vec<Glyph>>,
}

impl Normalized {
    /// Builds the letters-only stream, word ids, and per-word grouping from raw
    /// text. "Letters" are ASCII alphabetic characters, uppercased; "words" are
    /// maximal runs of them split on any non-letter.
    fn from_raw(raw: &str) -> Self {
        let mut letters = Vec::new();
        let mut word_id = Vec::new();
        let mut words: Vec<Vec<Glyph>> = Vec::new();
        let mut current: Vec<Glyph> = Vec::new();
        for ch in raw.chars() {
            if ch.is_ascii_alphabetic() {
                let glyph = letter_glyph(ch);
                letters.push(glyph);
                // The in-progress word's eventual index is `words.len()` (words
                // are pushed in order), so this records a contiguous 0-based id.
                word_id.push(words.len());
                current.push(glyph);
            } else if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        }
        if !current.is_empty() {
            words.push(current);
        }
        Self {
            letters,
            word_id,
            words,
        }
    }
}

/// Maps an ASCII alphabetic character to its `0..=25` [`Glyph`] index.
fn letter_glyph(ch: char) -> Glyph {
    Glyph(u16::from(ch.to_ascii_uppercase() as u8 - b'A'))
}

/// Renders a `0..=25` [`Glyph`] index back to its `A..=Z` letter.
fn glyph_char(glyph: Glyph) -> char {
    (b'A' + glyph.0 as u8) as char
}

/// Computes the full structural profile of an arbitrary raw text.
#[must_use]
pub fn profile_text(raw: &str) -> Profile {
    let norm = Normalized::from_raw(raw);
    let ioc = index_of_coincidence(&norm.letters);
    let (distinct_present, absent) = presence(&norm.letters);
    let single_letter_word_count = norm.words.iter().filter(|word| word.len() == 1).count();
    let (max_period_ioc_letters, max_period_ioc_letters_at) = max_period_ioc_letters(&norm.letters);
    let (max_period_ioc_fullchar, max_period_ioc_fullchar_at) = max_period_ioc_fullchar(raw);
    let per_word_col_ioc = per_word_columns(&norm.words);
    let repeats = maximal_repeats(&norm.letters, &norm.word_id, MIN_REPEAT_LEN);
    Profile {
        n_letters: norm.letters.len(),
        ioc,
        distinct_present,
        absent,
        single_letter_word_count,
        max_period_ioc_letters,
        max_period_ioc_letters_at,
        max_period_ioc_fullchar,
        max_period_ioc_fullchar_at,
        per_word_col_ioc,
        repeats,
    }
}

/// Computes the structural profile of a built-in practice letter-puzzle.
#[must_use]
pub fn profile_puzzle(puzzle: PracticePuzzle) -> Profile {
    profile_text(practice_puzzle_text(puzzle))
}

/// Returns the count of distinct present letters and the sorted absent letters.
fn presence(letters: &[Glyph]) -> (usize, Vec<char>) {
    let mut seen = [false; 26];
    for glyph in letters {
        if let Some(slot) = seen.get_mut(usize::from(glyph.0)) {
            *slot = true;
        }
    }
    let present = seen.iter().filter(|&&flag| flag).count();
    let absent = (0u8..26)
        .filter(|&index| !seen.get(usize::from(index)).copied().unwrap_or(false))
        .map(|index| (b'A' + index) as char)
        .collect();
    (present, absent)
}

/// Per-word column `IoC`s for every column reaching [`PER_WORD_MIN_N`] letters.
fn per_word_columns(words: &[Vec<Glyph>]) -> Vec<(usize, usize, f64)> {
    let max_len = words.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::new();
    for column in 0..max_len {
        let cells: Vec<Glyph> = words
            .iter()
            .filter_map(|word| word.get(column).copied())
            .collect();
        if cells.len() >= PER_WORD_MIN_N {
            out.push((column, cells.len(), index_of_coincidence(&cells)));
        }
    }
    out
}

/// Maximum pair-count-weighted per-period `IoC` over `P in 2..=40`, splitting the
/// letters-only stream into `P` columns by `letter_index mod P`. Returns
/// `(max_ioc, argmax_period)`.
fn max_period_ioc_letters(letters: &[Glyph]) -> (f64, usize) {
    let mut best = -1.0_f64;
    let mut best_at = MIN_PERIOD;
    for period in MIN_PERIOD..=MAX_PERIOD {
        let mut columns: Vec<Vec<Glyph>> = vec![Vec::new(); period];
        for (index, &glyph) in letters.iter().enumerate() {
            if let Some(column) = columns.get_mut(index % period) {
                column.push(glyph);
            }
        }
        let value = message_weighted_index_of_coincidence(&columns);
        if value > best {
            best = value;
            best_at = period;
        }
    }
    (best.max(0.0), best_at)
}

/// Maximum pair-count-weighted per-period `IoC` over `P in 2..=40`, splitting by
/// full-character position: every raw character advances the position counter and
/// only letters are scored, assigned to column `position mod P`. Returns
/// `(max_ioc, argmax_period)`.
fn max_period_ioc_fullchar(raw: &str) -> (f64, usize) {
    let mut best = -1.0_f64;
    let mut best_at = MIN_PERIOD;
    for period in MIN_PERIOD..=MAX_PERIOD {
        let mut columns: Vec<Vec<Glyph>> = vec![Vec::new(); period];
        // The position counter advances over every character (enumerate's index),
        // but only letters are placed into a column — the full-character convention.
        for (position, ch) in raw
            .chars()
            .enumerate()
            .filter(|(_, ch)| ch.is_ascii_alphabetic())
        {
            if let Some(column) = columns.get_mut(position % period) {
                column.push(letter_glyph(ch));
            }
        }
        let value = message_weighted_index_of_coincidence(&columns);
        if value > best {
            best = value;
            best_at = period;
        }
    }
    (best.max(0.0), best_at)
}

/// Finds the maximal repeated substrings of length `>= minlen` in `letters`.
///
/// A repeat group `(substring, offsets)` is reported only when it is both
/// left-maximal and right-maximal over its full occurrence set — i.e. its
/// occurrences cannot all be extended one letter to the left (resp. right) by the
/// same letter. That suppresses any shorter substring contained in a longer
/// reported repeat at the same offsets. The result is sorted by descending
/// length, ties broken by ascending offsets.
fn maximal_repeats(letters: &[Glyph], word_id: &[usize], minlen: usize) -> Vec<Repeat> {
    let n = letters.len();
    let mut found: Vec<Repeat> = Vec::new();
    if n <= minlen {
        return found;
    }
    for len in minlen..n {
        let mut groups: HashMap<Vec<Glyph>, Vec<usize>> = HashMap::new();
        for start in 0..=(n - len) {
            if let Some(window) = letters.get(start..start + len) {
                groups.entry(window.to_vec()).or_default().push(start);
            }
        }
        let mut any_repeat = false;
        for (substring, offsets) in groups {
            if offsets.len() < 2 {
                continue;
            }
            any_repeat = true;
            if is_maximal(letters, &offsets, len) {
                found.push(build_repeat(&substring, offsets, word_id));
            }
        }
        // No length-`len` substring repeats => no longer one can either, so stop.
        if !any_repeat {
            break;
        }
    }
    found.sort_by(|left, right| {
        right
            .length
            .cmp(&left.length)
            .then_with(|| left.offsets.cmp(&right.offsets))
    });
    found
}

/// Whether a repeat group is both left- and right-maximal over its occurrences.
fn is_maximal(letters: &[Glyph], offsets: &[usize], len: usize) -> bool {
    !uniform_extension(offsets.iter().map(|&offset| letters.get(offset + len)))
        && !uniform_extension(offsets.iter().map(|&offset| {
            // A left edge at the stream start cannot be uniformly extended.
            offset.checked_sub(1).and_then(|prev| letters.get(prev))
        }))
}

/// Whether every occurrence has the same in-bounds neighbour glyph (so the group
/// could be extended uniformly, making it non-maximal in that direction).
fn uniform_extension<'a>(mut neighbours: impl Iterator<Item = Option<&'a Glyph>>) -> bool {
    let mut shared: Option<Glyph> = None;
    neighbours.all(|neighbour| match neighbour {
        None => false,
        Some(&glyph) => match shared {
            None => {
                shared = Some(glyph);
                true
            }
            Some(previous) => previous == glyph,
        },
    })
}

/// Builds a [`Repeat`] from a substring, its offsets, and the per-letter word ids.
fn build_repeat(substring: &[Glyph], offsets: Vec<usize>, word_id: &[usize]) -> Repeat {
    let length = substring.len();
    let text: String = substring.iter().map(|&glyph| glyph_char(glyph)).collect();
    let crosses_word_boundary = offsets
        .iter()
        .map(|&offset| crosses_boundary(word_id, offset, length))
        .collect();
    Repeat {
        text,
        length,
        offsets,
        crosses_word_boundary,
    }
}

/// Whether the `len` letters starting at `start` do not all share one word id.
fn crosses_boundary(word_id: &[usize], start: usize, len: usize) -> bool {
    let first = word_id.get(start).copied();
    (0..len).any(|step| word_id.get(start + step).copied() != first)
}

impl Profile {
    /// Renders the profile as a human-readable, newline-terminated report.
    ///
    /// The wording is deliberately disciplined: the statistics are structural,
    /// negative findings that constrain the cipher family, not the plaintext.
    #[must_use]
    pub fn render_report(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        lines.push("Ciphertext structural profile (practice letter puzzle)".to_owned());
        lines.push(
            "Structural / negative findings: they constrain the cipher family, not the plaintext."
                .to_owned(),
        );
        lines.push(format!("n_letters: {}", self.n_letters));
        lines.push(format!(
            "whole-stream IoC: {:.4}  (English ~{:.4}, uniform-26 ~{:.4}; looks_monoalphabetic={})",
            self.ioc,
            ENGLISH_IOC,
            UNIFORM_IOC_26,
            looks_monoalphabetic(self.ioc),
        ));
        let absent = if self.absent.is_empty() {
            "(none)".to_owned()
        } else {
            self.absent
                .iter()
                .map(char::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        lines.push(format!(
            "distinct letters present: {} / 26   absent: {absent}",
            self.distinct_present,
        ));
        lines.push(format!(
            "single-letter words: {}",
            self.single_letter_word_count,
        ));
        lines.push(
            "per-period IoC (pair-count-weighted across the P columns), max over P=2..=40:"
                .to_owned(),
        );
        lines.push(format!(
            "  by letter index:    {:.4} at P={}",
            self.max_period_ioc_letters, self.max_period_ioc_letters_at,
        ));
        lines.push(format!(
            "  by full-char index: {:.4} at P={}",
            self.max_period_ioc_fullchar, self.max_period_ioc_fullchar_at,
        ));
        lines.push(format!(
            "  interpretation: the peak per-period IoC stays near uniform-26 (~{UNIFORM_IOC_26:.4}) \
             across every P in 2..=40 — no periodic-polyalphabetic peak in the tested range; the \
             whole-stream IoC ({:.4}) is likewise far below English (~{ENGLISH_IOC:.4}), so not \
             monoalphabetic either.",
            self.ioc,
        ));
        lines.push("per-word column IoC (0-based column, columns with n>=8):".to_owned());
        if self.per_word_col_ioc.is_empty() {
            lines.push("  (no column reaches n>=8)".to_owned());
        } else {
            for (column, n, ioc) in &self.per_word_col_ioc {
                lines.push(format!("  col {column:>2}  n={n:>3}  ioc={ioc:.4}"));
            }
        }
        lines.push(
            "maximal repeated substrings (length >= 4) in the letters-only stream:".to_owned(),
        );
        if self.repeats.is_empty() {
            lines.push("  (none)".to_owned());
        } else {
            for repeat in &self.repeats {
                let gaps: Vec<usize> = repeat
                    .offsets
                    .windows(2)
                    .map(|pair| {
                        pair.get(1)
                            .copied()
                            .unwrap_or(0)
                            .saturating_sub(pair.first().copied().unwrap_or(0))
                    })
                    .collect();
                let crosses: Vec<&str> = repeat
                    .crosses_word_boundary
                    .iter()
                    .map(|&flag| if flag { "yes" } else { "no" })
                    .collect();
                lines.push(format!(
                    "  {:?} len={} offsets={:?} gaps={:?} crosses-word-boundary=[{}]",
                    repeat.text,
                    repeat.length,
                    repeat.offsets,
                    gaps,
                    crosses.join(", "),
                ));
            }
            lines.push(
                "  (a repeat that crosses word boundaries is not explained by a single repeated word.)"
                    .to_owned(),
            );
        }
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ENGLISH_IOC, PracticePuzzle, UNIFORM_IOC_26, looks_monoalphabetic, profile_puzzle,
        profile_text,
    };

    #[test]
    fn five_scalar_profile_matches_reference() {
        let profile = profile_puzzle(PracticePuzzle::Five);
        assert_eq!(profile.n_letters, 274);
        assert!((profile.ioc - 0.0392).abs() < 0.001, "ioc={}", profile.ioc);
        assert_eq!(profile.distinct_present, 25);
        assert_eq!(profile.absent, vec!['J']);
        assert_eq!(profile.single_letter_word_count, 2);
        assert!(
            profile.max_period_ioc_letters < 0.052,
            "letters period IoC too high: {}",
            profile.max_period_ioc_letters
        );
        assert!(
            profile.max_period_ioc_fullchar < 0.055,
            "fullchar period IoC too high: {}",
            profile.max_period_ioc_fullchar
        );
        assert!(!looks_monoalphabetic(profile.ioc));
    }

    #[test]
    fn five_has_gap_40_cross_boundary_repeat() {
        let profile = profile_puzzle(PracticePuzzle::Five);
        let hit = profile.repeats.iter().find(|repeat| {
            let gap = repeat
                .offsets
                .get(1)
                .copied()
                .unwrap_or(0)
                .saturating_sub(repeat.offsets.first().copied().unwrap_or(0));
            repeat.length >= 8
                && repeat.offsets.len() == 2
                && gap == 40
                && repeat.crosses_word_boundary.iter().all(|&flag| flag)
        });
        assert!(
            hit.is_some(),
            "expected a length>=8 repeat at gap 40 with both occurrences crossing a word \
             boundary; got {:?}",
            profile.repeats
        );
    }

    #[test]
    fn seven_uses_all_letters_and_eight_single_letter_words() {
        let profile = profile_puzzle(PracticePuzzle::Seven);
        assert!(profile.absent.is_empty(), "absent={:?}", profile.absent);
        assert_eq!(profile.single_letter_word_count, 8);
    }

    #[test]
    fn three_and_four_are_missing_j_and_v() {
        assert_eq!(profile_puzzle(PracticePuzzle::Three).absent, vec!['J', 'V']);
        assert_eq!(profile_puzzle(PracticePuzzle::Four).absent, vec!['J', 'V']);
    }

    #[test]
    fn ioc_of_a_tiny_known_string() {
        // "ABAB" -> A,B,A,B: each letter appears twice, so IoC = (2 + 2) / (4*3).
        let profile = profile_text("ABAB");
        assert_eq!(profile.n_letters, 4);
        assert!(
            (profile.ioc - 1.0 / 3.0).abs() < 1e-9,
            "ioc={}",
            profile.ioc
        );
    }

    #[test]
    fn monoalphabetic_predicate_band() {
        assert!(looks_monoalphabetic(ENGLISH_IOC));
        assert!(!looks_monoalphabetic(UNIFORM_IOC_26));
        assert!(!looks_monoalphabetic(0.0385));
    }

    #[test]
    fn render_report_mentions_the_repeat_and_is_terminated() {
        let report = profile_puzzle(PracticePuzzle::Five).render_report();
        assert!(report.contains("DUXECHTINIT"), "report: {report}");
        assert!(report.ends_with('\n'));
    }
}
