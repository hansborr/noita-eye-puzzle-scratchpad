//! Word-trie lexicon with unigram log-probabilities for the pair-class solver.
//!
//! The trie stores lowercase `a..z` words only; node children are flat
//! 26-slot arrays for branch-free-ish lookups in the beam hot loop. A word
//! node carries `ln(count / total)`; interior nodes carry `f32::NEG_INFINITY`
//! as the not-a-word sentinel (exposed as `Option` by the accessor).

use super::{N_LETTERS, PairclassError};

/// Child-slot sentinel for "no child".
const NO_CHILD: u32 = u32::MAX;
/// The root node index (also the word-boundary state of the solver).
pub(super) const ROOT: u32 = 0;

/// A frequency-weighted word trie over `a..z`.
#[derive(Clone, Debug)]
pub struct Lexicon {
    /// Flat child table, 26 slots per node.
    children: Vec<[u32; 26]>,
    /// Word-end natural-log probability per node (`NEG_INFINITY` = interior).
    word_logp: Vec<f32>,
    /// Number of words inserted.
    n_words: usize,
}

impl Lexicon {
    /// Number of words in the lexicon.
    #[must_use]
    pub fn n_words(&self) -> usize {
        self.n_words
    }

    /// Number of trie nodes (a memory-footprint proxy: ~108 bytes per node).
    #[must_use]
    pub fn n_nodes(&self) -> usize {
        self.children.len()
    }

    /// The child of `node` along `letter` (`0..26`), if present.
    #[must_use]
    pub(super) fn child(&self, node: u32, letter: u8) -> Option<u32> {
        self.children
            .get(node as usize)
            .and_then(|slots| slots.get(usize::from(letter)))
            .copied()
            .filter(|&c| c != NO_CHILD)
    }

    /// The word log-probability at `node`, if `node` ends a word.
    #[must_use]
    pub(super) fn word_logp(&self, node: u32) -> Option<f32> {
        self.word_logp
            .get(node as usize)
            .copied()
            .filter(|logp| logp.is_finite())
    }
}

/// Parses a wordlist: one entry per line, `word` or `word count`. Words are
/// lowercased and dropped unless purely `a..z`; duplicates keep the larger
/// count; the result is sorted by descending count (then word) and truncated
/// to `cap` entries.
#[must_use]
pub fn parse_wordlist(text: &str, cap: usize) -> Vec<(String, u64)> {
    let mut entries: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_word) = fields.next() else {
            continue;
        };
        let word = raw_word.to_lowercase();
        if word.is_empty() || !word.bytes().all(|b| b.is_ascii_lowercase()) {
            continue;
        }
        let count = fields
            .next()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1)
            .max(1);
        let slot = entries.entry(word).or_insert(0);
        *slot = (*slot).max(count);
    }
    let mut words: Vec<(String, u64)> = entries.into_iter().collect();
    words.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    words.truncate(cap);
    words
}

/// Builds the trie from `(word, count)` entries (as from [`parse_wordlist`]).
///
/// # Errors
/// [`PairclassError::EmptyLexicon`] when no usable word remains.
pub fn build_lexicon(words: &[(String, u64)]) -> Result<Lexicon, PairclassError> {
    let mut lexicon = Lexicon {
        children: vec![[NO_CHILD; 26]],
        word_logp: vec![f32::NEG_INFINITY],
        n_words: 0,
    };
    let total: u64 = words
        .iter()
        .filter(|(word, _)| is_lower_alpha(word))
        .map(|&(_, count)| count.max(1))
        .sum();
    if total == 0 {
        return Err(PairclassError::EmptyLexicon);
    }
    for (word, count) in words {
        if !is_lower_alpha(word) {
            continue;
        }
        let node = insert_path(&mut lexicon, word);
        let logp = (((*count).max(1) as f64) / (total as f64)).ln() as f32;
        if let Some(slot) = lexicon.word_logp.get_mut(node as usize) {
            // Duplicate words keep their better (larger) log-probability.
            if !slot.is_finite() || logp > *slot {
                *slot = logp;
            }
        }
        lexicon.n_words += 1;
    }
    if lexicon.n_words == 0 {
        return Err(PairclassError::EmptyLexicon);
    }
    Ok(lexicon)
}

/// `true` when `word` is non-empty pure `a..z` (and short enough to index).
fn is_lower_alpha(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase())
}

/// Walks/creates the trie path for `word`, returning its end node.
fn insert_path(lexicon: &mut Lexicon, word: &str) -> u32 {
    let mut node = ROOT;
    for byte in word.bytes() {
        let letter = usize::from(byte - b'a').min(usize::from(N_LETTERS) - 1);
        let existing = lexicon
            .children
            .get(node as usize)
            .and_then(|slots| slots.get(letter))
            .copied()
            .unwrap_or(NO_CHILD);
        node = if existing == NO_CHILD {
            let fresh = lexicon.children.len() as u32;
            lexicon.children.push([NO_CHILD; 26]);
            lexicon.word_logp.push(f32::NEG_INFINITY);
            if let Some(slots) = lexicon.children.get_mut(node as usize)
                && let Some(slot) = slots.get_mut(letter)
            {
                *slot = fresh;
            }
            fresh
        } else {
            existing
        };
    }
    node
}
