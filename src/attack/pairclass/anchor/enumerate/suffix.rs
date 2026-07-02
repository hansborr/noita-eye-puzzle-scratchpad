use super::super::super::N_LETTERS;
use super::super::super::lexicon::{Lexicon, ROOT};

const NO_CHILD: u32 = u32::MAX;

pub(super) struct SuffixTrie {
    children: Vec<[u32; 26]>,
    terminal: Vec<bool>,
}

impl SuffixTrie {
    pub(super) fn from_lexicon(lexicon: &Lexicon, max_len: usize) -> Self {
        let mut trie = Self {
            children: vec![[NO_CHILD; 26]],
            terminal: vec![false],
        };
        let mut path = Vec::new();
        collect_suffixes(lexicon, ROOT, max_len, &mut path, &mut trie);
        trie
    }

    pub(super) fn child(&self, node: u32, letter: u8) -> Option<u32> {
        self.children
            .get(node as usize)
            .and_then(|slots| slots.get(usize::from(letter)))
            .copied()
            .filter(|&child| child != NO_CHILD)
    }

    pub(super) fn terminal(&self, node: u32) -> bool {
        self.terminal.get(node as usize).copied().unwrap_or(false)
    }

    fn insert(&mut self, suffix: &[u8]) {
        if suffix.is_empty() {
            return;
        }
        let mut node = 0u32;
        for &letter in suffix {
            let slot = usize::from(letter);
            let existing = self
                .children
                .get(node as usize)
                .and_then(|slots| slots.get(slot))
                .copied()
                .unwrap_or(NO_CHILD);
            if existing == NO_CHILD {
                let next = self.children.len() as u32;
                self.children.push([NO_CHILD; 26]);
                self.terminal.push(false);
                if let Some(child_slot) = self
                    .children
                    .get_mut(node as usize)
                    .and_then(|slots| slots.get_mut(slot))
                {
                    *child_slot = next;
                }
                node = next;
            } else {
                node = existing;
            }
        }
        if let Some(slot) = self.terminal.get_mut(node as usize) {
            *slot = true;
        }
    }
}

fn collect_suffixes(
    lexicon: &Lexicon,
    node: u32,
    max_len: usize,
    path: &mut Vec<u8>,
    trie: &mut SuffixTrie,
) {
    if lexicon.word_logp(node).is_some() {
        for start in 1..path.len() {
            if let Some(suffix) = path.get(start..)
                && suffix.len() <= max_len
            {
                trie.insert(suffix);
            }
        }
    }
    for letter in 0..N_LETTERS {
        if let Some(child) = lexicon.child(node, letter) {
            path.push(letter);
            collect_suffixes(lexicon, child, max_len, path, trie);
            let _popped = path.pop();
        }
    }
}
