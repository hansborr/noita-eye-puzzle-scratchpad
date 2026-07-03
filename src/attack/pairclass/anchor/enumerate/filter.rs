use std::collections::BTreeMap;

use super::super::super::N_LETTERS;
use super::super::super::lexicon::ROOT;
use super::super::{HarvestWindowInput, HarvestedColoring};
use super::suffix::SuffixTrie;

const UNSET_SOURCE: u8 = u8::MAX;

#[derive(Clone, Copy)]
pub(super) struct TieFilterCfg {
    pub(super) max_gaps: u8,
    pub(super) max_gap_len: u8,
    pub(super) parse_budget: u64,
}

pub(super) struct TieFilterResult {
    pub(super) colorings: Vec<HarvestedColoring>,
    pub(super) expanded: u64,
    pub(super) budget_hit: bool,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct VerifyKey {
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap_node: u32,
    used: u32,
    source: Vec<u8>,
}

#[derive(Clone, Copy)]
struct VerifyValue {
    gap_letters: usize,
}

#[derive(Clone, Copy)]
struct VerifyTransition {
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap_node: u32,
    gap: bool,
}

pub(super) fn retain_full_tie_colorings(
    input: HarvestWindowInput<'_>,
    cfg: TieFilterCfg,
    suffix_trie: &SuffixTrie,
    colorings: Vec<HarvestedColoring>,
) -> TieFilterResult {
    let mut kept = Vec::new();
    let mut expanded = 0u64;
    let mut budget_hit = false;
    for candidate in colorings {
        let (accepted, candidate_budget_hit) = {
            let mut verifier = TieVerifier {
                input,
                cfg,
                suffix_trie,
                coloring: &candidate.coloring,
                target_used: pinned_mask(&candidate.coloring),
                expanded: &mut expanded,
                budget_hit: false,
            };
            let accepted = verifier.accepts();
            (accepted, verifier.budget_hit)
        };
        if accepted {
            kept.push(candidate);
        }
        if candidate_budget_hit {
            budget_hit = true;
            break;
        }
    }
    rerank(&mut kept);
    TieFilterResult {
        colorings: kept,
        expanded,
        budget_hit,
    }
}

struct TieVerifier<'a, 'b, 'c> {
    input: HarvestWindowInput<'a>,
    cfg: TieFilterCfg,
    suffix_trie: &'b SuffixTrie,
    coloring: &'c [Option<u8>; 26],
    target_used: u32,
    expanded: &'c mut u64,
    budget_hit: bool,
}

impl TieVerifier<'_, '_, '_> {
    fn accepts(&mut self) -> bool {
        let mut current = BTreeMap::new();
        let _old = current.insert(
            VerifyKey {
                node: ROOT,
                gap_len: 0,
                gaps_used: 0,
                gap_node: ROOT,
                used: 0,
                source: vec![UNSET_SOURCE; self.input.window.span_len],
            },
            VerifyValue { gap_letters: 0 },
        );
        for position in 0..self.input.tokens.len() {
            if current.is_empty() {
                return false;
            }
            let mut next = BTreeMap::new();
            for (key, value) in &current {
                self.expand_state(position, key, *value, &mut next);
                if self.budget_hit {
                    return false;
                }
            }
            current = next;
        }
        current
            .into_iter()
            .any(|(key, value)| self.accept_final(&key, value))
    }

    fn expand_state(
        &mut self,
        position: usize,
        key: &VerifyKey,
        value: VerifyValue,
        next: &mut BTreeMap<VerifyKey, VerifyValue>,
    ) {
        let Some(&token) = self.input.tokens.get(position) else {
            return;
        };
        if let Some(src) = self.input.tie_table.get(position).copied().flatten() {
            let Some(letter) = self.source_letter(src, key) else {
                return;
            };
            self.try_letter(position, key, value, letter, token, next);
            return;
        }
        for letter in 0..N_LETTERS {
            self.try_letter(position, key, value, letter, token, next);
            if self.budget_hit {
                break;
            }
        }
    }

    fn source_letter(&self, src: usize, key: &VerifyKey) -> Option<u8> {
        let offset = src.checked_sub(self.input.window.first_offset)?;
        key.source
            .get(offset)
            .copied()
            .filter(|&letter| letter != UNSET_SOURCE)
    }

    fn try_letter(
        &mut self,
        position: usize,
        key: &VerifyKey,
        value: VerifyValue,
        letter: u8,
        token: u8,
        next: &mut BTreeMap<VerifyKey, VerifyValue>,
    ) {
        if !self.color_allows(letter, token) {
            return;
        }
        if key.gap_len > 0 {
            if value.gap_letters == position {
                if key.gap_len < self.cfg.max_gap_len
                    && let Some(child) = self.suffix_trie.child(key.gap_node, letter)
                {
                    self.emit_gap(
                        position,
                        key,
                        value,
                        letter,
                        (key.gap_len + 1, key.gaps_used, child),
                        next,
                    );
                }
                if self.suffix_trie.terminal(key.gap_node)
                    && let Some(child) = self.input.lexicon.child(ROOT, letter)
                {
                    self.emit_word(position, key, value, letter, child, next);
                }
            }
            return;
        }
        if key.node == ROOT {
            if let Some(child) = self.input.lexicon.child(ROOT, letter) {
                self.emit_word(position, key, value, letter, child, next);
            }
            if value.gap_letters == position
                && key.gaps_used < self.cfg.max_gaps
                && let Some(child) = self.suffix_trie.child(ROOT, letter)
            {
                self.emit_gap(
                    position,
                    key,
                    value,
                    letter,
                    (1, key.gaps_used + 1, child),
                    next,
                );
            }
            return;
        }
        if let Some(child) = self.input.lexicon.child(key.node, letter) {
            self.emit_word(position, key, value, letter, child, next);
        }
        if self.input.lexicon.word_logp(key.node).is_some()
            && let Some(child) = self.input.lexicon.child(ROOT, letter)
        {
            self.emit_word(position, key, value, letter, child, next);
        }
    }

    fn color_allows(&self, letter: u8, token: u8) -> bool {
        letter < N_LETTERS
            && self
                .coloring
                .get(usize::from(letter))
                .is_some_and(|&class| class == Some(token))
    }

    fn emit_word(
        &mut self,
        position: usize,
        key: &VerifyKey,
        value: VerifyValue,
        letter: u8,
        node: u32,
        next: &mut BTreeMap<VerifyKey, VerifyValue>,
    ) {
        self.emit_transition(
            position,
            key,
            value,
            letter,
            VerifyTransition {
                node,
                gap_len: 0,
                gaps_used: key.gaps_used,
                gap_node: ROOT,
                gap: false,
            },
            next,
        );
    }

    fn emit_gap(
        &mut self,
        position: usize,
        key: &VerifyKey,
        value: VerifyValue,
        letter: u8,
        gap: (u8, u8, u32),
        next: &mut BTreeMap<VerifyKey, VerifyValue>,
    ) {
        let (gap_len, gaps_used, gap_node) = gap;
        self.emit_transition(
            position,
            key,
            value,
            letter,
            VerifyTransition {
                node: ROOT,
                gap_len,
                gaps_used,
                gap_node,
                gap: true,
            },
            next,
        );
    }

    fn emit_transition(
        &mut self,
        position: usize,
        key: &VerifyKey,
        value: VerifyValue,
        letter: u8,
        transition: VerifyTransition,
        next: &mut BTreeMap<VerifyKey, VerifyValue>,
    ) {
        if *self.expanded >= self.cfg.parse_budget {
            self.budget_hit = true;
            return;
        }
        let Some(source) = self.next_source(position, key, letter) else {
            return;
        };
        let next_key = VerifyKey {
            node: transition.node,
            gap_len: transition.gap_len,
            gaps_used: transition.gaps_used,
            gap_node: transition.gap_node,
            used: key.used | (1u32 << letter),
            source,
        };
        let next_value = VerifyValue {
            gap_letters: value.gap_letters + usize::from(transition.gap),
        };
        *self.expanded += 1;
        offer_verify_state(next, next_key, next_value);
    }

    fn next_source(&self, position: usize, key: &VerifyKey, letter: u8) -> Option<Vec<u8>> {
        let mut source = key.source.clone();
        let first_start = self.input.window.first_offset;
        let first_end = first_start.saturating_add(self.input.window.span_len);
        if (first_start..first_end).contains(&position) {
            let offset = position - first_start;
            let slot = source.get_mut(offset)?;
            if *slot != UNSET_SOURCE && *slot != letter {
                return None;
            }
            *slot = letter;
        }
        Some(source)
    }

    fn accept_final(&self, key: &VerifyKey, value: VerifyValue) -> bool {
        value.gap_letters != self.input.tokens.len()
            && key.used == self.target_used
            && (key.gap_len > 0
                || self.input.lexicon.word_logp(key.node).is_some()
                || key.node != ROOT)
    }
}

fn offer_verify_state(
    states: &mut BTreeMap<VerifyKey, VerifyValue>,
    key: VerifyKey,
    value: VerifyValue,
) {
    if let Some(current) = states.get(&key).copied()
        && value.gap_letters >= current.gap_letters
    {
        return;
    }
    let _old = states.insert(key, value);
}

fn pinned_mask(coloring: &[Option<u8>; 26]) -> u32 {
    coloring
        .iter()
        .enumerate()
        .fold(0u32, |mask, (letter, class)| {
            if class.is_some() {
                mask | (1u32 << letter)
            } else {
                mask
            }
        })
}

fn rerank(colorings: &mut [HarvestedColoring]) {
    for (index, coloring) in colorings.iter_mut().enumerate() {
        coloring.rank = index + 1;
    }
}
