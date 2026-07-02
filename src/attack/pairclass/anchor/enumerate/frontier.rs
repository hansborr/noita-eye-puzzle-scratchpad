use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::{DpKey, DpValue, EnumArena};

type StateRank = (
    usize,
    usize,
    Reverse<usize>,
    Reverse<usize>,
    Reverse<usize>,
    DpKey,
);

pub(super) struct StateLayer {
    cap: usize,
    depth: usize,
    states: BTreeMap<DpKey, DpValue>,
    retained: BTreeSet<StateRank>,
    pub(super) saturated: bool,
}

impl StateLayer {
    pub(super) fn new(cap: usize, depth: usize) -> Self {
        Self {
            cap,
            depth,
            states: BTreeMap::new(),
            retained: BTreeSet::new(),
            saturated: false,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.states.len()
    }

    pub(super) fn offer(
        &mut self,
        key: DpKey,
        parent: u32,
        packed: u8,
        gap_letters: usize,
        arena: &mut EnumArena,
    ) {
        if let Some(current) = self.states.get(&key).copied() {
            if (gap_letters, parent) >= (current.gap_letters, current.arena) {
                return;
            }
            let _removed = self
                .retained
                .remove(&state_rank(self.depth, &key, current.gap_letters));
            let arena_index = arena.push(parent, packed);
            let value = DpValue {
                arena: arena_index,
                gap_letters,
            };
            let _old = self.states.insert(key.clone(), value);
            let _inserted = self
                .retained
                .insert(state_rank(self.depth, &key, gap_letters));
            return;
        }

        let rank = state_rank(self.depth, &key, gap_letters);
        if self.states.len() < self.cap {
            self.insert_new(key, rank, parent, packed, gap_letters, arena);
            return;
        }
        self.saturated = true;
        if let Some(worst) = self.retained.iter().next().cloned()
            && rank > worst
        {
            let evicted = worst.5.clone();
            let _removed = self.retained.remove(&worst);
            let _old = self.states.remove(&evicted);
            self.insert_new(key, rank, parent, packed, gap_letters, arena);
        }
    }

    pub(super) fn into_states(self) -> BTreeMap<DpKey, DpValue> {
        self.states
    }

    fn insert_new(
        &mut self,
        key: DpKey,
        rank: StateRank,
        parent: u32,
        packed: u8,
        gap_letters: usize,
        arena: &mut EnumArena,
    ) {
        let arena_index = arena.push(parent, packed);
        let value = DpValue {
            arena: arena_index,
            gap_letters,
        };
        let _old = self.states.insert(key, value);
        let _inserted = self.retained.insert(rank);
    }
}

fn state_rank(depth: usize, key: &DpKey, gap_letters: usize) -> StateRank {
    (
        depth.saturating_sub(gap_letters),
        key.pinned.count_ones() as usize,
        Reverse(usize::from(key.gaps_used)),
        Reverse(gap_letters),
        Reverse(usize::from(key.gap_len)),
        key.clone(),
    )
}
