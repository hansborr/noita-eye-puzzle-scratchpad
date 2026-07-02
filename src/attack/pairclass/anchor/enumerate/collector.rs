use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::super::HarvestedColoring;

type CoverageKey = (usize, Reverse<usize>, Reverse<usize>, [Option<u8>; 26]);

/// Distinct-coloring collector with LM-free coverage cap selection.
pub(super) struct ColoringCollector {
    limit: usize,
    by_coloring: BTreeMap<[Option<u8>; 26], HarvestedColoring>,
    retained: BTreeSet<CoverageKey>,
    cap_hit: bool,
    dropped_colorings: usize,
}

impl ColoringCollector {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            by_coloring: BTreeMap::new(),
            retained: BTreeSet::new(),
            cap_hit: false,
            dropped_colorings: 0,
        }
    }

    pub(super) fn offer(&mut self, candidate: HarvestedColoring) {
        let key = coverage_key(&candidate);
        if let Some(existing) = self.by_coloring.get(&candidate.coloring) {
            let old_key = coverage_key(existing);
            if key > old_key {
                let _removed = self.retained.remove(&old_key);
                let _inserted = self.retained.insert(key);
                let _old = self.by_coloring.insert(candidate.coloring, candidate);
            }
            return;
        }
        if self.by_coloring.len() < self.limit {
            let _inserted = self.retained.insert(key);
            let _old = self.by_coloring.insert(candidate.coloring, candidate);
            return;
        }
        self.cap_hit = true;
        if let Some(&worst_key) = self.retained.iter().next()
            && key > worst_key
        {
            let evicted = worst_key.3;
            let _removed = self.retained.remove(&worst_key);
            let _old = self.by_coloring.remove(&evicted);
            let _inserted = self.retained.insert(key);
            let _old = self.by_coloring.insert(candidate.coloring, candidate);
        }
        self.dropped_colorings = self.dropped_colorings.saturating_add(1);
    }

    pub(super) fn finish(self) -> (Vec<HarvestedColoring>, bool, usize) {
        let mut out: Vec<HarvestedColoring> = self.by_coloring.into_values().collect();
        out.sort_by(|a, b| {
            b.pinned
                .cmp(&a.pinned)
                .then_with(|| a.gaps_used.cmp(&b.gaps_used))
                .then_with(|| a.gap_letters.cmp(&b.gap_letters))
                .then_with(|| a.coloring.cmp(&b.coloring))
                .then_with(|| a.rendered.cmp(&b.rendered))
        });
        for (index, coloring) in out.iter_mut().enumerate() {
            coloring.rank = index + 1;
        }
        (out, self.cap_hit, self.dropped_colorings)
    }
}

fn coverage_key(candidate: &HarvestedColoring) -> CoverageKey {
    (
        candidate.pinned,
        Reverse(usize::from(candidate.gaps_used)),
        Reverse(candidate.gap_letters),
        candidate.coloring,
    )
}
