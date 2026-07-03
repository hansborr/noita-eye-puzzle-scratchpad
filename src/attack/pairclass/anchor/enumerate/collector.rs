use std::cmp::Reverse;
use std::collections::BTreeMap;

use super::super::HarvestedColoring;

type CoverageKey = (usize, Reverse<usize>, Reverse<usize>, [Option<u8>; 26]);

/// Distinct-coloring collector with no cap or eviction.
pub(super) struct ColoringCollector {
    by_coloring: BTreeMap<[Option<u8>; 26], HarvestedColoring>,
}

impl ColoringCollector {
    pub(super) fn new() -> Self {
        Self {
            by_coloring: BTreeMap::new(),
        }
    }

    pub(super) fn offer(&mut self, candidate: HarvestedColoring) {
        let _entry = self
            .by_coloring
            .entry(candidate.coloring)
            .and_modify(|existing| {
                if better_representative(&candidate, existing) {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }

    pub(super) fn finish(self) -> Vec<HarvestedColoring> {
        let mut out: Vec<HarvestedColoring> = self.by_coloring.into_values().collect();
        out.sort_by(|a, b| {
            coverage_key(b)
                .cmp(&coverage_key(a))
                .then_with(|| a.rendered.cmp(&b.rendered))
        });
        for (index, coloring) in out.iter_mut().enumerate() {
            coloring.rank = index + 1;
        }
        out
    }
}

fn better_representative(candidate: &HarvestedColoring, existing: &HarvestedColoring) -> bool {
    candidate
        .gaps_used
        .cmp(&existing.gaps_used)
        .then_with(|| candidate.gap_letters.cmp(&existing.gap_letters))
        .then_with(|| candidate.rendered.cmp(&existing.rendered))
        .is_lt()
}

fn coverage_key(candidate: &HarvestedColoring) -> CoverageKey {
    (
        candidate.pinned,
        Reverse(usize::from(candidate.gaps_used)),
        Reverse(candidate.gap_letters),
        candidate.coloring,
    )
}
