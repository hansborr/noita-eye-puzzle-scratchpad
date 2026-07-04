//! Anchor derivation for the closure-shadow key search.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::isomorph_map::ColumnMap;

use super::{Anchor, ShadowSearchError};

pub(super) fn derive_hard_anchors(
    maps: &[ColumnMap],
    closure_elements: &[Vec<usize>],
    min_support: usize,
    trim: usize,
    min_len: usize,
) -> Result<Vec<Anchor>, ShadowSearchError> {
    let mut seen = BTreeSet::new();
    let mut anchors = Vec::new();
    for map in maps {
        if map_support(map) < min_support {
            continue;
        }
        if !map_extends_to_closure(map, closure_elements) {
            continue;
        }
        let span = map.span;
        let Some(anchor) = trim_anchor(span.first, span.second, span.length, trim)? else {
            continue;
        };
        if anchor.length < min_len {
            continue;
        }
        if seen.insert((anchor.first, anchor.second, anchor.length)) {
            anchors.push(anchor);
        }
    }
    if anchors.len() <= 1 {
        return Ok(anchors);
    }

    anchors.sort_by(|left, right| {
        let left_end = left.second + left.length;
        let right_end = right.second + right.length;
        left_end
            .cmp(&right_end)
            .then_with(|| right.length.cmp(&left.length))
            .then_with(|| left.first.cmp(&right.first))
            .then_with(|| left.second.cmp(&right.second))
    });
    let first = anchors.remove(0);
    anchors.sort_by(|left, right| {
        right
            .length
            .cmp(&left.length)
            .then_with(|| left.first.cmp(&right.first))
            .then_with(|| left.second.cmp(&right.second))
    });
    anchors.insert(0, first);
    Ok(anchors)
}

fn map_support(map: &ColumnMap) -> usize {
    map.mapping.iter().filter(|target| target.is_some()).count()
}

fn map_extends_to_closure(map: &ColumnMap, closure_elements: &[Vec<usize>]) -> bool {
    closure_elements.iter().any(|element| {
        map.mapping.iter().enumerate().all(|(source, target)| {
            target.is_none_or(|target| element.get(source).copied() == Some(target))
        })
    })
}

pub(super) fn derive_soft_anchors(
    values: &[u16],
    min_len: usize,
    max_len: usize,
    trim: usize,
) -> Result<Vec<Anchor>, ShadowSearchError> {
    if min_len == 0 || min_len > max_len || values.len() < min_len {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for length in min_len..=max_len {
        for positions in literal_repeat_classes(values, length).values() {
            if positions.len() < 2 {
                continue;
            }
            let Some((&first, &second)) = positions.first().zip(positions.get(1)) else {
                continue;
            };
            if literal_lcp(values, first, second) != length {
                continue;
            }
            if positions.len() == 2 && extends_left(values, first, second) {
                continue;
            }
            let Some(anchor) = trim_anchor(first, second, length, trim)? else {
                continue;
            };
            candidates.push(anchor);
        }
    }
    candidates.sort_by(|left, right| {
        left.raw_length
            .cmp(&right.raw_length)
            .then_with(|| left.raw_first.cmp(&right.raw_first))
            .then_with(|| left.raw_second.cmp(&right.raw_second))
    });
    Ok(candidates)
}

fn literal_repeat_classes(values: &[u16], length: usize) -> BTreeMap<Vec<u16>, Vec<usize>> {
    let mut classes = BTreeMap::<Vec<u16>, Vec<usize>>::new();
    if length > values.len() {
        return classes;
    }
    for start in 0..=values.len() - length {
        if let Some(window) = values.get(start..start + length) {
            classes.entry(window.to_vec()).or_default().push(start);
        }
    }
    classes
}

fn trim_anchor(
    first: usize,
    second: usize,
    length: usize,
    trim: usize,
) -> Result<Option<Anchor>, ShadowSearchError> {
    let Some(double_trim) = trim.checked_mul(2) else {
        return Err(ShadowSearchError::TrimTooLarge { trim, length });
    };
    if length <= double_trim {
        return Ok(None);
    }
    Ok(Some(Anchor {
        first: first + trim,
        second: second + trim,
        length: length - double_trim,
        raw_first: first,
        raw_second: second,
        raw_length: length,
        trim,
    }))
}

fn literal_lcp(values: &[u16], first: usize, second: usize) -> usize {
    let mut length = 0usize;
    while values
        .get(first + length)
        .zip(values.get(second + length))
        .is_some_and(|(left, right)| left == right)
    {
        length += 1;
    }
    length
}

fn extends_left(values: &[u16], first: usize, second: usize) -> bool {
    if first == 0 || second == 0 {
        return false;
    }
    values.get(first - 1) == values.get(second - 1)
}
