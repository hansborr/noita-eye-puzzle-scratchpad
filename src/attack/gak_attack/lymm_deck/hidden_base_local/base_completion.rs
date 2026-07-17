//! Hidden-base completion enumeration shared by ranking and exact SAT.

use super::corpus::LocalCorpus;

pub(super) fn base_completions(
    n: usize,
    corpus: &LocalCorpus,
    hypothesis: &[Option<usize>],
    cap: usize,
) -> Option<(Vec<Vec<usize>>, bool)> {
    let mut partial = vec![None; n];
    let mut value_owner = vec![None; n];
    for (letter, target) in corpus.anchors.iter().copied().enumerate() {
        let Some(target) = target else {
            continue;
        };
        let source = hypothesis.get(letter).copied().flatten()?;
        if source >= n || target >= n {
            return None;
        }
        match partial.get_mut(source)? {
            Some(existing) if *existing != target => return None,
            Some(_existing) => {}
            slot @ None => {
                if value_owner.get(target).copied().flatten().is_some() {
                    return None;
                }
                *slot = Some(target);
                *value_owner.get_mut(target)? = Some(source);
            }
        }
    }
    let positions = partial
        .iter()
        .enumerate()
        .filter_map(|(position, value)| value.is_none().then_some(position))
        .collect::<Vec<_>>();
    let remaining = value_owner
        .iter()
        .enumerate()
        .filter_map(|(value, owner)| owner.is_none().then_some(value))
        .collect::<Vec<_>>();
    enumerate_completions(&partial, &positions, remaining, cap)
}

fn enumerate_completions(
    partial: &[Option<usize>],
    positions: &[usize],
    mut remaining: Vec<usize>,
    cap: usize,
) -> Option<(Vec<Vec<usize>>, bool)> {
    if positions.len() != remaining.len() {
        return None;
    }
    if cap == 0 {
        return Some((Vec::new(), true));
    }
    let mut completions = Vec::new();
    loop {
        let mut base = partial.to_vec();
        for (&position, &value) in positions.iter().zip(&remaining) {
            *base.get_mut(position)? = Some(value);
        }
        completions.push(base.into_iter().collect::<Option<Vec<_>>>()?);
        let has_more = next_permutation(&mut remaining);
        if completions.len() == cap {
            return Some((completions, has_more));
        }
        if !has_more {
            return Some((completions, false));
        }
    }
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = values.windows(2).rposition(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left < right)
    }) else {
        return false;
    };
    let Some(&pivot_value) = values.get(pivot) else {
        return false;
    };
    let Some(successor) = values
        .iter()
        .enumerate()
        .skip(pivot.saturating_add(1))
        .rfind(|(_index, value)| pivot_value < **value)
        .map(|(index, _value)| index)
    else {
        return false;
    };
    values.swap(pivot, successor);
    let Some(tail) = values.get_mut(pivot.saturating_add(1)..) else {
        return false;
    };
    tail.reverse();
    true
}
