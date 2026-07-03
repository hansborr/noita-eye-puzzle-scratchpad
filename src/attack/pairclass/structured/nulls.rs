//! Tie-aware null resampling for structured oracle mode.

use crate::attack::pairclass::PairclassError;
use crate::attack::pairclass::campaign::StreamPrep;
use crate::attack::pairclass::plant::markov_resample;

pub(super) fn markov_resample_with_ties(
    prep: &StreamPrep,
    seed: u64,
) -> Result<Vec<u8>, PairclassError> {
    let mut tokens = markov_resample(&prep.tokens, prep.n_classes, seed)?;
    copy_tied_tokens(&mut tokens, &prep.tie_table);
    Ok(tokens)
}

pub(super) fn prep_tie_to(prep: &StreamPrep) -> Option<&[Option<usize>]> {
    (!prep.tie_table.is_empty()).then_some(prep.tie_table.as_slice())
}

fn copy_tied_tokens(tokens: &mut [u8], tie_table: &[Option<usize>]) {
    for (index, &target) in tie_table.iter().enumerate().take(tokens.len()) {
        let Some(target) = target else {
            continue;
        };
        if let Some(value) = tokens.get(target).copied()
            && let Some(slot) = tokens.get_mut(index)
        {
            *slot = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_tied_tokens, prep_tie_to};
    use crate::attack::pairclass::campaign::StreamPrep;

    #[test]
    fn copy_tied_tokens_matches_representative_classes() {
        let mut tokens = vec![0, 1, 2, 3, 0];
        let tie_table = vec![None, None, Some(0), Some(1), Some(3)];
        copy_tied_tokens(&mut tokens, &tie_table);
        assert_eq!(tokens, vec![0, 1, 0, 1, 1]);
    }

    #[test]
    fn prep_tie_to_returns_only_non_empty_tables() {
        let empty = StreamPrep {
            tokens: vec![0],
            n_classes: 1,
            tie_table: Vec::new(),
            n_tied: 0,
            longest_tie: None,
        };
        assert!(prep_tie_to(&empty).is_none());
        let tied = StreamPrep {
            tie_table: vec![None],
            ..empty
        };
        assert!(prep_tie_to(&tied).is_some());
    }
}
