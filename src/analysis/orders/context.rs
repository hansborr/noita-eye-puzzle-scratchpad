//! Shared corpus-loading context for the structural battery and analyses.
//!
//! The within-message-shuffle nulls and the mapping-independent analyses all
//! open with the same preamble: reconstruct the verified grids, take the
//! accepted honeycomb order, collect the per-message keys, and read each
//! message's reading-layer trigram values. [`CorpusContext::load`] centralizes
//! that preamble so the consumers share one source of truth.

use crate::core::trigram::TrigramValue;

use super::{
    GlyphGrid, GridError, ReadingOrder, accepted_honeycomb_order, corpus_grids,
    read_corpus_message_values,
};

/// The verified corpus read under the accepted honeycomb order.
///
/// The intermediate [`GlyphGrid`] vector is a pure derivation of the corpus and
/// is deliberately not retained: every current consumer needs only the order,
/// the per-message keys, and the per-message values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusContext {
    /// The accepted honeycomb reading order the values were read under.
    pub order: ReadingOrder,
    /// Per-message keys, in corpus (grid) order.
    pub keys: Vec<&'static str>,
    /// Per-message reading-layer trigram values, in corpus (grid) order.
    pub message_values: Vec<Vec<TrigramValue>>,
}

impl CorpusContext {
    /// Loads the verified corpus under the accepted honeycomb reading order.
    ///
    /// # Errors
    /// Returns [`GridError`] if any verified message cannot be reconstructed as
    /// a grid or read under the accepted honeycomb order.
    pub fn load() -> Result<Self, GridError> {
        let grids = corpus_grids()?;
        let order = accepted_honeycomb_order();
        let keys = grids.iter().map(GlyphGrid::message_key).collect();
        let message_values = read_corpus_message_values(&grids, order)?;
        Ok(Self {
            order,
            keys,
            message_values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CorpusContext;
    use crate::analysis::orders::{
        GlyphGrid, accepted_honeycomb_order, corpus_grids, read_corpus_message_values,
    };

    #[test]
    fn load_reproduces_grid_keys_and_message_values() {
        let context = CorpusContext::load().unwrap();

        let grids = corpus_grids().unwrap();
        let order = accepted_honeycomb_order();
        let expected_keys: Vec<&'static str> = grids.iter().map(GlyphGrid::message_key).collect();
        let expected_values = read_corpus_message_values(&grids, order).unwrap();

        assert_eq!(context.order, order);
        assert_eq!(context.keys, expected_keys);
        assert_eq!(context.message_values, expected_values);
    }
}
