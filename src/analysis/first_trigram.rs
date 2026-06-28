//! First-trigram "message start" analysis.
//!
//! The wiki's Message-Starts page asks an open question: the first trigram of
//! every eye message is different, and there are "interesting observations about
//! the base 5 values of these first trigrams" the community has not pinned down.
//! This module tabulates the nine first trigrams in two *distinct*
//! representations and tests the named hypotheses, every number computed from
//! [`crate::data::corpus`] rather than hand-copied.
//!
//! Two representations, never conflated:
//! 1. **Storage-order base-5 digit form** — the first trigram of
//!    [`crate::data::corpus::Message::trigrams`], grouped from the raw stored digits;
//!    its value is `first*25 + second*5 + third`, range `0..=124`.
//! 2. **Honeycomb reading-layer value** — the first trigram of the accepted
//!    reading order ([`crate::analysis::orders::accepted_honeycomb_order`]), range
//!    `0..=82`.
//!
//! They differ because the honeycomb walk groups a different triple of eyes than
//! consecutive storage digits. The contrast is itself a finding: the
//! reading-layer values are all distinct (matching the wiki), while the raw
//! base-5 storage forms collide. With `n = 9` the honest output is descriptive:
//! report exact per-position digit sets and verdicts, never manufactured
//! significance from nine related messages.

use std::collections::BTreeSet;
use std::fmt;

use crate::analysis::orders::{
    self, GridError, accepted_honeycomb_order, read_corpus_message_values,
};
use crate::data::corpus::{self, CorpusError};
use crate::report::{self, Report};

// Re-exported so the existing `first_trigram::base5_digits` path keeps working
// while the single definition lives in `crate::core::trigram`.
pub use crate::core::trigram::base5_digits;

/// Storage-layer base-5 trigram alphabet size (`0..=124`).
pub const STORAGE_MODULUS: u32 = crate::core::trigram::TRIGRAM_VALUE_COUNT as u32;
/// Reading-layer alphabet size (`0..=82`).
pub const READING_MODULUS: u32 = orders::READING_LAYER_ALPHABET_SIZE as u32;

/// Error returned while tabulating first trigrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstTrigramError {
    /// A corpus message could not be parsed into trigrams.
    Corpus(CorpusError),
    /// The corpus grids could not be read in honeycomb order.
    Grid(GridError),
    /// A message produced no trigrams, so it has no first trigram.
    EmptyMessage {
        /// The message key that was empty.
        message_key: &'static str,
    },
    /// The storage and reading layers disagreed on the message count.
    MessageCountMismatch {
        /// Number of storage-layer messages.
        storage: usize,
        /// Number of reading-layer messages.
        reading: usize,
    },
}

impl fmt::Display for FirstTrigramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(f, "corpus error: {error}"),
            Self::Grid(error) => write!(f, "grid/order error: {error:?}"),
            Self::EmptyMessage { message_key } => {
                write!(f, "message {message_key} has no trigrams")
            }
            Self::MessageCountMismatch { storage, reading } => write!(
                f,
                "layer message-count mismatch: storage={storage}, reading={reading}"
            ),
        }
    }
}

impl std::error::Error for FirstTrigramError {}

impl From<CorpusError> for FirstTrigramError {
    fn from(value: CorpusError) -> Self {
        Self::Corpus(value)
    }
}

impl From<GridError> for FirstTrigramError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

/// One message's first trigram in both representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstTrigram {
    /// Engine/message id `0..=8`.
    pub message_id: u8,
    /// ngraham20 transcription key, such as `east1`.
    pub message_key: &'static str,
    /// Storage-order base-5 digits `[leading, middle, units]`, each `0..=4`.
    pub storage_digits: [u8; 3],
    /// Storage-order base-5 value, `0..=124`.
    pub storage_value: u8,
    /// Honeycomb reading-layer base-5 digits `[leading, middle, units]`.
    pub reading_digits: [u8; 3],
    /// Honeycomb reading-layer value, `0..=82`.
    pub reading_value: u8,
}

/// The set of base-5 digits seen at each trigram position across the nine messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DigitPositionSets {
    /// Distinct leading (`*25`) digits.
    pub leading: BTreeSet<u8>,
    /// Distinct middle (`*5`) digits.
    pub middle: BTreeSet<u8>,
    /// Distinct units (`*1`) digits.
    pub units: BTreeSet<u8>,
}

impl DigitPositionSets {
    /// Tallies the per-position digit sets from a slice of base-5 digit triples.
    #[must_use]
    pub fn from_digits(digits: &[[u8; 3]]) -> Self {
        Self {
            leading: digits.iter().map(|&[a, _, _]| a).collect(),
            middle: digits.iter().map(|&[_, b, _]| b).collect(),
            units: digits.iter().map(|&[_, _, c]| c).collect(),
        }
    }

    /// Returns the single units digit if every message shares it.
    #[must_use]
    pub fn constant_units(&self) -> Option<u8> {
        if self.units.len() == 1 {
            self.units.iter().next().copied()
        } else {
            None
        }
    }
}

/// Verdict on the "numerical index" hypothesis for one representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexVerdict {
    /// Whether all nine values are distinct.
    pub all_distinct: bool,
    /// Smallest observed value.
    pub min: u8,
    /// Largest observed value.
    pub max: u8,
    /// Whether the nine values are exactly the set `0..=8`.
    pub is_permutation_of_0_8: bool,
    /// Whether the nine values are exactly the set `1..=9`.
    pub is_permutation_of_1_9: bool,
}

impl IndexVerdict {
    /// Evaluates the index hypothesis over the nine values.
    #[must_use]
    pub fn evaluate(values: &[u8]) -> Self {
        let set: BTreeSet<u8> = values.iter().copied().collect();
        let min = values.iter().copied().min().unwrap_or(0);
        let max = values.iter().copied().max().unwrap_or(0);
        let range_0_8: BTreeSet<u8> = (0..=8).collect();
        let range_1_9: BTreeSet<u8> = (1..=9).collect();
        Self {
            all_distinct: set.len() == values.len(),
            min,
            max,
            is_permutation_of_0_8: set == range_0_8,
            is_permutation_of_1_9: set == range_1_9,
        }
    }

    /// Whether any tested index interpretation holds.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.is_permutation_of_0_8 || self.is_permutation_of_1_9
    }
}

/// One tested relation between a message's first trigram and its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChecksumRelation {
    /// `first == last` (the "last character moved to the front" signature).
    EqualsLast,
    /// `first == sum(body) mod modulus`.
    EqualsBodySumMod,
    /// `first == sum(all) mod modulus`.
    EqualsAllSumMod,
    /// `first == XOR(body)`.
    EqualsBodyXor,
}

impl ChecksumRelation {
    /// All tested relations.
    pub const ALL: [Self; 4] = [
        Self::EqualsLast,
        Self::EqualsBodySumMod,
        Self::EqualsAllSumMod,
        Self::EqualsBodyXor,
    ];
}

/// Verdict on relating the first trigram to the message body: the set of
/// relations that hold for **all nine** messages (empty means none).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChecksumVerdict {
    /// Relations satisfied by every message.
    pub holding: BTreeSet<ChecksumRelation>,
}

impl ChecksumVerdict {
    /// Evaluates the checksum / last-character hypotheses over per-message value
    /// sequences. `modulus` is the layer alphabet size.
    #[must_use]
    pub fn evaluate(message_values: &[Vec<u8>], modulus: u32) -> Self {
        let mut equals_last = true;
        let mut body_sum_mod = true;
        let mut all_sum_mod = true;
        let mut body_xor = true;
        for values in message_values {
            let Some(&first) = values.first() else {
                continue;
            };
            let last = values.last().copied().unwrap_or(first);
            let body_sum: u32 = values.iter().skip(1).map(|&v| u32::from(v)).sum();
            let all_sum: u32 = values.iter().map(|&v| u32::from(v)).sum();
            let xor = values.iter().skip(1).fold(0u8, |acc, &v| acc ^ v);
            let first32 = u32::from(first);
            equals_last &= first == last;
            body_sum_mod &= first32 == body_sum % modulus;
            all_sum_mod &= first32 == all_sum % modulus;
            body_xor &= first == xor;
        }
        let flags = [
            (ChecksumRelation::EqualsLast, equals_last),
            (ChecksumRelation::EqualsBodySumMod, body_sum_mod),
            (ChecksumRelation::EqualsAllSumMod, all_sum_mod),
            (ChecksumRelation::EqualsBodyXor, body_xor),
        ];
        Self {
            holding: flags
                .into_iter()
                .filter_map(|(relation, ok)| ok.then_some(relation))
                .collect(),
        }
    }

    /// Whether the given relation holds for all nine messages.
    #[must_use]
    pub fn holds(&self, relation: ChecksumRelation) -> bool {
        self.holding.contains(&relation)
    }

    /// Whether any tested checksum / last-character relation holds for all nine.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        !self.holding.is_empty()
    }
}

/// The complete first-trigram analysis over the verified corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstTrigramAnalysis {
    /// Per-message first-trigram table in corpus id order.
    pub rows: Vec<FirstTrigram>,
    /// Per-position digit sets for the storage-order first trigrams.
    pub storage_positions: DigitPositionSets,
    /// Per-position digit sets for the reading-layer first trigrams.
    pub reading_positions: DigitPositionSets,
    /// Index-hypothesis verdict for the storage-order values.
    pub storage_index: IndexVerdict,
    /// Index-hypothesis verdict for the reading-layer values.
    pub reading_index: IndexVerdict,
    /// Checksum / last-character verdict for the storage layer.
    pub storage_checksum: ChecksumVerdict,
    /// Checksum / last-character verdict for the reading layer.
    pub reading_checksum: ChecksumVerdict,
    /// Units-digit histogram over *all* storage trigrams (index = digit `0..=4`).
    ///
    /// Context for the first-trigram units observation: corpus-wide the units
    /// digit is not concentrated on 1 (digit 1 is ~24.5%), so a constant
    /// first-trigram units digit is specific to the first trigram, not a
    /// corpus-wide property.
    pub storage_units_histogram: [usize; 5],
}

impl FirstTrigramAnalysis {
    /// Storage-order first-trigram base-5 values in corpus order.
    #[must_use]
    pub fn storage_values(&self) -> Vec<u8> {
        self.rows.iter().map(|row| row.storage_value).collect()
    }

    /// Reading-layer first-trigram values in corpus order.
    #[must_use]
    pub fn reading_values(&self) -> Vec<u8> {
        self.rows.iter().map(|row| row.reading_value).collect()
    }
}

/// Per-message base-5 value sequences for both layers.
struct LayerValues {
    storage: Vec<Vec<u8>>,
    reading: Vec<Vec<u8>>,
}

fn layer_values() -> Result<LayerValues, FirstTrigramError> {
    let mut storage = Vec::new();
    for message in corpus::messages() {
        let values = message
            .trigrams()?
            .iter()
            .map(|trigram| trigram.value().get())
            .collect();
        storage.push(values);
    }

    let grids = orders::corpus_grids()?;
    let reading = read_corpus_message_values(&grids, accepted_honeycomb_order())?
        .into_iter()
        .map(|message| message.iter().map(|value| value.get()).collect())
        .collect::<Vec<Vec<u8>>>();

    if storage.len() != reading.len() {
        return Err(FirstTrigramError::MessageCountMismatch {
            storage: storage.len(),
            reading: reading.len(),
        });
    }
    Ok(LayerValues { storage, reading })
}

fn storage_units_histogram(storage: &[Vec<u8>]) -> [usize; 5] {
    let mut histogram = [0usize; 5];
    for values in storage {
        for &value in values {
            if let Some(slot) = histogram.get_mut((value % 5) as usize) {
                *slot += 1;
            }
        }
    }
    histogram
}

/// Computes the full first-trigram analysis from the verified corpus.
///
/// ```
/// use noita_eye_puzzle::analysis::first_trigram;
///
/// let analysis = first_trigram::analyze().expect("the verified corpus tabulates");
/// assert_eq!(analysis.rows.len(), 9);
/// // The wiki's claim holds in the reading layer but not the raw base-5 form.
/// assert!(analysis.reading_index.all_distinct);
/// assert!(!analysis.storage_index.all_distinct);
/// // Neither layer's values are a 1-9 / 0-8 index.
/// assert!(!analysis.storage_index.is_supported());
/// assert!(!analysis.reading_index.is_supported());
/// ```
///
/// # Errors
/// Returns [`FirstTrigramError`] if the corpus cannot be parsed into trigrams or
/// read in honeycomb order.
pub fn analyze() -> Result<FirstTrigramAnalysis, FirstTrigramError> {
    let layers = layer_values()?;
    let keys: Vec<(u8, &'static str)> = corpus::messages()
        .iter()
        .map(|message| (message.id, message.key))
        .collect();

    let mut rows = Vec::new();
    for (index, &(message_id, message_key)) in keys.iter().enumerate() {
        let storage_value = *layers
            .storage
            .get(index)
            .and_then(|values| values.first())
            .ok_or(FirstTrigramError::EmptyMessage { message_key })?;
        let reading_value = *layers
            .reading
            .get(index)
            .and_then(|values| values.first())
            .ok_or(FirstTrigramError::EmptyMessage { message_key })?;
        rows.push(FirstTrigram {
            message_id,
            message_key,
            storage_digits: base5_digits(storage_value),
            storage_value,
            reading_digits: base5_digits(reading_value),
            reading_value,
        });
    }

    let storage_digits: Vec<[u8; 3]> = rows.iter().map(|row| row.storage_digits).collect();
    let reading_digits: Vec<[u8; 3]> = rows.iter().map(|row| row.reading_digits).collect();
    let storage_values: Vec<u8> = rows.iter().map(|row| row.storage_value).collect();
    let reading_values: Vec<u8> = rows.iter().map(|row| row.reading_value).collect();

    Ok(FirstTrigramAnalysis {
        rows,
        storage_positions: DigitPositionSets::from_digits(&storage_digits),
        reading_positions: DigitPositionSets::from_digits(&reading_digits),
        storage_index: IndexVerdict::evaluate(&storage_values),
        reading_index: IndexVerdict::evaluate(&reading_values),
        storage_checksum: ChecksumVerdict::evaluate(&layers.storage, STORAGE_MODULUS),
        reading_checksum: ChecksumVerdict::evaluate(&layers.reading, READING_MODULUS),
        storage_units_histogram: storage_units_histogram(&layers.storage),
    })
}

fn render_digit_set(set: &BTreeSet<u8>) -> String {
    let items: Vec<String> = set.iter().map(u8::to_string).collect();
    format!("{{{}}}", items.join(","))
}

impl Report for FirstTrigramAnalysis {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "First-trigram (message-start) analysis");
        report::appendln!(
            &mut out,
            "[A] storage-order base-5 (0..=124) ; [B] honeycomb reading-layer (0..=82) ; n=9 (low power)"
        );
        report::appendln!(
            &mut out,
            "{:>6} {:>3}  A-digits A-val  B-digits B-val",
            "key",
            "id"
        );
        for row in &self.rows {
            let [sa, sb, sc] = row.storage_digits;
            let [ra, rb, rc] = row.reading_digits;
            report::appendln!(
                &mut out,
                "{:>6} {:>3}    {sa}{sb}{sc} {:>5}     {ra}{rb}{rc} {:>5}",
                row.message_key,
                row.message_id,
                row.storage_value,
                row.reading_value
            );
        }
        let sp = &self.storage_positions;
        let rp = &self.reading_positions;
        report::appendln!(
            &mut out,
            "[A] digit sets: leading {} middle {} units {}",
            render_digit_set(&sp.leading),
            render_digit_set(&sp.middle),
            render_digit_set(&sp.units)
        );
        report::appendln!(
            &mut out,
            "[B] digit sets: leading {} middle {} units {}",
            render_digit_set(&rp.leading),
            render_digit_set(&rp.middle),
            render_digit_set(&rp.units)
        );
        report::appendln!(
            &mut out,
            "storage units-digit histogram over all trigrams (0..4): {:?}",
            self.storage_units_histogram
        );
        report::appendln!(
            &mut out,
            "index hypothesis: [A] supported={} distinct={} ; [B] supported={} distinct={}",
            self.storage_index.is_supported(),
            self.storage_index.all_distinct,
            self.reading_index.is_supported(),
            self.reading_index.all_distinct
        );
        report::appendln!(
            &mut out,
            "checksum/last-char hypothesis: [A] supported={} ; [B] supported={}",
            self.storage_checksum.is_supported(),
            self.reading_checksum.is_supported()
        );
        out
    }
}
