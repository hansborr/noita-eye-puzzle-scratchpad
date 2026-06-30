//! Stored `u32` target cataloging for `crcscan`.

use std::collections::{BTreeMap, BTreeSet};

use crate::data::generator::ENGINE_MESSAGES;

/// Which half of a stored pair supplied a target value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoredHalf {
    /// The low `u32` half of the engine `[u32, u32]` pair.
    Low,
    /// The high `u32` half of the engine `[u32, u32]` pair.
    High,
    /// A standalone `u32` supplied by a file-driven target input.
    Value,
}

impl StoredHalf {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::Value => "value",
        }
    }
}

impl std::fmt::Display for StoredHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Location of a stored `u32` value in the target input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoredLocation {
    /// Zero-based message index.
    pub message_index: usize,
    /// Zero-based pair/value position within the message.
    pub position: usize,
    /// Pair half, or standalone value marker.
    pub half: StoredHalf,
}

/// One raw stored `u32` observation before duplicate and zero filtering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredObservation {
    /// Raw stored value.
    pub value: u32,
    /// Location where this value was found.
    pub location: StoredLocation,
}

/// Catalog of nonzero stored targets, preserving all locations for reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCatalog {
    observations: Vec<StoredObservation>,
    locations_by_value: BTreeMap<u32, Vec<StoredLocation>>,
    pair_count: usize,
}

impl TargetCatalog {
    /// Builds the default catalog from the verified engine-message pairs.
    #[must_use]
    pub fn from_engine_messages() -> Self {
        let mut observations = Vec::new();
        let mut pair_count = 0usize;
        for (message_index, pairs) in ENGINE_MESSAGES.iter().enumerate() {
            for (position, &(low, high)) in pairs.iter().enumerate() {
                pair_count += 1;
                observations.push(StoredObservation {
                    value: low,
                    location: StoredLocation {
                        message_index,
                        position,
                        half: StoredHalf::Low,
                    },
                });
                observations.push(StoredObservation {
                    value: high,
                    location: StoredLocation {
                        message_index,
                        position,
                        half: StoredHalf::High,
                    },
                });
            }
        }
        Self::from_observations(observations, pair_count)
    }

    /// Builds a catalog from raw observations and a caller-supplied pair count.
    #[must_use]
    pub fn from_observations(observations: Vec<StoredObservation>, pair_count: usize) -> Self {
        let mut locations_by_value: BTreeMap<u32, Vec<StoredLocation>> = BTreeMap::new();
        for observation in &observations {
            if observation.value != 0 {
                locations_by_value
                    .entry(observation.value)
                    .or_default()
                    .push(observation.location);
            }
        }
        Self {
            observations,
            locations_by_value,
            pair_count,
        }
    }

    /// All raw stored observations, including zero padding and duplicates.
    #[must_use]
    pub fn observations(&self) -> &[StoredObservation] {
        &self.observations
    }

    /// Number of engine pairs represented by this catalog.
    #[must_use]
    pub const fn pair_count(&self) -> usize {
        self.pair_count
    }

    /// Number of raw stored `u32` observations, including zeros and duplicates.
    #[must_use]
    pub fn stored_u32_count(&self) -> usize {
        self.observations.len()
    }

    /// Number of unique nonzero target values used for significance.
    #[must_use]
    pub fn unique_nonzero_u32_count(&self) -> usize {
        self.locations_by_value.len()
    }

    /// Returns `true` when `value` is one of the unique nonzero stored targets.
    #[must_use]
    pub fn contains(&self, value: u32) -> bool {
        self.locations_by_value.contains_key(&value)
    }

    /// All stored locations for a target value.
    #[must_use]
    pub fn locations_for(&self, value: u32) -> Option<&[StoredLocation]> {
        self.locations_by_value.get(&value).map(Vec::as_slice)
    }

    /// Unique nonzero raw targets.
    #[must_use]
    pub fn unique_targets(&self) -> BTreeSet<u32> {
        self.locations_by_value.keys().copied().collect()
    }
}

/// Error returned when parsing file-driven stored-target input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetParseError {
    /// A bracketed pair did not contain exactly two `u32` tokens.
    InvalidPairArity {
        /// One-based line number.
        line: usize,
        /// Number of parsed values in the bracket.
        found: usize,
    },
    /// A `[` pair opener was not closed on the same line.
    UnclosedPair {
        /// One-based line number.
        line: usize,
    },
    /// A token that looked numeric could not be parsed as a `u32`.
    InvalidNumber {
        /// One-based line number.
        line: usize,
        /// Offending token.
        token: String,
    },
    /// No stored values were found.
    Empty,
}

impl std::fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPairArity { line, found } => write!(
                f,
                "line {line}: bracketed pairs must contain exactly two u32 values, found {found}"
            ),
            Self::UnclosedPair { line } => {
                write!(f, "line {line}: bracketed pair is missing a closing ]")
            }
            Self::InvalidNumber { line, token } => {
                write!(f, "line {line}: invalid u32 token {token:?}")
            }
            Self::Empty => f.write_str("no stored u32 targets found"),
        }
    }
}

impl std::error::Error for TargetParseError {}

/// Parses file-driven targets from hex `u32` values and `[low, high]` pairs.
///
/// Blank lines split message indices. Bracketed pairs contribute low/high
/// locations at one shared pair position; standalone values get `value`
/// locations at their own positions. Zero values are retained in observations
/// but excluded from the tested target set.
///
/// # Errors
/// Returns [`TargetParseError`] when pair syntax is malformed or no target
/// values are found.
pub fn parse_target_text(text: &str) -> Result<TargetCatalog, TargetParseError> {
    let mut builder = TargetBuilder::default();
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.trim().is_empty() {
            builder.finish_message();
        } else {
            parse_line(line, line_number, &mut builder)?;
        }
    }
    if builder.observations.is_empty() {
        return Err(TargetParseError::Empty);
    }
    Ok(builder.finish())
}

#[derive(Default)]
struct TargetBuilder {
    observations: Vec<StoredObservation>,
    message_index: usize,
    position: usize,
    pair_count: usize,
}

impl TargetBuilder {
    fn finish_message(&mut self) {
        if self.position > 0 {
            self.message_index += 1;
            self.position = 0;
        }
    }

    fn add_pair(&mut self, low: u32, high: u32) {
        self.pair_count += 1;
        self.observations.push(StoredObservation {
            value: low,
            location: StoredLocation {
                message_index: self.message_index,
                position: self.position,
                half: StoredHalf::Low,
            },
        });
        self.observations.push(StoredObservation {
            value: high,
            location: StoredLocation {
                message_index: self.message_index,
                position: self.position,
                half: StoredHalf::High,
            },
        });
        self.position += 1;
    }

    fn add_value(&mut self, value: u32) {
        self.observations.push(StoredObservation {
            value,
            location: StoredLocation {
                message_index: self.message_index,
                position: self.position,
                half: StoredHalf::Value,
            },
        });
        self.position += 1;
    }

    fn finish(self) -> TargetCatalog {
        TargetCatalog::from_observations(self.observations, self.pair_count)
    }
}

fn parse_line(
    line: &str,
    line_number: usize,
    builder: &mut TargetBuilder,
) -> Result<(), TargetParseError> {
    let mut outside = String::new();
    let mut pair = String::new();
    let mut in_pair = false;
    for ch in line.chars() {
        match (in_pair, ch) {
            (false, '[') => {
                add_standalone_values(&outside, line_number, builder)?;
                outside.clear();
                pair.clear();
                in_pair = true;
            }
            (true, ']') => {
                add_pair_values(&pair, line_number, builder)?;
                pair.clear();
                in_pair = false;
            }
            (true, _) => pair.push(ch),
            (false, _) => outside.push(ch),
        }
    }
    if in_pair {
        return Err(TargetParseError::UnclosedPair { line: line_number });
    }
    add_standalone_values(&outside, line_number, builder)
}

fn add_pair_values(
    text: &str,
    line_number: usize,
    builder: &mut TargetBuilder,
) -> Result<(), TargetParseError> {
    let values = parse_u32_tokens(text, line_number)?;
    match values.as_slice() {
        [low, high] => {
            builder.add_pair(*low, *high);
            Ok(())
        }
        _ => Err(TargetParseError::InvalidPairArity {
            line: line_number,
            found: values.len(),
        }),
    }
}

fn add_standalone_values(
    text: &str,
    line_number: usize,
    builder: &mut TargetBuilder,
) -> Result<(), TargetParseError> {
    for value in parse_u32_tokens(text, line_number)? {
        builder.add_value(value);
    }
    Ok(())
}

fn parse_u32_tokens(text: &str, line_number: usize) -> Result<Vec<u32>, TargetParseError> {
    let mut values = Vec::new();
    let mut token = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch);
        } else {
            maybe_push_token(&token, line_number, &mut values)?;
            token.clear();
        }
    }
    maybe_push_token(&token, line_number, &mut values)?;
    Ok(values)
}

fn maybe_push_token(
    token: &str,
    line_number: usize,
    values: &mut Vec<u32>,
) -> Result<(), TargetParseError> {
    if token.is_empty() {
        return Ok(());
    }
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        let value = parse_hex_token(hex, line_number, token)?;
        values.push(value);
        return Ok(());
    }
    if token.chars().all(|ch| ch.is_ascii_hexdigit()) {
        let value = parse_hex_token(token, line_number, token)?;
        values.push(value);
    }
    Ok(())
}

fn parse_hex_token(hex: &str, line_number: usize, token: &str) -> Result<u32, TargetParseError> {
    if hex.is_empty() || hex.len() > 8 {
        return Err(TargetParseError::InvalidNumber {
            line: line_number,
            token: token.to_owned(),
        });
    }
    u32::from_str_radix(hex, 16).map_err(|_error| TargetParseError::InvalidNumber {
        line: line_number,
        token: token.to_owned(),
    })
}
