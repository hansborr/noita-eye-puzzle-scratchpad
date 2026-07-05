//! Loader and verifier for `shadowsearch --output` artifacts.

use std::collections::BTreeMap;

use crate::analysis::shadow_search::{Anchor, KeyChoice, RepresentativeKey};
use crate::ciphers::{CipherError, validate_permutation};

use super::json::{
    JsonError, JsonValue, array, member, object, parse_json, string, u64_value, usize_value,
};
use super::{ShadowFinishError, ShadowFinishTable};

/// File-driven input produced by `shadowsearch --output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowFinishArtifact {
    /// Raw ciphertext length reported by `shadowsearch`.
    pub input_len: usize,
    /// Declared ciphertext alphabet size.
    pub alphabet_size: usize,
    /// Legal readout symbols, in q-index order.
    pub legal_readouts: Vec<usize>,
    /// Hard q-equality anchors carried from stage (ii).
    pub hard_anchors: Vec<Anchor>,
    /// Canonical residual classes retained by `shadowsearch`.
    pub classes: Vec<FinishClass>,
}

/// One canonical q-pattern class with a representative shadow key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishClass {
    /// Canonical first-occurrence relabel pattern over q-index symbols.
    pub canonical_pattern: Vec<u16>,
    /// Stage-(ii) soft-anchor score.
    pub soft_score: usize,
    /// Deduped survivor sequence count in this canonical class.
    pub sequence_count: usize,
    /// Sum of key multiplicities in this canonical class.
    pub key_multiplicity: u64,
    /// Representative key that induces one sequence in this class.
    pub representative_key: RepresentativeKey,
}

/// A class plus the actual q-index sequence induced by its representative key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedClass {
    /// Artifact class metadata.
    pub class: FinishClass,
    /// q-index sequence replayed from ciphertext and representative key.
    pub actual_q_sequence: Vec<u16>,
    /// Canonical label -> actual q-index mapping for this representative.
    pub canonical_to_actual: Vec<u16>,
}

impl ShadowFinishArtifact {
    /// Parses a `shadowsearch --output` JSON artifact.
    ///
    /// # Errors
    /// Returns [`ShadowFinishError`] if required artifact fields are missing or
    /// malformed.
    pub fn parse(text: &str) -> Result<Self, ShadowFinishError> {
        parse_artifact(text)
    }

    /// Replays every representative key against `ciphertext`.
    ///
    /// # Errors
    /// Returns [`ShadowFinishError`] if a key is malformed, illegal on the
    /// ciphertext, or does not induce the class's canonical pattern.
    pub fn prepare_classes(
        &self,
        ciphertext: &[u16],
    ) -> Result<Vec<PreparedClass>, ShadowFinishError> {
        if ciphertext.len() != self.input_len {
            return Err(ShadowFinishError::Artifact(format!(
                "artifact input_len {} does not match ciphertext length {}",
                self.input_len,
                ciphertext.len()
            )));
        }
        self.classes
            .iter()
            .map(|class| {
                let q_sequence = replay_q_sequence(
                    ciphertext,
                    self.alphabet_size,
                    &self.legal_readouts,
                    &class.representative_key,
                )?;
                let canonical_to_actual =
                    canonical_actual_map(&class.canonical_pattern, &q_sequence)?;
                Ok(PreparedClass {
                    class: class.clone(),
                    actual_q_sequence: q_sequence,
                    canonical_to_actual,
                })
            })
            .collect()
    }
}

impl PreparedClass {
    /// Converts a canonical q-pattern into this representative's actual q-index
    /// sequence.
    ///
    /// # Errors
    /// Returns [`ShadowFinishError`] if the canonical pattern mentions a label
    /// outside the representative mapping.
    pub fn actual_from_canonical(&self, canonical: &[u16]) -> Result<Vec<u16>, ShadowFinishError> {
        canonical
            .iter()
            .map(|&label| {
                self.canonical_to_actual
                    .get(usize::from(label))
                    .copied()
                    .ok_or_else(|| {
                        ShadowFinishError::Artifact(format!(
                            "canonical label {label} is outside representative mapping"
                        ))
                    })
            })
            .collect()
    }
}

/// Runs the representative key forward from a q-index sequence to ciphertext.
///
/// # Errors
/// Returns [`ShadowFinishError`] if the key or q sequence is malformed.
pub fn encode_with_key(
    q_sequence: &[u16],
    alphabet_size: usize,
    legal_readouts: &[usize],
    key: &RepresentativeKey,
) -> Result<Vec<u16>, ShadowFinishError> {
    validate_key(alphabet_size, legal_readouts, key)?;
    let choices = choices_by_readout(legal_readouts, key)?;
    let mut state = key.initial_state.clone();
    let mut ciphertext = Vec::with_capacity(q_sequence.len());
    for &q_index_raw in q_sequence {
        let q_index = usize::from(q_index_raw);
        let readout = *legal_readouts.get(q_index).ok_or_else(|| {
            ShadowFinishError::RoundTrip(format!("q-index {q_index} outside legal readouts"))
        })?;
        let symbol = *state.get(readout).ok_or_else(|| {
            ShadowFinishError::RoundTrip(format!("readout {readout} outside state permutation"))
        })?;
        ciphertext.push(u16::try_from(symbol).map_err(|_error| {
            ShadowFinishError::RoundTrip(format!("symbol {symbol} does not fit in u16"))
        })?);
        let gamma = choices.get(&readout).ok_or_else(|| {
            ShadowFinishError::RoundTrip(format!("representative key has no choice for {readout}"))
        })?;
        state = compose_stage(gamma, &state)?;
    }
    Ok(ciphertext)
}

/// Reconstructs a canonical q pattern by re-encoding `plaintext` through a table.
///
/// # Errors
/// Returns [`ShadowFinishError`] if a plaintext byte is absent from the table or
/// if a value/digit cannot be mapped back to a canonical label.
pub fn canonical_from_plaintext(
    plaintext: &[u8],
    table: &ShadowFinishTable,
    order: super::DigitOrder,
    permutation: [u8; 8],
) -> Result<Vec<u16>, ShadowFinishError> {
    let mut digit_to_label = [None; 8];
    for (label, &digit) in permutation.iter().enumerate() {
        let slot = digit_to_label.get_mut(usize::from(digit)).ok_or_else(|| {
            ShadowFinishError::RoundTrip(format!("digit {digit} outside octal range"))
        })?;
        *slot = Some(u16::try_from(label).map_err(|_error| {
            ShadowFinishError::RoundTrip("canonical label does not fit in u16".to_owned())
        })?);
    }
    let mut out = Vec::with_capacity(plaintext.len().saturating_mul(2));
    for &byte in plaintext {
        let value = table.encode(byte).ok_or_else(|| {
            ShadowFinishError::RoundTrip(format!(
                "byte 0x{byte:02x} is not encodable by table {}",
                table.name
            ))
        })?;
        let first = value / 8;
        let second = value % 8;
        let (left, right) = match order {
            super::DigitOrder::HighLow => (first, second),
            super::DigitOrder::LowHigh => (second, first),
        };
        out.push(
            digit_to_label
                .get(usize::from(left))
                .copied()
                .flatten()
                .ok_or_else(|| {
                    ShadowFinishError::RoundTrip(format!("digit {left} has no canonical label"))
                })?,
        );
        out.push(
            digit_to_label
                .get(usize::from(right))
                .copied()
                .flatten()
                .ok_or_else(|| {
                    ShadowFinishError::RoundTrip(format!("digit {right} has no canonical label"))
                })?,
        );
    }
    Ok(out)
}

fn parse_artifact(text: &str) -> Result<ShadowFinishArtifact, ShadowFinishError> {
    let root = parse_json(text).map_err(json_error)?;
    let root = object(&root).map_err(json_error)?;
    if let Ok(tool) = member(root, "tool").and_then(string)
        && tool != "shadowsearch"
    {
        return Err(ShadowFinishError::Artifact(format!(
            "expected shadowsearch artifact, got {tool:?}"
        )));
    }
    let input_len = get_usize(root, "input_len")?;
    let alphabet_size = get_usize(root, "alphabet_size")?;
    let basis = object(member(root, "basis").map_err(json_error)?).map_err(json_error)?;
    let legal_readouts = get_usize_array(basis, "legal_readouts")?;
    let hard_anchors = parse_anchors(member(root, "hard_anchors").map_err(json_error)?)?;
    let outcome = object(member(root, "outcome").map_err(json_error)?).map_err(json_error)?;
    let classes = parse_classes(member(outcome, "top_canonical_classes").map_err(json_error)?)?;
    if classes.is_empty() {
        return Err(ShadowFinishError::Artifact(
            "artifact has no top canonical classes".to_owned(),
        ));
    }
    Ok(ShadowFinishArtifact {
        input_len,
        alphabet_size,
        legal_readouts,
        hard_anchors,
        classes,
    })
}

fn parse_classes(value: &JsonValue) -> Result<Vec<FinishClass>, ShadowFinishError> {
    array(value)
        .map_err(json_error)?
        .iter()
        .map(|row| {
            let row = object(row).map_err(json_error)?;
            let key = parse_key(member(row, "representative_key").map_err(json_error)?)?;
            Ok(FinishClass {
                canonical_pattern: get_u16_array(row, "canonical_pattern")?,
                soft_score: get_usize(row, "soft_score")?,
                sequence_count: get_usize(row, "sequence_count")?,
                key_multiplicity: get_u64(row, "key_multiplicity")?,
                representative_key: key,
            })
        })
        .collect()
}

fn parse_key(value: &JsonValue) -> Result<RepresentativeKey, ShadowFinishError> {
    let row = object(value).map_err(json_error)?;
    let choices = array(member(row, "choices").map_err(json_error)?)
        .map_err(json_error)?
        .iter()
        .map(parse_choice)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RepresentativeKey {
        initial_state_index: get_usize(row, "initial_state_index")?,
        initial_state: get_usize_array(row, "initial_state")?,
        choices,
    })
}

fn parse_choice(value: &JsonValue) -> Result<KeyChoice, ShadowFinishError> {
    let row = object(value).map_err(json_error)?;
    Ok(KeyChoice {
        readout: get_usize(row, "readout")?,
        fiber_choice: get_usize(row, "fiber_choice")?,
        element_index: get_usize(row, "element_index")?,
        element: get_usize_array(row, "element")?,
    })
}

fn parse_anchors(value: &JsonValue) -> Result<Vec<Anchor>, ShadowFinishError> {
    array(value)
        .map_err(json_error)?
        .iter()
        .map(|row| {
            let row = object(row).map_err(json_error)?;
            Ok(Anchor {
                first: get_usize(row, "first")?,
                second: get_usize(row, "second")?,
                length: get_usize(row, "length")?,
                raw_first: get_usize(row, "raw_first")?,
                raw_second: get_usize(row, "raw_second")?,
                raw_length: get_usize(row, "raw_length")?,
                trim: get_usize(row, "trim")?,
            })
        })
        .collect()
}

fn replay_q_sequence(
    ciphertext: &[u16],
    alphabet_size: usize,
    legal_readouts: &[usize],
    key: &RepresentativeKey,
) -> Result<Vec<u16>, ShadowFinishError> {
    validate_key(alphabet_size, legal_readouts, key)?;
    let choices = choices_by_readout(legal_readouts, key)?;
    let readout_to_q = legal_readouts
        .iter()
        .enumerate()
        .map(|(index, &readout)| (readout, index))
        .collect::<BTreeMap<_, _>>();
    let mut state = key.initial_state.clone();
    let mut out = Vec::with_capacity(ciphertext.len());
    for &symbol_raw in ciphertext {
        let symbol = usize::from(symbol_raw);
        let inverse = invert_permutation(&state, alphabet_size)?;
        let readout = *inverse.get(symbol).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("ciphertext symbol {symbol} outside state"))
        })?;
        let q_index = *readout_to_q.get(&readout).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("readout {readout} is not legal for artifact"))
        })?;
        out.push(u16::try_from(q_index).map_err(|_error| {
            ShadowFinishError::Artifact(format!("q-index {q_index} does not fit in u16"))
        })?);
        let gamma = choices.get(&readout).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("representative key has no choice for {readout}"))
        })?;
        state = compose_stage(gamma, &state)?;
    }
    Ok(out)
}

fn canonical_actual_map(canonical: &[u16], actual: &[u16]) -> Result<Vec<u16>, ShadowFinishError> {
    if canonical.len() != actual.len() {
        return Err(ShadowFinishError::Artifact(format!(
            "canonical length {} does not match actual q length {}",
            canonical.len(),
            actual.len()
        )));
    }
    let mut map: Vec<Option<u16>> = Vec::new();
    for (&canon, &actual_q) in canonical.iter().zip(actual) {
        let index = usize::from(canon);
        if index >= map.len() {
            map.resize(index + 1, None);
        }
        let slot = map.get_mut(index).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("canonical label {canon} outside map"))
        })?;
        match *slot {
            Some(existing) if existing != actual_q => {
                return Err(ShadowFinishError::Artifact(format!(
                    "canonical label {canon} maps to both {existing} and {actual_q}"
                )));
            }
            Some(_) => {}
            None => *slot = Some(actual_q),
        }
    }
    map.into_iter()
        .enumerate()
        .map(|(label, value)| {
            value.ok_or_else(|| {
                ShadowFinishError::Artifact(format!("canonical label {label} is unused"))
            })
        })
        .collect()
}

fn validate_key(
    alphabet_size: usize,
    legal_readouts: &[usize],
    key: &RepresentativeKey,
) -> Result<(), ShadowFinishError> {
    validate_permutation(
        "shadow-finish initial state",
        &key.initial_state,
        alphabet_size,
    )
    .map_err(cipher_error)?;
    for choice in &key.choices {
        validate_permutation("shadow-finish key choice", &choice.element, alphabet_size)
            .map_err(cipher_error)?;
    }
    for &readout in legal_readouts {
        if readout >= alphabet_size {
            return Err(ShadowFinishError::Artifact(format!(
                "legal readout {readout} outside alphabet size {alphabet_size}"
            )));
        }
    }
    Ok(())
}

fn choices_by_readout(
    legal_readouts: &[usize],
    key: &RepresentativeKey,
) -> Result<BTreeMap<usize, Vec<usize>>, ShadowFinishError> {
    let mut choices = BTreeMap::new();
    for choice in &key.choices {
        let _previous = choices.insert(choice.readout, choice.element.clone());
    }
    for &readout in legal_readouts {
        if !choices.contains_key(&readout) {
            return Err(ShadowFinishError::Artifact(format!(
                "representative key missing choice for readout {readout}"
            )));
        }
    }
    Ok(choices)
}

fn invert_permutation(
    permutation: &[usize],
    alphabet_size: usize,
) -> Result<Vec<usize>, ShadowFinishError> {
    validate_permutation("shadow-finish inverse", permutation, alphabet_size)
        .map_err(cipher_error)?;
    let mut inverse = vec![0usize; alphabet_size];
    for (source, &target) in permutation.iter().enumerate() {
        let slot = inverse.get_mut(target).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("permutation target {target} outside inverse"))
        })?;
        *slot = source;
    }
    Ok(inverse)
}

fn compose_stage(first: &[usize], second: &[usize]) -> Result<Vec<usize>, ShadowFinishError> {
    let mut composed = Vec::with_capacity(first.len());
    for &image in first {
        composed.push(*second.get(image).ok_or_else(|| {
            ShadowFinishError::Artifact(format!("composition index {image} outside permutation"))
        })?);
    }
    Ok(composed)
}

fn get_usize(object: &BTreeMap<String, JsonValue>, key: &str) -> Result<usize, ShadowFinishError> {
    usize_value(member(object, key).map_err(json_error)?).map_err(json_error)
}

fn get_u64(object: &BTreeMap<String, JsonValue>, key: &str) -> Result<u64, ShadowFinishError> {
    u64_value(member(object, key).map_err(json_error)?).map_err(json_error)
}

fn get_usize_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<Vec<usize>, ShadowFinishError> {
    array(member(object, key).map_err(json_error)?)
        .map_err(json_error)?
        .iter()
        .map(|value| usize_value(value).map_err(json_error))
        .collect()
}

fn get_u16_array(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<Vec<u16>, ShadowFinishError> {
    get_usize_array(object, key)?
        .into_iter()
        .map(|value| {
            u16::try_from(value).map_err(|_error| {
                ShadowFinishError::Artifact(format!("{key} value {value} does not fit in u16"))
            })
        })
        .collect()
}

fn json_error(error: JsonError) -> ShadowFinishError {
    let message = error.message;
    ShadowFinishError::Artifact(format!("artifact JSON error: {message}"))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err adapter consumes the concrete cipher error into a stable artifact message"
)]
fn cipher_error(error: CipherError) -> ShadowFinishError {
    ShadowFinishError::Artifact(format!("artifact key error: {error}"))
}
