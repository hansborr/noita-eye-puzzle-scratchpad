//! Parser for Lymm's labeled known-plaintext/ciphertext corpus files.

use std::collections::BTreeMap;

use super::{LymmDeckError, LymmDeckSpec};

/// One aligned known-plaintext/ciphertext message pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownPlaintextPair {
    /// Arbitrary corpus label shared by the plaintext and ciphertext files.
    pub label: String,
    /// Known plaintext for this independent identity-restarted message.
    pub plaintext: String,
    /// Ciphertext symbols for the plaintext-alphabet characters.
    pub ciphertext: String,
}

/// Parses Lymm's plaintext and ciphertext files into label-aligned message pairs.
///
/// Plaintext lines have shape `"<label>: <PT>"`. Ciphertext files have
/// `"<label>:"` followed by the ciphertext on the next nonblank line. Labels are
/// matched by string, not by numeric contiguity or sort order. Each pair is
/// checked with `count(spec.pt_alphabet chars in plaintext) == ciphertext.len()`.
///
/// # Errors
/// Returns [`LymmDeckError`] if either file is malformed, labels do not match, or
/// a pair has mismatched symbol counts.
pub fn parse_known_plaintext_pairs(
    spec: &LymmDeckSpec,
    plaintexts: &str,
    ciphertexts: &str,
) -> Result<Vec<KnownPlaintextPair>, LymmDeckError> {
    let plaintext_rows = parse_plaintexts(plaintexts)?;
    let ciphertext_rows = parse_ciphertexts(ciphertexts)?;

    for label in ciphertext_rows.keys() {
        if !plaintext_rows
            .iter()
            .any(|(plain_label, _)| plain_label == label)
        {
            return Err(LymmDeckError::UnexpectedCiphertextLabel {
                label: label.clone(),
            });
        }
    }

    let mut pairs = Vec::with_capacity(plaintext_rows.len());
    for (label, plaintext) in plaintext_rows {
        let ciphertext =
            ciphertext_rows
                .get(&label)
                .ok_or_else(|| LymmDeckError::MissingCiphertextLabel {
                    label: label.clone(),
                })?;
        let plaintext_alpha_chars = plaintext
            .chars()
            .filter(|&ch| spec.is_plaintext_char(ch))
            .count();
        let ciphertext_chars = ciphertext.chars().count();
        if plaintext_alpha_chars != ciphertext_chars {
            return Err(LymmDeckError::MessageLengthMismatch {
                label,
                plaintext_alpha_chars,
                ciphertext_chars,
            });
        }
        pairs.push(KnownPlaintextPair {
            label,
            plaintext,
            ciphertext: ciphertext.clone(),
        });
    }
    Ok(pairs)
}

fn parse_plaintexts(text: &str) -> Result<Vec<(String, String)>, LymmDeckError> {
    let mut rows = Vec::new();
    let mut seen = BTreeMap::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line_no = line_index + 1;
        if raw_line.trim().is_empty() {
            continue;
        }
        let (label, plaintext) = raw_line.split_once(':').ok_or(LymmDeckError::CorpusLine {
            line: line_no,
            reason: "missing ':' separator",
        })?;
        let label = label.trim().to_owned();
        if label.is_empty() {
            return Err(LymmDeckError::CorpusLine {
                line: line_no,
                reason: "empty label",
            });
        }
        if seen.insert(label.clone(), line_no).is_some() {
            return Err(LymmDeckError::DuplicateLabel { label });
        }
        rows.push((
            label,
            plaintext.strip_prefix(' ').unwrap_or(plaintext).to_owned(),
        ));
    }
    Ok(rows)
}

fn parse_ciphertexts(text: &str) -> Result<BTreeMap<String, String>, LymmDeckError> {
    let mut rows = BTreeMap::new();
    let mut pending_label: Option<(String, usize)> = None;
    for (line_index, raw_line) in text.lines().enumerate() {
        let line_no = line_index + 1;
        if raw_line.is_empty() {
            continue;
        }
        if let Some((label, _label_line)) = pending_label.take() {
            if rows.insert(label.clone(), raw_line.to_owned()).is_some() {
                return Err(LymmDeckError::DuplicateLabel { label });
            }
            continue;
        }

        let (label, rest) = raw_line.split_once(':').ok_or(LymmDeckError::CorpusLine {
            line: line_no,
            reason: "missing label line",
        })?;
        if !rest.trim().is_empty() {
            return Err(LymmDeckError::CorpusLine {
                line: line_no,
                reason: "ciphertext label line must not contain inline text",
            });
        }
        let label = label.trim().to_owned();
        if label.is_empty() {
            return Err(LymmDeckError::CorpusLine {
                line: line_no,
                reason: "empty label",
            });
        }
        pending_label = Some((label, line_no));
    }
    if let Some((_label, line)) = pending_label {
        return Err(LymmDeckError::CorpusLine {
            line,
            reason: "label has no ciphertext line",
        });
    }
    Ok(rows)
}
