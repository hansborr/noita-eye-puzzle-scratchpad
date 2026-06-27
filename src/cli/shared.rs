//! Helpers shared across more than one command handler: input resolution,
//! cipher-sequence parsing, the `--seed` parser (referenced by the clap
//! `value_parser` attribute), and rendered-text truncation.

use std::io::{self, Read};

use noita_eye_puzzle::core::{glyph::Alphabet, ingest};

#[derive(Debug)]
pub(crate) enum CliSequenceError {
    InvalidAlphabet(char),
    Ingest(ingest::IngestError),
}

impl std::fmt::Display for CliSequenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAlphabet(ch) => {
                write!(
                    f,
                    "invalid --alphabet: repeated or unrepresentable character {ch:?}"
                )
            }
            Self::Ingest(error) => write!(f, "{error}"),
        }
    }
}

pub(crate) fn resolve_input_text(
    sequence: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
) -> Result<String, io::Error> {
    match (sequence, input_file, stdin) {
        (Some(text), _, _) => Ok(text.to_owned()),
        (None, Some(path), _) => std::fs::read_to_string(path),
        (None, None, true | false) => {
            let mut text = String::new();
            let _bytes_read = io::stdin().read_to_string(&mut text)?;
            Ok(text)
        }
    }
}

pub(crate) fn parse_cli_sequence(
    text: &str,
    alphabet_spec: Option<&str>,
    honeycomb: bool,
) -> Result<ingest::ParsedSequence, CliSequenceError> {
    let transparent = ingest::TransparentSet::default();
    let alphabet;
    let layer = match alphabet_spec {
        Some(spec) => match Alphabet::from_chars(spec) {
            Ok(built) => {
                alphabet = built;
                ingest::SequenceLayer::CipherAlphabet {
                    alphabet: &alphabet,
                    transparent: &transparent,
                }
            }
            Err(c) => {
                return Err(CliSequenceError::InvalidAlphabet(c));
            }
        },
        None if honeycomb => ingest::SequenceLayer::HoneycombReading,
        None => ingest::SequenceLayer::RenderedOrientation,
    };
    ingest::parse_sequence(text, layer).map_err(CliSequenceError::Ingest)
}

/// Parses a `--seed` value as either decimal or a `0x`/`0X`-prefixed hexadecimal
/// integer. The solve record's Provenance section prints the seed as
/// `--seed 0x{:016x}`, so accepting that hex form here keeps the emitted command
/// copy-pasteable (the D2 reproducibility guarantee).
pub(crate) fn parse_seed(raw: &str) -> Result<u64, std::num::ParseIntError> {
    match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    }
}

pub(crate) fn display_prefix(text: &str, max_chars: usize) -> String {
    let mut rendered = text.chars().take(max_chars).collect::<String>();
    if text.chars().count() > max_chars {
        rendered.push_str("...");
    }
    rendered
}
