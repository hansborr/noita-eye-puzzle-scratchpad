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

/// Splits raw stream text into one or more messages on blank-line boundaries.
///
/// A *blank line* is empty or whitespace-only; one or more consecutive blank
/// lines separate messages, and leading/trailing blank lines are ignored. Input
/// with no blank-line separator yields exactly one message (the whole text), so
/// the single-message path is fully backward compatible. Each returned element
/// keeps its message's raw, whitespace-separated symbols verbatim for
/// [`parse_cli_sequence`] to tokenize unchanged (newlines inside a message are
/// just more whitespace). An empty or all-blank input yields no messages.
pub(crate) fn split_blank_line_messages(text: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                messages.push(std::mem::take(&mut current));
            }
        } else {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        messages.push(current);
    }
    messages
}

/// Mints stable per-message display labels for a file-driven multi-message
/// stream. A lone message keeps the friendly `"input"` label (matching the
/// single-stream path); two or more messages get positional `m0`, `m1`, ...
/// labels, so the report's per-message lengths and the cross-message occurrence
/// pairs are distinguishable.
///
/// The structural reports inherit `&'static str` message keys from the finite,
/// statically-named eye corpus, but a file-driven stream has a runtime message
/// count. The positional labels are therefore interned for the remainder of the
/// process via [`Box::leak`]: the leaked set is bounded by one run's message
/// count (the CLI parses one input and exits), and the labels are display-only --
/// the cross-message detectors key on message *position*, never on these strings.
pub(crate) fn stream_message_keys(count: usize) -> Vec<&'static str> {
    match count {
        0 => Vec::new(),
        1 => vec!["input"],
        _ => (0..count)
            .map(|index| -> &'static str { Box::leak(format!("m{index}").into_boxed_str()) })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{split_blank_line_messages, stream_message_keys};

    #[test]
    fn no_blank_line_is_a_single_message() {
        assert_eq!(split_blank_line_messages("a b c"), vec!["a b c".to_owned()]);
    }

    #[test]
    fn one_blank_line_separates_two_messages() {
        assert_eq!(
            split_blank_line_messages("a b\n\nc d"),
            vec!["a b".to_owned(), "c d".to_owned()]
        );
    }

    #[test]
    fn whitespace_only_lines_and_runs_split_and_are_trimmed() {
        // Leading/trailing blanks, whitespace-only separators, and multiple
        // consecutive blank lines all collapse to message boundaries.
        let text = "\n  \na b\nc d\n \n\n\ne f\n  \n";
        assert_eq!(
            split_blank_line_messages(text),
            vec!["a b\nc d".to_owned(), "e f".to_owned()]
        );
    }

    #[test]
    fn empty_and_all_blank_inputs_yield_no_messages() {
        assert!(split_blank_line_messages("").is_empty());
        assert!(split_blank_line_messages("   \n\t\n  ").is_empty());
    }

    #[test]
    fn keys_label_single_vs_multi_message_streams() {
        assert!(stream_message_keys(0).is_empty());
        assert_eq!(stream_message_keys(1), vec!["input"]);
        assert_eq!(stream_message_keys(2), vec!["m0", "m1"]);
        assert_eq!(stream_message_keys(4), vec!["m0", "m1", "m2", "m3"]);
    }
}
