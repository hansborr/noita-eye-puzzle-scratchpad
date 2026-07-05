//! Charset tables for the residual two-octal-digit finish surface.

use std::collections::BTreeMap;

use super::ShadowFinishError;

/// One decode table from a 6-bit value to a byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowFinishTable {
    /// Stable table name shown in reports and machine-readable output.
    pub name: String,
    bytes: Vec<u8>,
    encode: BTreeMap<u8, u8>,
}

impl ShadowFinishTable {
    /// Builds a table from a byte string. Duplicate bytes are rejected so exact
    /// re-encoding is unambiguous.
    ///
    /// # Errors
    /// Returns [`ShadowFinishError`] if the table is empty, too long for 6-bit
    /// values, or not injective.
    pub fn new(
        name: impl Into<String>,
        chars: impl AsRef<[u8]>,
    ) -> Result<Self, ShadowFinishError> {
        let name = name.into();
        let bytes = chars.as_ref().to_vec();
        if bytes.is_empty() {
            return Err(ShadowFinishError::Table(format!(
                "table {name} has no characters"
            )));
        }
        if bytes.len() > 96 {
            return Err(ShadowFinishError::Table(format!(
                "table {name} has {} characters; cap is 96",
                bytes.len()
            )));
        }
        let mut encode = BTreeMap::new();
        for (value, &byte) in bytes.iter().enumerate() {
            let value_u8 = u8::try_from(value).map_err(|_error| {
                ShadowFinishError::Table(format!("table {name} index {value} exceeds u8"))
            })?;
            if encode.insert(byte, value_u8).is_some() {
                return Err(ShadowFinishError::Table(format!(
                    "table {name} repeats byte 0x{byte:02x}"
                )));
            }
        }
        Ok(Self {
            name,
            bytes,
            encode,
        })
    }

    /// Decodes a value to a byte.
    #[must_use]
    pub fn decode(&self, value: u8) -> Option<u8> {
        self.bytes.get(usize::from(value)).copied()
    }

    /// Encodes a byte back to its table value.
    #[must_use]
    pub fn encode(&self, byte: u8) -> Option<u8> {
        self.encode.get(&byte).copied()
    }

    /// Number of table entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the table contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns a displayable escaped table prefix.
    #[must_use]
    pub fn preview(&self, max: usize) -> String {
        let mut out = String::new();
        for &byte in self.bytes.iter().take(max) {
            out.push_str(&escape_byte(byte));
        }
        out
    }
}

/// Returns the built-in finish tables.
///
/// # Errors
/// Returns [`ShadowFinishError`] only if a built-in table definition is invalid.
pub fn builtin_tables() -> Result<Vec<ShadowFinishTable>, ShadowFinishError> {
    Ok(vec![
        ascii_offset("ascii32", 32, 64)?,
        ascii_offset("ascii64", 64, 64)?,
        ascii_offset("ascii96", 32, 96)?,
        ShadowFinishTable::new(
            "sixbit-lower-space",
            b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.",
        )?,
        ShadowFinishTable::new(
            "sixbit-upper-space",
            b" ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.",
        )?,
        ShadowFinishTable::new(
            "sixbit-base64",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        )?,
        ShadowFinishTable::new(
            "sixbit-base64url",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        )?,
    ])
}

/// Parses additional tables from a simple data file.
///
/// Each nonblank, non-comment line is `name=characters`. The characters are
/// read as bytes; use `\s` for a literal space and standard `\n`, `\r`, `\t`,
/// `\\`, `\xHH` escapes when needed.
///
/// # Errors
/// Returns [`ShadowFinishError`] if a line is malformed or a table is invalid.
pub fn parse_table_file(text: &str) -> Result<Vec<ShadowFinishTable>, ShadowFinishError> {
    let mut tables = Vec::new();
    for (line_index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, chars)) = line.split_once('=') else {
            return Err(ShadowFinishError::Table(format!(
                "table file line {} must be name=characters",
                line_index + 1
            )));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(ShadowFinishError::Table(format!(
                "table file line {} has an empty name",
                line_index + 1
            )));
        }
        tables.push(ShadowFinishTable::new(name, parse_escaped_bytes(chars)?)?);
    }
    Ok(tables)
}

/// Returns true for bytes accepted by the loose printable sanity filter.
#[must_use]
pub const fn loose_printable(byte: u8) -> bool {
    byte == b' ' || (byte >= 0x21 && byte <= 0x7e)
}

/// Returns true for bytes accepted by the strict natural-language value set.
#[must_use]
pub const fn strict_language_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b' '
            | b'.'
            | b','
            | b'\''
            | b'"'
            | b'!'
            | b'?'
            | b'-'
            | b':'
            | b';'
    )
}

fn ascii_offset(name: &str, start: u8, len: usize) -> Result<ShadowFinishTable, ShadowFinishError> {
    let bytes = (0..len)
        .map(|offset| start.saturating_add(u8::try_from(offset).unwrap_or(0)))
        .collect::<Vec<_>>();
    ShadowFinishTable::new(name, bytes)
}

fn parse_escaped_bytes(text: &str) -> Result<Vec<u8>, ShadowFinishError> {
    let mut bytes = Vec::new();
    let mut iter = text.as_bytes().iter().copied().peekable();
    while let Some(byte) = iter.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        match iter.next() {
            Some(b's') => bytes.push(b' '),
            Some(b'n') => bytes.push(b'\n'),
            Some(b'r') => bytes.push(b'\r'),
            Some(b't') => bytes.push(b'\t'),
            Some(b'\\') => bytes.push(b'\\'),
            Some(b'x') => {
                let high = iter.next().ok_or_else(|| {
                    ShadowFinishError::Table("short \\xHH escape in table file".to_owned())
                })?;
                let low = iter.next().ok_or_else(|| {
                    ShadowFinishError::Table("short \\xHH escape in table file".to_owned())
                })?;
                bytes.push(hex_pair(high, low)?);
            }
            Some(other) => {
                return Err(ShadowFinishError::Table(format!(
                    "unsupported table escape \\{}",
                    other as char
                )));
            }
            None => {
                return Err(ShadowFinishError::Table(
                    "trailing backslash in table file".to_owned(),
                ));
            }
        }
    }
    Ok(bytes)
}

fn hex_pair(high: u8, low: u8) -> Result<u8, ShadowFinishError> {
    let high = hex_digit(high)?;
    let low = hex_digit(low)?;
    Ok(high * 16 + low)
}

fn hex_digit(byte: u8) -> Result<u8, ShadowFinishError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ShadowFinishError::Table(format!(
            "invalid hex digit {} in table file",
            byte as char
        ))),
    }
}

fn escape_byte(byte: u8) -> String {
    match byte {
        b'\n' => "\\n".to_owned(),
        b'\r' => "\\r".to_owned(),
        b'\t' => "\\t".to_owned(),
        b'\\' => "\\\\".to_owned(),
        b' ' => " ".to_owned(),
        0x21..=0x7e => (byte as char).to_string(),
        _ => format!("\\x{byte:02x}"),
    }
}
