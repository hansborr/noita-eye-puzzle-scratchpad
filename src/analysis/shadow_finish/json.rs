//! Small JSON reader for the `shadowsearch --output` artifact.
//!
//! The crate intentionally avoids a general JSON dependency. This parser accepts
//! the JSON subset emitted by the in-repo writer: objects, arrays, strings,
//! booleans, nulls, and non-exponent numeric literals.

use std::collections::BTreeMap;
use std::fmt;

/// JSON value used by the shadow-finish artifact loader.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum JsonValue {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON number, retained as source text.
    Number(String),
    /// JSON string.
    String(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// JSON object.
    Object(BTreeMap<String, JsonValue>),
}

/// Error returned by the artifact JSON parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct JsonError {
    pub(super) message: String,
}

impl JsonError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JsonError {}

/// Parses a JSON document into a [`JsonValue`].
pub(super) fn parse_json(text: &str) -> Result<JsonValue, JsonError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(JsonError::new("trailing bytes after JSON document"));
    }
    Ok(value)
}

pub(super) fn object(value: &JsonValue) -> Result<&BTreeMap<String, JsonValue>, JsonError> {
    match value {
        JsonValue::Object(object) => Ok(object),
        _ => Err(JsonError::new("expected JSON object")),
    }
}

pub(super) fn array(value: &JsonValue) -> Result<&[JsonValue], JsonError> {
    match value {
        JsonValue::Array(array) => Ok(array),
        _ => Err(JsonError::new("expected JSON array")),
    }
}

pub(super) fn string(value: &JsonValue) -> Result<&str, JsonError> {
    match value {
        JsonValue::String(string) => Ok(string),
        _ => Err(JsonError::new("expected JSON string")),
    }
}

pub(super) fn usize_value(value: &JsonValue) -> Result<usize, JsonError> {
    match value {
        JsonValue::Number(raw) => raw
            .parse::<usize>()
            .map_err(|_error| JsonError::new(format!("expected usize number, got {raw:?}"))),
        _ => Err(JsonError::new("expected JSON number")),
    }
}

pub(super) fn u64_value(value: &JsonValue) -> Result<u64, JsonError> {
    match value {
        JsonValue::Number(raw) => raw
            .parse::<u64>()
            .map_err(|_error| JsonError::new(format!("expected u64 number, got {raw:?}"))),
        _ => Err(JsonError::new("expected JSON number")),
    }
}

pub(super) fn member<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<&'a JsonValue, JsonError> {
    object
        .get(key)
        .ok_or_else(|| JsonError::new(format!("missing JSON member {key:?}")))
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            Some(byte) => Err(JsonError::new(format!(
                "unexpected byte {:?} while parsing JSON value",
                byte as char
            ))),
            None => Err(JsonError::new("unexpected end of JSON document")),
        }
    }

    fn parse_literal(&mut self, expected: &[u8], value: JsonValue) -> Result<JsonValue, JsonError> {
        if self.bytes.get(self.pos..self.pos + expected.len()) == Some(expected) {
            self.pos += expected.len();
            Ok(value)
        } else {
            Err(JsonError::new("invalid JSON literal"))
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                0x00..=0x1f => return Err(JsonError::new("unescaped control byte in string")),
                other => out.push(other as char),
            }
        }
        Err(JsonError::new("unterminated JSON string"))
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        match self.next() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{0008}'),
            Some(b'f') => Ok('\u{000c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.parse_unicode_escape(),
            Some(other) => Err(JsonError::new(format!(
                "unsupported JSON escape {:?}",
                other as char
            ))),
            None => Err(JsonError::new("unterminated JSON escape")),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.next() else {
                return Err(JsonError::new("short unicode escape"));
            };
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return Err(JsonError::new("invalid unicode escape digit")),
            };
            value = value * 16 + digit;
        }
        char::from_u32(value).ok_or_else(|| JsonError::new("invalid unicode scalar"))
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        loop {
            self.skip_ws();
            if self.try_consume(b']') {
                break;
            }
            values.push(self.parse_value()?);
            self.skip_ws();
            if self.try_consume(b',') {
                continue;
            }
            self.expect(b']')?;
            break;
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.try_consume(b'}') {
                break;
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            let _previous = values.insert(key, value);
            self.skip_ws();
            if self.try_consume(b',') {
                continue;
            }
            self.expect(b'}')?;
            break;
        }
        Ok(JsonValue::Object(values))
    }

    fn parse_number(&mut self) -> Result<String, JsonError> {
        let start = self.pos;
        let _negative = self.try_consume(b'-');
        self.consume_digits();
        if self.try_consume(b'.') {
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let _e = self.next();
            let _sign = self.try_consume(b'+') || self.try_consume(b'-');
            self.consume_digits();
        }
        let raw_bytes = self
            .bytes
            .get(start..self.pos)
            .ok_or_else(|| JsonError::new("number slice outside JSON input"))?;
        let raw = std::str::from_utf8(raw_bytes)
            .map_err(|_error| JsonError::new("number was not UTF-8"))?;
        if raw.is_empty() || raw == "-" {
            return Err(JsonError::new("invalid JSON number"));
        }
        Ok(raw.to_owned())
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsonError> {
        if self.try_consume(expected) {
            Ok(())
        } else {
            Err(JsonError::new(format!(
                "expected JSON byte {:?}",
                expected as char
            )))
        }
    }

    fn try_consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }
}
