//! Shareable output helpers for recovered Lymm mappings.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Formats a recovered mapping as a copy-pasteable Python `pt_mapping` dict.
///
/// The literal assumes the surrounding file has already imported `numpy as np`,
/// matching Lymm's vendored `noita_test_cipher.py`.
#[must_use]
pub fn python_pt_mapping_literal(pt_mapping: &BTreeMap<char, Vec<usize>>) -> String {
    let mut out = String::from("pt_mapping = {\n");
    for (&letter, permutation) in pt_mapping {
        writeln!(
            &mut out,
            "    {}: np.array({}, dtype=int),",
            python_string_literal(letter),
            python_usize_list(permutation)
        )
        .expect("write to String");
    }
    out.push_str("}\n");
    out
}

fn python_usize_list(values: &[usize]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn python_string_literal(ch: char) -> String {
    let mut out = String::from("\"");
    match ch {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        other if other.is_control() => push_python_unicode_escape(&mut out, other),
        other => out.push(other),
    }
    out.push('"');
    out
}

fn push_python_unicode_escape(out: &mut String, ch: char) {
    let code = u32::from(ch);
    if code <= 0xffff {
        write!(out, "\\u{code:04x}").expect("write to String");
    } else {
        write!(out, "\\U{code:08x}").expect("write to String");
    }
}
