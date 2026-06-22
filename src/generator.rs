//! Engine storage-layer base-7 generator and decoder.
//!
//! Noita stores each eye message as a list of 64-bit integers, vendored here as
//! `[u32, u32]` low/high pairs ([`ENGINE_MESSAGES`]). The engine decodes one
//! integer by dropping its least-significant base-7 digit (always zero in the
//! authored data, a sentinel from multiplying by seven during encoding) and then
//! emitting `digit - 1` for every remaining base-7 digit, most-significant
//! first. Emitted storage symbols lie in `-1..=5`, where `5` is a row delimiter
//! and `-1` is an unused control value that never occurs in the authored corpus.
//!
//! This is the *storage* layer and is kept deliberately separate from the base-5
//! [`crate::trigram`] *reading* layer (see [`crate::glyph::StorageSymbol`] vs
//! [`crate::glyph::Orientation`]). The decoder here is an independent
//! re-implementation of the same algorithm the `corpus` integrity test uses; the
//! two agreeing byte-for-byte on all nine messages is the cross-check.
//!
//! It underpins Experiment 2 (generation-pipeline artifact test): feeding
//! structure-matched random integers through this exact decode lets
//! [`crate::pipeline_null`] ask whether the eyes' reading-layer structure is a
//! by-product of base-7 expansion rather than of the specific authored values.

use crate::glyph::{Orientation, StorageSymbol};

/// Verified engine `[u32, u32]` pairs (low, high) per message, vendored from
/// Xkeeper0's transcoder. Cross-validated against the parsed PHP fixture and the
/// rendered [`crate::corpus`] byte-for-byte in tests.
#[allow(
    clippy::unreadable_literal,
    reason = "vendored engine pairs stay visually comparable to the source fixture"
)]
pub const ENGINE_MESSAGES: [&[(u32, u32)]; 9] = [
    // east1 (id 0): 14 pairs
    &[
        (0x5634505c, 0xacf68674),
        (0x2c9ac076, 0x981e2346),
        (0x2e474a1f, 0x29848a73),
        (0xc220213a, 0x75a31019),
        (0x01fecf4e, 0x2c7aa564),
        (0x2bf7569a, 0xf9b307f9),
        (0x3e145ee9, 0xeb76f050),
        (0xb54a6af2, 0x993474bb),
        (0x5eea05e8, 0x43ea988d),
        (0xadde7d91, 0x4136e1da),
        (0x0101ef86, 0x472533a7),
        (0x3fe75e9e, 0x90a4b336),
        (0xc9b9c908, 0x863f83a7),
        (0x52329ab4, 0x20c91280),
    ],
    // west1 (id 1): 15 pairs
    &[
        (0xb1c95194, 0xeaf95a7c),
        (0x2ca1eeba, 0x981e2346),
        (0x2e474a1f, 0x29848a73),
        (0xac567db9, 0x75a31019),
        (0x56f0b2ae, 0x2c7a8998),
        (0x9dfd44ec, 0xf9b30744),
        (0x7b7555aa, 0x48353272),
        (0xcc6a521c, 0x993f346f),
        (0xe9153d2e, 0x53c3db0d),
        (0x7293312c, 0x628375f9),
        (0xe49c1fef, 0xb40dac02),
        (0xccc378b2, 0x537dbb53),
        (0x4d4eaf5f, 0xf319978d),
        (0x40e1fc47, 0xbca3f152),
        (0xbf905626, 0x00000000),
    ],
    // east2 (id 2): 17 pairs
    &[
        (0x1cf72f99, 0x8634c1ef),
        (0x2ca1f81b, 0x981e2346),
        (0x2e474a1f, 0x29848a73),
        (0xe1637be9, 0x75a31019),
        (0xb914ade3, 0xe2cfe1d3),
        (0xb723d349, 0x786f45ab),
        (0x48c7c97b, 0xbee5b2a5),
        (0xef63311a, 0x2cbc058b),
        (0x655c358a, 0xae1bc859),
        (0x797cd4b3, 0x805b0e68),
        (0x64bf17b9, 0x87eb66f8),
        (0xc737f7dd, 0x40a4cabc),
        (0x4f299b43, 0x8dfe0c08),
        (0xe0b4b2f4, 0x2aabf66d),
        (0xfae456c4, 0x5a0d593c),
        (0x072a8e6a, 0x2b885f6a),
        (0x616cf703, 0x00002d28),
    ],
    // west2 (id 3): 15 pairs
    &[
        (0xba591cfd, 0xe339e9b5),
        (0x9f5fdb97, 0x40aa767c),
        (0x6a205b2d, 0x292a2b08),
        (0xe906ad86, 0x2819fcb0),
        (0x2d7097c7, 0xb3ad535d),
        (0x5f701c14, 0xe25103af),
        (0x3d510e03, 0x7941b070),
        (0x0e4ab73f, 0x7d50d317),
        (0x71e3af41, 0x2a497ecf),
        (0xc25d5cb0, 0x87dfd311),
        (0x00ae0a79, 0xed860703),
        (0x07cb6914, 0x31468f6d),
        (0x856d0002, 0xfac360d1),
        (0x9449c363, 0x47499296),
        (0x4b209af6, 0x00000000),
    ],
    // east3 (id 4): 20 pairs
    &[
        (0x3f7f2d6f, 0xbc7824f9),
        (0xd99610d2, 0xec6ae62e),
        (0x9c10ea2f, 0x2929e6c7),
        (0xaf3a9d6b, 0x3f77f101),
        (0x72274d9d, 0x867e7502),
        (0x89efd32a, 0x888f5ab2),
        (0x80a77a7b, 0xae3ea520),
        (0x1bcfa31f, 0x7d640202),
        (0xc2abe496, 0x40c36cc3),
        (0x8a590904, 0x2584e684),
        (0xeb45f210, 0xe9d5b567),
        (0x1f571e0d, 0x40d17965),
        (0x7628b91f, 0xec75a14d),
        (0x70e3ed4a, 0x7ee7240c),
        (0xd76e5ea0, 0xb536c25e),
        (0xd4da8afe, 0x2a9c303c),
        (0xec314373, 0xedaf6daf),
        (0x96eca434, 0x61f5113b),
        (0x9fb1a087, 0x281000c2),
        (0x08a797d1, 0x00000000),
    ],
    // west3 (id 5): 18 pairs
    &[
        (0x9445728a, 0x7e7550ff),
        (0x0d0f6513, 0xf30328d5),
        (0x9d27ce70, 0x292a0d5c),
        (0x52a05d69, 0xbfca758c),
        (0xe8109a74, 0x251a1f3f),
        (0x5dedc516, 0x24d30587),
        (0x44e5f584, 0xb3d39014),
        (0x5790c997, 0x82380e0a),
        (0xb411f01b, 0xe2449c62),
        (0x7ebe9feb, 0xb5e7969a),
        (0x4471d7ec, 0x4a9c0282),
        (0x866a064b, 0x313a62bf),
        (0xa8f7fe37, 0x29b312b3),
        (0xeccf2773, 0x79186c2a),
        (0x3f22c3ac, 0xb85b08f3),
        (0xf689a796, 0x286b232d),
        (0x0577b0f1, 0x4eeb3967),
        (0x42200715, 0x0000020c),
    ],
    // east4 (id 6): 17 pairs
    &[
        (0xd85141c4, 0x76b4f66f),
        (0x910a0cde, 0x8f93f5f0),
        (0x84925ae2, 0x2929e6c7),
        (0x29a68a25, 0x40933e6d),
        (0xc75f5618, 0xc57372ac),
        (0x794787b0, 0xbb64926d),
        (0xb2dbe0fe, 0xf1fe39ca),
        (0x936186e5, 0x474efd70),
        (0x6cad7fcf, 0xc342342e),
        (0x81bafa5d, 0xe7a638fd),
        (0x40004d4a, 0x29a2c904),
        (0x5cdb6750, 0xb62839cb),
        (0xfd8931dd, 0x8dfa2566),
        (0x030d69c9, 0xee71ed89),
        (0x22f7029a, 0xce69520b),
        (0x4f349ac3, 0x4748bf1d),
        (0x9690947d, 0x00013c03),
    ],
    // west4 (id 7): 17 pairs
    &[
        (0x789603e6, 0xe339e97e),
        (0xb2c91190, 0x8f93f5e9),
        (0x84925ae2, 0x2929e6c7),
        (0x4feb4015, 0x409374a5),
        (0xf7e604ea, 0x94979e7e),
        (0x01bcc357, 0x4a96793f),
        (0x36f40675, 0xc355c0a8),
        (0xb0f85513, 0x2a752013),
        (0x1b30e279, 0xbc7decdd),
        (0x8a93175e, 0xc62c6bc0),
        (0x63dafb6f, 0x9781e76a),
        (0xf3ba1e66, 0xb0a58e3b),
        (0x641fde95, 0x297c940b),
        (0x7874c807, 0x95120e03),
        (0x1017d733, 0xf6a5f2ff),
        (0xdf851acf, 0x9540156f),
        (0x2fdb567c, 0x2167abfb),
    ],
    // east5 (id 8): 17 pairs
    &[
        (0xe3c3e1eb, 0x7e7550f0),
        (0x67eb65a7, 0x8f93f5f3),
        (0x84925ae2, 0x2929e6c7),
        (0x5d0b8d5d, 0x40935218),
        (0xa3e4e814, 0xc671e036),
        (0xdc181d46, 0x5047870a),
        (0x3dbac96b, 0x85653473),
        (0xaa9846f1, 0x24ee71d2),
        (0xc9269dc8, 0x76ba6749),
        (0xa9c340c6, 0x8da82039),
        (0x32d0143b, 0x802c4c1b),
        (0xb02e0347, 0x77df0666),
        (0x5cb83226, 0x8fbb8712),
        (0x99246bfc, 0x569c4f81),
        (0xa564670b, 0xb4e02af6),
        (0xeb81e037, 0x5159ba32),
        (0x0000008c, 0x00000000),
    ],
];

/// Decodes one 64-bit engine integer into storage symbols in `-1..=5`,
/// most-significant first, after dropping the trailing base-7 digit.
///
/// This is the core of the storage decode; [`decode_pair`] reconstructs the
/// 64-bit integer from a `[u32, u32]` low/high pair and delegates here.
#[must_use]
pub fn decode_u64(value: u64) -> Vec<i8> {
    let mut value = value / 7;
    let mut symbols = Vec::new();
    while value > 0 {
        // `value % 7` is in `0..=6`; the match keeps the result in `i8` without
        // any lossy cast and maps the engine's `digit - 1` offset.
        let symbol: i8 = match value % 7 {
            0 => -1,
            1 => 0,
            2 => 1,
            3 => 2,
            4 => 3,
            5 => 4,
            _ => 5,
        };
        symbols.push(symbol);
        value /= 7;
    }
    symbols.reverse();
    symbols
}

/// Decodes one engine `[u32, u32]` pair into storage symbols in `-1..=5`,
/// most-significant first, after dropping the trailing base-7 digit.
///
/// Reproduces the wiki worked example: `decode_pair(0x5634505c, 0xacf68674)`
/// yields the 22-value sequence `[2, 0, 1, 0, 1, 3, 2, 2, 3, 3, 0, 4, 0, 4, 1,
/// 1, 3, 0, 2, 3, 2, 1]`.
#[must_use]
pub fn decode_pair(low: u32, high: u32) -> Vec<i8> {
    decode_u64((u64::from(high) << 32) + u64::from(low))
}

/// Decodes a full message (list of pairs) into storage symbols in reading order.
///
/// The engine processes the pair list in reverse and reverses the whole symbol
/// stream at the end; that is algebraically equivalent to decoding each pair
/// most-significant-first and concatenating them in forward order, which is what
/// this does. The corpus integrity test confirms the equivalence by matching all
/// nine rendered messages byte-for-byte.
#[must_use]
pub fn decode_message(pairs: &[(u32, u32)]) -> Vec<i8> {
    pairs
        .iter()
        .flat_map(|&(low, high)| decode_pair(low, high))
        .collect()
}

/// Returns the number of storage symbols a pair decodes to.
#[must_use]
pub fn pair_output_len(low: u32, high: u32) -> usize {
    decode_pair(low, high).len()
}

/// Per-pair decoded lengths for every verified message, in corpus order.
///
/// These are the base-7 "output lengths" Experiment 2 holds fixed when feeding
/// structure-matched random integers through the same decode.
#[must_use]
pub fn engine_pair_lengths() -> Vec<Vec<usize>> {
    ENGINE_MESSAGES
        .iter()
        .map(|pairs| {
            pairs
                .iter()
                .map(|&(low, high)| pair_output_len(low, high))
                .collect()
        })
        .collect()
}

/// Interprets a decoded storage symbol as a reading orientation, if it is one.
///
/// Returns `None` for the control values `-1` and the row delimiter `5`.
#[must_use]
pub fn storage_orientation(symbol: i8) -> Option<Orientation> {
    match StorageSymbol::from_value(symbol) {
        Ok(StorageSymbol::Orientation(orientation)) => Some(orientation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ENGINE_MESSAGES, decode_message, decode_pair, engine_pair_lengths, storage_orientation,
    };
    use crate::corpus::messages;
    use crate::glyph::Orientation;

    const XK_EYE: &str = include_str!("../research/data/eye-messages/xk_eye.php");

    fn render(symbols: &[i8]) -> String {
        symbols
            .iter()
            .map(|&symbol| {
                assert!(
                    (0..=5).contains(&symbol),
                    "rendered an out-of-range storage symbol {symbol}"
                );
                char::from_digit(u32::from(symbol.unsigned_abs()), 10)
                    .expect("0..=5 is always a valid digit")
            })
            .collect()
    }

    #[test]
    fn reproduces_wiki_worked_example() {
        // int('acf686745634505c', 16) = 12463296853015023708, base-7, drop the
        // trailing 0, subtract 1.
        let decoded = decode_pair(0x5634_505c, 0xacf6_8674);
        assert_eq!(
            decoded,
            vec![
                2, 0, 1, 0, 1, 3, 2, 2, 3, 3, 0, 4, 0, 4, 1, 1, 3, 0, 2, 3, 2, 1
            ]
        );
        assert_eq!(decoded.len(), 22);
    }

    #[test]
    fn decode_matches_rendered_corpus_byte_for_byte() {
        for (message, pairs) in messages().iter().zip(ENGINE_MESSAGES) {
            let decoded = decode_message(pairs);
            assert!(
                decoded.iter().all(|&symbol| symbol >= 0),
                "{} decoded an engine -1 control symbol",
                message.key
            );
            assert_eq!(
                render(&decoded),
                message.digits,
                "engine decode differs from rendered corpus for {}",
                message.key
            );
        }
    }

    #[test]
    fn vendored_pairs_match_parsed_php_fixture() {
        let parsed = parse_xkeeper_pairs(XK_EYE);
        assert_eq!(parsed.len(), ENGINE_MESSAGES.len());
        for (id, pairs) in ENGINE_MESSAGES.iter().enumerate() {
            let key = u8::try_from(id).expect("nine messages fit in u8");
            let expected = parsed
                .get(&key)
                .unwrap_or_else(|| panic!("missing parsed pairs for message {id}"));
            assert_eq!(
                pairs.to_vec(),
                *expected,
                "vendored engine pairs differ from xk_eye.php for message {id}"
            );
        }
    }

    #[test]
    fn structure_totals_match_the_confirmed_anchors() {
        let lengths = engine_pair_lengths();
        let block_counts: Vec<usize> = lengths.iter().map(Vec::len).collect();
        assert_eq!(block_counts, vec![14, 15, 17, 15, 20, 18, 17, 17, 17]);
        assert_eq!(block_counts.iter().sum::<usize>(), 150);

        let total_symbols: usize = lengths.iter().flatten().sum();
        assert_eq!(total_symbols, 3194);
        // Every per-pair length stays at or below 22 base-7 digits, one short of
        // the 23-digit ceiling of a 64-bit integer (7^22 < 2^64 < 7^23). The
        // length-22 blocks therefore carry the real `u64` ceiling into the
        // pipeline null instead of silently pretending all 23-digit base-7
        // inputs are representable.
        assert!(lengths.iter().flatten().all(|&length| length <= 22));
        assert_eq!(
            lengths
                .iter()
                .flatten()
                .filter(|&&length| length == 22)
                .count(),
            112
        );

        let total_delimiters: usize = messages()
            .iter()
            .map(|message| message.raw_len_including_delimiters() - message.eye_count)
            .sum();
        let total_eyes: usize = messages().iter().map(|message| message.eye_count).sum();
        assert_eq!(total_delimiters, 86);
        assert_eq!(total_eyes, 3108);
        assert_eq!(total_symbols, total_eyes + total_delimiters);
    }

    #[test]
    fn storage_orientation_rejects_control_values() {
        assert_eq!(storage_orientation(-1), None);
        assert_eq!(storage_orientation(5), None);
        assert_eq!(storage_orientation(0), Some(Orientation::Zero));
        assert_eq!(storage_orientation(4), Some(Orientation::Four));
        assert_eq!(storage_orientation(9), None);
    }

    fn parse_xkeeper_pairs(input: &str) -> BTreeMap<u8, Vec<(u32, u32)>> {
        let mut messages = BTreeMap::new();
        let mut current_id = None;
        for line in input.lines() {
            let trimmed = line.trim();
            if trimmed == "$num++;" {
                current_id = Some(current_id.map_or(1, |id| id + 1));
                continue;
            }
            if trimmed == "// 0 -----------------------------------------" {
                current_id = Some(0);
                continue;
            }
            if let Some(id) = current_id
                && let Some(pair) = parse_php_pair(trimmed)
            {
                messages.entry(id).or_insert_with(Vec::new).push(pair);
            }
        }
        messages
    }

    fn parse_php_pair(line: &str) -> Option<(u32, u32)> {
        let start = line.find("[ ")? + 2;
        let end = line.find(" ];")?;
        let body = line.get(start..end)?;
        let mut parts = body.split(", ");
        let low = parse_php_int(parts.next()?)?;
        let high = parse_php_int(parts.next()?)?;
        Some((low, high))
    }

    fn parse_php_int(input: &str) -> Option<u32> {
        if let Some(hex) = input.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()
        } else {
            input.parse().ok()
        }
    }
}
