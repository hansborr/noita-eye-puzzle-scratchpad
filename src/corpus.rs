//! Verified eye-message corpus.
//!
//! The nine messages here are the rendered transcription layer: digits `0..=4`
//! are eye orientations and digit `5` is a non-rendered row delimiter. Integrity
//! tests cross-check these strings against the vendored ngraham20 transcription
//! and against Xkeeper0's base-7 engine transcoder data.

use std::fmt;

use crate::glyph::{Orientation, RenderedSymbol, Sequence, SymbolError};
use crate::trigram::ReadingTrigram;

/// Error returned when corpus data fails integrity checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    /// A corpus digit is not part of the rendered eye alphabet.
    MalformedSymbol {
        /// The message key whose data failed to parse.
        message_key: &'static str,
        /// The invalid symbol.
        symbol: SymbolError,
    },
    /// Delimiter-stripped orientations cannot be evenly grouped into trigrams.
    IncompleteTrigram {
        /// The message key whose data failed the trigram grouping check.
        message_key: &'static str,
        /// Number of delimiter-stripped orientations in the message.
        orientations: usize,
    },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSymbol {
                message_key,
                symbol,
            } => write!(
                f,
                "corpus parse error in {message_key}: invalid symbol {symbol:?}"
            ),
            Self::IncompleteTrigram {
                message_key,
                orientations,
            } => write!(
                f,
                "corpus parse error in {message_key}: {orientations} orientations cannot form complete trigrams"
            ),
        }
    }
}

impl std::error::Error for CorpusError {}

/// East or West parallel-world side for an eye message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    /// East parallel-world message.
    East,
    /// West parallel-world message.
    West,
}

impl Region {
    /// Returns the human-readable region name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::East => "East",
            Self::West => "West",
        }
    }
}

/// Provenance metadata for a corpus message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// Machine-readable transcription source.
    pub transcription_source: &'static str,
    /// Engine transcoder source used for cross-validation.
    pub engine_source: &'static str,
    /// Local vendored fixture directory.
    pub vendored_path: &'static str,
}

/// One verified eye message in rendered storage order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// Stable message id, matching the Xkeeper0 engine transcoder ids `0..=8`.
    pub id: u8,
    /// Key used by the ngraham20 transcription.
    pub key: &'static str,
    /// In-game parallel-world side.
    pub region: Region,
    /// One-based in-game message number for this side.
    pub region_index: u8,
    /// Rendered digits in stored row order; `5` is the row delimiter.
    pub digits: &'static str,
    /// Verified count of rendered eyes, excluding row delimiters.
    pub eye_count: usize,
    /// Verified count of base-5 trigrams after delimiter removal.
    pub trigram_count: usize,
    /// Source metadata for this message.
    pub provenance: Provenance,
}

impl Message {
    /// Returns a concise in-game origin label.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("{} {}", self.region.name(), self.region_index)
    }

    /// Parses all rendered symbols, preserving row delimiters.
    ///
    /// # Errors
    /// Returns [`CorpusError`] if a byte is not a corpus digit or is outside
    /// `0..=5`.
    pub fn rendered_symbols(&self) -> Result<Vec<RenderedSymbol>, CorpusError> {
        let mut symbols = Vec::new();
        for byte in self.digits.bytes() {
            let symbol = digit_from_byte(byte).and_then(RenderedSymbol::from_digit);
            symbols.push(symbol.map_err(|symbol| CorpusError::MalformedSymbol {
                message_key: self.key,
                symbol,
            })?);
        }
        Ok(symbols)
    }

    /// Parses orientation digits, dropping row delimiters.
    ///
    /// # Errors
    /// Returns [`CorpusError`] if any non-delimiter digit is outside `0..=4` or
    /// if a byte is not a corpus digit.
    pub fn orientations(&self) -> Result<Vec<Orientation>, CorpusError> {
        let mut orientations = Vec::new();
        for byte in self.digits.bytes() {
            let symbol = digit_from_byte(byte).and_then(RenderedSymbol::from_digit);
            match symbol.map_err(|symbol| CorpusError::MalformedSymbol {
                message_key: self.key,
                symbol,
            })? {
                RenderedSymbol::Orientation(orientation) => orientations.push(orientation),
                RenderedSymbol::RowDelimiter => {}
            }
        }
        Ok(orientations)
    }

    /// Returns the message as generic glyph indices after dropping delimiters.
    ///
    /// # Errors
    /// Returns [`CorpusError`] if the rendered digits are malformed.
    pub fn sequence(&self) -> Result<Sequence, CorpusError> {
        let glyphs = self
            .orientations()?
            .into_iter()
            .map(Orientation::glyph)
            .collect();
        Ok(Sequence { glyphs })
    }

    /// Groups delimiter-stripped orientations into base-5 reading trigrams.
    ///
    /// # Errors
    /// Returns [`CorpusError`] if the rendered digits are malformed or the
    /// delimiter-stripped orientation count is not divisible by three.
    pub fn trigrams(&self) -> Result<Vec<ReadingTrigram>, CorpusError> {
        trigrams_from_orientations(self.key, &self.orientations()?)
    }

    /// Returns the raw string length including row delimiters.
    #[must_use]
    pub fn raw_len_including_delimiters(&self) -> usize {
        self.digits.len()
    }
}

/// Shared source metadata for the verified corpus.
pub const PROVENANCE: Provenance = Provenance {
    transcription_source: "https://github.com/ngraham20/NoitaCryptographyResearch/blob/master/eye/eyes.json",
    engine_source: "https://gist.github.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8",
    vendored_path: "research/data/eye-messages/",
};

/// Verified eye-message corpus in engine/message id order.
pub const MESSAGES: [Message; 9] = [
    Message {
        id: 0,
        key: "east1",
        region: Region::East,
        region_index: 1,
        digits: "20101322330404113023211431303300402400050320412200014222421222201100032013411135310221044000200104040144142033022034241523131313003113212014223133144134144121150140032121141300411101002412410040310015040331432341122101010040120412442442402513331220330103113111211210322314513104242241303041102031232043135",
        eye_count: 297,
        trigram_count: 99,
        provenance: PROVENANCE,
    },
    Message {
        id: 1,
        key: "west1",
        region: Region::West,
        region_index: 1,
        digits: "31101322330404113023211431303300402400450320412200014222421222201100032013411015020201044000104044040144142033022034131511121313000110202014223133144134144140152122233032440002432311102212310310220435403431401222111340210301413341221330132502414221422203024200123212402323201403531013221121302032222004223103132241135",
        eye_count: 309,
        trigram_count: 103,
        provenance: PROVENANCE,
    },
    Message {
        id: 2,
        key: "east2",
        region: Region::East,
        region_index: 2,
        digits: "1210132233040411302321143130330040240045132041220001422242122220110003201341132530201323004421014300121414031102410422351024411132222314033301302310103224414225014113030144102020311114241034232132112514112012004010302212240204000010322104050011322100422310432420131030102003002215020142240312031330231000103310441201422503420104310110020012451314020220201413223115",
        eye_count: 354,
        trigram_count: 118,
        provenance: PROVENANCE,
    },
    Message {
        id: 3,
        key: "west2",
        region: Region::West,
        region_index: 2,
        digits: "30101430423111113010320011421114204214451320410024412002221410132400222201204025110120210044012022014100202130013243312540113011201032231343142231321303110000351431102230242242010212231422001031112235203401230041222213132220230242140211440512220100001214310123331201022420322150110101013212311030320302413203220305",
        eye_count: 306,
        trigram_count: 102,
        provenance: PROVENANCE,
    },
    Message {
        id: 4,
        key: "east3",
        region: Region::East,
        region_index: 3,
        digits: "221014304000100302220231222232144144211533204100222243134100324200001022004243153132233121201340041413023100012310431305020020140002021212311100003112220110032514021422202304200121424121122310401003450030210313002122103100003123320032404225001240241020232043043031224131312301142523231113021102102022234141211324032123050010301242212240330032110242131332310015410210103300432031412111422330403400041504124012304504230101045",
        eye_count: 411,
        trigram_count: 137,
        provenance: PROVENANCE,
    },
    Message {
        id: 5,
        key: "west3",
        region: Region::West,
        region_index: 3,
        digits: "1110143040440231010332321201132400320235432041002342120301441212222401420211130503303113422414411130300314223404213111254314132002101412021124312302031114300215103133214200230011143034143033110122120510113221112044231013132123102031102220051201201231300110240141330210230022200445210312220001440122003232142141332131220512022402223420303312024404020050021211001411022421034024114425",
        eye_count: 372,
        trigram_count: 124,
        provenance: PROVENANCE,
    },
    Message {
        id: 6,
        key: "east4",
        region: Region::East,
        region_index: 4,
        digits: "1010143040001000000102132331201421330035232041002222431212430430300110203421130510100422321003430014421422402220030002253034110223132024033020302224411420101415143234300120242230110301302001040030130501233240134134130244130141241222230332252122221431303020131021131022300031032325432331411032403200122103112431440120231512202423010131123221303534212102201003230340345",
        eye_count: 357,
        trigram_count: 119,
        provenance: PROVENANCE,
    },
    Message {
        id: 7,
        key: "west4",
        region: Region::West,
        region_index: 4,
        digits: "3010143040001000000102132331201400400025232041002222431212430430300110222113142521131021400103212224112430010013122331350302212301323014304134203000323324211405040210240103202210243021012103012033232540221110313241210214244031112202143114152042332412033020233010412042410122321015311140311421232122410240132440030221440522431411404212111414013050202310000310001021400115",
        eye_count: 360,
        trigram_count: 120,
        provenance: PROVENANCE,
    },
    Message {
        id: 8,
        key: "east5",
        region: Region::East,
        region_index: 5,
        digits: "1110143040001000000102132331201430441335332041002222431212430430300110211112430510121422330202401414421222223021221323353034110224012020413020022424202403412025014110114103111010240110204010013100130521121113011044121111240341012204004121351020410412211341301330132430110420102215020203002240010120442311042111142031102513122422022204152324421013314315",
        eye_count: 342,
        trigram_count: 114,
        provenance: PROVENANCE,
    },
];

/// Returns all verified messages in engine/message id order.
///
/// ```
/// use noita_eye_puzzle::corpus;
///
/// // The verified investigation fixes the corpus at exactly nine messages.
/// assert_eq!(corpus::messages().len(), 9);
/// ```
#[must_use]
pub const fn messages() -> &'static [Message; 9] {
    &MESSAGES
}

/// Returns all delimiter-stripped corpus glyphs in message order.
///
/// # Errors
/// Returns [`CorpusError`] if any message contains a malformed rendered digit.
pub fn combined_sequence() -> Result<Sequence, CorpusError> {
    let mut glyphs = Vec::new();
    for message in messages() {
        glyphs.extend(message.sequence()?.glyphs);
    }
    Ok(Sequence { glyphs })
}

fn digit_from_byte(byte: u8) -> Result<u8, SymbolError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        _ => Err(SymbolError {
            value: i16::from(byte),
        }),
    }
}

fn trigrams_from_orientations(
    message_key: &'static str,
    orientations: &[Orientation],
) -> Result<Vec<ReadingTrigram>, CorpusError> {
    if !orientations.len().is_multiple_of(3) {
        return Err(CorpusError::IncompleteTrigram {
            message_key,
            orientations: orientations.len(),
        });
    }

    let mut trigrams = Vec::new();
    for chunk in orientations.chunks_exact(3) {
        let [first, second, third] = *chunk else {
            continue;
        };
        trigrams.push(ReadingTrigram::new(first, second, third));
    }
    Ok(trigrams)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{CorpusError, MESSAGES, Message, PROVENANCE, Region, messages};
    use crate::glyph::StorageSymbol;

    const NG_EYES: &str = include_str!("../research/data/eye-messages/ng_eyes.json");
    const XK_EYE: &str = include_str!("../research/data/eye-messages/xk_eye.php");

    #[test]
    fn experiment_0_cross_validates_transcription_against_engine_decode() {
        let upstream = parse_ngraham_messages(NG_EYES);
        let engine = parse_xkeeper_pairs(XK_EYE);

        assert_eq!(upstream.len(), MESSAGES.len());
        assert_eq!(engine.len(), MESSAGES.len());

        for message in messages() {
            let upstream_digits = upstream
                .get(message.key)
                .unwrap_or_else(|| panic!("missing upstream transcription for {}", message.key));
            assert_eq!(
                *upstream_digits, message.digits,
                "vendored corpus differs from ngraham20 transcription for {}",
                message.key
            );

            let pairs = engine
                .get(&message.id)
                .unwrap_or_else(|| panic!("missing engine pairs for message {}", message.id));
            let decoded = decode_engine_pairs(pairs);
            assert_eq!(
                decoded, message.digits,
                "engine decode differs byte-for-byte for {}",
                message.key
            );
        }
    }

    #[test]
    fn real_corpus_is_parseable_and_records_origins() {
        for message in messages() {
            assert!(!message.origin().is_empty());
            assert_eq!(message.sequence().unwrap().len(), message.eye_count);
            assert_eq!(message.trigrams().unwrap().len(), message.trigram_count);
        }
    }

    #[test]
    fn trigrams_reject_non_divisible_orientation_count() {
        let message = Message {
            id: 99,
            key: "synthetic",
            region: Region::East,
            region_index: 99,
            digits: "0123",
            eye_count: 4,
            trigram_count: 1,
            provenance: PROVENANCE,
        };

        assert_eq!(
            message.trigrams(),
            Err(CorpusError::IncompleteTrigram {
                message_key: "synthetic",
                orientations: 4,
            })
        );
    }

    #[test]
    fn experiment_3_eye_counts_are_divisible_into_1036_trigrams() {
        let expected_eye_counts = [297, 309, 354, 306, 411, 372, 357, 360, 342];
        let actual_eye_counts: Vec<_> =
            messages().iter().map(|message| message.eye_count).collect();
        assert_eq!(actual_eye_counts, expected_eye_counts);

        let total_trigrams: usize = messages()
            .iter()
            .map(|message| {
                assert_eq!(
                    message.eye_count % 3,
                    0,
                    "{} eye count must be divisible by 3 after delimiters are removed",
                    message.key
                );
                assert_eq!(message.eye_count / 3, message.trigram_count);
                message.trigram_count
            })
            .sum();
        assert_eq!(total_trigrams, 1036);
    }

    #[test]
    fn experiment_3_raw_lengths_include_delimiters_and_most_are_not_divisible_by_3() {
        let raw_lengths: Vec<_> = messages()
            .iter()
            .map(super::Message::raw_len_including_delimiters)
            .collect();
        assert_eq!(raw_lengths, [305, 317, 364, 314, 423, 382, 367, 370, 352]);

        let divisible_raw_lengths = raw_lengths.iter().filter(|length| *length % 3 == 0).count();
        assert_eq!(
            divisible_raw_lengths, 1,
            "divisibility is an eye-count property, not a raw delimiter-including length property"
        );
    }

    fn parse_ngraham_messages(input: &str) -> BTreeMap<&str, &str> {
        let mut messages = BTreeMap::new();
        for key in MESSAGES.map(|message| message.key) {
            let needle = format!("\"{key}\":\"");
            let start = input
                .find(&needle)
                .unwrap_or_else(|| panic!("missing key {key} in ng_eyes.json"));
            let value_start = start + needle.len();
            let rest = input
                .get(value_start..)
                .unwrap_or_else(|| panic!("invalid value start for {key}"));
            let value_end = rest
                .find('"')
                .unwrap_or_else(|| panic!("unterminated value for {key}"));
            let value = rest
                .get(..value_end)
                .unwrap_or_else(|| panic!("invalid value end for {key}"));
            assert!(
                messages.insert(key, value).is_none(),
                "duplicate upstream transcription key {key}"
            );
        }
        messages
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

    fn decode_engine_pairs(pairs: &[(u32, u32)]) -> String {
        let mut out = Vec::new();
        for &(low, high) in pairs.iter().rev() {
            let mut value = (u64::from(high) << 32) + u64::from(low);
            value /= 7;
            while value > 0 {
                let symbol = i8::try_from(value % 7).unwrap() - 1;
                let storage = StorageSymbol::from_value(symbol).unwrap();
                assert_ne!(
                    storage,
                    StorageSymbol::NegativeOne,
                    "real corpus decoded an engine -1 symbol"
                );
                out.push(symbol);
                value /= 7;
            }
        }
        out.reverse();
        out.into_iter()
            .map(|symbol| {
                u8::try_from(symbol)
                    .ok()
                    .and_then(|digit| char::from_digit(u32::from(digit), 10))
                    .unwrap_or_else(|| panic!("invalid decoded engine symbol {symbol}"))
            })
            .collect()
    }
}
