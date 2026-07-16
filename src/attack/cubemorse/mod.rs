//! Cube-face-walk to International Morse candidate instrument.
//!
//! A six-face stream is read as successive top faces of a rolling cube. Opposite
//! face pairs are `(0,5)`, `(1,4)`, and `(2,3)`; every observed face must be
//! adjacent to the current top. A valid carrier uses exactly three of the four
//! roll directions. The bounded sweep assigns those three directions to Morse
//! dot, dash, and letter separator, while visible whitespace remains the word
//! separator. Candidates must use only standard International Morse codes and
//! re-encode every observed face exactly under the same cell.
//!
//! Because the initial cube orientation and the three direction roles are
//! swept, exact replay is an implementation/consistency gate rather than
//! independent proof of plaintext. The decisive candidate gate reruns the full
//! sweep on direction-shuffled cube walks with the same length, word boundaries,
//! and roll-direction counts.

use std::fmt;

use crate::attack::quadgram::{QuadgramError, QuadgramModel};
use crate::core::glyph::Glyph;
use crate::nulls::null::{RandomBoundError, SplitMix64, fisher_yates, mix_seed};

mod cube;
mod morse;
mod selftest;

#[cfg(test)]
mod tests;

pub use selftest::{CubeMorseSelfTest, PLANT_TEXT, cubemorse_self_test};

use cube::{
    all_orientations, cells_for_carrier, derive_commands, encode_commands, flatten,
    matched_symbols, used_directions, validate_words,
};
use morse::{decode_words, encode_words};

/// Default deterministic seed for matched cube-walk nulls.
pub const DEFAULT_SEED: u64 = 0x6375_6265_6d6f_7273;
/// Default number of matched null trials.
pub const DEFAULT_NULL_TRIALS: usize = 64;
/// Default number of ranked plaintexts retained.
pub const DEFAULT_TOP: usize = 5;

const NULL_TAG: u64 = 0x6375_6265_6e75_6c6c;

/// One absolute roll direction in the observer's frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// Roll toward north.
    North,
    /// Roll toward east.
    East,
    /// Roll toward south.
    South,
    /// Roll toward west.
    West,
}

impl Direction {
    const ALL: [Self; 4] = [Self::North, Self::East, Self::South, Self::West];

    /// Stable short display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::North => "N",
            Self::East => "E",
            Self::South => "S",
            Self::West => "W",
        }
    }
}

/// Complete labeled-cube orientation before the first observed roll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceOrientation {
    /// Top face.
    pub top: u8,
    /// North face.
    pub north: u8,
    /// East face.
    pub east: u8,
    /// South face.
    pub south: u8,
    /// West face.
    pub west: u8,
    /// Bottom face.
    pub bottom: u8,
}

/// Assignment of three observed roll directions to Morse roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MorseRoles {
    /// Direction interpreted as dot.
    pub dot: Direction,
    /// Direction interpreted as dash.
    pub dash: Direction,
    /// Direction interpreted as an inter-letter separator.
    pub separator: Direction,
}

/// One swept cube-orientation/Morse-role cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CubeMorseCell {
    /// Cube orientation immediately before the first observed face.
    pub start: FaceOrientation,
    /// Roll-direction to Morse-role assignment.
    pub roles: MorseRoles,
}

/// One distinct readable candidate; symmetric cells are collapsed.
#[derive(Clone, Debug, PartialEq)]
pub struct CubeMorseCandidate {
    /// Decoded International Morse text.
    pub plaintext: String,
    /// English quadgram mean log-likelihood used only for ranking candidates.
    pub quadgram_score: f64,
    /// Canonical cell among symmetry-equivalent exact cells.
    pub cell: CubeMorseCell,
    /// Number of cells yielding this same plaintext and exact replay.
    pub equivalent_cells: usize,
    /// Input symbols reproduced by exact re-encoding.
    pub matched: usize,
    /// Total input symbols.
    pub total: usize,
}

impl CubeMorseCandidate {
    /// Whether every input face was reproduced exactly.
    #[must_use]
    pub const fn exact(&self) -> bool {
        self.total > 0 && self.matched == self.total
    }
}

/// Candidate classification after the matched-null sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CubeMorseVerdict {
    /// A valid exact candidate beat every matched-null trial.
    ExactCandidate,
    /// Valid Morse candidates occurred, but a matched null scored as well.
    MatchedNull,
    /// No cube/Morse cell decoded entirely to standard Morse.
    NoCandidate,
}

/// Full report for one word-bounded input stream.
#[derive(Clone, Debug, PartialEq)]
pub struct CubeMorseReport {
    /// Final calibrated verdict.
    pub verdict: CubeMorseVerdict,
    /// Number of face symbols.
    pub symbols: usize,
    /// Number of externally supplied word blocks.
    pub words: usize,
    /// Distinct exact plaintext candidates, ranked by quadgram score.
    pub candidates: Vec<CubeMorseCandidate>,
    /// Matched-null trials run.
    pub null_trials: usize,
    /// Null trials producing at least one all-valid Morse candidate.
    pub null_survivors: usize,
    /// Null best scores greater than or equal to the observed best score.
    pub null_ge: usize,
    /// Add-one empirical p-value for the observed best score.
    pub p_empirical: f64,
    /// Observed best score minus the best surviving-null score, if one exists.
    pub margin_vs_null_max: Option<f64>,
}

/// Runtime configuration for [`analyze_cube_morse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CubeMorseConfig {
    /// Number of matched direction-shuffle nulls.
    pub null_trials: usize,
    /// Deterministic null seed.
    pub seed: u64,
    /// Number of distinct candidates retained.
    pub top: usize,
}

impl Default for CubeMorseConfig {
    fn default() -> Self {
        Self {
            null_trials: DEFAULT_NULL_TRIALS,
            seed: DEFAULT_SEED,
            top: DEFAULT_TOP,
        }
    }
}

/// Errors returned by the cube/Morse instrument.
#[derive(Debug)]
pub enum CubeMorseError {
    /// No non-empty words were supplied.
    EmptyInput,
    /// A symbol was outside the required six-face alphabet.
    SymbolOutOfRange {
        /// Rejected symbol index.
        value: usize,
    },
    /// The English ranking model could not be built.
    Quadgram(QuadgramError),
    /// A deterministic null shuffle failed.
    Random(RandomBoundError),
}

impl fmt::Display for CubeMorseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("cube/Morse input needs non-empty word blocks"),
            Self::SymbolOutOfRange { value } => {
                write!(
                    f,
                    "cube face {value} is outside the required six-face alphabet"
                )
            }
            Self::Quadgram(error) => write!(f, "quadgram model: {error}"),
            Self::Random(error) => {
                write!(f, "matched-null shuffle rejected bound {}", error.bound)
            }
        }
    }
}

impl std::error::Error for CubeMorseError {}

impl From<QuadgramError> for CubeMorseError {
    fn from(error: QuadgramError) -> Self {
        Self::Quadgram(error)
    }
}

impl From<RandomBoundError> for CubeMorseError {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

/// Encodes plaintext through a declared cube/Morse cell, preserving spaces as
/// word boundaries. This is the exact inverse used by the replay gate.
#[must_use]
pub fn encode_cube_morse(text: &str, cell: CubeMorseCell) -> Option<Vec<Vec<Glyph>>> {
    let commands = encode_words(text, cell.roles)?;
    Some(encode_commands(&commands, cell.start))
}

/// Runs the complete cube-carrier, Morse, exact-replay, and matched-null sweep.
///
/// `words` supplies the visible word boundaries independently of the six-symbol
/// face stream. Each glyph must be in `0..6`.
///
/// # Errors
/// Returns [`CubeMorseError`] for empty/malformed input, language-model failure,
/// or deterministic-null failure.
pub fn analyze_cube_morse(
    words: &[Vec<Glyph>],
    config: CubeMorseConfig,
) -> Result<CubeMorseReport, CubeMorseError> {
    let symbols = validate_words(words)?;
    let model = QuadgramModel::english()?;
    let mut candidates = scan_candidates(words, &model, symbols);
    let carrier = first_carrier(words);
    let mut null_scores = Vec::new();
    if let Some((start, commands)) = carrier {
        for trial in 0..config.null_trials {
            let mut shuffled = flatten(&commands);
            let mut rng = SplitMix64::new(mix_seed(config.seed ^ NULL_TAG, trial as u64));
            fisher_yates(&mut shuffled, &mut rng)?;
            let mut cursor = 0;
            let shuffled_words: Vec<Vec<Direction>> = commands
                .iter()
                .map(|word| {
                    let chunk = shuffled
                        .iter()
                        .skip(cursor)
                        .take(word.len())
                        .copied()
                        .collect();
                    cursor += word.len();
                    chunk
                })
                .collect();
            let null_faces = encode_commands(&shuffled_words, start);
            if let Some(best) = scan_candidates(&null_faces, &model, symbols).first() {
                null_scores.push(best.quadgram_score);
            }
        }
    }
    let observed = candidates.first().map(|candidate| candidate.quadgram_score);
    let null_ge = observed.map_or(0, |score| {
        null_scores.iter().filter(|&&null| null >= score).count()
    });
    let null_max = null_scores.iter().copied().reduce(f64::max);
    let margin_vs_null_max = observed.zip(null_max).map(|(real, null)| real - null);
    let p_empirical = (null_ge + 1) as f64 / (config.null_trials + 1) as f64;
    let verdict = if candidates.is_empty() {
        CubeMorseVerdict::NoCandidate
    } else if null_ge == 0 {
        CubeMorseVerdict::ExactCandidate
    } else {
        CubeMorseVerdict::MatchedNull
    };
    candidates.truncate(config.top);
    Ok(CubeMorseReport {
        verdict,
        symbols,
        words: words.len(),
        candidates,
        null_trials: config.null_trials,
        null_survivors: null_scores.len(),
        null_ge,
        p_empirical,
        margin_vs_null_max,
    })
}

fn first_carrier(words: &[Vec<Glyph>]) -> Option<(FaceOrientation, Vec<Vec<Direction>>)> {
    all_orientations().into_iter().find_map(|start| {
        let commands = derive_commands(words, start)?;
        (used_directions(&commands).len() == 3).then_some((start, commands))
    })
}

fn scan_candidates(
    words: &[Vec<Glyph>],
    model: &QuadgramModel,
    symbols: usize,
) -> Vec<CubeMorseCandidate> {
    let mut candidates: Vec<CubeMorseCandidate> = Vec::new();
    for start in all_orientations() {
        let Some(commands) = derive_commands(words, start) else {
            continue;
        };
        for cell in cells_for_carrier(start, &commands) {
            let Some(plaintext) = decode_words(&commands, cell.roles) else {
                continue;
            };
            let Some(reencoded) = encode_cube_morse(&plaintext, cell) else {
                continue;
            };
            let matched = matched_symbols(words, &reencoded);
            if matched != symbols || reencoded != words {
                continue;
            }
            if let Some(existing) = candidates
                .iter_mut()
                .find(|candidate| candidate.plaintext == plaintext)
            {
                existing.equivalent_cells += 1;
                if cell < existing.cell {
                    existing.cell = cell;
                }
                continue;
            }
            candidates.push(CubeMorseCandidate {
                quadgram_score: model.score_letters(&plaintext),
                plaintext,
                cell,
                equivalent_cells: 1,
                matched,
                total: symbols,
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .quadgram_score
            .total_cmp(&left.quadgram_score)
            .then_with(|| left.plaintext.cmp(&right.plaintext))
    });
    candidates
}
