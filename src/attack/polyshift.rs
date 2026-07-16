//! Exhaustive position-polynomial shift attack for `A..Z` ciphertexts.
//!
//! The searched keystream has a constant modular second difference:
//! `k_i = a*i*(i-1)/2 + b*i + c (mod 26)`, with `a = 0` for the linear-only
//! mode. The binomial basis is integer-valued and includes period-52 streams
//! when `a` is odd, beyond the prior period-`<=40` profile. Both `C = P + K`
//! and Beaufort `C = K - P` are enumerated. This is a bounded position-keyed
//! family, not a generic polyalphabetic solver.

use std::fmt;

use crate::attack::quadgram::QuadgramModel;

/// Default matched-null trial count.
pub const DEFAULT_NULL_TRIALS: usize = 16;
/// Default deterministic seed.
pub const DEFAULT_SEED: u64 = 0x706f_6c79_7368_6966;
/// Required matched-null z-score.
pub const Z_THRESHOLD: f64 = 6.0;
/// Required absolute mean-log-score margin.
pub const MIN_SCORE_MARGIN: f64 = 1.0;

/// Error from a position-polynomial analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolyshiftError {
    /// Fewer than four symbols cannot form a quadgram score.
    TooShort(usize),
    /// A symbol is outside the fixed `A..Z` residue range.
    OutOfRange {
        /// Zero-based stream position.
        position: usize,
        /// Rejected residue.
        value: u8,
    },
    /// Only degree one or two is supported.
    InvalidDegree(usize),
}

impl fmt::Display for PolyshiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort(len) => write!(f, "need at least four symbols, got {len}"),
            Self::OutOfRange { position, value } => {
                write!(f, "symbol {value} at position {position} is outside 0..26")
            }
            Self::InvalidDegree(degree) => {
                write!(f, "polynomial degree must be 1 or 2, got {degree}")
            }
        }
    }
}

impl std::error::Error for PolyshiftError {}

/// Algebraic readout convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolyshiftConvention {
    /// `C = P + K`, hence `P = C - K`.
    Additive,
    /// `C = K - P`, hence `P = K - C`.
    Beaufort,
}

impl PolyshiftConvention {
    /// Stable report label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Additive => "additive",
            Self::Beaufort => "beaufort",
        }
    }
}

/// Globally best candidate in the exhaustively enumerated family.
#[derive(Clone, Debug, PartialEq)]
pub struct PolyshiftCandidate {
    /// Readout convention.
    pub convention: PolyshiftConvention,
    /// Quadratic coefficient (`0` in linear-only runs).
    pub quadratic: u8,
    /// Linear coefficient.
    pub linear: u8,
    /// Constant coefficient.
    pub constant: u8,
    /// Mean English quadgram score.
    pub score: f64,
    /// Candidate plaintext indices.
    pub plaintext: Vec<u8>,
    /// Whether the parameters exactly replay all ciphertext symbols.
    pub round_trip_ok: bool,
}

impl PolyshiftCandidate {
    /// Renders candidate indices as uppercase letters.
    #[must_use]
    pub fn render_plaintext(&self) -> String {
        self.plaintext
            .iter()
            .map(|&value| (b'A' + value) as char)
            .collect()
    }
}

/// Candidate plus matched-null gate statistics.
#[derive(Clone, Debug, PartialEq)]
pub struct PolyshiftReport {
    /// Best candidate from the complete registered sweep.
    pub candidate: PolyshiftCandidate,
    /// Maximum degree searched.
    pub degree: usize,
    /// Number of parameter/convention cells enumerated per stream.
    pub searched_cells: usize,
    /// Matched-null trial count.
    pub null_trials: usize,
    /// Mean per-shuffle maximum.
    pub null_mean: f64,
    /// Population standard deviation of per-shuffle maxima.
    pub null_std: f64,
    /// Candidate score minus null mean.
    pub margin: f64,
    /// Margin in null standard deviations.
    pub z: f64,
    /// Exact replay plus enabled z/margin gates.
    pub survives: bool,
}

/// Planted-control result, including direct plaintext recovery accuracy.
#[derive(Clone, Debug, PartialEq)]
pub struct PolyshiftControl {
    /// Full attack report on the planted ciphertext.
    pub report: PolyshiftReport,
    /// Fraction of planted plaintext symbols recovered exactly.
    pub accuracy: f64,
    /// Whether the control recovered every symbol and cleared every gate.
    pub passes: bool,
}

/// Runs the exhaustive family sweep and the identical max-over-family matched
/// shuffle null.
///
/// # Errors
///
/// Returns [`PolyshiftError`] when the stream is too short, contains a residue
/// outside `0..26`, or requests a degree other than one or two.
pub fn analyze(
    ciphertext: &[u8],
    degree: usize,
    null_trials: usize,
    seed: u64,
    model: &QuadgramModel,
) -> Result<PolyshiftReport, PolyshiftError> {
    validate(ciphertext, degree)?;
    let candidate = search(ciphertext, degree, model);
    let stats = crate::attack::crack::matched_null_loop(
        ciphertext,
        null_trials,
        |trial| seed ^ 0x9e37_79b9_7f4a_7c15 ^ trial as u64,
        |shuffled, _trial| {
            let score = search(shuffled, degree, model).score;
            (score, score)
        },
    );
    let comparison =
        crate::attack::crack::NullComparison::new(candidate.score, stats.full_mean, stats.full_std);
    let survives = candidate.round_trip_ok
        && comparison.clears(null_trials > 0, Z_THRESHOLD, MIN_SCORE_MARGIN);
    Ok(PolyshiftReport {
        candidate,
        degree,
        searched_cells: cell_count(degree),
        null_trials,
        null_mean: comparison.mean,
        null_std: comparison.std,
        margin: comparison.margin,
        z: comparison.z,
        survives,
    })
}

/// Exercises the complete attack and gate on a fixed degree-two plant.
///
/// # Errors
///
/// Returns [`PolyshiftError`] if the internal planted stream fails the same
/// input validation used for real ciphertext.
pub fn planted_control(
    null_trials: usize,
    seed: u64,
    model: &QuadgramModel,
) -> Result<PolyshiftControl, PolyshiftError> {
    let plaintext = normalize(CONTROL_TEXT);
    let ciphertext = encipher(&plaintext, PolyshiftConvention::Additive, 5, 7, 11);
    let report = analyze(
        &ciphertext,
        2,
        null_trials,
        seed ^ 0x706c_616e_7465_6400,
        model,
    )?;
    let matches = report
        .candidate
        .plaintext
        .iter()
        .zip(&plaintext)
        .filter(|(left, right)| left == right)
        .count();
    let accuracy = matches as f64 / plaintext.len() as f64;
    let passes = report.survives && matches == plaintext.len();
    Ok(PolyshiftControl {
        report,
        accuracy,
        passes,
    })
}

fn validate(ciphertext: &[u8], degree: usize) -> Result<(), PolyshiftError> {
    if ciphertext.len() < 4 {
        return Err(PolyshiftError::TooShort(ciphertext.len()));
    }
    if !(1..=2).contains(&degree) {
        return Err(PolyshiftError::InvalidDegree(degree));
    }
    if let Some((position, &value)) = ciphertext
        .iter()
        .enumerate()
        .find(|(_position, value)| **value >= 26)
    {
        return Err(PolyshiftError::OutOfRange { position, value });
    }
    Ok(())
}

fn search(ciphertext: &[u8], degree: usize, model: &QuadgramModel) -> PolyshiftCandidate {
    let quadratic_values = if degree == 1 { 0..1 } else { 0..26 };
    let mut best: Option<PolyshiftCandidate> = None;
    for quadratic in quadratic_values {
        for linear in 0..26 {
            for constant in 0..26 {
                for convention in [PolyshiftConvention::Additive, PolyshiftConvention::Beaufort] {
                    let plaintext = decipher(ciphertext, convention, quadratic, linear, constant);
                    let indices: Vec<usize> =
                        plaintext.iter().map(|&value| usize::from(value)).collect();
                    let score = model.score_indices(&indices);
                    if best
                        .as_ref()
                        .is_none_or(|candidate| score > candidate.score)
                    {
                        let replay = encipher(&plaintext, convention, quadratic, linear, constant);
                        best = Some(PolyshiftCandidate {
                            convention,
                            quadratic,
                            linear,
                            constant,
                            score,
                            round_trip_ok: replay == ciphertext,
                            plaintext,
                        });
                    }
                }
            }
        }
    }
    best.unwrap_or_else(|| PolyshiftCandidate {
        convention: PolyshiftConvention::Additive,
        quadratic: 0,
        linear: 0,
        constant: 0,
        score: f64::NEG_INFINITY,
        plaintext: Vec::new(),
        round_trip_ok: false,
    })
}

fn decipher(
    ciphertext: &[u8],
    convention: PolyshiftConvention,
    quadratic: u8,
    linear: u8,
    constant: u8,
) -> Vec<u8> {
    ciphertext
        .iter()
        .enumerate()
        .map(|(position, &cipher)| {
            let key = polynomial(position, quadratic, linear, constant);
            match convention {
                PolyshiftConvention::Additive => (cipher + 26 - key) % 26,
                PolyshiftConvention::Beaufort => (key + 26 - cipher) % 26,
            }
        })
        .collect()
}

fn encipher(
    plaintext: &[u8],
    convention: PolyshiftConvention,
    quadratic: u8,
    linear: u8,
    constant: u8,
) -> Vec<u8> {
    plaintext
        .iter()
        .enumerate()
        .map(|(position, &plain)| {
            let key = polynomial(position, quadratic, linear, constant);
            match convention {
                PolyshiftConvention::Additive => (plain + key) % 26,
                PolyshiftConvention::Beaufort => (key + 26 - plain) % 26,
            }
        })
        .collect()
}

fn polynomial(position: usize, quadratic: u8, linear: u8, constant: u8) -> u8 {
    let index = position % 52;
    let triangular = index * index.saturating_sub(1) / 2;
    ((usize::from(quadratic) * triangular + usize::from(linear) * index + usize::from(constant))
        % 26) as u8
}

const fn cell_count(degree: usize) -> usize {
    if degree == 1 {
        2 * 26 * 26
    } else {
        2 * 26 * 26 * 26
    }
}

fn normalize(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| byte.to_ascii_uppercase() - b'A')
        .collect()
}

const CONTROL_TEXT: &str = "the quick brown fox jumps over the lazy dog while the morning sun \
    rises slowly above the quiet village near the river where children play together after \
    school and the old baker prepares fresh bread for everyone who passes his little shop on \
    the corner of the street before returning home through the peaceful valley at sunset";

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SEED, PolyshiftError, analyze, planted_control};
    use crate::attack::quadgram::QuadgramModel;

    #[test]
    fn planted_degree_two_cipher_is_recovered_and_gated() {
        let model = QuadgramModel::english().unwrap();
        let control = planted_control(8, DEFAULT_SEED, &model).unwrap();
        assert!(control.passes, "control: {control:?}");
        assert_eq!(control.report.candidate.quadratic, 5);
        assert_eq!(control.report.candidate.linear, 7);
        assert_eq!(control.report.candidate.constant, 11);
    }

    #[test]
    fn noise_does_not_survive() {
        let model = QuadgramModel::english().unwrap();
        let noise = (0_usize..180)
            .map(|index| u8::try_from((index * 17 + 3) % 26).unwrap_or(0))
            .collect::<Vec<_>>();
        let report = analyze(&noise, 2, 8, DEFAULT_SEED, &model).unwrap();
        assert!(!report.survives);
    }

    #[test]
    fn rejects_bad_input() {
        let model = QuadgramModel::english().unwrap();
        assert_eq!(
            analyze(&[0, 1, 26, 3], 2, 0, 1, &model),
            Err(PolyshiftError::OutOfRange {
                position: 2,
                value: 26
            })
        );
        assert_eq!(
            analyze(&[0, 1, 2, 3], 3, 0, 1, &model),
            Err(PolyshiftError::InvalidDegree(3))
        );
    }
}
