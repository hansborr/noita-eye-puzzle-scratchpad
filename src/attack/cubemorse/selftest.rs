use super::{
    CubeMorseCell, CubeMorseConfig, CubeMorseError, CubeMorseVerdict, Direction, FaceOrientation,
    MorseRoles, analyze_cube_morse, encode_cube_morse,
};

/// Planted phrase used by the end-to-end control.
pub const PLANT_TEXT: &str = "CUBES MAKE ROLLS NON-COMMUTATIVE.";

const PLANT_CELL: CubeMorseCell = CubeMorseCell {
    start: FaceOrientation {
        top: 2,
        north: 1,
        east: 0,
        south: 4,
        west: 5,
        bottom: 3,
    },
    roles: MorseRoles {
        dot: Direction::East,
        dash: Direction::West,
        separator: Direction::North,
    },
};

/// End-to-end planted-positive and matched-null self-test result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CubeMorseSelfTest {
    /// The plant was recovered verbatim by the same analysis the CLI uses.
    pub plant_recovered: bool,
    /// The recovered plant replayed every generated cube face.
    pub plant_exact: bool,
    /// No matched direction-shuffle null produced an all-valid Morse candidate.
    pub matched_null_negative: bool,
}

impl CubeMorseSelfTest {
    /// Whether every control leg passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.plant_recovered && self.plant_exact && self.matched_null_negative
    }
}

/// Runs a planted encode/analyze/re-encode control and its matched walk nulls.
///
/// # Errors
/// Returns [`CubeMorseError`] if the plant cannot be constructed or analyzed.
pub fn cubemorse_self_test(seed: u64) -> Result<CubeMorseSelfTest, CubeMorseError> {
    let plant = encode_cube_morse(PLANT_TEXT, PLANT_CELL).ok_or(CubeMorseError::EmptyInput)?;
    let report = analyze_cube_morse(
        &plant,
        CubeMorseConfig {
            null_trials: 32,
            seed,
            top: 8,
        },
    )?;
    let hit = report
        .candidates
        .iter()
        .find(|candidate| candidate.plaintext == PLANT_TEXT);
    Ok(CubeMorseSelfTest {
        plant_recovered: hit.is_some(),
        plant_exact: hit.is_some_and(super::CubeMorseCandidate::exact),
        matched_null_negative: report.verdict == CubeMorseVerdict::ExactCandidate
            && report.null_survivors == 0,
    })
}
