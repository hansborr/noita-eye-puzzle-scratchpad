use crate::core::glyph::Glyph;

use super::{CubeMorseCell, CubeMorseError, Direction, FaceOrientation, MorseRoles};

const FACE_COUNT: u8 = 6;

pub(super) const fn opposite(face: u8) -> u8 {
    5 - face
}

impl FaceOrientation {
    pub(super) const fn new(top: u8, north: u8, east: u8) -> Self {
        Self {
            top,
            north,
            east,
            south: opposite(north),
            west: opposite(east),
            bottom: opposite(top),
        }
    }

    pub(super) fn direction_of(self, face: u8) -> Option<Direction> {
        if face == self.north {
            Some(Direction::North)
        } else if face == self.east {
            Some(Direction::East)
        } else if face == self.south {
            Some(Direction::South)
        } else if face == self.west {
            Some(Direction::West)
        } else {
            None
        }
    }

    pub(super) const fn rolled(self, direction: Direction) -> Self {
        match direction {
            Direction::North => Self {
                top: self.north,
                north: self.bottom,
                east: self.east,
                south: self.top,
                west: self.west,
                bottom: self.south,
            },
            Direction::East => Self {
                top: self.east,
                north: self.north,
                east: self.bottom,
                south: self.south,
                west: self.top,
                bottom: self.west,
            },
            Direction::South => Self {
                top: self.south,
                north: self.top,
                east: self.east,
                south: self.bottom,
                west: self.west,
                bottom: self.north,
            },
            Direction::West => Self {
                top: self.west,
                north: self.north,
                east: self.top,
                south: self.south,
                west: self.bottom,
                bottom: self.east,
            },
        }
    }
}

pub(super) fn all_orientations() -> Vec<FaceOrientation> {
    let mut orientations = Vec::with_capacity(48);
    for top in 0..FACE_COUNT {
        for north in 0..FACE_COUNT {
            if north == top || north == opposite(top) {
                continue;
            }
            for east in 0..FACE_COUNT {
                if east == top || east == opposite(top) || east == north || east == opposite(north)
                {
                    continue;
                }
                orientations.push(FaceOrientation::new(top, north, east));
            }
        }
    }
    orientations
}

pub(super) fn derive_commands(
    words: &[Vec<Glyph>],
    start: FaceOrientation,
) -> Option<Vec<Vec<Direction>>> {
    let mut orientation = start;
    let mut output = Vec::with_capacity(words.len());
    for word in words {
        let mut commands = Vec::with_capacity(word.len());
        for glyph in word {
            let face = u8::try_from(glyph.0).ok()?;
            let direction = orientation.direction_of(face)?;
            orientation = orientation.rolled(direction);
            commands.push(direction);
        }
        output.push(commands);
    }
    Some(output)
}

pub(super) fn encode_commands(
    commands: &[Vec<Direction>],
    start: FaceOrientation,
) -> Vec<Vec<Glyph>> {
    let mut orientation = start;
    commands
        .iter()
        .map(|word| {
            word.iter()
                .map(|&direction| {
                    orientation = orientation.rolled(direction);
                    Glyph(u16::from(orientation.top))
                })
                .collect()
        })
        .collect()
}

pub(super) fn flatten(commands: &[Vec<Direction>]) -> Vec<Direction> {
    commands.iter().flatten().copied().collect()
}

pub(super) fn used_directions(commands: &[Vec<Direction>]) -> Vec<Direction> {
    Direction::ALL
        .into_iter()
        .filter(|direction| commands.iter().flatten().any(|seen| seen == direction))
        .collect()
}

pub(super) fn cells_for_carrier(
    start: FaceOrientation,
    commands: &[Vec<Direction>],
) -> Vec<CubeMorseCell> {
    let used = used_directions(commands);
    if used.len() != 3 {
        return Vec::new();
    }
    let mut cells = Vec::with_capacity(6);
    for &separator in &used {
        let marks: Vec<Direction> = used
            .iter()
            .copied()
            .filter(|&direction| direction != separator)
            .collect();
        let [first, second] = marks.as_slice() else {
            continue;
        };
        cells.push(CubeMorseCell {
            start,
            roles: MorseRoles {
                dot: *first,
                dash: *second,
                separator,
            },
        });
        cells.push(CubeMorseCell {
            start,
            roles: MorseRoles {
                dot: *second,
                dash: *first,
                separator,
            },
        });
    }
    cells
}

pub(super) fn validate_words(words: &[Vec<Glyph>]) -> Result<usize, CubeMorseError> {
    if words.is_empty() || words.iter().any(Vec::is_empty) {
        return Err(CubeMorseError::EmptyInput);
    }
    let mut total = 0;
    for glyph in words.iter().flatten() {
        let value = usize::from(glyph.0);
        if value >= usize::from(FACE_COUNT) {
            return Err(CubeMorseError::SymbolOutOfRange { value });
        }
        total += 1;
    }
    Ok(total)
}

pub(super) fn matched_symbols(left: &[Vec<Glyph>], right: &[Vec<Glyph>]) -> usize {
    left.iter()
        .flatten()
        .zip(right.iter().flatten())
        .filter(|(a, b)| a == b)
        .count()
}
