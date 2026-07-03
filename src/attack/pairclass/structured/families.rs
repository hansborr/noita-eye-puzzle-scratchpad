//! Curated deterministic base-coloring families for structured mode.

use std::collections::BTreeSet;

use super::enumerate::StructuredFamilyProfile;

mod curated;

#[derive(Clone)]
pub(super) struct BaseColoring {
    pub(super) family: String,
    pub(super) projection: String,
    pub(super) order: String,
    pub(super) label_mode: LabelMode,
    pub(super) coloring: [u8; 26],
}

#[derive(Clone, Copy)]
pub(super) enum LabelMode {
    FixedBits,
    Relabel,
}

pub(super) fn base_colorings(profile: StructuredFamilyProfile) -> Vec<BaseColoring> {
    match profile {
        StructuredFamilyProfile::Core => core_base_colorings(),
        StructuredFamilyProfile::CoreCurated => core_curated_base_colorings(),
        StructuredFamilyProfile::Toy => toy_base_colorings(),
    }
}

fn toy_base_colorings() -> Vec<BaseColoring> {
    vec![BaseColoring {
        family: "toy-rank".to_owned(),
        projection: "rank-low2".to_owned(),
        order: "natural offset0".to_owned(),
        label_mode: LabelMode::Relabel,
        coloring: std::array::from_fn(|letter| (letter % 4) as u8),
    }]
}

fn core_base_colorings() -> Vec<BaseColoring> {
    let mut out = Vec::new();
    add_rank_bases(&mut out);
    add_rank6_bases(&mut out);
    add_ascii_bases(&mut out);
    add_historical_bases(&mut out);
    add_simple_bases(&mut out);
    add_keyword_bases(&mut out);
    dedup_bases(out)
}

fn core_curated_base_colorings() -> Vec<BaseColoring> {
    let mut out = Vec::new();
    curated::add_rank_bases(&mut out);
    curated::add_rank6_bases(&mut out);
    curated::add_ascii_bases(&mut out);
    add_historical_bases(&mut out);
    add_simple_bases(&mut out);
    curated::add_keyword_bases(&mut out);
    dedup_bases(out)
}

fn dedup_bases(bases: Vec<BaseColoring>) -> Vec<BaseColoring> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for base in bases {
        if seen.insert(base.coloring) {
            out.push(base);
        }
    }
    out
}

fn add_rank_bases(out: &mut Vec<BaseColoring>) {
    let offsets = [0u8, 1, 2, 5, 13];
    let projections = rank_projections(5);
    for origin in [0u8, 1] {
        for reversed in [false, true] {
            for offset in offsets {
                for basis in [RankBasis::Binary, RankBasis::Gray, RankBasis::BitReversed] {
                    for projection in &projections {
                        let projection_label = format!(
                            "{} affine({},{})",
                            basis.name(),
                            projection.high_label(),
                            projection.low_label()
                        );
                        let order = rank_order(origin, reversed, offset);
                        out.push(BaseColoring {
                            family: "rank5".to_owned(),
                            projection: projection_label,
                            order,
                            label_mode: LabelMode::Relabel,
                            coloring: std::array::from_fn(|letter| {
                                let rank = rank_value(letter as u8, origin, reversed, offset);
                                let code = basis.apply(rank);
                                projection.project(code)
                            }),
                        });
                    }
                }
            }
        }
    }
}

fn add_rank6_bases(out: &mut Vec<BaseColoring>) {
    for origin in [0u8, 1] {
        for reversed in [false, true] {
            for offset in [0u8, 1, 5, 13] {
                for pad in [PadBit::Zero, PadBit::One, PadBit::Parity] {
                    for pad_pos in 0..6u8 {
                        let order = rank_order(origin, reversed, offset);
                        out.push(BaseColoring {
                            family: "rank6-octal".to_owned(),
                            projection: format!("pad:{}@{pad_pos} octal-high", pad.name()),
                            order,
                            label_mode: LabelMode::FixedBits,
                            coloring: std::array::from_fn(|letter| {
                                let rank = rank_value(letter as u8, origin, reversed, offset);
                                let bits = rank6_bits(rank, pad, pad_pos);
                                let high = bits.get(5).copied().unwrap_or(0);
                                let low = bits.get(2).copied().unwrap_or(0);
                                (high << 1) | low
                            }),
                        });
                    }
                }
            }
        }
    }
}

fn add_ascii_bases(out: &mut Vec<BaseColoring>) {
    let direct_pairs = [
        (0u8, 1u8),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 6),
        (0, 6),
        (2, 5),
    ];
    for lower in [false, true] {
        let order = if lower { "lowercase" } else { "uppercase" };
        for (first, second) in direct_pairs {
            out.push(BaseColoring {
                family: "ascii".to_owned(),
                projection: format!("7bit bits({first},{second})"),
                order: order.to_owned(),
                label_mode: LabelMode::FixedBits,
                coloring: std::array::from_fn(|letter| {
                    let base = if lower { b'a' } else { b'A' };
                    let code = base.saturating_add(letter as u8);
                    project_bits(code, first, second)
                }),
            });
        }
        for drop_bit in 0..7u8 {
            for chunk in 0..3u8 {
                out.push(BaseColoring {
                    family: "ascii".to_owned(),
                    projection: format!("drop-bit{drop_bit} chunk{chunk}"),
                    order: order.to_owned(),
                    label_mode: LabelMode::FixedBits,
                    coloring: std::array::from_fn(|letter| {
                        let base = if lower { b'a' } else { b'A' };
                        let code = base.saturating_add(letter as u8);
                        let packed = drop_ascii_bit(code, drop_bit);
                        project_bits(packed, chunk * 2, chunk * 2 + 1)
                    }),
                });
            }
        }
        for chunk_offset in 0..=1u8 {
            let chunks = if chunk_offset == 0 { 4 } else { 3 };
            for chunk in 0..chunks {
                let first = chunk_offset + chunk * 2;
                let second = first + 1;
                out.push(BaseColoring {
                    family: "ascii".to_owned(),
                    projection: format!("8bit-chunk offset{chunk_offset} chunk{chunk}"),
                    order: order.to_owned(),
                    label_mode: LabelMode::FixedBits,
                    coloring: std::array::from_fn(|letter| {
                        let base = if lower { b'a' } else { b'A' };
                        let code = base.saturating_add(letter as u8);
                        project_bits(code, first, second)
                    }),
                });
            }
        }
    }
}

fn add_historical_bases(out: &mut Vec<BaseColoring>) {
    for (first, second) in [(0u8, 1u8), (1, 3), (2, 4), (0, 4)] {
        out.push(BaseColoring {
            family: "bacon".to_owned(),
            projection: format!("bits({first},{second})"),
            order: "a0-25".to_owned(),
            label_mode: LabelMode::Relabel,
            coloring: std::array::from_fn(|letter| project_bits(letter as u8, first, second)),
        });
        out.push(BaseColoring {
            family: "baudot-ita2".to_owned(),
            projection: format!("bits({first},{second})"),
            order: "letters".to_owned(),
            label_mode: LabelMode::Relabel,
            coloring: std::array::from_fn(|letter| {
                project_bits(baudot_code(letter), first, second)
            }),
        });
    }
    out.push(polybius("row-parity col-parity", |row, col| {
        ((row & 1) << 1) | (col & 1)
    }));
    out.push(polybius("row-high col-high", |row, col| {
        (((row >> 1) & 1) << 1) | ((col >> 1) & 1)
    }));
}

fn add_simple_bases(out: &mut Vec<BaseColoring>) {
    out.push(simple("rank-mod4", |letter| letter % 4));
    out.push(simple("rank-blocks", |letter| (letter / 7).min(3)));
    let frequency = b"etaoinshrdlcumwfgypbvkjxqz";
    out.push(BaseColoring {
        family: "simple".to_owned(),
        projection: "frequency-blocks".to_owned(),
        order: "etaoin".to_owned(),
        label_mode: LabelMode::Relabel,
        coloring: std::array::from_fn(|letter| {
            let ch = b'a'.saturating_add(letter as u8);
            let rank = frequency
                .iter()
                .position(|&byte| byte == ch)
                .unwrap_or(usize::from(letter as u8));
            (rank / 7).min(3) as u8
        }),
    });
    out.push(simple("vowel-consonant-subclass", |letter| {
        let ch = b'a'.saturating_add(letter);
        let vowel = matches!(ch, b'a' | b'e' | b'i' | b'o' | b'u');
        if vowel { letter % 2 } else { 2 + (letter % 2) }
    }));
}

fn add_keyword_bases(out: &mut Vec<BaseColoring>) {
    let projections = rank_projections(5);
    for keyword in [
        "permutation",
        "representation",
        "destination",
        "noita",
        "eye",
        "group",
        "gak",
        "rotor",
    ] {
        let order = keyword_order(keyword);
        for basis in [RankBasis::Binary, RankBasis::Gray, RankBasis::BitReversed] {
            for projection in &projections {
                out.push(BaseColoring {
                    family: "keyword-rank".to_owned(),
                    projection: format!(
                        "{} affine({},{})",
                        basis.name(),
                        projection.high_label(),
                        projection.low_label()
                    ),
                    order: keyword.to_owned(),
                    label_mode: LabelMode::Relabel,
                    coloring: std::array::from_fn(|letter| {
                        let rank = order.get(letter).copied().unwrap_or(letter as u8);
                        let code = basis.apply(rank);
                        projection.project(code)
                    }),
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
struct RankProjection {
    high_mask: u8,
    low_mask: u8,
}

impl RankProjection {
    fn high_label(self) -> String {
        mask_label(self.high_mask)
    }

    fn low_label(self) -> String {
        mask_label(self.low_mask)
    }

    fn project(self, value: u8) -> u8 {
        (parity(value & self.high_mask) << 1) | parity(value & self.low_mask)
    }
}

fn rank_projections(width: u8) -> Vec<RankProjection> {
    let max_mask = 1u8 << width;
    let mut seen_subspaces = BTreeSet::new();
    let mut out = Vec::new();
    for high in 1..max_mask {
        for low in (high + 1)..max_mask {
            let third = high ^ low;
            if third == 0 {
                continue;
            }
            let mut subspace = [high, low, third];
            subspace.sort_unstable();
            if seen_subspaces.insert(subspace) {
                out.push(RankProjection {
                    high_mask: subspace[0],
                    low_mask: subspace[1],
                });
            }
        }
    }
    out
}

fn mask_label(mask: u8) -> String {
    format!("xor{mask:02x}")
}

fn parity(value: u8) -> u8 {
    (value.count_ones() as u8) & 1
}

#[derive(Clone, Copy)]
enum RankBasis {
    Binary,
    Gray,
    BitReversed,
}

impl RankBasis {
    fn name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Gray => "gray",
            Self::BitReversed => "bitrev",
        }
    }

    fn apply(self, rank: u8) -> u8 {
        match self {
            Self::Binary => rank,
            Self::Gray => rank ^ (rank >> 1),
            Self::BitReversed => reverse_low_bits(rank, 5),
        }
    }
}

#[derive(Clone, Copy)]
enum PadBit {
    Zero,
    One,
    Parity,
}

impl PadBit {
    fn name(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::One => "one",
            Self::Parity => "parity",
        }
    }

    fn value(self, rank: u8) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Parity => (rank.count_ones() as u8) & 1,
        }
    }
}

fn rank_order(origin: u8, reversed: bool, offset: u8) -> String {
    format!(
        "A={} {} offset{}",
        origin,
        if reversed { "reversed" } else { "natural" },
        offset
    )
}

fn rank_value(letter: u8, origin: u8, reversed: bool, offset: u8) -> u8 {
    let base = if reversed {
        25u8.saturating_sub(letter)
    } else {
        letter
    };
    ((base + offset) % 26).saturating_add(origin)
}

fn rank6_bits(rank: u8, pad: PadBit, pad_pos: u8) -> [u8; 6] {
    let mut out = [0u8; 6];
    let mut src = 0u8;
    for dst in 0..6u8 {
        let bit = if dst == pad_pos {
            pad.value(rank)
        } else {
            let value = (rank >> src) & 1;
            src = src.saturating_add(1);
            value
        };
        if let Some(slot) = out.get_mut(usize::from(dst)) {
            *slot = bit;
        }
    }
    out
}

fn reverse_low_bits(value: u8, width: u8) -> u8 {
    let mut out = 0u8;
    for bit in 0..width {
        let source = (value >> bit) & 1;
        out |= source << (width - bit - 1);
    }
    out
}

fn project_bits(value: u8, first: u8, second: u8) -> u8 {
    (((value >> first) & 1) << 1) | ((value >> second) & 1)
}

fn drop_ascii_bit(value: u8, drop_bit: u8) -> u8 {
    let mut out = 0u8;
    let mut dst = 0u8;
    for src in 0..7u8 {
        if src == drop_bit {
            continue;
        }
        let bit = (value >> src) & 1;
        out |= bit << dst;
        dst = dst.saturating_add(1);
    }
    out
}

fn baudot_code(letter: usize) -> u8 {
    const ITA2: [u8; 26] = [
        0b00011, 0b11001, 0b01110, 0b01001, 0b00001, 0b01101, 0b11010, 0b10100, 0b00110, 0b01011,
        0b01111, 0b10010, 0b11100, 0b01100, 0b11000, 0b10110, 0b10111, 0b01010, 0b00101, 0b10000,
        0b00111, 0b11110, 0b10011, 0b11101, 0b10101, 0b10001,
    ];
    ITA2.get(letter).copied().unwrap_or(0)
}

fn polybius(name: &str, f: fn(u8, u8) -> u8) -> BaseColoring {
    BaseColoring {
        family: "polybius".to_owned(),
        projection: name.to_owned(),
        order: "6x5".to_owned(),
        label_mode: LabelMode::Relabel,
        coloring: std::array::from_fn(|letter| {
            let row = (letter / 5) as u8;
            let col = (letter % 5) as u8;
            f(row, col)
        }),
    }
}

fn simple(name: &str, f: fn(u8) -> u8) -> BaseColoring {
    BaseColoring {
        family: "simple".to_owned(),
        projection: name.to_owned(),
        order: "natural".to_owned(),
        label_mode: LabelMode::Relabel,
        coloring: std::array::from_fn(|letter| f(letter as u8).min(3)),
    }
}

fn keyword_order(keyword: &str) -> [u8; 26] {
    let mut alphabet = Vec::with_capacity(26);
    for byte in keyword.bytes().chain(b'a'..=b'z') {
        let lower = byte.to_ascii_lowercase();
        if lower.is_ascii_lowercase() && !alphabet.contains(&lower) {
            alphabet.push(lower);
        }
    }
    std::array::from_fn(|letter| {
        let ch = b'a'.saturating_add(letter as u8);
        alphabet
            .iter()
            .position(|&byte| byte == ch)
            .unwrap_or(letter) as u8
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BaseColoring, add_ascii_bases, add_keyword_bases, add_rank_bases, add_rank6_bases,
    };

    #[test]
    fn core_rank5_builder_includes_xor_combined_projection() {
        let mut bases = Vec::new();
        add_rank_bases(&mut bases);
        assert!(
            bases
                .iter()
                .any(|base| { base.family == "rank5" && base.projection.contains("xor03") }),
            "rank5 must include XOR-combined affine projections"
        );
    }

    #[test]
    fn core_rank6_builder_includes_all_pad_positions() {
        let mut bases = Vec::new();
        add_rank6_bases(&mut bases);
        for pad_pos in 0..6u8 {
            assert!(
                bases
                    .iter()
                    .any(|base| base.projection.contains(&format!("@{pad_pos} "))),
                "rank6 must include pad position {pad_pos}"
            );
        }
    }

    #[test]
    fn core_ascii_builder_includes_drop_and_chunk_variants() {
        let mut bases = Vec::new();
        add_ascii_bases(&mut bases);
        assert_has_projection(&bases, "drop-bit");
        assert_has_projection(&bases, "8bit-chunk");
    }

    #[test]
    fn core_keyword_builder_uses_rank_projection_set() {
        let mut bases = Vec::new();
        add_keyword_bases(&mut bases);
        assert!(
            bases
                .iter()
                .any(|base| { base.family == "keyword-rank" && base.projection.contains("xor03") }),
            "keyword-rank must apply the rank affine projection set"
        );
    }

    fn assert_has_projection(bases: &[BaseColoring], needle: &str) {
        assert!(
            bases.iter().any(|base| base.projection.contains(needle)),
            "missing projection containing {needle}"
        );
    }
}
