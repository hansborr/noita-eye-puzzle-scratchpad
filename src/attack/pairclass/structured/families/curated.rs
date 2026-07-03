//! Pre-broadening curated core family builders.

use super::{
    BaseColoring, LabelMode, PadBit, RankBasis, keyword_order, project_bits, rank_order,
    rank_value, rank6_bits,
};

pub(super) fn add_rank_bases(out: &mut Vec<BaseColoring>) {
    let offsets = [0u8, 1, 2, 5, 13];
    let projections = [(0u8, 1u8), (1, 3), (2, 4), (0, 4)];
    for origin in [0u8, 1] {
        for reversed in [false, true] {
            for offset in offsets {
                for basis in [RankBasis::Binary, RankBasis::Gray, RankBasis::BitReversed] {
                    for (first, second) in projections {
                        let projection = format!("{} bits({first},{second})", basis.name());
                        let order = rank_order(origin, reversed, offset);
                        out.push(BaseColoring {
                            family: "rank5".to_owned(),
                            projection,
                            order,
                            label_mode: LabelMode::Relabel,
                            coloring: std::array::from_fn(|letter| {
                                let rank = rank_value(letter as u8, origin, reversed, offset);
                                let code = basis.apply(rank);
                                project_bits(code, first, second)
                            }),
                        });
                    }
                }
            }
        }
    }
}

pub(super) fn add_rank6_bases(out: &mut Vec<BaseColoring>) {
    for origin in [0u8, 1] {
        for reversed in [false, true] {
            for offset in [0u8, 1, 5, 13] {
                for pad in [PadBit::Zero, PadBit::One, PadBit::Parity] {
                    for pad_pos in [0u8, 2, 5] {
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

pub(super) fn add_ascii_bases(out: &mut Vec<BaseColoring>) {
    let projections = [
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
        for (first, second) in projections {
            out.push(BaseColoring {
                family: "ascii".to_owned(),
                projection: format!("7bit bits({first},{second})"),
                order: if lower { "lowercase" } else { "uppercase" }.to_owned(),
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

pub(super) fn add_keyword_bases(out: &mut Vec<BaseColoring>) {
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
        for (first, second) in [(0u8, 1u8), (1, 3), (2, 4)] {
            out.push(BaseColoring {
                family: "keyword-rank".to_owned(),
                projection: format!("rank bits({first},{second})"),
                order: keyword.to_owned(),
                label_mode: LabelMode::Relabel,
                coloring: std::array::from_fn(|letter| {
                    let rank = order.get(letter).copied().unwrap_or(letter as u8);
                    project_bits(rank, first, second)
                }),
            });
        }
    }
}
