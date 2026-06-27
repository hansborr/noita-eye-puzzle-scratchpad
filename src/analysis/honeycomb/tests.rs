use super::compute::{
    RowPair, chi_square_independence, lattice_for_grid, read_lattice_row_pair, stats_for_lattices,
};
use super::{HoneycombCoordinate, HoneycombParity, LatticeTrigram, MessageLattice};
use crate::analysis::orders::{self, GlyphGrid};
use crate::core::glyph::Orientation;
use crate::core::trigram::TrigramValue;

const FLOAT_EPSILON: f64 = 1.0e-12;

fn value(raw: u8) -> TrigramValue {
    TrigramValue::new(raw).unwrap()
}

fn assert_close(actual: f64, expected: f64, label: &str) {
    let difference = (actual - expected).abs();
    assert!(
        difference <= FLOAT_EPSILON,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e}"
    );
}

#[test]
fn lattice_flattening_reproduces_accepted_honeycomb_order() {
    let grids = orders::corpus_grids().unwrap();
    let order = orders::accepted_honeycomb_order();
    for grid in &grids {
        let lattice = lattice_for_grid(grid).unwrap();
        let flattened = lattice.flattened_values();
        let accepted = orders::read_grid_values(grid, order).unwrap();
        assert_eq!(flattened, accepted, "{}", grid.message_key());
    }
}

#[test]
fn row_pair_coordinates_follow_interlocking_triangle_geometry() {
    let grid = GlyphGrid::from_orientation_rows(
        "fixture",
        vec![
            vec![
                Orientation::Zero,
                Orientation::One,
                Orientation::Two,
                Orientation::Three,
                Orientation::Four,
                Orientation::Zero,
            ],
            vec![
                Orientation::One,
                Orientation::Two,
                Orientation::Three,
                Orientation::Four,
                Orientation::Zero,
                Orientation::One,
            ],
        ],
    );
    let mut sequence_index = 0;
    let trigrams = read_lattice_row_pair(
        &grid,
        RowPair {
            upper_row: 0,
            lower_row: 1,
            band: 0,
        },
        crate::analysis::orders::TrigramPermutation::IDENTITY,
        crate::analysis::orders::TrigramPermutation::IDENTITY,
        &mut sequence_index,
    )
    .unwrap();

    let observed: Vec<(usize, HoneycombParity, u8)> = trigrams
        .iter()
        .map(|trigram| {
            (
                trigram.coordinate.pos_in_band,
                trigram.coordinate.parity,
                trigram.value.get(),
            )
        })
        .collect();
    assert_eq!(
        observed,
        vec![
            (0, HoneycombParity::Upper, 6),
            (1, HoneycombParity::Lower, 87),
            (2, HoneycombParity::Upper, 99),
            (3, HoneycombParity::Lower, 25),
        ]
    );
    assert_eq!(sequence_index, 4);
}

#[test]
fn statistics_cover_vertical_position_and_parity_signals() {
    let lattice = MessageLattice {
        message_key: "fixture",
        bands: vec![
            vec![
                trigram(0, 0, HoneycombParity::Upper, 0, 0),
                trigram(0, 1, HoneycombParity::Lower, 1, 80),
                trigram(0, 2, HoneycombParity::Upper, 2, 0),
            ],
            vec![
                trigram(1, 0, HoneycombParity::Upper, 3, 0),
                trigram(1, 1, HoneycombParity::Lower, 4, 81),
                trigram(1, 2, HoneycombParity::Upper, 5, 40),
            ],
        ],
    };
    let stats = stats_for_lattices(&[lattice]);

    assert_eq!(stats.total_trigrams, 6);
    assert_eq!(stats.vertical.pairs, 3);
    assert_eq!(stats.vertical.exact_equal, 1);
    assert_close(
        stats.vertical.exact_equal_rate,
        1.0 / 3.0,
        "vertical equality",
    );
    assert_close(
        stats.vertical.mean_abs_diff,
        41.0 / 3.0,
        "vertical mean diff",
    );
    assert_eq!(stats.position_conditioning.total, 6);
    assert_eq!(stats.position_conditioning.positions, 3);
    assert!(stats.position_conditioning.chi_square > 0.0);
    assert_eq!(stats.parity_split.upper_total, 4);
    assert_eq!(stats.parity_split.lower_total, 2);
    assert!(stats.parity_split.chi_square > 0.0);
    assert!(stats.parity_split.ioc_abs_diff > 0.0);
}

#[test]
fn independence_statistic_matches_manual_two_by_two_case() {
    let table = vec![vec![8, 2], vec![2, 8]];
    let stats = chi_square_independence(&table);

    assert_eq!(stats.total, 20);
    assert_eq!(stats.rows, 2);
    assert_eq!(stats.columns, 2);
    assert_eq!(stats.degrees_of_freedom, 1);
    assert_close(stats.chi_square, 7.2, "chi-square");
}

#[test]
fn real_eye_lattice_headline_numbers_are_pinned() {
    let grids = orders::corpus_grids().unwrap();
    let lattices = super::lattices_for_grids(&grids).unwrap();
    let stats = stats_for_lattices(&lattices);

    assert_eq!(stats.total_trigrams, 1036);
    assert_eq!(stats.vertical.pairs, 802);
    assert_eq!(stats.vertical.exact_equal, 13);
    assert_close(
        stats.vertical.exact_equal_rate,
        0.016_209_476_309_226_933,
        "real vertical equality rate",
    );
    assert_close(
        stats.vertical.mean_abs_diff,
        26.862_842_892_768_08,
        "real vertical mean absolute difference",
    );
    assert_eq!(stats.sequence_distance_control.pairs, 802);
    assert_eq!(stats.sequence_distance_control.exact_equal, 13);
    assert_close(
        stats.sequence_distance_control.exact_equal_rate,
        stats.vertical.exact_equal_rate,
        "same-lag control equality rate",
    );
    assert_close(
        stats.sequence_distance_control.mean_abs_diff,
        stats.vertical.mean_abs_diff,
        "same-lag control mean absolute difference",
    );
    assert_eq!(stats.position_conditioning.total, 1036);
    assert_eq!(stats.position_conditioning.positions, 26);
    assert_eq!(stats.position_conditioning.value_deciles, 7);
    assert_eq!(stats.position_conditioning.degrees_of_freedom, 150);
    assert_close(
        stats.position_conditioning.chi_square,
        260.202_406_109_249_75,
        "real position chi-square",
    );
    assert_eq!(stats.parity_split.upper_total, 520);
    assert_eq!(stats.parity_split.lower_total, 516);
    assert_eq!(stats.parity_split.degrees_of_freedom, 82);
    assert_close(
        stats.parity_split.chi_square,
        113.161_658_646_215_14,
        "real parity chi-square",
    );
    assert_close(
        stats.parity_split.upper_ioc,
        0.013_250_333_481_547_354,
        "real upper IoC",
    );
    assert_close(
        stats.parity_split.lower_ioc,
        0.013_637_389_930_006_773,
        "real lower IoC",
    );
    assert_close(
        stats.parity_split.ioc_abs_diff,
        0.000_387_056_448_459_419_1,
        "real parity IoC divergence",
    );
}

fn trigram(
    band: usize,
    pos_in_band: usize,
    parity: HoneycombParity,
    sequence_index: usize,
    raw_value: u8,
) -> LatticeTrigram {
    LatticeTrigram {
        coordinate: HoneycombCoordinate {
            band,
            pos_in_band,
            parity,
            sequence_index,
        },
        value: value(raw_value),
    }
}
