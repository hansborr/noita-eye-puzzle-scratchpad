//! Tests for the crib-synchronous MDL-like affine codec instrument.

use crate::attack::cribfit::derive_crib_geometry;
use crate::attack::rlcodec::{derive_magnitudes, one_practice_digits};

use super::eval::{codec_cost_bits, text_cost_bits};
use super::grid::{AffineCell, affine_stream, canonical_pair, crib_consistent};
use super::{DEFAULT_SEED, mdlcodec_self_test};

fn one_geometry() -> crate::attack::cribfit::CribGeometry {
    let digits = one_practice_digits().expect("embedded one parses");
    let derivation = derive_magnitudes(&digits, 5).expect("one is a clean walk");
    derive_crib_geometry(&derivation.magnitudes, 8, 40, 0x6d64_6c63_0000_0001)
        .expect("geometry derives")
        .0
}

#[test]
fn crib_modular_check_agrees_with_cribfit_for_cumsum() {
    let geometry = one_geometry();
    let mdl_admissible = (1usize..=26)
        .filter(|&ring| crib_consistent(&geometry.anchors, AffineCell { ring, a: 1, b: 0 }))
        .collect::<Vec<_>>();
    assert_eq!(mdl_admissible, geometry.bit_periods);
    assert!(
        mdl_admissible.contains(&21),
        "a=1,b=0 must include cribfit's R=21 cumsum modulus"
    );
}

#[test]
fn affine_index_stream_is_deterministic() {
    let magnitudes = [1usize, 3, 2, 5, 1, 4, 2, 2];
    let cell = AffineCell {
        ring: 13,
        a: 2,
        b: 3,
    };
    let left = affine_stream(&magnitudes, cell);
    let right = affine_stream(&magnitudes, cell);
    assert_eq!(left.raw, right.raw);
    assert_eq!(left.dense, right.dense);
    assert_eq!(left.alphabet, right.alphabet);
}

#[test]
fn unit_scaled_coefficients_share_a_canonical_representative() {
    // 2 is a unit mod 11, so (2,4) is the same residue relabeling as (1,2).
    assert_eq!(canonical_pair(11, 1, 2), canonical_pair(11, 2, 4));
}

#[test]
fn mdl_accounting_uses_summed_nat_log_bits_and_effective_alphabet() {
    let five_bits = text_cost_bits(-5.0 * std::f64::consts::LN_2);
    assert!((five_bits - 5.0).abs() < 1e-9);
    assert!(codec_cost_bits(11, 100) > codec_cost_bits(10, 100));
    assert!(codec_cost_bits(10, 200) > codec_cost_bits(10, 100));
}

#[test]
fn planted_affine_round_trip_and_crib_check() {
    let symbols = [0usize, 1, 2, 0, 3, 1, 0, 1, 2, 0, 3, 1, 4, 2, 0];
    let ring = 7usize;
    let mut magnitudes = Vec::new();
    for pair in symbols.windows(2) {
        let [current, next] = pair else { continue };
        let diff = (*next + ring - *current) % ring;
        magnitudes.push(if diff == 0 { ring } else { diff });
    }
    magnitudes.push(1);

    let cell = AffineCell { ring, a: 1, b: 0 };
    let stream = affine_stream(&magnitudes, cell);
    assert_eq!(stream.raw, symbols);

    let plaintext = stream
        .raw
        .iter()
        .map(|&symbol| char::from(b'A'.saturating_add(u8::try_from(symbol).unwrap_or(0))))
        .collect::<String>();
    assert_eq!(plaintext, "ABCADBABCADBECA");

    let anchor = crate::attack::cribfit::AnchorPair {
        length: 6,
        first: 0,
        second: 6,
        run_gap: 6,
        bit_gap: magnitudes.iter().take(6).sum(),
    };
    assert!(crib_consistent(&[anchor], cell));
}

#[test]
fn self_test_passes() {
    let report = mdlcodec_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(report.passed(), "self-test must pass: {report:?}");
}
