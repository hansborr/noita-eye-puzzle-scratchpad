//! Tests for the `codecpower` calibration instrument.

use crate::attack::rlcodec::{
    BatteryCfg, DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE, PLANT_PLAINTEXT, RlCodec, derive_magnitudes,
    encode_comma, english_letters, partition_of,
};

use super::{PowerCfg, codecpower_self_test, measure_power};

fn size_control_cfg(seed: u64) -> PowerCfg {
    PowerCfg {
        source_letters: english_letters(PLANT_PLAINTEXT),
        lengths: vec![8, 64],
        trials: 3,
        sep: DEFAULT_COMMA_SEP,
        base: DEFAULT_PLANT_BASE,
        power_threshold: 0.8,
        gate: BatteryCfg {
            null_trials: 20,
            restarts: 8,
            iters: 1_000,
            top_k: 0,
            census_null_trials: 0,
            seed,
        },
    }
}

fn glyph_hash(digits: &[crate::core::glyph::Glyph]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325u64;
    for digit in digits {
        state ^= u64::from(digit.0);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state
}

#[test]
fn encode_comma_round_trips_through_comma_decoder() {
    let letters = vec![19usize, 7, 4, 17, 0, 8, 13, 19, 7, 4, 17, 14, 0, 3];
    let digits = encode_comma(&letters, DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE);
    let derivation = derive_magnitudes(&digits, DEFAULT_PLANT_BASE).expect("plant derives");
    let decoded = RlCodec::Comma {
        sep: DEFAULT_COMMA_SEP,
    }
    .decode(&derivation.magnitudes);
    assert_eq!(decoded, Some(partition_of(&letters)));
}

#[test]
fn promoted_encoder_preserves_selftest_plant_bytes() {
    let letters = english_letters(PLANT_PLAINTEXT);
    let digits = encode_comma(&letters, DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE);
    let derivation = derive_magnitudes(&digits, DEFAULT_PLANT_BASE).expect("plant derives");
    assert_eq!(
        (
            letters.len(),
            digits.len(),
            derivation.magnitudes.len(),
            glyph_hash(&digits),
        ),
        (285, 2079, 755, 0x8a22_6096_a97d_ccae)
    );
}

#[test]
fn self_test_passes_and_power_rises_with_length() {
    let report = codecpower_self_test(0xc0de_c001_0000_0003).expect("self-test runs");
    assert!(
        report.passed(),
        "directional planted controls should pass: {report:?}"
    );
    assert!(
        report.long_power > report.short_power,
        "long plants should be easier to detect: {report:?}"
    );
}

#[test]
fn non_english_size_control_stays_low() {
    let report =
        measure_power(&size_control_cfg(0xc0de_c001_0000_0002)).expect("power run succeeds");
    assert!(
        report.false_positive_rate <= 0.10,
        "uniform-letter control should stay near alpha: {report:?}"
    );
}
