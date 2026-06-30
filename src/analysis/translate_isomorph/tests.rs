//! Tests for the translate-isomorph scanner. These exercise the same library
//! functions the `isoscan` CLI handler calls, so the instrument and its
//! regression cannot drift.

use super::{DEFAULT_NULL_TRIALS, DEFAULT_TOP_K, IsoScanError, iso_scan, iso_scan_self_test};
use crate::nulls::null::{SplitMix64, random_index_below};

/// The planted positive control fires: the scanner recovers the planted repeat
/// and the matched null stays below it.
#[test]
fn self_test_recovers_planted_repeat() {
    let report = iso_scan_self_test(0x0011_2233_4455_6677).expect("self-test runs");
    assert!(
        report.passed,
        "planted repeat must be recovered above the null ceiling: {report:?}"
    );
    assert!(report.recovered_len >= report.planted_len);
    assert!(report.null_max_ceiling < report.planted_len);
}

/// A random (memoryless) stream has no repeat beyond the null floor — the gate
/// does not manufacture a false positive.
#[test]
fn random_stream_is_not_significant() {
    let mut rng = SplitMix64::new(0xABCD_0123_4567_89AB);
    let stream: Vec<u16> = (0..400)
        .map(|_| u16::try_from(random_index_below(5, &mut rng).expect("draw")).unwrap_or(0))
        .collect();
    let report = iso_scan(&stream, 5, None, DEFAULT_TOP_K, DEFAULT_NULL_TRIALS, 99).expect("scan");
    assert!(
        !report.significant,
        "a memoryless stream must not clear the matched null: {report:?}"
    );
    assert!(report.anchors.is_empty());
}

/// On the difference channel, a planted repeat in the *differences* (a repeated
/// additive-walk plaintext span) is recovered at the right gap and length.
#[test]
fn delta_channel_recovers_walk_repeat() {
    const MODULUS: usize = 3;
    const PLANT_LEN: usize = 28;
    let mut rng = SplitMix64::new(0x0BAD_F00D_DEAD_BEEF);
    let n = 360usize;
    // Random difference stream over 0..MODULUS.
    let mut diffs: Vec<u32> = (0..n)
        .map(|_| u32::try_from(random_index_below(MODULUS, &mut rng).expect("draw")).unwrap_or(0))
        .collect();
    // Plant an exact repeat block in the differences.
    let p1 = 30usize;
    let p2 = 200usize;
    let block: Vec<u32> = diffs
        .get(p1..p1 + PLANT_LEN)
        .map(<[u32]>::to_vec)
        .expect("source block in range");
    if let Some(slot) = diffs.get_mut(p2..p2 + PLANT_LEN) {
        slot.copy_from_slice(&block);
    }
    // Integrate to the raw stream (running sum mod MODULUS), so the difference
    // channel recovers `diffs` exactly.
    let mut values: Vec<u16> = Vec::with_capacity(n + 1);
    let mut acc = 0u32;
    values.push(0);
    for &d in &diffs {
        acc = (acc + d) % u32::try_from(MODULUS).unwrap_or(3);
        values.push(u16::try_from(acc).unwrap_or(0));
    }

    let report = iso_scan(
        &values,
        MODULUS,
        Some(MODULUS),
        DEFAULT_TOP_K,
        DEFAULT_NULL_TRIALS,
        7,
    )
    .expect("scan");
    assert!(
        report.significant,
        "planted walk repeat must be significant"
    );
    assert!(report.observed_max >= PLANT_LEN);
    // The anchor at the planted gap must cover the planted span. Its boundaries
    // may extend a symbol or two past the plant when a neighbouring difference
    // coincidentally matches, so assert containment, not exact endpoints.
    let anchor = report
        .anchors
        .iter()
        .find(|a| a.gap == p2 - p1)
        .expect("an anchor at the planted gap");
    assert!(anchor.length >= PLANT_LEN);
    assert!(anchor.first <= p1);
    assert!(anchor.first + anchor.length >= p1 + PLANT_LEN);
    assert_eq!(anchor.second, anchor.first + (p2 - p1));
}

/// The scan is deterministic in its seed.
#[test]
fn scan_is_deterministic() {
    let mut rng = SplitMix64::new(0xFEED_FACE_CAFE_0001);
    let stream: Vec<u16> = (0..300)
        .map(|_| u16::try_from(random_index_below(4, &mut rng).expect("draw")).unwrap_or(0))
        .collect();
    let a = iso_scan(&stream, 4, Some(4), DEFAULT_TOP_K, 64, 12345).expect("scan a");
    let b = iso_scan(&stream, 4, Some(4), DEFAULT_TOP_K, 64, 12345).expect("scan b");
    assert_eq!(a, b);
}

/// Degenerate inputs are rejected, not silently mis-scanned.
#[test]
fn rejects_degenerate_inputs() {
    assert_eq!(
        iso_scan(&[0, 1, 2], 0, None, 8, 16, 1),
        Err(IsoScanError::EmptyAlphabet)
    );
    assert_eq!(
        iso_scan(&[0, 1, 2, 3], 4, Some(0), 8, 16, 1),
        Err(IsoScanError::ZeroModulus)
    );
    // Two raw symbols project to a length-1 difference stream -> too short.
    assert_eq!(
        iso_scan(&[0, 1], 4, Some(4), 8, 16, 1),
        Err(IsoScanError::StreamTooShort { length: 1 })
    );
}
