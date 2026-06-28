use super::{
    KeystreamCandidate, KeystreamFamily, KeystreamSearchConfig, PracticePuzzle, crack,
    crack_with_model, decrypt, encrypt, normalize_puzzle, practice_puzzle_text,
    write_keystream_record,
};
use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::SplitMix64;

// ~265 letters of plain English (lots of common quadgrams), used as the
// planted-recovery corpus. Real prose, not a slice of any committed corpus.
const PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning sun \
    rises slowly above the quiet little village near the river where children often play \
    together after school and the old baker prepares fresh bread for everyone who passes by \
    his small wooden shop on the corner of the street that leads down toward the harbor";

fn random_residues(len: usize, n: usize, rng: &mut SplitMix64) -> Vec<u8> {
    (0..len)
        .map(|_| (rng.next_u64() % n as u64) as u8)
        .collect()
}

fn match_fraction(expected: &[u8], actual: &[u8]) -> f64 {
    let matches = expected
        .iter()
        .zip(actual)
        .filter(|(left, right)| left == right)
        .count();
    matches as f64 / expected.len().max(1) as f64
}

#[test]
fn round_trip_each_family() {
    let mut rng = SplitMix64::new(0x_a11ce);
    for &n in &[5usize, 26, 29] {
        for l in 1..=6usize {
            let data = random_residues(120, n, &mut rng);
            let key = random_residues(l, n, &mut rng);
            for &family in &KeystreamFamily::all() {
                let cipher = encrypt(family, &data, &key, n);
                let plain = decrypt(family, &cipher, &key, n);
                assert_eq!(
                    plain, data,
                    "decrypt(encrypt) failed: {family:?} n={n} l={l}"
                );
                // encrypt(decrypt(c)) == c for every key (the round-trip gate).
                let recipher = encrypt(family, &plain, &key, n);
                assert_eq!(
                    recipher, cipher,
                    "encrypt(decrypt) failed: {family:?} n={n} l={l}"
                );
            }
        }
    }
}

#[test]
fn empty_key_is_a_no_op() {
    let data = vec![1u8, 2, 3, 25, 0];
    for &family in &KeystreamFamily::all() {
        let cipher = encrypt(family, &data, &[], 26);
        assert_eq!(cipher, data);
        assert_eq!(decrypt(family, &cipher, &[], 26), data);
    }
}

#[test]
fn planted_recovery_searchable_families() {
    let model = QuadgramModel::english().unwrap();
    let plain = normalize_puzzle(PLAINTEXT);
    assert!(
        plain.len() >= 250,
        "planted corpus too short: {}",
        plain.len()
    );
    let n = 26usize;
    let key = vec![3u8, 15, 8, 20, 13]; // L = 5, within 5..=8
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 20,
        iterations: 4_000,
        anneal_temp: 1.0,
        seed: 0x00C0_FFEE,
        null_trials: 40,
        // Small matched null: the true cipher still clears it (a true cipher
        // of real English decrypts to ~-10.x while the matched null overfits
        // shuffled ciphertext only to ~-12.x), and it keeps `make verify` fast.
        matched_null_trials: 4,
    };
    // CiphertextAutokey is excluded here: it is key-independent for i>=L, so a
    // long plaintext cannot beat a random-key null — see the dedicated test.
    for &family in &[
        KeystreamFamily::Vigenere,
        KeystreamFamily::Beaufort,
        KeystreamFamily::PlaintextAutokey,
    ] {
        let cipher = encrypt(family, &plain, &key, n);
        let candidate = crack_with_model(&cipher, family, key.len(), &cfg, &model);
        let fraction = match_fraction(&plain, &candidate.decrypt);
        assert!(
            fraction >= 0.95,
            "{family:?} recovered only {:.1}% (z={:.2})",
            fraction * 100.0,
            candidate.z
        );
        assert!(
            candidate.survives,
            "{family:?} did not survive the matched-null gate \
             (matched_z={:.2} matched_margin={:.3} matched_mean={:.3} heldout={:.3} best={:.3})",
            candidate.matched_z,
            candidate.best_score - candidate.matched_mean,
            candidate.matched_mean,
            candidate.heldout_score,
            candidate.best_score
        );
    }
}

#[test]
fn planted_decode_survives_full_gate() {
    // Regression for the held-out gate miscalibration (T1): the gate must compare
    // the candidate's odd-index held-out fold against the matched null's held-out
    // fold (`matched_heldout_mean`), not the full-stream `matched_mean`. A fold of
    // English is not contiguous English, so it scores below the full stream; the
    // old fold-vs-full-stream comparison could falsely fail a perfectly recovered
    // decode. A planted true decode must clear the corrected gate.
    let model = QuadgramModel::english().unwrap();
    let plain = normalize_puzzle(PLAINTEXT);
    assert!(
        plain.len() >= 250,
        "planted corpus too short: {}",
        plain.len()
    );
    let n = 26usize;
    let key = vec![3u8, 15, 8, 20, 13];
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 20,
        iterations: 4_000,
        anneal_temp: 1.0,
        seed: 0x00C0_FFEE,
        null_trials: 40,
        matched_null_trials: 4,
    };
    let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, n);
    let candidate = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
    assert!(
        candidate.round_trip_ok,
        "round-trip is an algebraic identity"
    );
    assert!(
        candidate.beats_matched_null,
        "planted decode failed matched-null (best={:.3} matched_mean={:.3} matched_z={:.2})",
        candidate.best_score, candidate.matched_mean, candidate.matched_z
    );
    // The corrected (fold-vs-fold) held-out comparison.
    assert!(
        candidate.heldout_score > candidate.matched_heldout_mean,
        "held-out fold must beat the matched null's held-out fold \
         (heldout={:.3} matched_heldout_mean={:.3})",
        candidate.heldout_score,
        candidate.matched_heldout_mean
    );
    assert!(
        candidate.heldout_ok,
        "planted decode failed held-out (heldout={:.3} matched_heldout_mean={:.3})",
        candidate.heldout_score, candidate.matched_heldout_mean
    );
    assert!(
        candidate.survives,
        "a recovered planted decode must survive the gate (else the gate is too strict)"
    );
}

#[test]
fn ciphertext_autokey_recovers_bulk_but_honestly_does_not_survive() {
    // Ciphertext-autokey decryption is key-independent for i>=L
    // (p_i = c_i - c_{i-L}, the classic ciphertext-autokey leak). On a long
    // plaintext the bulk decrypts correctly regardless of the primer guess —
    // and for the same reason the random-key null also reads as English, so
    // best_score cannot clear MIN_NAT_MARGIN above it (beats_null == false).
    // The matched null does not police this: it shuffles the ciphertext, which
    // destroys the leak, so it would (wrongly) promote ct-autokey on its own —
    // which is exactly why survival keeps requiring the random-key null too.
    // This proves the gate does not manufacture a survivor from a key-leaking
    // cipher.
    let model = QuadgramModel::english().unwrap();
    let plain = normalize_puzzle(PLAINTEXT);
    let n = 26usize;
    let key = vec![3u8, 15, 8, 20, 13];
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 20,
        iterations: 4_000,
        anneal_temp: 1.0,
        seed: 0x00C0_FFEE,
        null_trials: 40,
        // Small matched null: the true cipher still clears it (a true cipher
        // of real English decrypts to ~-10.x while the matched null overfits
        // shuffled ciphertext only to ~-12.x), and it keeps `make verify` fast.
        matched_null_trials: 4,
    };
    let cipher = encrypt(KeystreamFamily::CiphertextAutokey, &plain, &key, n);
    let candidate = crack_with_model(
        &cipher,
        KeystreamFamily::CiphertextAutokey,
        key.len(),
        &cfg,
        &model,
    );
    // The key-independent tail (>=95% of positions) is recovered for free.
    assert!(
        match_fraction(&plain, &candidate.decrypt) >= 0.95,
        "ct-autokey failed to recover the key-independent bulk"
    );
    assert!(candidate.round_trip_ok);
    assert!(
        !candidate.survives,
        "ct-autokey unexpectedly survived on a long plaintext \
         (matched_margin={:.3} matched_z={:.2})",
        candidate.best_score - candidate.matched_mean,
        candidate.matched_z
    );
}

#[test]
fn random_ciphertext_yields_no_survivor() {
    let model = QuadgramModel::english().unwrap();
    let mut rng = SplitMix64::new(0x_dead_beef);
    let n = 26usize;
    let cipher = random_residues(220, n, &mut rng);
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 12,
        iterations: 3_000,
        anneal_temp: 1.0,
        seed: 0x0000_5151,
        null_trials: 40,
        matched_null_trials: 4,
    };
    for &family in &KeystreamFamily::all() {
        for key_len in [1usize, 3, 5] {
            let candidate = crack_with_model(&cipher, family, key_len, &cfg, &model);
            assert!(
                !candidate.survives,
                "noise survived: {family:?} l={key_len} (matched_z={:.2} matched_margin={:.3})",
                candidate.matched_z,
                candidate.best_score - candidate.matched_mean
            );
        }
    }
}

#[test]
fn matched_null_rejects_overfitting_at_high_key_len() {
    // Regression for the false-positive bug. At a high key length the annealed
    // search overfits short random ciphertext (many free key parameters),
    // reaching a best score whose z against the no-search random-key null
    // clears the gate — so the old (random-key-only) survival verdict promoted
    // pure noise (beats_null == true below). The matched null reruns the same
    // search on shuffled copies of the same ciphertext, so it overfits just as
    // hard; the real result no longer clears it (beats_matched_null == false).
    // This test fails under the old gate and passes under the matched-null fix.
    let model = QuadgramModel::english().unwrap();
    let mut rng = SplitMix64::new(0x_0ddc_0ffe_e000_1234);
    let n = 26usize;
    let cipher = random_residues(274, n, &mut rng);
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 12,
        iterations: 8_000,
        anneal_temp: 1.0,
        seed: 0x00BA_DBED,
        null_trials: 16,
        matched_null_trials: 4,
    };
    let mut random_key_null_was_fooled = false;
    for key_len in [60usize, 80] {
        let candidate = crack_with_model(&cipher, KeystreamFamily::Vigenere, key_len, &cfg, &model);
        // The matched null (the fix) is not fooled: the search's best on real
        // random ciphertext is no higher than what the same search extracts
        // from the shuffled multiset, so it cannot clear the matched gate.
        assert!(
            !candidate.beats_matched_null,
            "overfit beat the matched null at L={key_len} \
             (best={:.3} matched_mean={:.3} matched_z={:.2})",
            candidate.best_score, candidate.matched_mean, candidate.matched_z
        );
        assert!(
            !candidate.survives,
            "overfit survived at L={key_len} (matched_z={:.2} matched_margin={:.3})",
            candidate.matched_z,
            candidate.best_score - candidate.matched_mean
        );
        // The random-key null (the old gate) is fooled on its headline z: pure
        // noise clears Z_THRESHOLD against it — the exact false positive the
        // matched null now catches.
        assert!(
            candidate.z >= super::Z_THRESHOLD,
            "expected the random-key null z to be fooled at L={key_len}, got z={:.2}",
            candidate.z
        );
        if candidate.beats_null {
            random_key_null_was_fooled = true;
        }
    }
    assert!(
        random_key_null_was_fooled,
        "expected the random-key null to FULLY pass on pure noise for at least \
         one high key length (the false positive the matched null fixes)"
    );
}

#[test]
fn deterministic_for_fixed_seed() {
    let model = QuadgramModel::english().unwrap();
    let plain = normalize_puzzle(PLAINTEXT);
    let n = 26usize;
    let key = vec![1u8, 2, 3, 4];
    let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, n);
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 5,
        iterations: 1_000,
        anneal_temp: 0.5,
        seed: 0x0000_0777,
        null_trials: 10,
        matched_null_trials: 4,
    };
    let first = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
    let second = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
    assert_eq!(first.key, second.key);
    assert_eq!(first.best_score.to_bits(), second.best_score.to_bits());
    assert_eq!(first.z.to_bits(), second.z.to_bits());
    // Matched-null stats (and the verdict they drive) are deterministic too.
    assert_eq!(first.matched_mean.to_bits(), second.matched_mean.to_bits());
    assert_eq!(first.matched_std.to_bits(), second.matched_std.to_bits());
    assert_eq!(
        first.matched_heldout_mean.to_bits(),
        second.matched_heldout_mean.to_bits()
    );
    assert_eq!(first.matched_z.to_bits(), second.matched_z.to_bits());
    assert_eq!(first.beats_matched_null, second.beats_matched_null);
    assert_eq!(first.survives, second.survives);
    assert_eq!(first.decrypt, second.decrypt);
}

#[test]
fn practice_puzzles_normalize_to_letters() {
    for puzzle in [
        PracticePuzzle::Three,
        PracticePuzzle::Four,
        PracticePuzzle::Five,
        PracticePuzzle::Seven,
    ] {
        let indices = normalize_puzzle(practice_puzzle_text(puzzle));
        assert!(!indices.is_empty(), "{puzzle:?} parsed to no letters");
        assert!(
            indices.iter().all(|&v| v < 26),
            "{puzzle:?} produced a non-letter index"
        );
    }
    // The seven puzzle's `#` markers are dropped (not letters).
    assert!(
        !practice_puzzle_text(PracticePuzzle::Seven).contains('A')
            || normalize_puzzle("A#B") == vec![0u8, 1u8]
    );
}

#[test]
fn crack_builds_model_and_renders_letters() {
    let plain = normalize_puzzle(PLAINTEXT);
    let key = vec![5u8, 9, 2];
    let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, 26);
    let cfg = KeystreamSearchConfig {
        restarts: 3,
        iterations: 500,
        ..KeystreamSearchConfig::default()
    };
    let candidate = crack(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg).unwrap();
    assert_eq!(candidate.family, KeystreamFamily::Vigenere);
    assert_eq!(candidate.key_len, 3);
    assert!(
        candidate
            .render_plaintext()
            .chars()
            .all(|ch| ch.is_ascii_uppercase())
    );
}

#[test]
fn record_writer_emits_hypothesis_label() {
    let candidate = KeystreamCandidate {
        family: KeystreamFamily::Vigenere,
        key_len: 3,
        key: vec![1, 2, 3],
        best_score: -10.0,
        null_mean: -14.0,
        null_std: 0.2,
        z: 20.0,
        matched_mean: -12.0,
        matched_std: 0.2,
        matched_z: 10.0,
        round_trip_ok: true,
        heldout_score: -11.0,
        matched_heldout_mean: -12.5,
        beats_null: true,
        beats_matched_null: true,
        heldout_ok: true,
        survives: true,
        decrypt: vec![0, 1, 2],
    };
    let dir = std::env::temp_dir().join(format!("noita-keystream-rec-{}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    let path = write_keystream_record(&dir, "unit", 0x1234, &candidate).unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains("hypothesis, not a decode"));
    assert!(body.contains("vigenere"));
    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn frozen_bits_anti_drift_baseline() {
    // Anti-drift pin (Report 03 consolidation): a uniform RNG-stream shift in the
    // shared `attack::crack` matched-null loop is invisible to the determinism and
    // planted/honest-negative tests but would change these frozen f64 bits. The
    // whole-struct assert_eq is bit-exact here (every frozen float is finite and
    // non-zero, so PartialEq coincides with .to_bits() equality).
    let model = QuadgramModel::english().unwrap();
    let plain = normalize_puzzle("the quick brown fox jumps over the lazy dog");
    let n = 26usize;
    let key = vec![3u8, 15, 8];
    let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, n);
    let cfg = KeystreamSearchConfig {
        alphabet_size: n,
        restarts: 4,
        iterations: 600,
        anneal_temp: 1.0,
        seed: 0x00C0_FFEE,
        null_trials: 8,
        matched_null_trials: 3,
    };
    let candidate = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
    let expected = KeystreamCandidate {
        family: KeystreamFamily::Vigenere,
        key_len: 3,
        key: vec![20, 21, 1],
        best_score: f64::from_bits(0xc02a_a1d1_5000_0000),
        null_mean: f64::from_bits(0xc02c_c7ce_abe0_0000),
        null_std: f64::from_bits(0x3fd4_d649_19db_972b),
        z: f64::from_bits(0x400a_6511_1ac3_1436),
        matched_mean: f64::from_bits(0xc02a_85e6_4300_0000),
        matched_std: f64::from_bits(0x3fc6_070f_ce59_eb28),
        matched_z: f64::from_bits(0xbfd4_4758_8c3f_55b6),
        round_trip_ok: true,
        heldout_score: f64::from_bits(0xc02d_760f_9924_9249),
        matched_heldout_mean: f64::from_bits(0xc02b_e17a_e6db_6db7),
        beats_null: false,
        beats_matched_null: false,
        heldout_ok: false,
        survives: false,
        decrypt: vec![
            2, 1, 11, 25, 14, 15, 11, 4, 8, 0, 8, 3, 22, 25, 21, 6, 3, 1, 21, 9, 25, 23, 15, 11, 0,
            13, 14, 13, 5, 7, 8, 18, 10, 23, 0,
        ],
    };
    assert_eq!(
        candidate, expected,
        "keystream candidate drifted from the frozen baseline"
    );
}

#[test]
fn render_record_full_body_is_byte_stable() {
    // Full-body pin: the entire record body (the invariant decrypt block now in
    // `attack::crack`, plus the bespoke keystream lines) must stay byte-identical
    // for a survivor and a non-survivor.
    let survivor = KeystreamCandidate {
        family: KeystreamFamily::Vigenere,
        key_len: 3,
        key: vec![1, 2, 3],
        best_score: -10.0,
        null_mean: -14.0,
        null_std: 0.2,
        z: 20.0,
        matched_mean: -12.0,
        matched_std: 0.2,
        matched_z: 10.0,
        round_trip_ok: true,
        heldout_score: -11.0,
        matched_heldout_mean: -12.5,
        beats_null: true,
        beats_matched_null: true,
        heldout_ok: true,
        survives: true,
        decrypt: vec![0, 1, 2],
    };
    let expected_survivor = r"# Keystream candidate record: unit

Stable label (no wall-clock): label=unit seed=0x0000000000001234 family=vigenere key-len=3

## Verdict

**candidate survived all gates (round-trip + matched-null + random-key-null + held-out) — logged as a hypothesis, not a decode.**

## Gates (never collapsed)

Survival requires both nulls plus round-trip and held-out. The matched null (the same annealed search rerun on Fisher-Yates shuffled ciphertext, holding the unigram multiset fixed and destroying higher-order structure) polices search overfitting. The random-key null (random keys on the un-shuffled ciphertext) polices the ciphertext-autokey key-independence leak, which the matched null cannot see. Neither alone is sufficient.

- round_trip_ok: true
- best_score: -10.000000
- matched_mean: -12.000000  matched_std: 0.200000  matched_z: 10.0000
- beats_matched_null [survival gate: overfitting] (z >= 6 and margin >= 1): true
- null_mean: -14.000000  null_std: 0.200000  z: 20.0000
- beats_null [survival gate: key-independence leak] (z >= 6 and margin >= 1): true
- heldout_score: -11.000000  matched_heldout_mean: -12.500000  heldout_ok (> matched_heldout_mean): true

## Recovered key (letter indices)

[1, 2, 3]

## Decrypt (hypothesis, not a decode)

ABC
";
    assert_eq!(
        super::render_record("unit", 0x1234, &survivor).unwrap(),
        expected_survivor
    );

    let non_survivor = KeystreamCandidate {
        family: KeystreamFamily::Beaufort,
        key_len: 4,
        key: vec![5, 6, 7, 8],
        best_score: -13.25,
        null_mean: -13.5,
        null_std: 0.4,
        z: 0.625,
        matched_mean: -13.0,
        matched_std: 0.3,
        matched_z: -0.8333,
        round_trip_ok: true,
        heldout_score: -14.0,
        matched_heldout_mean: -13.75,
        beats_null: false,
        beats_matched_null: false,
        heldout_ok: false,
        survives: false,
        decrypt: vec![25, 24, 23, 22],
    };
    let expected_non_survivor = r"# Keystream candidate record: probe

Stable label (no wall-clock): label=probe seed=0x000000000000feed family=beaufort key-len=4

## Verdict

**no surviving candidate — decode remains blocked.**

## Gates (never collapsed)

Survival requires both nulls plus round-trip and held-out. The matched null (the same annealed search rerun on Fisher-Yates shuffled ciphertext, holding the unigram multiset fixed and destroying higher-order structure) polices search overfitting. The random-key null (random keys on the un-shuffled ciphertext) polices the ciphertext-autokey key-independence leak, which the matched null cannot see. Neither alone is sufficient.

- round_trip_ok: true
- best_score: -13.250000
- matched_mean: -13.000000  matched_std: 0.300000  matched_z: -0.8333
- beats_matched_null [survival gate: overfitting] (z >= 6 and margin >= 1): false
- null_mean: -13.500000  null_std: 0.400000  z: 0.6250
- beats_null [survival gate: key-independence leak] (z >= 6 and margin >= 1): false
- heldout_score: -14.000000  matched_heldout_mean: -13.750000  heldout_ok (> matched_heldout_mean): false

## Recovered key (letter indices)

[5, 6, 7, 8]

## Decrypt (hypothesis, not a decode)

ZYXW
";
    assert_eq!(
        super::render_record("probe", 0xfeed, &non_survivor).unwrap(),
        expected_non_survivor
    );
}
