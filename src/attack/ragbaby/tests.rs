use super::{
    ControlConfig, Numbering, RagbabyCandidate, RagbabyProblem, RagbabySearchConfig, Sign,
    best_decryption, char_accuracy, control_sweep, crack_with_model, decrypt_indices, decrypt_str,
    encrypt_indices, encrypt_str, keep_for_base, key_numbers, prepare, random_keyed_alphabet,
    write_ragbaby_record,
};
use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::SplitMix64;

// The worked-example keyed alphabet pinning the ACA std-numbering convention.
const WORKED_KEY: &str = "CRYPTOABDEFGHIJKLMNQSUVWXZ";

// ~270 letters of plain English prose (real prose, not a slice of the corpus),
// used where recovery is NOT required (random-text null, determinism).
const PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning sun \
    rises slowly above the quiet little village near the river where children often play \
    together after school and the old baker prepares fresh bread for everyone who passes by \
    his small wooden shop on the corner of the street that leads down toward the harbor";

// ~600 letters of plain English prose for the planted-recovery test. Keyed
// alphabet recovery sharpens with length, so the longer excerpt recovers
// reliably at a modest (debug-affordable) search budget.
const LONG_PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning \
    sun rises slowly above the quiet little village near the river where children often play \
    together after school and the old baker prepares fresh bread for everyone who passes by \
    his small wooden shop on the corner of the street that leads down toward the harbor where \
    fishing boats return each evening with their heavy nets and the salt wind carries the sound \
    of gulls across the water as families gather along the shore to share warm meals and quiet \
    stories before the early stars appear above the gentle hills that frame the sleepy town in \
    the fading golden light of another calm and ordinary autumn day beside the northern sea";

#[test]
fn worked_example_vector_and_round_trip() {
    let ciphertext = encrypt_str("THE CAT", WORKED_KEY, Numbering::Std, Sign::Plus, 26);
    assert_eq!(
        ciphertext, "OJH YED",
        "ACA std worked example must pin to OJH YED"
    );
    let back = decrypt_str(&ciphertext, WORKED_KEY, Numbering::Std, Sign::Plus, 26);
    assert_eq!(back, "THE CAT", "string-form decrypt must round-trip");
}

#[test]
fn round_trip_all_bases() {
    let text = "THE QUICK BROWN FOX JUMPED OVER A VERY LAZY DOG NEAR JADED RIVERS";
    let mut rng = SplitMix64::new(0x00A9_0BA8);
    for &base in &[24usize, 25, 26] {
        let keep = keep_for_base(base);
        let key = random_keyed_alphabet(&keep, &mut rng);
        for &sign in &[Sign::Plus, Sign::Minus] {
            let (plain_idx, nums) = prepare(text, Numbering::Std, base);
            let cipher = encrypt_indices(&plain_idx, &nums, &key, sign.value(), base);
            let back = decrypt_indices(&cipher, &nums, &key, sign.value(), base);
            assert_eq!(
                back,
                plain_idx,
                "index round-trip failed at base {base} sign {}",
                sign.label()
            );
        }
    }
}

#[test]
fn numbering_conventions_match_documented_sequences() {
    // Two words "THE" (len 3) and "CAT" (len 3).
    let text = "THE CAT";
    assert_eq!(
        key_numbers(text, Numbering::Std),
        vec![1, 2, 3, 2, 3, 4],
        "std: word w, k-th letter -> w + (k - 1)"
    );
    assert_eq!(
        key_numbers(text, Numbering::PerWord),
        vec![1, 2, 3, 1, 2, 3],
        "perword: each word numbered 1.."
    );
    assert_eq!(
        key_numbers(text, Numbering::Continuous),
        vec![1, 2, 3, 4, 5, 6],
        "continuous: 1.. across the whole text"
    );
}

#[test]
fn planted_recovery_recovers_random_alphabet_base26() {
    let model = QuadgramModel::english().unwrap();
    let base = 26usize;
    let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
    assert!(
        plain_idx.len() >= 200,
        "planted plaintext too short: {}",
        plain_idx.len()
    );
    let keep = keep_for_base(base);
    let mut rng = SplitMix64::new(0x_01A4_7ED0);
    let planted = random_keyed_alphabet(&keep, &mut rng);
    let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
    // Recovery sharpens with length: a ~600-letter planted Ragbaby is recovered
    // by a low-restart anneal (debug-affordable). Nulls disabled — this is a
    // single multi-restart anneal.
    let cfg = RagbabySearchConfig {
        restarts: 8,
        iterations: 6_000,
        basin_hops: 2,
        seed: 0x00C0_FFEE,
        null_trials: 0,
        matched_null_trials: 0,
        ..RagbabySearchConfig::default()
    };
    let problem = RagbabyProblem {
        cipher: &cipher,
        nums: &nums,
        base,
        sign: Sign::Plus,
        numbering: Numbering::Std,
    };
    let recovered = best_decryption(&problem, &cfg, &model);
    let accuracy = char_accuracy(&recovered, &plain_idx);
    assert!(
        accuracy >= 0.9,
        "optimizer recovered only {:.1}% of a planted base-26 Ragbaby",
        accuracy * 100.0
    );
}

#[test]
fn planted_recovery_recovers_reduced_bases() {
    // The base-24/25 real-letter-index path (J->I, V->U folding) is the
    // highest-risk arithmetic; a planted reduced-base Ragbaby must also recover.
    let model = QuadgramModel::english().unwrap();
    for base in [25usize, 24] {
        let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
        let keep = keep_for_base(base);
        let mut rng = SplitMix64::new(0x_0BA5_E024 ^ base as u64);
        let planted = random_keyed_alphabet(&keep, &mut rng);
        let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
        let cfg = RagbabySearchConfig {
            restarts: 8,
            iterations: 6_000,
            basin_hops: 2,
            seed: 0x00C0_FFEE,
            null_trials: 0,
            matched_null_trials: 0,
            ..RagbabySearchConfig::default()
        };
        let problem = RagbabyProblem {
            cipher: &cipher,
            nums: &nums,
            base,
            sign: Sign::Plus,
            numbering: Numbering::Std,
        };
        let recovered = best_decryption(&problem, &cfg, &model);
        let accuracy = char_accuracy(&recovered, &plain_idx);
        assert!(
            accuracy >= 0.9,
            "optimizer recovered only {:.1}% of a planted base-{base} Ragbaby",
            accuracy * 100.0
        );
    }
}

#[test]
fn planted_decode_survives_full_gate() {
    // The positive control for the GATE itself (not just the optimizer): a
    // planted Ragbaby decode, recovered and run through the full survival gate,
    // MUST survive. Regression test for the held-out miscalibration — comparing
    // the odd-fold to the full-stream `matched_mean` (instead of the matched
    // null's odd-fold) falsely failed even a perfectly recovered decode.
    let model = QuadgramModel::english().unwrap();
    let base = 26usize;
    let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
    let keep = keep_for_base(base);
    let mut rng = SplitMix64::new(0x_5EED_60D5);
    let planted = random_keyed_alphabet(&keep, &mut rng);
    let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
    let cfg = RagbabySearchConfig {
        restarts: 8,
        iterations: 6_000,
        basin_hops: 2,
        seed: 0x00C0_FFEE,
        null_trials: 16,
        matched_null_trials: 4,
        ..RagbabySearchConfig::default()
    };
    let problem = RagbabyProblem {
        cipher: &cipher,
        nums: &nums,
        base,
        sign: Sign::Plus,
        numbering: Numbering::Std,
    };
    let candidate = crack_with_model(&problem, &cfg, &model);
    assert!(
        candidate.round_trip_ok,
        "round-trip is an algebraic identity"
    );
    assert!(
        candidate.beats_matched_null,
        "planted decode failed matched-null (best={:.3} matched_mean={:.3} matched_z={:.2})",
        candidate.best_score, candidate.matched_mean, candidate.matched_z
    );
    assert!(
        candidate.heldout_ok,
        "planted decode failed held-out (heldout={:.3} matched_heldout_mean={:.3})",
        candidate.heldout_score, candidate.matched_heldout_mean
    );
    assert!(
        candidate.survives,
        "a recovered planted decode MUST survive the gate (else the gate is too strict)"
    );
}

#[test]
fn matched_null_rejects_overfitting_on_random_text() {
    // Pure random ciphertext with real word structure: the search overfits, but
    // the matched null (the same search on a re-shuffled letter stream) overfits
    // just as hard, so the candidate cannot clear the gate.
    let model = QuadgramModel::english().unwrap();
    let base = 26usize;
    let nums = key_numbers(PLAINTEXT, Numbering::Std);
    let mut rng = SplitMix64::new(0x_0ddc_0ffe_e000_5151);
    let cipher: Vec<usize> = (0..nums.len())
        .map(|_| (rng.next_u64() % 26) as usize)
        .collect();
    let cfg = RagbabySearchConfig {
        restarts: 8,
        iterations: 6_000,
        basin_hops: 2,
        seed: 0x00BA_DBED,
        null_trials: 16,
        matched_null_trials: 4,
        ..RagbabySearchConfig::default()
    };
    let problem = RagbabyProblem {
        cipher: &cipher,
        nums: &nums,
        base,
        sign: Sign::Plus,
        numbering: Numbering::Std,
    };
    let candidate = crack_with_model(&problem, &cfg, &model);
    assert!(
        candidate.round_trip_ok,
        "round-trip is an algebraic identity"
    );
    assert!(
        !candidate.beats_matched_null,
        "overfit beat the matched null (best={:.3} matched_mean={:.3} matched_z={:.2})",
        candidate.best_score, candidate.matched_mean, candidate.matched_z
    );
    assert!(
        !candidate.survives,
        "random ciphertext produced a survivor (matched_z={:.2})",
        candidate.matched_z
    );
}

#[test]
fn control_sweep_returns_well_formed_grid() {
    // Fast plumbing smoke: the sweep yields one point per (length, base) with
    // matching fields and accuracies in [0, 1]. Recovery is NOT asserted here
    // (a real recovery needs the heavier budget exercised by the ignored test
    // below); a tiny budget keeps `make verify` fast.
    let model = QuadgramModel::english().unwrap();
    let control = ControlConfig {
        lengths: vec![60, 90],
        bases: vec![26, 24],
        trials: 1,
        numbering: Numbering::Std,
        sign: Sign::Plus,
        search: RagbabySearchConfig {
            restarts: 2,
            iterations: 800,
            basin_hops: 1,
            seed: 0x5_eed,
            null_trials: 0,
            matched_null_trials: 0,
            ..RagbabySearchConfig::default()
        },
    };
    let points = control_sweep(
        crate::attack::quadgram::ENGLISH_CORPUS_LARGE,
        &control,
        &model,
    );
    assert_eq!(points.len(), 4, "one point per (length, base) cell");
    for point in &points {
        assert!(control.lengths.contains(&point.length));
        assert!(control.bases.contains(&point.base));
        assert_eq!(point.trials, 1);
        assert!((0.0..=1.0).contains(&point.recovery_rate));
        assert!((0.0..=1.0).contains(&point.median_acc));
        assert!((0.0..=1.0).contains(&point.mean_acc));
    }
}

#[test]
#[ignore = "heavy positive-control reproduction (~10s); run with cargo test -- --ignored"]
fn control_sweep_recovers_planted_english_heavy() {
    // The positive control proper: with the validated budget a planted base-26
    // Ragbaby of a real English excerpt is recovered with high accuracy
    // (Python gets 100% at L=274).
    let model = QuadgramModel::english().unwrap();
    let control = ControlConfig {
        lengths: vec![274],
        bases: vec![26],
        trials: 2,
        numbering: Numbering::Std,
        sign: Sign::Plus,
        search: RagbabySearchConfig {
            restarts: 20,
            iterations: 15_000,
            basin_hops: 4,
            seed: 0x5_eed,
            null_trials: 0,
            matched_null_trials: 0,
            ..RagbabySearchConfig::default()
        },
    };
    let points = control_sweep(
        crate::attack::quadgram::ENGLISH_CORPUS_LARGE,
        &control,
        &model,
    );
    let point = points.first().copied().unwrap();
    assert!(
        point.median_acc >= 0.9,
        "planted control median accuracy too low: {:.3}",
        point.median_acc
    );
}

#[test]
fn deterministic_for_fixed_seed() {
    let model = QuadgramModel::english().unwrap();
    let base = 26usize;
    let (plain_idx, nums) = prepare(PLAINTEXT, Numbering::Std, base);
    let keep = keep_for_base(base);
    let mut rng = SplitMix64::new(0x_de7);
    let planted = random_keyed_alphabet(&keep, &mut rng);
    let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
    let cfg = RagbabySearchConfig {
        restarts: 3,
        iterations: 1_500,
        basin_hops: 1,
        seed: 0x0000_0777,
        null_trials: 8,
        matched_null_trials: 2,
        ..RagbabySearchConfig::default()
    };
    let problem = RagbabyProblem {
        cipher: &cipher,
        nums: &nums,
        base,
        sign: Sign::Plus,
        numbering: Numbering::Std,
    };
    let first = crack_with_model(&problem, &cfg, &model);
    let second = crack_with_model(&problem, &cfg, &model);
    assert_eq!(first.key, second.key);
    assert_eq!(first.best_score.to_bits(), second.best_score.to_bits());
    assert_eq!(first.matched_mean.to_bits(), second.matched_mean.to_bits());
    assert_eq!(first.survives, second.survives);
    assert_eq!(first.decrypt, second.decrypt);
}

#[test]
fn record_writer_emits_claim_ceiling() {
    let candidate = RagbabyCandidate {
        base: 26,
        numbering: Numbering::Std,
        sign: Sign::Plus,
        key: vec![0, 1, 2],
        best_score: -10.0,
        null_mean: -14.0,
        null_std: 0.2,
        z: 20.0,
        matched_mean: -12.0,
        matched_std: 0.2,
        matched_z: 10.0,
        round_trip_ok: true,
        heldout_score: -11.0,
        matched_heldout_mean: -13.0,
        beats_null: true,
        beats_matched_null: true,
        heldout_ok: true,
        survives: true,
        decrypt: vec![0, 1, 2],
    };
    let dir = std::env::temp_dir().join(format!("noita-ragbaby-rec-{}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    let path = write_ragbaby_record(&dir, "unit", 0x1234, &candidate).unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains(crate::attack::solve::SOLVE_CLAIM_CEILING));
    assert!(body.contains("HYPOTHESIS, NOT a decode"));
    assert!(body.contains("base=26"));
    let _cleanup = std::fs::remove_dir_all(&dir);
}
