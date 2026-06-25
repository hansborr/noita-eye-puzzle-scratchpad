//! Byte-exact golden-master coverage for the CLI.

// Golden-master regeneration guard:
//
// A fixture change in a future refactor PR is a BEHAVIOR CHANGE. Review it
// line-by-line and justify it in that PR; never blindly regenerate snapshots
// just to make this test pass.
//
// Regenerate from a release binary and diff two captures before replacing
// tests/golden/:
//
//   cargo build --release --locked
//   OUT=/tmp/noita-eye-golden-recapture
//   BIN=target/release/noita-eye
//   EYES_DIR=/tmp/noita-eye-golden-master-gak-eyes-candidates
//   rm -rf "$OUT" "$EYES_DIR" && mkdir -p "$OUT" "$EYES_DIR"
//   run_stdout() { name="$1"; shift; "$BIN" "$@" > "$OUT/$name.stdout"; }
//   run_failure() { name="$1"; shift; "$BIN" "$@" > /tmp/noita-eye-golden-empty 2> "$OUT/$name.stderr" && exit 1; test ! -s /tmp/noita-eye-golden-empty; }
//   run_stdout demo demo
//   run_stdout orders orders
//   run_stdout stats_012340123455 stats 012340123455
//   run_stdout stats_all_delimiters stats 555
//   run_stdout agl-gak_nt32_s123 agl-gak --null-trials 32 --seed 123
//   run_stdout gak-attack_spk2_s123 gak-attack --seeds-per-kind 2 --seed 123
//   run_stdout gak-attack-eyes_t16 gak-attack-eyes --trials 16 --candidates-dir "$EYES_DIR"
//   # gak-attack-eyes prints the candidates-dir path; redact it to the portable
//   # placeholder the test compares against (the record filename stays pinned):
//   sed -i "s#$EYES_DIR#<CANDIDATES_DIR>#g" "$OUT/gak-attack-eyes_t16.stdout"
//   run_stdout nulltest_t5_s123 nulltest --trials 5 --seed 123
//   run_stdout dofnull_t5_ct5_s123 dofnull --trials 5 --calib-trials 5 --seed 123
//   run_stdout periodicity_t1_s0_l4_p1 periodicity --trials 1 --seed 0 --max-lag 4 --max-period 1
//   run_stdout honeycomb_t5_s123 honeycomb --trials 5 --seed 123
//   run_stdout pipelinenull_t5_s123 pipelinenull --trials 5 --seed 123
//   run_stdout grouping grouping
//   run_stdout homogeneity_t8_seeds2 homogeneity --trials 8 --seeds 2
//   run_stdout isomorphnull_t5_s123 isomorphnull --trials 5 --seed 123
//   run_stdout chaining_t8_s123_p2_p3 chaining --trials 8 --seed 123 --min-period 2 --max-period 3
//   run_stdout chaining-graph_t1_s123 chaining-graph --trials 1 --seed 123
//   run_stdout moddiff_t8_s123_p8_l8 moddiff --trials 8 --seed 123 --max-period 8 --max-lag 8
//   run_stdout perseus_t8_s123 perseus --trials 8 --seed 123
//   run_stdout perfectiso_t32_s123 perfectiso --trials 32 --seed 123
//   run_stdout zeroadjnull zeroadjnull
//   run_stdout treeresidual_t5_sc1_s123 treeresidual --trials 5 --seed-count 1 --seed 123
//   run_stdout transitivity_t1_s123 transitivity --trials 1 --seed 123
//   run_stdout conditional_tps2_seeds2_s123 conditional --trials-per-seed 2 --seeds 2 --seed 123
//   run_stdout cipherattack_samp1_nt1_vp1_s123 cipherattack --samples 1 --null-trials 1 --max-vigenere-period 1 --seed 123
//   run_stdout pyry_d4_s123 pyry --seed 123 --draws 4
//   run_stdout controls_monoalphabetic_s123 controls monoalphabetic --seed 123
//   run_stdout controls_isomorph_s123 controls isomorph --seed 123
//   run_stdout controls_polyalphabetic_s123 controls polyalphabetic --seed 123
//   run_stdout controls_no_target_s123 controls --seed 123
//   run_failure stats_unknown_digit stats 012x
//   run_failure nulltest_t0_s123 nulltest --trials 0 --seed 123
//   run_failure pipelinenull_t0_s123 pipelinenull --trials 0 --seed 123

mod common;

use common::{assert_contains, run_noita_eye, run_noita_eye_raw};

fn assert_golden_stdout(args: &[&str], expected_stdout: &str) {
    let run = run_noita_eye_raw(args);

    assert!(run.success, "args: {args:?}\nstderr:\n{}", run.stderr);
    assert_eq!(
        run.status_code,
        Some(0),
        "args: {args:?}\nstderr:\n{}",
        run.stderr
    );
    assert_eq!(run.stderr, "", "args: {args:?}");
    assert_eq!(run.stdout, expected_stdout, "args: {args:?}");
}

fn assert_golden_stderr_failure(args: &[&str], expected_stderr: &str) {
    let run = run_noita_eye_raw(args);

    assert!(!run.success, "args: {args:?}\nstdout:\n{}", run.stdout);
    assert_eq!(run.status_code, Some(1), "args: {args:?}");
    assert_eq!(run.stdout, "", "args: {args:?}");
    assert_eq!(run.stderr, expected_stderr, "args: {args:?}");
}

macro_rules! golden_stdout_test {
    ($test_name:ident, $fixture:literal, [$($arg:literal),+ $(,)?]) => {
        #[test]
        fn $test_name() {
            assert_golden_stdout(&[$($arg),+], include_str!($fixture));
        }
    };
}

macro_rules! golden_stderr_failure_test {
    ($test_name:ident, $fixture:literal, [$($arg:literal),+ $(,)?]) => {
        #[test]
        fn $test_name() {
            assert_golden_stderr_failure(&[$($arg),+], include_str!($fixture));
        }
    };
}

golden_stdout_test!(demo_stdout_matches_golden, "golden/demo.stdout", ["demo"]);
golden_stdout_test!(
    orders_stdout_matches_golden,
    "golden/orders.stdout",
    ["orders"]
);
golden_stdout_test!(
    stats_stdout_matches_golden,
    "golden/stats_012340123455.stdout",
    ["stats", "012340123455"]
);
// Behavior-preserving guard: all-delimiter (and empty) rendered input yields the
// clean 0-glyph report at exit 0, exactly as the pre-refactor `stats` parser did.
golden_stdout_test!(
    stats_all_delimiters_stdout_matches_golden,
    "golden/stats_all_delimiters.stdout",
    ["stats", "555"]
);
golden_stdout_test!(
    agl_gak_stdout_matches_golden,
    "golden/agl-gak_nt32_s123.stdout",
    ["agl-gak", "--null-trials", "32", "--seed", "123"]
);
golden_stdout_test!(
    gak_attack_stdout_matches_golden,
    "golden/gak-attack_spk2_s123.stdout",
    ["gak-attack", "--seeds-per-kind", "2", "--seed", "123"]
);
golden_stdout_test!(
    nulltest_stdout_matches_golden,
    "golden/nulltest_t5_s123.stdout",
    ["nulltest", "--trials", "5", "--seed", "123"]
);
golden_stdout_test!(
    dofnull_stdout_matches_golden,
    "golden/dofnull_t5_ct5_s123.stdout",
    [
        "dofnull",
        "--trials",
        "5",
        "--calib-trials",
        "5",
        "--seed",
        "123",
    ]
);
golden_stdout_test!(
    periodicity_stdout_matches_golden,
    "golden/periodicity_t1_s0_l4_p1.stdout",
    [
        "periodicity",
        "--trials",
        "1",
        "--seed",
        "0",
        "--max-lag",
        "4",
        "--max-period",
        "1",
    ]
);
golden_stdout_test!(
    honeycomb_stdout_matches_golden,
    "golden/honeycomb_t5_s123.stdout",
    ["honeycomb", "--trials", "5", "--seed", "123"]
);
golden_stdout_test!(
    pipelinenull_stdout_matches_golden,
    "golden/pipelinenull_t5_s123.stdout",
    ["pipelinenull", "--trials", "5", "--seed", "123"]
);
golden_stdout_test!(
    grouping_stdout_matches_golden,
    "golden/grouping.stdout",
    ["grouping"]
);
golden_stdout_test!(
    homogeneity_stdout_matches_golden,
    "golden/homogeneity_t8_seeds2.stdout",
    ["homogeneity", "--trials", "8", "--seeds", "2"]
);
golden_stdout_test!(
    isomorphnull_stdout_matches_golden,
    "golden/isomorphnull_t5_s123.stdout",
    ["isomorphnull", "--trials", "5", "--seed", "123"]
);
golden_stdout_test!(
    chaining_stdout_matches_golden,
    "golden/chaining_t8_s123_p2_p3.stdout",
    [
        "chaining",
        "--trials",
        "8",
        "--seed",
        "123",
        "--min-period",
        "2",
        "--max-period",
        "3",
    ]
);
golden_stdout_test!(
    chaining_graph_stdout_matches_golden,
    "golden/chaining-graph_t1_s123.stdout",
    ["chaining-graph", "--trials", "1", "--seed", "123"]
);
golden_stdout_test!(
    moddiff_stdout_matches_golden,
    "golden/moddiff_t8_s123_p8_l8.stdout",
    [
        "moddiff",
        "--trials",
        "8",
        "--seed",
        "123",
        "--max-period",
        "8",
        "--max-lag",
        "8",
    ]
);
golden_stdout_test!(
    perseus_stdout_matches_golden,
    "golden/perseus_t8_s123.stdout",
    ["perseus", "--trials", "8", "--seed", "123"]
);
golden_stdout_test!(
    perfectiso_stdout_matches_golden,
    "golden/perfectiso_t32_s123.stdout",
    ["perfectiso", "--trials", "32", "--seed", "123"]
);
golden_stdout_test!(
    zeroadjnull_stdout_matches_golden,
    "golden/zeroadjnull.stdout",
    ["zeroadjnull"]
);
golden_stdout_test!(
    treeresidual_stdout_matches_golden,
    "golden/treeresidual_t5_sc1_s123.stdout",
    [
        "treeresidual",
        "--trials",
        "5",
        "--seed-count",
        "1",
        "--seed",
        "123",
    ]
);
golden_stdout_test!(
    transitivity_stdout_matches_golden,
    "golden/transitivity_t1_s123.stdout",
    ["transitivity", "--trials", "1", "--seed", "123"]
);
golden_stdout_test!(
    conditional_stdout_matches_golden,
    "golden/conditional_tps2_seeds2_s123.stdout",
    [
        "conditional",
        "--trials-per-seed",
        "2",
        "--seeds",
        "2",
        "--seed",
        "123",
    ]
);
golden_stdout_test!(
    cipherattack_stdout_matches_golden,
    "golden/cipherattack_samp1_nt1_vp1_s123.stdout",
    [
        "cipherattack",
        "--samples",
        "1",
        "--null-trials",
        "1",
        "--max-vigenere-period",
        "1",
        "--seed",
        "123",
    ]
);
golden_stdout_test!(
    pyry_stdout_matches_golden,
    "golden/pyry_d4_s123.stdout",
    ["pyry", "--seed", "123", "--draws", "4"]
);
golden_stdout_test!(
    controls_monoalphabetic_stdout_matches_golden,
    "golden/controls_monoalphabetic_s123.stdout",
    ["controls", "monoalphabetic", "--seed", "123"]
);
golden_stdout_test!(
    controls_isomorph_stdout_matches_golden,
    "golden/controls_isomorph_s123.stdout",
    ["controls", "isomorph", "--seed", "123"]
);
golden_stdout_test!(
    controls_polyalphabetic_stdout_matches_golden,
    "golden/controls_polyalphabetic_s123.stdout",
    ["controls", "polyalphabetic", "--seed", "123"]
);
golden_stdout_test!(
    controls_no_target_stdout_matches_golden,
    "golden/controls_no_target_s123.stdout",
    ["controls", "--seed", "123"]
);

golden_stderr_failure_test!(
    stats_unknown_digit_stderr_matches_golden,
    "golden/stats_unknown_digit.stderr",
    ["stats", "012x"]
);
golden_stderr_failure_test!(
    nulltest_zero_trials_stderr_matches_golden,
    "golden/nulltest_t0_s123.stderr",
    ["nulltest", "--trials", "0", "--seed", "123"]
);
golden_stderr_failure_test!(
    pipelinenull_zero_trials_stderr_matches_golden,
    "golden/pipelinenull_t0_s123.stderr",
    ["pipelinenull", "--trials", "0", "--seed", "123"]
);

#[test]
fn gak_attack_eyes_stdout_matches_golden_and_writes_record() {
    // Unique per-process candidates dir: portable (no hardcoded /tmp) and
    // collision-free under parallel `cargo test`. The candidates-dir path is the
    // one machine-coupled token in this stream, so it is redacted to the stable
    // `<CANDIDATES_DIR>` placeholder before the byte-exact comparison; the
    // seed-stable record filename stays pinned. To regenerate the fixture, apply
    // the same redaction (see the regeneration guard at the top of this file).
    let dir =
        std::env::temp_dir().join(format!("noita-eye-golden-gak-eyes-{}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp candidates dir");
    let dir_str = dir
        .to_str()
        .expect("temp candidates dir path is valid UTF-8");

    let run = run_noita_eye_raw(&[
        "gak-attack-eyes",
        "--trials",
        "16",
        "--candidates-dir",
        dir_str,
    ]);
    assert!(run.success, "stderr:\n{}", run.stderr);
    assert_eq!(run.status_code, Some(0), "stderr:\n{}", run.stderr);
    assert_eq!(run.stderr, "");
    let normalized = run.stdout.replace(dir_str, "<CANDIDATES_DIR>");
    assert_eq!(
        normalized,
        include_str!("golden/gak-attack-eyes_t16.stdout")
    );

    let record_written = std::fs::read_dir(&dir)
        .expect("read temp candidates dir")
        .any(|entry| {
            entry
                .expect("read temp candidates dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("eyes-")
        });
    assert!(
        record_written,
        "gak-attack-eyes must write an eyes-* record under {dir:?}"
    );

    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn controls_polyalphabetic_alias_fixture_matches_isomorph_fixture() {
    assert_eq!(
        include_str!("golden/controls_polyalphabetic_s123.stdout"),
        include_str!("golden/controls_isomorph_s123.stdout")
    );
}

#[test]
fn demo_corpus_fingerprint_headlines_remain_pinned() {
    let stdout = run_noita_eye(&["demo"]);

    assert_contains(&stdout, "2.2801 bits/glyph");
    assert_contains(&stdout, "0.2108");
}

#[test]
fn null_and_structural_headlines_remain_pinned() {
    let nulltest = run_noita_eye(&["nulltest", "--trials", "5", "--seed", "123"]);
    assert_contains(
        &nulltest,
        "headline exact 0..=82: 0/5 = 0.000000 (95% Wilson 0.000000..0.434482)",
    );

    let homogeneity = run_noita_eye(&["homogeneity", "--trials", "8", "--seeds", "2"]);
    assert_contains(
        &homogeneity,
        "pooled counts: 0:774, 1:739, 2:699, 3:490, 4:406",
    );
    assert_contains(
        &homogeneity,
        "Pearson X^2: 21.917 df 32 asymptotic p>=X^2 9.095989e-1",
    );
    assert_contains(
        &homogeneity,
        "G-test: 21.999 df 32 asymptotic p>=G 9.074206e-1",
    );

    let moddiff = run_noita_eye(&[
        "moddiff",
        "--trials",
        "8",
        "--seed",
        "123",
        "--max-period",
        "8",
        "--max-lag",
        "8",
    ]);
    assert_contains(
        &moddiff,
        "Headline k=1 mod-83: top difference 7 occurs 25/1027 (0.0243); delta-IoC +0.000444; placement structureless.",
    );

    let honeycomb = run_noita_eye(&["honeycomb", "--trials", "5", "--seed", "123"]);
    assert_contains(
        &honeycomb,
        "vertical same pos: 13/802 = 0.016209; mean |diff| 26.863",
    );
    assert_contains(
        &honeycomb,
        "trigrams: 1036; positions: 26; value bands: 7; chi-square: 260.202; df: 150",
    );
    assert_contains(
        &honeycomb,
        "upper/lower trigrams: 520/516; chi-square: 113.162; df: 82",
    );
}
