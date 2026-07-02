//! Unit and integration tests for the pair-class instrument. Every test calls
//! the same library functions the CLI dispatches to.

use super::campaign::{PowerCfg, measure_power, null_gate, prepare_stream, solve_cfg};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::plant::{CopySpan, PlantSpec, copy_ties, markov_resample, plant_from_text};
use super::selftest::{
    TWO_ANCHOR_MIN_LEN, TWO_ANCHORS, TWO_PHASE0_MARGINALS, pairclass_self_test, recovery_fraction,
};
use super::solve::{SolveCfg, SolveInput, TruthFate, estimate_peak_mib, solve};
use super::ties::{TieSpan, maximal_repeats, tie_targets, token_ties};
use super::{
    AnchorHarvestMode, DEFAULT_SEED, PairDerivation, PairclassError, TWO_MODULUS,
    derive_pair_tokens, embedded_two, measure_anchor_seed_power, validate_tokens,
};
use crate::core::glyph::Glyph;

fn letters(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_lowercase)
        .map(|b| b - b'a')
        .collect()
}

fn toy_lexicon(entries: &str) -> super::lexicon::Lexicon {
    build_lexicon(&parse_wordlist(entries, usize::MAX)).expect("toy lexicon builds")
}

/// A coloring table from `(letter, class)` pairs (other letters class 0).
fn coloring_of(pairs: &[(char, u8)]) -> [u8; 26] {
    let mut coloring = [0u8; 26];
    for &(ch, class) in pairs {
        let slot = coloring
            .get_mut(usize::from(ch as u8 - b'a'))
            .expect("letter in range");
        *slot = class;
    }
    coloring
}

/// The class of `letter` under `coloring`.
fn class_of(coloring: &[u8; 26], letter: u8) -> u8 {
    coloring
        .get(usize::from(letter))
        .copied()
        .expect("letter in range")
}

/// Tokens for `text` under an explicit letter->class table.
fn tokens_for(text: &str, coloring: &[u8; 26]) -> Vec<u8> {
    letters(text)
        .into_iter()
        .map(|l| class_of(coloring, l))
        .collect()
}

#[test]
fn embedded_two_derivation_matches_the_campaign_record() {
    let values = embedded_two().expect("fixture parses");
    assert_eq!(values.len(), 698, "two is 698 symbols");
    let PairDerivation::Walk(pair) =
        derive_pair_tokens(&values, TWO_MODULUS).expect("derivation runs")
    else {
        panic!("two's residue channel is a verified ±1 walk");
    };
    assert_eq!(pair.bits.len(), 697);
    assert_eq!(pair.tokens(0).len(), 348);
    assert_eq!(pair.tokens(1).len(), 348);
    assert_eq!(pair.marginals(0), TWO_PHASE0_MARGINALS);
}

#[test]
fn embedded_two_anchors_reproduce_exactly() {
    let values = embedded_two().expect("fixture parses");
    let PairDerivation::Walk(pair) =
        derive_pair_tokens(&values, TWO_MODULUS).expect("derivation runs")
    else {
        panic!("two is a walk");
    };
    let anchors = maximal_repeats(&pair.bits, TWO_ANCHOR_MIN_LEN);
    assert_eq!(anchors, TWO_ANCHORS.to_vec());
}

#[test]
fn walk_gate_rejects_non_walks() {
    // C3: a repeated residue is the violation (diff 0).
    let stalled = [Glyph(0), Glyph(1), Glyph(1)];
    match derive_pair_tokens(&stalled, 3).expect("runs") {
        PairDerivation::NotAWalk(violation) => {
            assert_eq!(violation.position, 1);
            assert_eq!(violation.diff, 0);
        }
        PairDerivation::Walk(_) => panic!("stalled residue must fail the gate"),
    }
    // Modulus 4: a diff-2 jump is the violation.
    let jump = [Glyph(0), Glyph(2)];
    assert!(matches!(
        derive_pair_tokens(&jump, 4).expect("runs"),
        PairDerivation::NotAWalk(_)
    ));
    // Modulus below 3 is rejected outright.
    assert_eq!(
        derive_pair_tokens(&jump, 2),
        Err(PairclassError::ModulusTooSmall { modulus: 2 })
    );
}

#[test]
fn token_tie_mapping_covers_interior_tokens_only() {
    let spans = [TieSpan {
        a: 4,
        b: 10,
        len: 6,
    }];
    // Phase 0: token t covers bits (2t, 2t+1); tokens 2..=4 lie inside [4,10).
    assert_eq!(token_ties(&spans, 0, 100), vec![(2, 5), (3, 6), (4, 7)]);
    // Phase 1: token t covers bits (1+2t, 2+2t); tokens 2..=3 fit.
    assert_eq!(token_ties(&spans, 1, 100), vec![(2, 5), (3, 6)]);
    // Odd start distance cannot tie same-phase tokens.
    let odd = [TieSpan { a: 4, b: 9, len: 6 }];
    assert!(token_ties(&odd, 0, 100).is_empty());
}

#[test]
fn tie_targets_collapse_to_minimum_representative() {
    let table = tie_targets(&[(2, 5), (5, 9), (7, 3)], 10);
    let expected = vec![
        None,
        None,
        None,
        None,
        None,
        Some(2),
        None,
        Some(3),
        None,
        Some(2),
    ];
    assert_eq!(table, expected);
}

#[test]
fn wordlist_parsing_filters_sorts_and_caps() {
    let words = parse_wordlist("The 10\nzebra\nnope! 5\ncat 30\nthe 40\nB2B 9\ndog 30\n", 3);
    // "the" keeps its max count (40); count ties break alphabetically.
    assert_eq!(
        words,
        vec![
            ("the".to_owned(), 40),
            ("cat".to_owned(), 30),
            ("dog".to_owned(), 30),
        ]
    );
    assert!(build_lexicon(&parse_wordlist("!!! ???\n", usize::MAX)).is_err());
}

#[test]
fn toy_solve_recovers_a_two_word_plant() {
    let lexicon = toy_lexicon("cat 10\ndog 10\n");
    let coloring = coloring_of(&[('c', 0), ('a', 1), ('t', 2), ('d', 3), ('o', 0), ('g', 1)]);
    let truth = letters("catdog");
    let tokens = tokens_for("catdog", &coloring);
    let report = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: Some(&truth),
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg::default(),
    )
    .expect("solve runs");
    let best = report.solutions.first().expect("a solution exists");
    assert_eq!(best.letters, truth);
    assert_eq!(best.rendered, "cat dog");
    assert!(matches!(report.truth, Some(TruthFate::Found { .. })));
    // The induced coloring pins exactly the used letters to their classes.
    for letter in letters("catdog") {
        let induced = best
            .coloring
            .get(usize::from(letter))
            .copied()
            .expect("letter in range");
        assert_eq!(induced, Some(class_of(&coloring, letter)));
    }
}

#[test]
fn higher_frequency_words_outscore_pattern_collisions() {
    // "sat" and "cat" collide when c and s share a class; the commoner wins.
    let lexicon = toy_lexicon("sat 100\ncat 10\n");
    let coloring = coloring_of(&[('c', 1), ('s', 1), ('a', 2), ('t', 3)]);
    let truth = letters("cat");
    let tokens = tokens_for("cat", &coloring);
    let report = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: Some(&truth),
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg::default(),
    )
    .expect("solve runs");
    let best = report.solutions.first().expect("a solution exists");
    assert_eq!(best.rendered, "sat", "the commoner pattern-collision wins");
    match report.truth {
        Some(TruthFate::OutScored {
            truth_score,
            best_score,
        }) => assert!(truth_score < best_score),
        other => panic!("expected OutScored, got {other:?}"),
    }
}

#[test]
fn gap_segments_bridge_out_of_vocabulary_spans() {
    let lexicon = toy_lexicon("cat 10\ndog 10\n");
    let coloring = coloring_of(&[
        ('c', 0),
        ('a', 1),
        ('t', 2),
        ('d', 3),
        ('o', 0),
        ('g', 1),
        ('x', 2),
        ('y', 3),
        ('z', 0),
    ]);
    // "catxyzdog": xyz is out of vocabulary and needs one gap segment.
    let tokens = tokens_for("catxyzdog", &coloring);
    let truth = letters("catxyzdog");
    let report = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: Some(&truth),
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg::default(),
    )
    .expect("solve runs");
    let best = report.solutions.first().expect("a gap solution exists");
    assert_eq!(best.gaps_used, 1);
    assert!(
        best.rendered.starts_with("cat "),
        "rendering: {}",
        best.rendered
    );
    assert!(
        best.rendered.chars().any(char::is_uppercase),
        "gap letters render uppercase: {}",
        best.rendered
    );
    // With gaps disabled the stream has no solution at all.
    let no_gaps = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: None,
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg {
            max_gaps: 0,
            ..SolveCfg::default()
        },
    )
    .expect("solve runs");
    assert!(no_gaps.solutions.is_empty());
}

#[test]
fn ties_force_letter_equality_across_positions() {
    // Two three-letter words; the tie forces position 3 to equal position 0.
    let lexicon = toy_lexicon("cat 10\nsat 100\n");
    let coloring = coloring_of(&[('c', 1), ('s', 1), ('a', 2), ('t', 3)]);
    let tokens = tokens_for("catcat", &coloring);
    let ties = tie_targets(
        &copy_ties(
            CopySpan {
                src: 0,
                dst: 3,
                len: 3,
            },
            6,
        )
        .expect("ties"),
        6,
    );
    let report = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: Some(&ties),
            lexicon: &lexicon,
            truth: None,
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg::default(),
    )
    .expect("solve runs");
    assert!(!report.solutions.is_empty());
    for solution in &report.solutions {
        assert_eq!(
            solution.letters.first(),
            solution.letters.get(3),
            "tied positions must agree: {}",
            solution.rendered
        );
    }
}

#[test]
fn memory_cap_refuses_oversized_configurations() {
    let lexicon = toy_lexicon("cat 10\n");
    let tokens = vec![0u8; 348];
    let result = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: None,
            seed_coloring: None,
            accept_partial_final: false,
        },
        &SolveCfg {
            beam: 20_000,
            max_mem_mib: 0,
            ..SolveCfg::default()
        },
    );
    assert!(matches!(result, Err(PairclassError::MemoryCap { .. })));
    assert!(estimate_peak_mib(348, 20_000, 1000) > estimate_peak_mib(348, 100, 1000));
}

#[test]
fn plant_construction_is_deterministic_and_validated() {
    let spec = PlantSpec {
        len: 12,
        n_classes: 4,
        copy: Some(CopySpan {
            src: 0,
            dst: 6,
            len: 6,
        }),
    };
    let a = plant_from_text("The Quick! brown fox jumps over", &spec, 7).expect("plant builds");
    let b = plant_from_text("The Quick! brown fox jumps over", &spec, 7).expect("plant builds");
    assert_eq!(a.letters, b.letters);
    assert_eq!(a.coloring, b.coloring);
    assert_eq!(a.tokens, b.tokens);
    assert_eq!(a.letters.len(), 12);
    assert_eq!(a.letters.get(..6), a.letters.get(6..), "copy span imposed");
    for (&token, &letter) in a.tokens.iter().zip(a.letters.iter()) {
        assert_eq!(token, class_of(&a.coloring, letter));
    }
    assert!(matches!(
        plant_from_text(
            "abc",
            &PlantSpec {
                len: 10,
                n_classes: 4,
                copy: None
            },
            7
        ),
        Err(PairclassError::PlantTooShort {
            needed: 10,
            have: 3
        })
    ));
    assert!(matches!(
        plant_from_text(
            "abcdefghij",
            &PlantSpec {
                len: 10,
                n_classes: 4,
                copy: Some(CopySpan {
                    src: 4,
                    dst: 8,
                    len: 4
                })
            },
            7
        ),
        Err(PairclassError::SpanOutOfRange)
    ));
}

#[test]
fn markov_resample_preserves_length_start_and_alphabet() {
    let tokens = vec![0u8, 1, 2, 0, 1, 3, 2, 2, 0, 1, 0, 3, 1, 2];
    let resampled = markov_resample(&tokens, 4, 42).expect("resample runs");
    assert_eq!(resampled.len(), tokens.len());
    assert_eq!(resampled.first(), tokens.first());
    assert!(resampled.iter().all(|&t| t < 4));
    let again = markov_resample(&tokens, 4, 42).expect("resample runs");
    assert_eq!(resampled, again, "seed-deterministic");
    let other = markov_resample(&tokens, 4, 43).expect("resample runs");
    assert!(
        resampled != other || tokens.len() < 4,
        "seeds vary the draw"
    );
}

#[test]
fn token_validation_reports_class_counts() {
    assert_eq!(validate_tokens(&[0, 1, 2, 3, 1]), Ok(4));
    assert_eq!(validate_tokens(&[0, 0]), Ok(1));
    assert!(matches!(
        validate_tokens(&[]),
        Err(PairclassError::EmptyInput)
    ));
    assert!(matches!(
        validate_tokens(&[0, 4]),
        Err(PairclassError::TooManyClasses { found: 5 })
    ));
}

#[test]
fn recovery_fraction_counts_matches() {
    assert!((recovery_fraction(&[1, 2, 3], &[1, 2, 4]) - 2.0 / 3.0).abs() < 1e-12);
    assert!((recovery_fraction(&[], &[]) - 0.0).abs() < 1e-12);
}

#[test]
fn prepare_stream_derives_two_and_finds_the_repeat_run() {
    let values = embedded_two().expect("fixture parses");
    let prep = prepare_stream(&values, TWO_MODULUS, 0, false, TWO_ANCHOR_MIN_LEN)
        .expect("prepare runs")
        .expect("two is a walk");
    assert_eq!(prep.tokens.len(), 348);
    assert_eq!(prep.n_classes, 4);
    assert!(prep.n_tied > 0, "the anchors tie some positions");
    // The 68-bit anchor is a 33-token run in phase-0 token coordinates.
    let (_src, _dst, len) = prep.longest_tie.expect("a longest run exists");
    assert_eq!(len, 33);
    // The tie table never points a position at itself or later.
    for (position, target) in prep.tie_table.iter().enumerate() {
        if let Some(src) = target {
            assert!(*src < position);
        }
    }
    // A non-walk stream (a diff-2 jump under modulus 4) is surfaced, not solved.
    let jump = [Glyph(0), Glyph(2), Glyph(0)];
    let outcome = prepare_stream(&jump, 4, 0, false, 0).expect("runs");
    assert!(outcome.is_err(), "non-walk streams return the violation");
}

#[test]
fn measure_power_tolerates_non_letter_plant_text() {
    // Regression: the plant-letter filter must not underflow on spaces/digits.
    let lexicon = toy_lexicon("the 100\ncat 50\ndog 40\nand 30\nsat 20\n");
    let text = "The cat sat!  And the dog... 1234 ran, THE cat and dog.\n";
    let cfg = solve_cfg(256, 2, 8, 3.6, 3, 2048);
    let power = measure_power(
        text,
        &PowerCfg {
            n_plants: 2,
            plant_len: 9,
            n_classes: 4,
            longest_tie: None,
            bar: 0.4,
            seed: 7,
        },
        &lexicon,
        &cfg,
    )
    .expect("power measurement runs");
    assert_eq!(power.plants.len(), 2);
    assert!((0.0..=1.0).contains(&power.mean_recovery));
}

#[test]
fn anchor_seed_power_reports_harvest_diagnostics() {
    let lexicon = toy_lexicon("the 100\ncat 90\nsat 80\non 70\nmat 60\nand 50\nrug 40\n");
    let text = "the cat sat on the mat and the cat sat on the rug";
    let phrase_cfg = solve_cfg(128, 6, 8, 3.6, 16, 2048);
    let full_cfg = solve_cfg(128, 2, 8, 3.6, 3, 2048);
    let power = measure_anchor_seed_power(
        text,
        &PowerCfg {
            n_plants: 1,
            plant_len: 20,
            n_classes: 4,
            longest_tie: Some((0, 6, 6)),
            bar: 0.4,
            seed: 7,
        },
        &lexicon,
        &phrase_cfg,
        &full_cfg,
        16,
        AnchorHarvestMode::ScoreBeam,
    )
    .expect("anchor power runs");
    assert_eq!(power.plants.len(), 1);
    let plant = power.plants.first().expect("one plant outcome");
    assert!(plant.harvested > 0);
    assert!(plant.max_occupancy > 0);
}

#[test]
fn null_gate_reports_resample_scores() {
    let lexicon = toy_lexicon("the 100\ncat 50\ndog 40\n");
    let coloring = coloring_of(&[('t', 0), ('h', 1), ('e', 2), ('c', 3), ('a', 0), ('d', 1)]);
    let tokens = tokens_for("thecat", &coloring);
    let cfg = solve_cfg(256, 2, 8, 3.6, 3, 2048);
    let real = solve(
        &SolveInput {
            tokens: &tokens,
            n_classes: 4,
            tie_to: None,
            lexicon: &lexicon,
            truth: None,
            seed_coloring: None,
            accept_partial_final: false,
        },
        &cfg,
    )
    .expect("solve runs");
    let real_best = real.solutions.first().map(|s| s.score);
    let gate = null_gate(&tokens, 4, &lexicon, &cfg, 8, real_best, 11).expect("gate runs");
    assert_eq!(gate.null_bests.len(), 8);
    let p = gate.p_value();
    assert!((0.0..=1.0).contains(&p), "p-value in range: {p}");
}

#[test]
fn self_test_passes_at_the_default_seed() {
    let report = pairclass_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(report.plant.passed(), "plant leg: {:?}", report.plant);
    assert!(report.null.passed(), "null leg: {:?}", report.null);
    assert!(report.prune.passed(), "prune leg: {:?}", report.prune);
    assert!(report.walk_gate, "walk gate leg");
    assert!(report.two.passed(), "two regression: {:?}", report.two);
    assert!(report.passed());
}
