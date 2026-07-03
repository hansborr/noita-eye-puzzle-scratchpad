//! Focused anchor-seed regressions.

use super::campaign::{StreamPrep, solve_cfg};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::plant::{CopySpan, copy_ties};
use super::ties::tie_targets;
use super::{AnchorHarvestMode, MAX_HARVEST_COLORINGS, N_LETTERS, harvest_anchor_colorings};

fn letters(text: &str) -> Vec<u8> {
    text.bytes()
        .filter(u8::is_ascii_lowercase)
        .map(|byte| byte - b'a')
        .collect()
}

fn class_of(coloring: &[u8; 26], letter: u8) -> u8 {
    coloring
        .get(usize::from(letter))
        .copied()
        .expect("letter in range")
}

#[test]
fn harvest_keeps_truth_when_window_ends_mid_word() {
    let lexicon = build_lexicon(&parse_wordlist(
        "hello 100\nthere 90\nworld 80\n",
        usize::MAX,
    ))
    .expect("lexicon builds");
    let mut coloring = [0u8; 26];
    for (ch, class) in [
        ('h', 0),
        ('e', 1),
        ('l', 2),
        ('o', 3),
        ('t', 0),
        ('r', 1),
        ('w', 0),
        ('d', 1),
    ] {
        if let Some(slot) = coloring.get_mut(usize::from(ch as u8 - b'a')) {
            *slot = class;
        }
    }
    let truth = letters("hellotherehelloworld");
    let tokens: Vec<u8> = truth
        .iter()
        .copied()
        .map(|letter| class_of(&coloring, letter))
        .collect();
    let repeat = CopySpan {
        src: 0,
        dst: 10,
        len: 2,
    };
    let ties = tie_targets(
        &copy_ties(repeat, tokens.len()).expect("copy ties"),
        tokens.len(),
    );
    let prep = StreamPrep {
        tokens,
        n_classes: 4,
        tie_table: ties,
        n_tied: repeat.len,
        longest_tie: Some((repeat.src, repeat.dst, repeat.len)),
    };
    let phrase_cfg = solve_cfg(256, 0, 0, 3.6, 64, 2048);
    let harvest = harvest_anchor_colorings(
        &prep,
        &lexicon,
        &phrase_cfg,
        64,
        AnchorHarvestMode::ScoreBeam,
    )
    .expect("harvest runs");
    assert_eq!(harvest.window.start, 0);
    assert_eq!(harvest.window.len, 12, "window ends at he inside hello");
    let mut truth_coloring = [None; 26];
    for &letter in truth.get(..harvest.window.len).expect("window letters") {
        if let Some(slot) = truth_coloring.get_mut(usize::from(letter.min(N_LETTERS - 1))) {
            *slot = Some(class_of(&coloring, letter));
        }
    }
    assert!(
        harvest
            .distinct_colorings
            .iter()
            .any(|seed| seed.coloring == truth_coloring),
        "truth coloring must survive an interior trie final"
    );
}

#[test]
fn enumerate_keeps_truth_when_window_starts_mid_word_and_rejects_bad_coloring() {
    let lexicon =
        build_lexicon(&parse_wordlist("za 100\nb 90\n", usize::MAX)).expect("lexicon builds");
    let mut coloring = [0u8; 26];
    for (ch, class) in [('a', 0), ('b', 1), ('z', 2)] {
        if let Some(slot) = coloring.get_mut(usize::from(ch as u8 - b'a')) {
            *slot = class;
        }
    }
    let truth = letters("zabza");
    let tokens: Vec<u8> = truth
        .iter()
        .copied()
        .map(|letter| class_of(&coloring, letter))
        .collect();
    let repeat = CopySpan {
        src: 1,
        dst: 4,
        len: 1,
    };
    let ties = tie_targets(
        &copy_ties(repeat, tokens.len()).expect("copy ties"),
        tokens.len(),
    );
    let prep = StreamPrep {
        tokens,
        n_classes: 4,
        tie_table: ties,
        n_tied: repeat.len,
        longest_tie: Some((repeat.src, repeat.dst, repeat.len)),
    };
    let phrase_cfg = solve_cfg(4096, 1, 3, 3.6, 256, 2048);
    let harvest = harvest_anchor_colorings(
        &prep,
        &lexicon,
        &phrase_cfg,
        MAX_HARVEST_COLORINGS,
        AnchorHarvestMode::Enumerate,
    )
    .expect("enumeration harvest runs");
    assert_eq!(harvest.window.start, 1);
    assert_eq!(harvest.window.len, 4, "window starts at a inside za");
    assert!(
        !harvest.distinct_colorings.is_empty(),
        "positive control must be non-vacuous: expanded {} max_states {} budget_hit {} cap_hit {}",
        harvest.expanded,
        harvest.max_occupancy,
        harvest.budget_hit,
        harvest.cap_hit
    );
    let mut truth_coloring = [None; 26];
    for &letter in truth
        .get(harvest.window.start..harvest.window.start + harvest.window.len)
        .expect("window letters")
    {
        if let Some(slot) = truth_coloring.get_mut(usize::from(letter.min(N_LETTERS - 1))) {
            *slot = Some(class_of(&coloring, letter));
        }
    }
    assert!(
        harvest
            .distinct_colorings
            .iter()
            .any(|seed| seed.coloring == truth_coloring),
        "truth coloring must survive the leading partial fragment"
    );
    let mut bad_coloring = truth_coloring;
    if let Some(slot) = bad_coloring.get_mut(0) {
        *slot = Some(4);
    }
    assert!(
        !harvest
            .distinct_colorings
            .iter()
            .any(|seed| seed.coloring == bad_coloring),
        "a token-inconsistent coloring must not be emitted"
    );
}

#[test]
fn enumerate_post_filter_rejects_tie_violating_superset_coloring() {
    let lexicon =
        build_lexicon(&parse_wordlist("ab 100\ncd 90\n", usize::MAX)).expect("lexicon builds");
    let mut coloring = [0u8; 26];
    for (ch, class) in [('a', 0), ('b', 1), ('c', 0), ('d', 1)] {
        if let Some(slot) = coloring.get_mut(usize::from(ch as u8 - b'a')) {
            *slot = class;
        }
    }
    let tokens = vec![0, 1, 0, 1];
    let repeat = CopySpan {
        src: 0,
        dst: 2,
        len: 2,
    };
    let ties = tie_targets(
        &copy_ties(repeat, tokens.len()).expect("copy ties"),
        tokens.len(),
    );
    let prep = StreamPrep {
        tokens,
        n_classes: 4,
        tie_table: ties,
        n_tied: repeat.len,
        longest_tie: Some((repeat.src, repeat.dst, repeat.len)),
    };
    let phrase_cfg = solve_cfg(512, 0, 0, 3.6, 64, 2048);
    let harvest = harvest_anchor_colorings(
        &prep,
        &lexicon,
        &phrase_cfg,
        MAX_HARVEST_COLORINGS,
        AnchorHarvestMode::Enumerate,
    )
    .expect("enumeration harvest runs");

    let mut tied_coloring = [None; 26];
    for (ch, class) in [('a', 0), ('b', 1)] {
        if let Some(slot) = tied_coloring.get_mut(usize::from(ch as u8 - b'a')) {
            *slot = Some(class);
        }
    }
    assert!(
        harvest
            .distinct_colorings
            .iter()
            .any(|seed| seed.coloring == tied_coloring),
        "the exact tied coloring should survive"
    );

    let mut superset_only = tied_coloring;
    for (ch, class) in [('c', 0), ('d', 1)] {
        if let Some(slot) = superset_only.get_mut(usize::from(ch as u8 - b'a')) {
            *slot = Some(class);
        }
    }
    assert!(
        !harvest
            .distinct_colorings
            .iter()
            .any(|seed| seed.coloring == superset_only),
        "a coloring requiring occ2 letters different from occ1 must be post-filtered"
    );
}
