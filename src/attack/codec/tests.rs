use super::{
    AnyCodec, BINARY_MOVE_GROUP_LENS, Codec, CodecError, CodecSearch,
    DEFAULT_CODEC_SEARCH_MAX_GROUP_LEN, DEFAULT_LANGUAGE_ALPHABET_SIZE, DeltaCodec, DigitOrder,
    GroupingCodec, ProjectCodec, ProjectionOp, codec_round_trip_ok, default_codec_search,
    enumerate_codecs, honeycomb_codec, output_alphabet_hosts_language,
    output_exceeds_accepted_alphabet, resolved_output_alphabet_size,
};
use crate::core::glyph::{Glyph, Orientation};
use crate::core::trigram::ReadingTrigram;

fn glyphs(values: &[u16]) -> Vec<Glyph> {
    values.iter().copied().map(Glyph).collect()
}

fn honeycomb_grouping() -> GroupingCodec {
    GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Msb,
        stride: 3,
    }
}

/// The honeycomb base-5 trigram value for three rendered orientation digits,
/// taken straight from `src/trigram.rs` (the convention the codec must match).
fn trigram_value(first: u8, second: u8, third: u8) -> u16 {
    let orientation = |digit: u8| Orientation::from_digit(digit).unwrap();
    u16::from(
        ReadingTrigram::new(orientation(first), orientation(second), orientation(third))
            .value()
            .get(),
    )
}

#[test]
fn identity_is_the_identity() {
    let input = glyphs(&[3, 1, 4, 1, 0, 2]);
    assert_eq!(AnyCodec::Identity.transduce(&input).unwrap(), input);
    assert!(AnyCodec::Identity.is_invertible());
    assert_eq!(AnyCodec::Identity.name(), "identity");
}

#[test]
fn fixed_grouping_matches_honeycomb_trigram_values() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    // Hand values cross-checked against ReadingTrigram::value (MSB convention):
    //   [4,4,4] -> 4*25 + 4*5 + 4 = 124 (the raw-trigram maximum)
    //   [1,2,3] -> 1*25 + 2*5 + 3 = 38
    //   [2,0,0] -> 2*25          = 50
    assert_eq!(trigram_value(4, 4, 4), 124);
    assert_eq!(trigram_value(1, 2, 3), 38);
    assert_eq!(trigram_value(2, 0, 0), 50);

    let input = glyphs(&[4, 4, 4, 1, 2, 3, 2, 0, 0]);
    let out = codec.transduce(&input).unwrap();
    assert_eq!(out, glyphs(&[124, 38, 50]));
    // And each output equals the independent trigram computation.
    assert_eq!(
        out,
        glyphs(&[
            trigram_value(4, 4, 4),
            trigram_value(1, 2, 3),
            trigram_value(2, 0, 0),
        ])
    );
}

#[test]
fn fixed_grouping_lsb_reverses_significance() {
    let codec = AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Lsb,
        stride: 3,
    });
    // LSB: first digit least-significant -> 1 + 2*5 + 3*25 = 86.
    let out = codec.transduce(&glyphs(&[1, 2, 3])).unwrap();
    assert_eq!(out, glyphs(&[86]));
}

#[test]
fn fixed_grouping_output_alphabet_size_is_base_pow_group_len() {
    assert_eq!(
        AnyCodec::FixedGrouping(honeycomb_grouping()).output_alphabet_size(),
        125
    );
    assert_eq!(
        AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 6,
            order: DigitOrder::Msb,
            stride: 2,
        })
        .output_alphabet_size(),
        36
    );
}

#[test]
fn fixed_grouping_non_multiple_length_errors() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    let error = codec.transduce(&glyphs(&[0, 1, 2, 3])).unwrap_err();
    assert_eq!(
        error,
        CodecError::LengthNotGroupMultiple {
            len: 4,
            group_len: 3,
        }
    );
}

#[test]
fn fixed_grouping_digit_outside_base_errors() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    let error = codec.transduce(&glyphs(&[0, 5, 1])).unwrap_err();
    assert_eq!(error, CodecError::ValueOutsideBase { value: 5, base: 5 });
}

#[test]
fn fixed_grouping_empty_input_is_empty_output() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    assert_eq!(codec.transduce(&[]).unwrap(), Vec::<Glyph>::new());
}

// The +/-1-C5 hint (practice puzzle `one`, research/data/practice-puzzles/one):
// every transition of that 5-symbol sample is +/-1 mod 5 — a walk on the
// pentagon C5. Differencing collapses it to the move stream over {+1,-1} = {1,4}
// mod 5; re-integrating from the seed reproduces the walk. This is an observed
// ciphertext property and a search hint (Delta is the natural first codec),
// never a claim of "no message".
#[test]
fn delta_differences_c5_walk_and_reintegrates_from_seed() {
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    // A +/-1 walk on C5 (each step differs from the last by +/-1 mod 5).
    let walk = glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2]);
    let moves = codec.transduce(&walk).unwrap();

    // Differencing collapses the alphabet to the two moves {+1, -1} = {1, 4}.
    assert_eq!(moves.len(), walk.len() - 1);
    assert!(moves.iter().all(|step| step.0 == 1 || step.0 == 4));

    // Re-integration from the seed (the first symbol) reproduces the original
    // walk exactly: cumulative sum of the moves mod base, starting at the seed.
    let seed = walk.first().copied().unwrap();
    let mut accumulator = usize::from(seed.0);
    let mut reintegrated = vec![seed];
    for step in &moves {
        accumulator = (accumulator + usize::from(step.0)) % 5;
        reintegrated.push(Glyph(accumulator as u16));
    }
    assert_eq!(reintegrated, walk);

    // Inner Identity over the differenced base-5 alphabet keeps the output at 5.
    assert_eq!(codec.output_alphabet_size(), 5);
    assert_eq!(codec.name(), "delta");
    assert!(codec.is_invertible());
}

#[test]
fn delta_empty_input_errors() {
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    assert_eq!(codec.transduce(&[]).unwrap_err(), CodecError::EmptyInput);
}

#[test]
fn delta_digit_outside_base_errors() {
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    let error = codec.transduce(&glyphs(&[0, 1, 7])).unwrap_err();
    assert_eq!(error, CodecError::ValueOutsideBase { value: 7, base: 5 });
}

#[test]
fn identity_round_trips() {
    assert!(codec_round_trip_ok(
        &AnyCodec::Identity,
        &glyphs(&[3, 1, 4, 1, 0])
    ));
}

#[test]
fn fixed_grouping_round_trips_on_full_multiple() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    assert!(codec_round_trip_ok(&codec, &glyphs(&[4, 4, 4, 1, 2, 3])));
    // LSB ungroup must also reproduce its input.
    let lsb = AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Lsb,
        stride: 3,
    });
    assert!(codec_round_trip_ok(&lsb, &glyphs(&[1, 2, 3, 0, 4, 2])));
}

#[test]
fn fixed_grouping_partial_group_is_honest_false() {
    // A trailing partial group makes transduce error, so the round-trip is an
    // honest false (the codec is lossy on this input).
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    assert!(!codec_round_trip_ok(&codec, &glyphs(&[4, 4, 4, 1, 2])));
}

#[test]
fn delta_round_trips_on_c5_walk() {
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    assert!(codec_round_trip_ok(
        &codec,
        &glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2])
    ));
}

#[test]
fn delta_then_fixed_grouping_round_trips() {
    // Delta differences then groups the move stream; re-expand ungroups then
    // re-integrates from the seed. Length of the move stream (walk.len()-1)
    // must be a multiple of group_len for the grouping to be lossless.
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 5,
            order: DigitOrder::Msb,
            stride: 2,
        })),
    });
    // 11-symbol walk -> 10 moves -> 5 grouped values (even); round-trips.
    assert!(codec_round_trip_ok(
        &codec,
        &glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2])
    ));
}

#[test]
fn alphabet_size_sanity_rejects_small_identity_and_accepts_wide_grouping() {
    // Identity over 5 or 12 symbols cannot host 29-letter English.
    assert!(!output_alphabet_hosts_language(
        &AnyCodec::Identity,
        5,
        DEFAULT_LANGUAGE_ALPHABET_SIZE
    ));
    assert!(!output_alphabet_hosts_language(
        &AnyCodec::Identity,
        12,
        DEFAULT_LANGUAGE_ALPHABET_SIZE
    ));
    // Identity over the 83-symbol eyes is already wide enough.
    assert!(output_alphabet_hosts_language(
        &AnyCodec::Identity,
        83,
        DEFAULT_LANGUAGE_ALPHABET_SIZE
    ));
    // A base-6 pair grouping (6^2 = 36 >= 29) can host the language.
    let grouping = AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 2,
        base: 6,
        order: DigitOrder::Msb,
        stride: 2,
    });
    assert!(output_alphabet_hosts_language(
        &grouping,
        6,
        DEFAULT_LANGUAGE_ALPHABET_SIZE
    ));
}

#[test]
fn fixed_grouping_emitting_above_82_is_flagged_for_eye_consumer() {
    let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
    // [3,1,2] -> 82 (accepted); [4,4,4] -> 124 (raw, rejected by the 0..=82 policy).
    let accepted = crate::ciphers::EYE_READING_ALPHABET_SIZE; // 83
    assert!(!output_exceeds_accepted_alphabet(&codec, &glyphs(&[3, 1, 2]), accepted).unwrap());
    assert!(
        output_exceeds_accepted_alphabet(&codec, &glyphs(&[3, 1, 2, 4, 4, 4]), accepted).unwrap()
    );
}

#[test]
fn horner_usize_overflow_is_output_value_too_wide_not_panic() {
    // base 2 over a 70-digit group doubles the accumulator ~70 times, overflowing
    // usize around step 64. The checked Horner step must surface this as an
    // `OutputValueTooWide` error — never a debug panic or a silent release wrap.
    let codec = AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 70,
        base: 2,
        order: DigitOrder::Msb,
        stride: 70,
    });
    let input = glyphs(&[1; 70]);
    let error = codec.transduce(&input).unwrap_err();
    assert!(
        matches!(error, CodecError::OutputValueTooWide { .. }),
        "expected OutputValueTooWide, got {error:?}"
    );
}

#[test]
fn overlapping_stride_is_not_invertible_and_does_not_round_trip() {
    // stride (2) != group_len (3): an overlapping partition that `ungroup`
    // cannot invert. `is_invertible` now reports this honestly from the config,
    // and `codec_round_trip_ok` short-circuits to false on it.
    let overlapping = AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Msb,
        stride: 2,
    });
    assert!(!overlapping.is_invertible());
    assert!(!codec_round_trip_ok(
        &overlapping,
        &glyphs(&[1, 2, 3, 0, 4, 2])
    ));

    // A non-overlapping (`stride == group_len`) grouping stays invertible.
    assert!(AnyCodec::FixedGrouping(honeycomb_grouping()).is_invertible());
}

#[test]
fn enumerate_codecs_lists_groupings_and_dedupes_unit_group() {
    // No delta, both orders, base 5, group_len 1..=3.
    let search = CodecSearch {
        max_group_len: 3,
        try_delta: false,
        try_binary_move: false,
        try_fractionation: false,
        orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
        seed: 0,
    };
    let codecs = enumerate_codecs(&search, 5);
    // group_len 1 -> a single Identity (order-agnostic, deduped); group_len 2
    // and 3 -> one grouping per order. 1 + 2 + 2 = 5 codecs.
    assert_eq!(codecs.len(), 5);
    assert_eq!(codecs.first(), Some(&AnyCodec::Identity));
    assert!(codecs.contains(&AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Msb,
        stride: 3,
    })));
    // group_len 1 appears exactly once despite two orders requested.
    assert_eq!(
        codecs
            .iter()
            .filter(|codec| **codec == AnyCodec::Identity)
            .count(),
        1
    );
}

#[test]
fn cli_codec_helpers_expose_default_search_and_honeycomb() {
    // The CLI `--codec-search` default: group_len 1..=3, both orders, delta on.
    let search = default_codec_search(0x1234);
    assert_eq!(search.max_group_len, DEFAULT_CODEC_SEARCH_MAX_GROUP_LEN);
    assert!(search.try_delta);
    // binary-move on by default (makes puzzle `one`'s C5 walk testable);
    // fractionation off by default (see `default_codec_search` / CODEC-RESULTS.md).
    assert!(search.try_binary_move);
    assert!(!search.try_fractionation);
    assert_eq!(search.orders, vec![DigitOrder::Msb, DigitOrder::Lsb]);
    assert_eq!(search.seed, 0x1234);

    // The CLI `--codec honeycomb` selector is the base-5 trigram grouping.
    assert_eq!(
        honeycomb_codec(),
        AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Msb,
            stride: 3,
        })
    );
    assert_eq!(resolved_output_alphabet_size(&honeycomb_codec(), 5), 125);
}

#[test]
fn enumerate_codecs_wraps_delta_when_requested() {
    let search = CodecSearch {
        max_group_len: 3,
        try_delta: true,
        try_binary_move: false,
        try_fractionation: false,
        orders: vec![DigitOrder::Msb],
        seed: 0,
    };
    let codecs = enumerate_codecs(&search, 5);
    // delta off: Identity, FixedGrouping{2}, FixedGrouping{3} (3 codecs).
    // delta on: Delta{Identity}, Delta{FixedGrouping{2}}, Delta{FixedGrouping{3}}.
    assert_eq!(codecs.len(), 6);
    // The +/-1-C5 hint: Delta over the base-5 trigram grouping is enumerated,
    // and its resolved output alphabet (the inner grouping's 5^3) hosts the
    // language while a pure Delta-of-Identity (resolved 5) does not.
    let delta_trigram = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Msb,
            stride: 3,
        })),
    });
    assert!(codecs.contains(&delta_trigram));
    assert_eq!(resolved_output_alphabet_size(&delta_trigram, 5), 125);
    let delta_identity = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    assert!(codecs.contains(&delta_identity));
    assert_eq!(resolved_output_alphabet_size(&delta_identity, 5), 5);
}

// Project codec: channels, lossiness, the binary-move reading, the enum appends.
#[test]
fn project_keeps_residue_and_quotient_channels() {
    // base 12 -> residue mod 3 (puzzle two's r-channel): v % 3, base 3.
    let residue = AnyCodec::Project(ProjectCodec {
        input_base: 12,
        output_base: 3,
        op: ProjectionOp::Modulo,
        then: Box::new(AnyCodec::Identity),
    });
    assert_eq!(
        residue.transduce(&glyphs(&[0, 1, 2, 3, 4, 5, 11])).unwrap(),
        glyphs(&[0, 1, 2, 0, 1, 2, 2])
    );
    assert_eq!(residue.name(), "project");
    assert_eq!(resolved_output_alphabet_size(&residue, 12), 3);

    // base 12 -> quotient div 3 (puzzle two's q-channel): v / 3, base 4.
    let quotient = AnyCodec::Project(ProjectCodec {
        input_base: 12,
        output_base: 4,
        op: ProjectionOp::Div { divisor: 3 },
        then: Box::new(AnyCodec::Identity),
    });
    assert_eq!(
        quotient.transduce(&glyphs(&[0, 3, 6, 9, 11])).unwrap(),
        glyphs(&[0, 1, 2, 3, 3])
    );
    assert_eq!(resolved_output_alphabet_size(&quotient, 12), 4);
}

#[test]
fn project_symbol_outside_input_base_errors() {
    let codec = AnyCodec::Project(ProjectCodec {
        input_base: 5,
        output_base: 2,
        op: ProjectionOp::Modulo,
        then: Box::new(AnyCodec::Identity),
    });
    assert_eq!(
        codec.transduce(&glyphs(&[0, 5])).unwrap_err(),
        CodecError::ValueOutsideBase { value: 5, base: 5 }
    );
}

#[test]
fn project_is_lossy_and_breaks_delta_invertibility() {
    // A projection discards the complementary channel -> never invertible (lossy);
    // round-trip is an honest false (`candidate_survives` does not require it).
    let project = AnyCodec::Project(ProjectCodec {
        input_base: 5,
        output_base: 2,
        op: ProjectionOp::Modulo,
        then: Box::new(AnyCodec::Identity),
    });
    assert!(!project.is_invertible());
    assert!(!codec_round_trip_ok(&project, &glyphs(&[0, 1, 2, 3, 4])));

    // Delta over Identity stays invertible; Delta over a lossy Project does not.
    let delta_identity = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Identity),
    });
    assert!(delta_identity.is_invertible());
    let delta_project = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(project),
    });
    assert!(!delta_project.is_invertible());
    assert!(!codec_round_trip_ok(
        &delta_project,
        &glyphs(&[0, 1, 2, 3, 4, 0])
    ));
}

#[test]
fn binary_move_codec_groups_c5_walk_into_base32() {
    // Puzzle one: Delta -> Project{mod 2} -> base-2 group of 5 bits -> base-32 symbol.
    let codec = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Project(ProjectCodec {
            input_base: 5,
            output_base: 2,
            op: ProjectionOp::Modulo,
            then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 5,
                base: 2,
                order: DigitOrder::Msb,
                stride: 5,
            })),
        })),
    });
    // 11-symbol walk -> moves [1;5, 4;5] -> bits [1;5, 0;5] -> 2 symbols [31, 0].
    let walk = glyphs(&[0, 1, 2, 3, 4, 0, 4, 3, 2, 1, 0]);
    assert_eq!(
        codec.transduce(&walk).unwrap(),
        glyphs(&[0b1_1111, 0b0_0000])
    );
    assert_eq!(resolved_output_alphabet_size(&codec, 5), 32); // 2^5, hosts language
    assert!(!codec.is_invertible());
}

#[test]
fn enumerate_codecs_appends_binary_move_codecs() {
    let search = CodecSearch {
        max_group_len: 3,
        try_delta: false,
        try_binary_move: true,
        try_fractionation: false,
        orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
        seed: 0,
    };
    let codecs = enumerate_codecs(&search, 5);
    // Top level (delta off) = 5 codecs; appended: one per BINARY_MOVE_GROUP_LENS.
    assert_eq!(codecs.len(), 5 + BINARY_MOVE_GROUP_LENS.len());
    let bm5 = AnyCodec::Delta(DeltaCodec {
        base: 5,
        then: Box::new(AnyCodec::Project(ProjectCodec {
            input_base: 5,
            output_base: 2,
            op: ProjectionOp::Modulo,
            then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 5,
                base: 2,
                order: DigitOrder::Msb,
                stride: 5,
            })),
        })),
    });
    assert!(codecs.contains(&bm5));
    assert_eq!(resolved_output_alphabet_size(&bm5, 5), 32);
    assert!(!codecs.iter().any(|c| matches!(c, AnyCodec::Project(_))));
}

#[test]
fn enumerate_codecs_appends_fractionation_channels() {
    let search = CodecSearch {
        max_group_len: 2,
        try_delta: false,
        try_binary_move: false,
        try_fractionation: true,
        orders: vec![DigitOrder::Msb],
        seed: 0,
    };
    let codecs = enumerate_codecs(&search, 12);
    // 12's base-6 pair grouping (6^2 = 36) is reachable as the d=6 residue (Modulo)
    // and the d=2 quotient (Div).
    let frac_mod6_pair = AnyCodec::Project(ProjectCodec {
        input_base: 12,
        output_base: 6,
        op: ProjectionOp::Modulo,
        then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 6,
            order: DigitOrder::Msb,
            stride: 2,
        })),
    });
    let frac_div2_pair = AnyCodec::Project(ProjectCodec {
        input_base: 12,
        output_base: 6,
        op: ProjectionOp::Div { divisor: 2 },
        then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 6,
            order: DigitOrder::Msb,
            stride: 2,
        })),
    });
    assert!(codecs.contains(&frac_mod6_pair));
    assert!(codecs.contains(&frac_div2_pair));
    assert_eq!(resolved_output_alphabet_size(&frac_mod6_pair, 12), 36);
    assert!(
        codecs
            .iter()
            .all(|c| !matches!(c, AnyCodec::Project(p) if p.output_base < 2))
    );
}
