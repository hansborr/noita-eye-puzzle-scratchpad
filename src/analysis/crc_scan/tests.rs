use super::{
    DEFAULT_SEED, HASH_VARIANTS, HashVariant, LUMIKKI_BZIP2_RAW, LUMIKKI_STORED_VALUE,
    LUMIKKI_WORD, OutputByteOrder, TargetCatalog, config_count, parse_target_text, run_scan,
    run_self_test,
};

#[test]
fn crc_catalogue_check_values_for_123456789() {
    let input = b"123456789";
    let expected = [
        (HashVariant::Crc32IsoHdlc, 0xcbf4_3926),
        (HashVariant::Crc32Bzip2, 0xfc89_1918),
        (HashVariant::Crc32Mpeg2, 0x0376_e6e7),
        (HashVariant::Crc32Posix, 0x765e_7680),
        (HashVariant::Crc32Jamcrc, 0x340b_c6d9),
        (HashVariant::Crc32Xfer, 0xbd0b_e338),
        (HashVariant::Crc32C, 0xe306_9283),
        (HashVariant::Crc32D, 0x8731_5576),
        (HashVariant::Crc32Q, 0x3010_bf7f),
    ];
    for (variant, value) in expected {
        assert_eq!(variant.digest(input), value, "{variant}");
    }
}

#[test]
fn lumikki_bzip2_positive_control_matches_stored_value() {
    let raw = HashVariant::Crc32Bzip2.digest(LUMIKKI_WORD.as_bytes());
    assert_eq!(raw, LUMIKKI_BZIP2_RAW);
    assert_eq!(
        OutputByteOrder::ByteReversed.apply(raw),
        LUMIKKI_STORED_VALUE
    );
}

#[test]
fn digest_config_count_is_precommitted() {
    assert_eq!(HASH_VARIANTS.len(), 14);
    assert_eq!(config_count(), 28);
}

#[test]
fn parser_accepts_pairs_and_standalone_hex_values() {
    let catalog =
        parse_target_text("[0x5634505c, 0xacf68674]\n\ndeadbeef\n").expect("valid target text");
    assert_eq!(catalog.pair_count(), 1);
    assert_eq!(catalog.stored_u32_count(), 3);
    assert_eq!(catalog.unique_nonzero_u32_count(), 3);
    assert!(catalog.contains(0xacf6_8674));
    assert!(catalog.contains(0xdead_beef));
}

#[test]
fn scan_recovers_lumikki_in_engine_targets() {
    let words = vec![LUMIKKI_WORD.to_owned()];
    let targets = TargetCatalog::from_engine_messages();
    let report = run_scan(&words, &targets, 8, DEFAULT_SEED).expect("scan succeeds");
    assert_eq!(report.statistical_hit_count, 1);
    assert!(report.matches.iter().any(|hit| {
        hit.word == LUMIKKI_WORD
            && hit.variant == HashVariant::Crc32Bzip2
            && hit.output_order == OutputByteOrder::ByteReversed
            && hit.stored_value == LUMIKKI_STORED_VALUE
            && hit.location.message_index == 0
            && hit.location.position == 0
    }));
}

#[test]
fn self_test_passes_positive_control_and_null_agreement() {
    let report = run_self_test(8, DEFAULT_SEED).expect("self-test runs");
    assert!(report.crc_math_passed);
    assert!(report.planted_recovery_passed);
    assert!(report.null_agrees);
    assert!(report.passed());
}
