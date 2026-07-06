use super::{
    CertificateReport, DigitChange, DigitWindow, FirstBreak, PerturbationError, PerturbedMessage,
    certify, double_digit_perturbations, message_values_for_variant, perturbations,
    single_digit_perturbations,
};
use crate::analysis::{orders, perturbation};
use crate::core::trigram::TrigramValue;
use crate::data::corpus::messages;

#[test]
fn single_digit_variants_count_and_order_are_pinned() {
    let window = DigitWindow {
        message: 0,
        start: 0,
        len: 3,
    };
    let variants: Vec<_> = single_digit_perturbations(window).unwrap().collect();

    assert_eq!(variants.len(), 12);
    assert_eq!(
        variant_at(&variants, 0).changes,
        vec![DigitChange {
            message: 0,
            message_key: "east1",
            digit_index: 0,
            raw_index: 0,
            old: 2,
            new: 0,
        }]
    );
    assert_eq!(
        change_at(variant_at(&variants, 3), 0),
        DigitChange {
            message: 0,
            message_key: "east1",
            digit_index: 0,
            raw_index: 0,
            old: 2,
            new: 4,
        }
    );
    assert_eq!(change_at(variant_at(&variants, 4), 0).digit_index, 1);
    assert_ne!(
        variant_at(&variants, 4).digits,
        messages().first().unwrap().digits
    );
}

#[test]
fn double_digit_variants_are_counted_and_guarded() {
    let small = DigitWindow {
        message: 0,
        start: 0,
        len: 3,
    };
    let doubles: Vec<_> = double_digit_perturbations(small).unwrap().collect();
    assert_eq!(doubles.len(), 48);

    let combined = perturbations(small, 2).unwrap();
    assert_eq!(combined.len(), 60);

    let too_large = DigitWindow {
        message: 0,
        start: 0,
        len: 9,
    };
    assert_eq!(
        perturbations(too_large, 2),
        Err(PerturbationError::DoublePerturbationExplosion {
            variants: 576,
            limit: perturbation::MAX_DOUBLE_PERTURBATIONS,
            positions: 9,
        })
    );
}

#[test]
fn certify_reports_first_break() {
    let window = DigitWindow {
        message: 0,
        start: 0,
        len: 1,
    };
    let original_values = orders::read_corpus_message_values(
        &orders::corpus_grids().unwrap(),
        orders::accepted_honeycomb_order(),
    )
    .unwrap();
    let original_first = value_at(&original_values, 0, 0);

    let report = certify(window, 1, |messages| {
        value_at(messages, 0, 0) == original_first
    })
    .unwrap();

    assert_eq!(
        report,
        CertificateReport {
            window,
            max_changes: 1,
            total_variants: 4,
            holding_variants: 0,
            first_break: Some(FirstBreak {
                variant_index: 0,
                changes: vec![DigitChange {
                    message: 0,
                    message_key: "east1",
                    digit_index: 0,
                    raw_index: 0,
                    old: 2,
                    new: 0,
                }],
            }),
        }
    );
}

#[test]
fn variants_rebuild_through_the_reading_order() {
    let window = DigitWindow {
        message: 0,
        start: 0,
        len: 1,
    };
    let first_variant = single_digit_perturbations(window).unwrap().next().unwrap();
    let values = message_values_for_variant(&first_variant).unwrap();

    assert_eq!(values.len(), 9);
    assert_eq!(values.first().unwrap().len(), 99);
    assert_eq!(value_at(&values, 0, 0).get(), 0);
}

fn variant_at(variants: &[PerturbedMessage], index: usize) -> &PerturbedMessage {
    match variants.get(index) {
        Some(variant) => variant,
        None => panic!("missing variant {index}"),
    }
}

fn change_at(variant: &PerturbedMessage, index: usize) -> DigitChange {
    match variant.changes.get(index) {
        Some(change) => *change,
        None => panic!("missing change {index}"),
    }
}

fn value_at(messages: &[Vec<TrigramValue>], message: usize, offset: usize) -> TrigramValue {
    *messages
        .get(message)
        .and_then(|values| values.get(offset))
        .unwrap()
}
