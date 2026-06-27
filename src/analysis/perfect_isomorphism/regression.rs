//! Pinned wiki gap-pattern regression checks, the positive control, and the
//! synthetic short-island internal-violation fixture.

use crate::analysis::isomorph::PatternSignature;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::stateless_splitmix;

use super::breaks::{PairSlice, all_in_stutter_family, classify_break, range_overlap};
use super::catalog::{
    CatalogRecord, build_catalog_records, localize_extents, render_gap_signature,
    strong_repeat_catalog_records,
};
use super::{
    BreakClass, BreakLocalization, CATALOG_WINDOWS, IsomorphSignificance, MAIN_ISOMORPH_W9,
    MAIN_ISOMORPH_W11, POSITIVE_CONTROL_MIN_MARGIN, POSITIVE_CONTROL_TAG, POST_MIN,
    PerfectIsomorphismError, WikiRegressionCheck, WikiRegressionResult,
};

pub(super) fn run_regression_checks(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[CatalogRecord],
    breaks: &[BreakLocalization],
) -> Result<Vec<WikiRegressionResult>, PerfectIsomorphismError> {
    Ok(vec![
        regression_3a(keys, message_values)?,
        regression_3b(keys, message_values, breaks)?,
        regression_3c(),
        regression_main_isomorph(records),
    ])
}

fn regression_3a(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<WikiRegressionResult, PerfectIsomorphismError> {
    let expected = vec![
        "A..BC.D....AB.......DC...".to_owned(),
        "A..BC.D....AB.......DC..D".to_owned(),
        "Boundary@24".to_owned(),
    ];
    let top = fixed_span_signature(
        keys,
        message_values,
        "east1",
        1,
        25,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let bottom = fixed_span_signature(
        keys,
        message_values,
        "west1",
        1,
        25,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let break_row = fixed_break_classification(
        keys,
        message_values,
        "east1",
        "west1",
        1,
        24,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let produced = vec![top, bottom, break_label(&break_row)];
    let reproduced = produced == expected;
    Ok(WikiRegressionResult {
        check: WikiRegressionCheck::Messages12SharedAllomorph,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    })
}

fn regression_3b(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    breaks: &[BreakLocalization],
) -> Result<WikiRegressionResult, PerfectIsomorphismError> {
    let expected = vec![
        ".AB......B.A".to_owned(),
        ".AB......B.A".to_owned(),
        ".AB......B.A".to_owned(),
        "msg7 O-repeat @10/16/26".to_owned(),
        "no InternalCandidate in fixed 7/8/9 region".to_owned(),
    ];
    let produced = vec![
        fixed_span_signature(
            keys,
            message_values,
            "east4",
            50,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        fixed_span_signature(
            keys,
            message_values,
            "west4",
            52,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        fixed_span_signature(
            keys,
            message_values,
            "east5",
            51,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        msg7_extra_repeat_claim(keys, message_values)?,
        stutter_region_internal_claim(breaks),
    ];
    let reproduced = produced == expected;
    Ok(WikiRegressionResult {
        check: WikiRegressionCheck::Messages789ExtraRepeat,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    })
}

fn regression_3c() -> WikiRegressionResult {
    let row = "+++++xxxxx?????x++++++++++++".to_owned();
    WikiRegressionResult {
        check: WikiRegressionCheck::CorruptionTheoryBound,
        produced: vec![row.clone()],
        expected: vec![row],
        reproduced: true,
        hypothesis_label:
            "fixed cited annotation from Allomorphs.md; conditional on single-deletion assumption; bounds where a difference must be, does not locate it"
                .to_owned(),
    }
}

fn regression_main_isomorph(records: &[CatalogRecord]) -> WikiRegressionResult {
    let produced = records
        .iter()
        .find(|record| record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
        .map_or_else(Vec::new, |record| {
            vec![
                record.rendered.clone(),
                record.occurrences.len().to_string(),
            ]
        });
    let expected = vec![MAIN_ISOMORPH_W9.to_owned(), "6".to_owned()];
    let reproduced = produced == expected;
    WikiRegressionResult {
        check: WikiRegressionCheck::MainIsomorphPositiveControl,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    }
}

pub(super) fn ensure_all_regressions_reproduced(
    regression: &[WikiRegressionResult],
) -> Result<(), PerfectIsomorphismError> {
    for result in regression {
        if !result.reproduced {
            return Err(PerfectIsomorphismError::RegressionCheckFailed {
                check: result.check,
            });
        }
    }
    Ok(())
}

pub(super) fn run_positive_control(
    records: &[CatalogRecord],
    significance: &[IsomorphSignificance],
    breaks: &[BreakLocalization],
) -> Result<(), PerfectIsomorphismError> {
    let Some(record) = records
        .iter()
        .find(|record| record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 signature missing".to_owned(),
        });
    };
    let Some(row) = significance
        .iter()
        .find(|row| row.window == 9 && row.signature == MAIN_ISOMORPH_W9)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 significance row missing".to_owned(),
        });
    };
    let Some(w11_row) = significance
        .iter()
        .find(|row| row.window == 11 && row.signature == MAIN_ISOMORPH_W11)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w11 significance row missing".to_owned(),
        });
    };
    if !row.strong
        || row.observed_occurrences != 6
        || row.observed_occurrences < row.null_max_occurrences + POSITIVE_CONTROL_MIN_MARGIN
    {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 signature did not clear the strong matched-null margin".to_owned(),
        });
    }
    if !w11_row.strong
        || w11_row.observed_occurrences != 4
        || w11_row.observed_occurrences < w11_row.null_max_occurrences + POSITIVE_CONTROL_MIN_MARGIN
    {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w11 signature did not clear the strong matched-null margin".to_owned(),
        });
    }
    if breaks.iter().any(|break_row| {
        main_isomorph_break(record, break_row) && break_row.class == BreakClass::InternalCandidate
    }) {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 trailing divergence classified as internal".to_owned(),
        });
    }
    if !synthetic_internal_violation_fires()? {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "synthetic short-island internal violation was not detected".to_owned(),
        });
    }
    Ok(())
}

fn main_isomorph_break(record: &CatalogRecord, break_row: &BreakLocalization) -> bool {
    record.occurrences.iter().any(|occurrence| {
        occurrence.key == break_row.pair.0 && occurrence.start >= break_row.anchor.0
    }) && record.occurrences.iter().any(|occurrence| {
        occurrence.key == break_row.pair.1 && occurrence.start >= break_row.anchor.1
    })
}

pub(super) fn synthetic_internal_violation_fires() -> Result<bool, PerfectIsomorphismError> {
    let seed = stateless_splitmix(POSITIVE_CONTROL_TAG);
    let keys = ["synthetic-left", "synthetic-right"];
    let message_values = vec![
        synthetic_values(seed, true)?,
        synthetic_values(seed, false)?,
    ];
    let records = build_catalog_records(&keys, &message_values, &CATALOG_WINDOWS)?;
    let strong = strong_repeat_catalog_records(&records);
    let (breaks, _extents) = localize_extents(&keys, &message_values, &strong, true);
    Ok(breaks.iter().any(|break_row| {
        break_row.class == BreakClass::InternalCandidate
            && break_row.island_cols == 1
            && break_row.far_run >= POST_MIN
    }))
}

fn synthetic_values(
    seed: u64,
    left_variant: bool,
) -> Result<Vec<TrigramValue>, PerfectIsomorphismError> {
    let offset = (seed % 7) as u8;
    let raw_values = if left_variant {
        [
            1 + offset,
            2 + offset,
            3 + offset,
            1 + offset,
            4 + offset,
            2 + offset,
            5 + offset,
            3 + offset,
            6 + offset,
            2 + offset,
            7 + offset,
            8 + offset,
            1 + offset,
            9 + offset,
            10 + offset,
            11 + offset,
            12 + offset,
            13 + offset,
            14 + offset,
            15 + offset,
        ]
    } else {
        [
            31 + offset,
            32 + offset,
            33 + offset,
            31 + offset,
            34 + offset,
            32 + offset,
            35 + offset,
            33 + offset,
            36 + offset,
            37 + offset,
            38 + offset,
            39 + offset,
            31 + offset,
            40 + offset,
            41 + offset,
            42 + offset,
            43 + offset,
            44 + offset,
            45 + offset,
            46 + offset,
        ]
    };
    raw_values
        .into_iter()
        .map(|raw| {
            TrigramValue::new(raw).map_err(|value| PerfectIsomorphismError::PositiveControlFailed {
                detail: format!("synthetic value {value} outside trigram range"),
            })
        })
        .collect()
}

fn fixed_span_signature(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    key: &str,
    start: usize,
    len: usize,
    check: WikiRegressionCheck,
) -> Result<String, PerfectIsomorphismError> {
    let Some(values) = values_for_key(keys, message_values, key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    let Some(window) = values.get(start..start.saturating_add(len)) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    Ok(render_gap_signature(&PatternSignature::from_window(window)))
}

fn fixed_break_classification(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    break_index: usize,
    check: WikiRegressionCheck,
) -> Result<BreakLocalization, PerfectIsomorphismError> {
    let Some(left_values) = values_for_key(keys, message_values, left_key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    let Some(right_values) = values_for_key(keys, message_values, right_key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    Ok(classify_break(PairSlice {
        left_key,
        right_key,
        left_values,
        right_values,
        left_start: start,
        right_start: start,
        prefix_len: break_index,
    }))
}

fn break_label(break_row: &BreakLocalization) -> String {
    format!(
        "{}@{}",
        break_class_label(break_row.class),
        break_row.break_index
    )
}

fn stutter_region_internal_claim(breaks: &[BreakLocalization]) -> String {
    if breaks.iter().any(|break_row| {
        break_row.class == BreakClass::InternalCandidate
            && all_in_stutter_family(break_row.pair.0, break_row.pair.1)
            && break_overlaps_region(break_row, 35, 80)
    }) {
        "InternalCandidate in fixed 7/8/9 region".to_owned()
    } else {
        "no InternalCandidate in fixed 7/8/9 region".to_owned()
    }
}

fn break_overlaps_region(break_row: &BreakLocalization, start: usize, end: usize) -> bool {
    range_overlap(
        break_row.anchor.0 + break_row.break_index,
        break_row.anchor.1 + break_row.break_index,
        start,
        end,
    )
}

fn msg7_extra_repeat_claim(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<String, PerfectIsomorphismError> {
    let Some(values) = values_for_key(keys, message_values, "east4") else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    let absolute_positions = [45usize, 51, 61];
    let mut iter = absolute_positions.into_iter();
    let Some(first_position) = iter.next() else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    let Some(first) = values.get(first_position).copied() else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    if iter.all(|position| values.get(position).copied() == Some(first)) {
        Ok("msg7 O-repeat @10/16/26".to_owned())
    } else {
        Ok("msg7 O-repeat missing".to_owned())
    }
}

fn values_for_key<'a>(
    keys: &[&str],
    message_values: &'a [Vec<TrigramValue>],
    key: &str,
) -> Option<&'a [TrigramValue]> {
    keys.iter()
        .position(|candidate| *candidate == key)
        .and_then(|index| message_values.get(index))
        .map(Vec::as_slice)
}

fn break_class_label(class: BreakClass) -> &'static str {
    match class {
        BreakClass::Boundary => "Boundary",
        BreakClass::InternalCandidate => "InternalCandidate",
        BreakClass::BenignDesync { .. } => "BenignDesync",
    }
}
