use super::{
    AGREEMENT_CHECKS, ALPHABET_SIZE, AglGakAgreementCheck, AglGakError,
    AglGakFixedPointEnumeration, AglGakForwardSimulation, AglGakPositiveControls,
    AglMultiplierSubgroup, CONTROL_FIXED_POINT,
};
use crate::ciphers::{
    agl_apply, agl_compose, agl_coset_symbol, agl_inverse, mul_inverse_mod, quadratic_residues_mod,
    sub_mod,
};
use crate::nulls::null::{SplitMix64, add_one_p_value, mix_seed, random_index_below};

pub(super) fn validate_positive_controls(
    subgroup: AglMultiplierSubgroup,
    controls: AglGakPositiveControls,
) -> Result<(), AglGakError> {
    if !controls.constant_shared_run_ok {
        return Err(AglGakError::PositiveControlFailed {
            which: subgroup_control_name(subgroup, "constant shared run"),
        });
    }
    if !controls.pure_translation_rejected_ok {
        return Err(AglGakError::PositiveControlFailed {
            which: subgroup_control_name(subgroup, "pure translation"),
        });
    }
    Ok(())
}

pub(super) fn fixed_point_enumeration(
    subgroup: AglMultiplierSubgroup,
) -> AglGakFixedPointEnumeration {
    let mut discrepancies = 0usize;
    let mut fixing_at_least_two_points = 0usize;
    let mut max_fixed_points = 0usize;
    for multiplier in subgroup_multipliers(subgroup) {
        for translation in 1..ALPHABET_SIZE {
            discrepancies += 1;
            let fixed = fixed_point_count((multiplier, translation));
            if fixed >= 2 {
                fixing_at_least_two_points += 1;
            }
            max_fixed_points = max_fixed_points.max(fixed);
        }
    }
    AglGakFixedPointEnumeration {
        discrepancies,
        fixing_at_least_two_points,
        max_fixed_points,
    }
}

pub(super) fn agreement_check(
    seed: u64,
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakAgreementCheck, AglGakError> {
    let multipliers = subgroup_multipliers(subgroup);
    let mut rng = SplitMix64::new(mix_seed(seed, subgroup_tag(subgroup) ^ 0x6167_7265_6500));
    let mut violations = 0usize;
    for _trial in 0..AGREEMENT_CHECKS {
        let discrepancy = random_differing_discrepancy(&multipliers, &mut rng)?;
        let context = random_group_element(&multipliers, &mut rng)?;
        let point = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let agreement = point
            == agl_coset_symbol(
                agl_compose(discrepancy, context, ALPHABET_SIZE),
                0,
                ALPHABET_SIZE,
            );
        let fixes = agl_apply(discrepancy, point, ALPHABET_SIZE) == point;
        if agreement != fixes {
            violations += 1;
        }
    }
    Ok(AglGakAgreementCheck {
        checks: AGREEMENT_CHECKS,
        violations,
    })
}

pub(super) fn forward_simulation(
    seed: u64,
    trials: usize,
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakForwardSimulation, AglGakError> {
    let multipliers = subgroup_multipliers(subgroup);
    let mut rng = SplitMix64::new(mix_seed(
        seed,
        subgroup_tag(subgroup) ^ 0x6677_645f_7369_6d00,
    ));
    let mut varying_shared_runs = 0usize;
    for _trial in 0..trials {
        let discrepancy = random_differing_discrepancy(&multipliers, &mut rng)?;
        if simulated_varying_shared_run(discrepancy, &multipliers, &mut rng)? {
            varying_shared_runs += 1;
        }
    }
    Ok(AglGakForwardSimulation {
        trials,
        varying_shared_runs,
        add_one_p_value: add_one_p_value(varying_shared_runs, trials),
    })
}

fn simulated_varying_shared_run(
    discrepancy: (usize, usize),
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<bool, AglGakError> {
    // Collect the agreed-prefix values BEFORE the break, then test whether that
    // shared prefix (of length >= 2) varies. The empirical note
    // (thread-2-empirical.md:96) defines the sampled event as "varying shared
    // runs of length >= 2"; counting only a full-length-3 varying agreement
    // would silently lean on the very theorem this enumeration is meant to
    // corroborate (a varying length-2 agreement is algebraically impossible, so
    // a length-2 prefix that breaks at step 3 must be registered for the null to
    // match the note's definition rather than assume the result).
    let mut context = (1, 0);
    let mut shared_values = Vec::with_capacity(3);
    for _step in 0..3 {
        let element = random_group_element(multipliers, rng)?;
        context = agl_compose(context, element, ALPHABET_SIZE);
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left != right {
            break;
        }
        shared_values.push(left);
    }
    Ok(shared_values.len() >= 2 && run_is_varying(&shared_values))
}

pub(super) fn positive_controls(
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakPositiveControls, AglGakError> {
    let multiplier = control_multiplier(subgroup)?;
    let fixed_point = CONTROL_FIXED_POINT;
    let translation = sub_mod(
        fixed_point,
        (multiplier * fixed_point) % ALPHABET_SIZE,
        ALPHABET_SIZE,
    );
    let discrepancy = (multiplier, translation);
    let recovered_fixed_point = fixed_point_of(discrepancy);
    let constant_shared_run_ok = recovered_fixed_point == Some(fixed_point)
        && constant_control_forward(discrepancy, fixed_point);
    let pure_translation_rejected_ok = pure_translation_has_no_agreement(subgroup);
    Ok(AglGakPositiveControls {
        constant_shared_run_ok,
        pure_translation_rejected_ok,
        recovered_fixed_point,
    })
}

fn constant_control_forward(discrepancy: (usize, usize), fixed_point: usize) -> bool {
    let Some(inverse) = agl_inverse(discrepancy, ALPHABET_SIZE) else {
        return false;
    };
    if agl_compose(discrepancy, inverse, ALPHABET_SIZE) != (1, 0) {
        return false;
    }
    let mut context = (1, 0);
    let mut values = Vec::new();
    for step in 0..6 {
        let element = if step == 0 { (1, fixed_point) } else { (1, 0) };
        context = agl_compose(context, element, ALPHABET_SIZE);
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left != right {
            return false;
        }
        values.push(left);
    }
    values.iter().all(|&value| value == fixed_point)
}

fn pure_translation_has_no_agreement(subgroup: AglMultiplierSubgroup) -> bool {
    let discrepancy = (1, 1);
    for context in group_elements(subgroup) {
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left == right {
            return false;
        }
    }
    fixed_point_of(discrepancy).is_none()
}

fn fixed_point_count(element: (usize, usize)) -> usize {
    (0..ALPHABET_SIZE)
        .filter(|&point| agl_apply(element, point, ALPHABET_SIZE) == point)
        .count()
}

fn fixed_point_of(element: (usize, usize)) -> Option<usize> {
    let denom = sub_mod(1, element.0, ALPHABET_SIZE);
    if denom == 0 {
        return None;
    }
    let inv = mul_inverse_mod(denom, ALPHABET_SIZE)?;
    Some(((element.1 % ALPHABET_SIZE) * inv) % ALPHABET_SIZE)
}

fn subgroup_multipliers(subgroup: AglMultiplierSubgroup) -> Vec<usize> {
    match subgroup {
        AglMultiplierSubgroup::Full => (1..ALPHABET_SIZE).collect(),
        AglMultiplierSubgroup::QuadraticResidues => quadratic_residues_mod(ALPHABET_SIZE),
    }
}

fn group_elements(subgroup: AglMultiplierSubgroup) -> Vec<(usize, usize)> {
    let mut elements = Vec::new();
    for multiplier in subgroup_multipliers(subgroup) {
        for translation in 0..ALPHABET_SIZE {
            elements.push((multiplier, translation));
        }
    }
    elements
}

fn random_differing_discrepancy(
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<(usize, usize), AglGakError> {
    let multiplier = random_multiplier(multipliers, rng)?;
    let translation = random_index_below(ALPHABET_SIZE - 1, rng)? + 1;
    Ok((multiplier, translation))
}

fn random_group_element(
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<(usize, usize), AglGakError> {
    Ok((
        random_multiplier(multipliers, rng)?,
        random_index_below(ALPHABET_SIZE, rng)?,
    ))
}

fn random_multiplier(multipliers: &[usize], rng: &mut SplitMix64) -> Result<usize, AglGakError> {
    let index = random_index_below(multipliers.len(), rng)?;
    multipliers
        .get(index)
        .copied()
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL random multiplier lookup",
        })
}

fn control_multiplier(subgroup: AglMultiplierSubgroup) -> Result<usize, AglGakError> {
    subgroup_multipliers(subgroup)
        .into_iter()
        .find(|&multiplier| multiplier != 1)
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL control multiplier",
        })
}

pub(super) fn distinct_symbols_in_run(
    stream: &[usize],
    message_key: &'static str,
    start: usize,
    len: usize,
) -> Result<usize, AglGakError> {
    let mut values = Vec::new();
    for value in stream.iter().skip(start).take(len) {
        values.push(*value);
    }
    if values.len() != len {
        return Err(AglGakError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        });
    }
    values.sort_unstable();
    values.dedup();
    Ok(values.len())
}

pub(super) fn predecessor_differs(left: &[usize], right: &[usize], start: usize) -> bool {
    let Some(predecessor) = start.checked_sub(1) else {
        return false;
    };
    match (left.get(predecessor), right.get(predecessor)) {
        (Some(left_value), Some(right_value)) => left_value != right_value,
        _ => false,
    }
}

fn run_is_varying(values: &[usize]) -> bool {
    let Some(first) = values.first() else {
        return false;
    };
    values.iter().any(|value| value != first)
}

pub(super) fn message_index(
    keys: &[&'static str],
    key: &'static str,
) -> Result<usize, AglGakError> {
    keys.iter()
        .position(|candidate| *candidate == key)
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL message key lookup",
        })
}

pub(super) fn stream_at<'a>(
    streams: &'a [Vec<usize>],
    index: usize,
    message_key: &'static str,
) -> Result<&'a [usize], AglGakError> {
    streams
        .get(index)
        .map(Vec::as_slice)
        .ok_or(AglGakError::EmptyMessage { message_key })
}

pub(super) fn subgroups_to_run(preferred: AglMultiplierSubgroup) -> Vec<AglMultiplierSubgroup> {
    match preferred {
        AglMultiplierSubgroup::Full => vec![
            AglMultiplierSubgroup::Full,
            AglMultiplierSubgroup::QuadraticResidues,
        ],
        AglMultiplierSubgroup::QuadraticResidues => vec![
            AglMultiplierSubgroup::QuadraticResidues,
            AglMultiplierSubgroup::Full,
        ],
    }
}

const fn subgroup_tag(subgroup: AglMultiplierSubgroup) -> u64 {
    match subgroup {
        AglMultiplierSubgroup::Full => 0x6338_325f_6675_6c6c,
        AglMultiplierSubgroup::QuadraticResidues => 0x6334_315f_7172_0000,
    }
}

fn subgroup_control_name(subgroup: AglMultiplierSubgroup, control: &'static str) -> &'static str {
    match (subgroup, control) {
        (AglMultiplierSubgroup::Full, "constant shared run") => "C83:C82 constant shared run",
        (AglMultiplierSubgroup::Full, "pure translation") => "C83:C82 pure translation",
        (AglMultiplierSubgroup::QuadraticResidues, "constant shared run") => {
            "C83:C41 constant shared run"
        }
        (AglMultiplierSubgroup::QuadraticResidues, "pure translation") => {
            "C83:C41 pure translation"
        }
        _ => "unknown AGL-GAK control",
    }
}
