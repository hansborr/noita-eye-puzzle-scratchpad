//! Post-search audit and classification for hidden-base local recovery.

use super::super::{
    HiddenBaseSurfaceReport, KnownPlaintextPair, LymmDeckError, LymmDeckSpec,
    audit_hidden_base_mapping,
};
use super::{HiddenBaseLocalRecoveredKey, HiddenBaseLocalRecoveryState};

pub(super) fn representative_audit(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    key: Option<&HiddenBaseLocalRecoveredKey>,
    swap_budget: usize,
    planted_base: Option<&[usize]>,
) -> Result<Option<HiddenBaseSurfaceReport>, LymmDeckError> {
    let Some(key) = key else {
        return Ok(None);
    };
    let audit_spec = LymmDeckSpec::from_base(
        spec.n,
        &spec.pt_alphabet.iter().collect::<String>(),
        &spec.ct_alphabet.iter().collect::<String>(),
        key.base.clone(),
    )?;
    audit_hidden_base_mapping(
        &audit_spec,
        pairs,
        &key.pt_mapping,
        swap_budget,
        planted_base,
    )
    .map(Some)
}

pub(super) fn classify_recovery(
    exact_candidate_count: usize,
    planted_base_recovered: Option<bool>,
    representative_audit: Option<&HiddenBaseSurfaceReport>,
) -> HiddenBaseLocalRecoveryState {
    if exact_candidate_count == 0 {
        return HiddenBaseLocalRecoveryState::SearchCapExceeded;
    }
    if exact_candidate_count > 1
        || representative_audit.is_some_and(|audit| audit.base_candidate_count > 1)
    {
        return HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass;
    }
    if planted_base_recovered == Some(true) {
        HiddenBaseLocalRecoveryState::RecoveredPlantedBase
    } else {
        HiddenBaseLocalRecoveryState::RecoveredEquivalentKey
    }
}

pub(super) fn factorial_u128(n: usize) -> Option<u128> {
    let mut value = 1u128;
    for factor in 2..=n {
        value = value.checked_mul(u128::try_from(factor).ok()?)?;
    }
    Some(value)
}
