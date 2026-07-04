//! Shared state-transition helpers for swap recovery.

use super::super::{LymmComposeDirection, LymmDeckError, LymmDeckSpec, compose_lymm};
use super::SwapRecoveryError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ForcedObservation {
    pub(super) entry: usize,
    pub(super) target: usize,
}

pub(super) fn forced_observation(
    spec: &LymmDeckSpec,
    state: &[usize],
    ct_value: usize,
) -> Result<ForcedObservation, SwapRecoveryError> {
    match spec.compose_dir {
        LymmComposeDirection::Left => Ok(ForcedObservation {
            entry: spec.emit_index,
            target: inverse_position(state, ct_value)?,
        }),
        LymmComposeDirection::Right => {
            if ct_value >= spec.n {
                return Err(LymmDeckError::EmitIndexOutOfRange {
                    emit_index: ct_value,
                    n: spec.n,
                }
                .into());
            }
            let entry =
                state
                    .get(spec.emit_index)
                    .copied()
                    .ok_or(LymmDeckError::EmitIndexOutOfRange {
                        emit_index: spec.emit_index,
                        n: state.len(),
                    })?;
            Ok(ForcedObservation {
                entry,
                target: ct_value,
            })
        }
    }
}

pub(super) fn apply_recovered_permutation(
    spec: &LymmDeckSpec,
    perm: &[usize],
    state: &[usize],
) -> Result<Vec<usize>, SwapRecoveryError> {
    Ok(match spec.compose_dir {
        LymmComposeDirection::Left => compose_lymm(perm, state),
        LymmComposeDirection::Right => compose_lymm(state, perm),
    }
    .map_err(LymmDeckError::from)?)
}

pub(super) fn inverse_position(state: &[usize], value: usize) -> Result<usize, LymmDeckError> {
    state
        .iter()
        .position(|&candidate| candidate == value)
        .ok_or(LymmDeckError::EmitIndexOutOfRange {
            emit_index: value,
            n: state.len(),
        })
}
